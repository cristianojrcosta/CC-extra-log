package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// auditEntry is a structured per-connection record emitted when --audit is
// enabled. It is designed to answer the operational question:
//
//	"Did we receive traffic for R:<port>:<host>:<port>, and was the forward
//	to the target successful?"
//
// One entry is emitted per inbound connection received from the chisel
// tunnel, when that connection terminates.
type auditEntry struct {
	Timestamp   string `json:"timestamp"`
	RouteRule   string `json:"route_rule"`      // original "R:local:host:remote"
	Destination string `json:"destination"`     // resolved "host:port" of target
	SourceAddr  string `json:"source_addr"`     // remote addr of incoming conn (chisel side)
	Success     bool   `json:"success"`         // did dial to target succeed?
	LatencyMs   int64  `json:"latency_ms"`      // time to establish conn to target
	DurationMs  int64  `json:"duration_ms"`     // total connection lifetime
	BytesIn     int64  `json:"bytes_in"`        // bytes from tunnel -> target
	BytesOut    int64  `json:"bytes_out"`       // bytes from target -> tunnel
	Error       string `json:"error,omitempty"` // populated on failure
}

// auditEmitter is the sink for audit entries. Tests override this to capture
// emitted records. The default writes a single tagged line per entry to the
// standard logger so operators can grep / pipe through jq:
//
//	outsystemscc --audit ... 2>&1 | grep '\[audit\]' | sed 's/.*\[audit\] //' | jq .
var auditEmitter = func(e auditEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		log.Printf("[audit] failed to marshal entry: %v", err)
		return
	}
	log.Printf("[audit] %s", string(b))
}

// auditDialTimeout bounds how long we wait when dialing the target host.
// Exposed as a var (rather than a const) so tests can shorten it.
var auditDialTimeout = 30 * time.Second

// auditProxy interposes on a single reverse remote. It accepts connections
// from the chisel client and forwards them to the real target host:port,
// recording a per-connection audit entry on the way.
type auditProxy struct {
	routeRule string       // original remote string, e.g. "R:8081:192.168.0.3:8393"
	target    string       // dial address of the real target, "host:port"
	listener  net.Listener // local TCP listener chisel will dial into
}

// startAuditProxies inspects each remote and, for every reverse TCP remote,
// starts a local proxy on 127.0.0.1:<auto>. It returns a parallel slice of
// remotes with the host/port rewritten to point at the local proxy. The
// original local-port is preserved so that:
//   - validateRemotes' duplicate-port check still applies
//   - generateQueryParameters reports the correct ports to the server
//   - operators see the same R:<local-port>:... values they configured
//
// Non-reverse remotes, UDP remotes, and any remote we cannot parse are
// passed through unchanged with an informational log line.
func startAuditProxies(remotes []string) ([]string, []*auditProxy, error) {
	rewritten := make([]string, 0, len(remotes))
	proxies := make([]*auditProxy, 0, len(remotes))

	for _, r := range remotes {
		spec, ok := parseReverseTCPRemote(r)
		if !ok {
			log.Printf("[audit] skipping non-reverse-TCP remote (passthrough): %s", r)
			rewritten = append(rewritten, r)
			continue
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			// Best-effort cleanup of any proxies we already started.
			for _, p := range proxies {
				_ = p.listener.Close()
			}
			return nil, nil, fmt.Errorf("audit: failed to start local proxy for %q: %w", r, err)
		}

		proxy := &auditProxy{
			routeRule: r,
			target:    net.JoinHostPort(spec.targetHost, spec.targetPort),
			listener:  ln,
		}
		proxies = append(proxies, proxy)
		go proxy.serve()

		_, proxyPort, _ := net.SplitHostPort(ln.Addr().String())
		log.Printf("[audit] proxy active: %s -> 127.0.0.1:%s -> %s", r, proxyPort, proxy.target)

		rewritten = append(rewritten, fmt.Sprintf("R:%s:127.0.0.1:%s", spec.localPort, proxyPort))
	}

	return rewritten, proxies, nil
}

// stopAuditProxies closes all proxy listeners. Safe to call multiple times.
func stopAuditProxies(proxies []*auditProxy) {
	for _, p := range proxies {
		if p != nil && p.listener != nil {
			_ = p.listener.Close()
		}
	}
}

func (p *auditProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			// Listener closed or temporary error. If it's permanent (closed
			// listener) the loop exits naturally. If it were transient we'd
			// see repeated errors -- log them quietly.
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[audit] accept error on %s: %v", p.routeRule, err)
			return
		}
		go p.handle(conn)
	}
}

// handle owns the lifecycle of a single proxied connection: dial the target,
// pipe data both directions, and emit exactly one audit entry on close.
func (p *auditProxy) handle(client net.Conn) {
	start := time.Now()
	entry := auditEntry{
		RouteRule:   p.routeRule,
		Destination: p.target,
		SourceAddr:  client.RemoteAddr().String(),
		Timestamp:   start.UTC().Format(time.RFC3339Nano),
	}

	defer func() {
		entry.DurationMs = time.Since(start).Milliseconds()
		auditEmitter(entry)
	}()
	defer client.Close()

	dialStart := time.Now()
	target, err := net.DialTimeout("tcp", p.target, auditDialTimeout)
	entry.LatencyMs = time.Since(dialStart).Milliseconds()
	if err != nil {
		entry.Success = false
		entry.Error = err.Error()
		return
	}
	defer target.Close()
	entry.Success = true

	var bytesIn, bytesOut int64
	var wg sync.WaitGroup
	wg.Add(2)

	// tunnel -> target  (request bytes)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(target, client)
		atomic.StoreInt64(&bytesIn, n)
		// Half-close so the target sees EOF and can flush its response.
		if tc, ok := target.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// target -> tunnel  (response bytes)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(client, target)
		atomic.StoreInt64(&bytesOut, n)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	entry.BytesIn = atomic.LoadInt64(&bytesIn)
	entry.BytesOut = atomic.LoadInt64(&bytesOut)
}

// remoteSpec is the subset of a chisel remote definition we care about for
// audit purposes.
type remoteSpec struct {
	localHost  string // optional, defaults to ""
	localPort  string
	targetHost string
	targetPort string
}

// parseReverseTCPRemote understands the chisel remote forms we audit:
//
//	R:<local-port>:<host>:<remote-port>
//	R:<local-host>:<local-port>:<host>:<remote-port>
//
// It deliberately rejects anything ending in /udp (chisel's UDP marker) and
// any non-reverse form (no leading "R:"). When ok is false, callers should
// pass the remote through to chisel unchanged.
func parseReverseTCPRemote(r string) (spec remoteSpec, ok bool) {
	if !strings.HasPrefix(r, "R:") {
		return spec, false
	}
	body := strings.TrimPrefix(r, "R:")

	// Reject explicit UDP markers - we only audit TCP.
	if strings.Contains(body, "/udp") {
		return spec, false
	}
	// Strip a /tcp suffix if present, it doesn't change semantics.
	body = strings.TrimSuffix(body, "/tcp")

	parts := strings.Split(body, ":")
	switch len(parts) {
	case 3:
		// <local-port>:<remote-host>:<remote-port>
		spec.localPort = parts[0]
		spec.targetHost = parts[1]
		spec.targetPort = parts[2]
	case 4:
		// <local-host>:<local-port>:<remote-host>:<remote-port>
		spec.localHost = parts[0]
		spec.localPort = parts[1]
		spec.targetHost = parts[2]
		spec.targetPort = parts[3]
	default:
		return spec, false
	}

	// Sanity-check the ports are numeric. chisel will validate more
	// strictly later; we only need enough certainty to safely build
	// our proxy address.
	if !isNumericPort(spec.localPort) || !isNumericPort(spec.targetPort) {
		return spec, false
	}
	if spec.targetHost == "" {
		return spec, false
	}
	return spec, true
}

func isNumericPort(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
