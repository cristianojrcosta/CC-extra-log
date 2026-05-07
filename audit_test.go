package main

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureAuditEmitter swaps the package-level auditEmitter for a thread-safe
// recorder for the duration of a test, returning a getter and a restore fn.
func captureAuditEmitter(t *testing.T) (func() []auditEntry, func()) {
	t.Helper()
	orig := auditEmitter
	var mu sync.Mutex
	var got []auditEntry
	auditEmitter = func(e auditEntry) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, e)
	}
	return func() []auditEntry {
			mu.Lock()
			defer mu.Unlock()
			out := make([]auditEntry, len(got))
			copy(out, got)
			return out
		}, func() {
			auditEmitter = orig
		}
}

// startEchoServer starts a TCP server that echoes one read back and returns
// its listen address. It runs until the test ends.
func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()
	return ln
}

func Test_parseReverseTCPRemote(t *testing.T) {
	tests := []struct {
		in       string
		wantOK   bool
		wantHost string
		wantPort string
	}{
		{"R:8081:192.168.0.3:8393", true, "192.168.0.3", "8393"},
		{"R:127.0.0.1:8081:internal:443", true, "internal", "443"},
		{"R:8081:host:8393/tcp", true, "host", "8393"},
		{"R:8081:host:8393/udp", false, "", ""},
		{"8081:host:8393", false, "", ""},  // not reverse
		{"R:abc:host:8393", false, "", ""}, // non-numeric local port
		{"R:8081:host:xyz", false, "", ""}, // non-numeric remote port
		{"R:8081", false, "", ""},          // too few parts
		{"R::host:8393", false, "", ""},    // empty local port
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := parseReverseTCPRemote(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if got.targetHost != tt.wantHost {
				t.Errorf("targetHost = %q, want %q", got.targetHost, tt.wantHost)
			}
			if got.targetPort != tt.wantPort {
				t.Errorf("targetPort = %q, want %q", got.targetPort, tt.wantPort)
			}
		})
	}
}

func Test_startAuditProxies_passthrough(t *testing.T) {
	// UDP and non-reverse remotes should be passed through unchanged so that
	// chisel can handle (or reject) them as it normally would.
	in := []string{
		"R:8081:host:8393/udp",
		"8081:host:8393",
		"R:8082:host:8393",
	}
	out, proxies, err := startAuditProxies(in)
	if err != nil {
		t.Fatalf("startAuditProxies: %v", err)
	}
	t.Cleanup(func() { stopAuditProxies(proxies) })

	if len(out) != 3 {
		t.Fatalf("len(out) = %d, want 3", len(out))
	}
	if out[0] != in[0] {
		t.Errorf("UDP remote was rewritten: %q", out[0])
	}
	if out[1] != in[1] {
		t.Errorf("non-reverse remote was rewritten: %q", out[1])
	}
	// The third one *should* be rewritten to point at the local proxy.
	if !strings.HasPrefix(out[2], "R:8082:127.0.0.1:") {
		t.Errorf("expected reverse remote to be rewritten, got %q", out[2])
	}
	if len(proxies) != 1 {
		t.Errorf("expected 1 active proxy, got %d", len(proxies))
	}
}

func Test_auditProxy_successfulForward(t *testing.T) {
	getEntries, restore := captureAuditEmitter(t)
	defer restore()

	echo := startEchoServer(t)
	echoAddr := echo.Addr().String()
	host, port, _ := net.SplitHostPort(echoAddr)

	original := "R:9999:" + host + ":" + port
	rewritten, proxies, err := startAuditProxies([]string{original})
	if err != nil {
		t.Fatalf("startAuditProxies: %v", err)
	}
	defer stopAuditProxies(proxies)

	// Extract the proxy address from the rewritten remote: R:9999:127.0.0.1:<proxy>
	parts := strings.Split(rewritten[0], ":")
	if len(parts) != 4 {
		t.Fatalf("unexpected rewritten form: %s", rewritten[0])
	}
	proxyAddr := net.JoinHostPort(parts[2], parts[3])

	// Simulate chisel delivering a tunnel connection to our proxy.
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	payload := []byte("hello-audit")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Half-close so the echo server returns and our proxy goroutines unwind.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	// Read echoed bytes.
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
	_ = conn.Close()

	// Wait for the audit entry to be emitted (proxy completes asynchronously).
	deadline := time.Now().Add(2 * time.Second)
	var entries []auditEntry
	for time.Now().Before(deadline) {
		entries = getEntries()
		if len(entries) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.RouteRule != original {
		t.Errorf("RouteRule = %q, want %q", e.RouteRule, original)
	}
	if e.Destination != echoAddr {
		t.Errorf("Destination = %q, want %q", e.Destination, echoAddr)
	}
	if !e.Success {
		t.Errorf("Success = false, want true; error=%q", e.Error)
	}
	if e.BytesIn != int64(len(payload)) {
		t.Errorf("BytesIn = %d, want %d", e.BytesIn, len(payload))
	}
	if e.BytesOut != int64(len(payload)) {
		t.Errorf("BytesOut = %d, want %d", e.BytesOut, len(payload))
	}
	if e.Timestamp == "" {
		t.Errorf("Timestamp empty")
	}
	if e.LatencyMs < 0 {
		t.Errorf("LatencyMs negative: %d", e.LatencyMs)
	}
}

func Test_auditProxy_targetUnreachable(t *testing.T) {
	getEntries, restore := captureAuditEmitter(t)
	defer restore()

	// Reserve a port and immediately close it so the target is guaranteed
	// to refuse connections.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	deadAddr := tmp.Addr().String()
	host, port, _ := net.SplitHostPort(deadAddr)
	_ = tmp.Close()

	// Tighten the dial timeout so the test stays fast even on slow CI.
	origTimeout := auditDialTimeout
	auditDialTimeout = 500 * time.Millisecond
	defer func() { auditDialTimeout = origTimeout }()

	original := "R:9998:" + host + ":" + port
	rewritten, proxies, err := startAuditProxies([]string{original})
	if err != nil {
		t.Fatalf("startAuditProxies: %v", err)
	}
	defer stopAuditProxies(proxies)

	parts := strings.Split(rewritten[0], ":")
	proxyAddr := net.JoinHostPort(parts[2], parts[3])

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// On a closed target the proxy will close us right back.
	_, _ = io.ReadAll(conn)
	_ = conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	var entries []auditEntry
	for time.Now().Before(deadline) {
		entries = getEntries()
		if len(entries) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Success {
		t.Errorf("Success = true, want false")
	}
	if e.Error == "" {
		t.Errorf("Error empty, want a dial failure message")
	}
	if e.BytesIn != 0 || e.BytesOut != 0 {
		t.Errorf("expected zero bytes on failure, got in=%d out=%d", e.BytesIn, e.BytesOut)
	}
}
