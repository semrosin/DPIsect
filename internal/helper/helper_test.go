package helper

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/generator"
)

// recHandler collects slog records for assertions; WithAttrs shares the
// same store (logger.With must not lose entries).
type recHandler struct {
	mu    *sync.Mutex
	recs  *[]slog.Record
	attrs []slog.Attr
}

func newRecHandler() *recHandler {
	return &recHandler{mu: &sync.Mutex{}, recs: &[]slog.Record{}}
}

func (h *recHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := r.Clone()
	c.AddAttrs(h.attrs...)
	*h.recs = append(*h.recs, c)
	return nil
}

func (h *recHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recHandler{
		mu:    h.mu,
		recs:  h.recs,
		attrs: append(append([]slog.Attr{}, h.attrs...), attrs...),
	}
}

func (h *recHandler) WithGroup(string) slog.Handler { return h }

// records returns a snapshot taken under the handler lock.
func (h *recHandler) records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(*h.recs))
	copy(out, *h.recs)
	return out
}

func msgs(recs []slog.Record) []string {
	out := make([]string, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.Message)
	}
	return out
}

func hasMsg(recs []slog.Record, want string) bool {
	for _, r := range recs {
		if r.Message == want {
			return true
		}
	}
	return false
}

// findAttr returns the attribute key of the first record whose msg is
// event.
func findAttr(recs []slog.Record, event, key string) (slog.Value, bool) {
	for i := range recs {
		if recs[i].Message != event {
			continue
		}
		var (
			v     slog.Value
			found bool
		)
		recs[i].Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				v, found = a.Value, true
				return false
			}
			return true
		})
		if found {
			return v, true
		}
	}
	return slog.Value{}, false
}

// startTestServer runs a helper on 127.0.0.1:0 with fast timeouts and
// returns it with the address, the log sink and a stop function that
// cancels Serve and waits for it.
func startTestServer(t *testing.T, profile Profile) (string, *recHandler, func()) {
	t.Helper()

	handler := newRecHandler()
	srv, err := New(Config{
		Addr:             "127.0.0.1:0",
		Profile:          profile,
		Logger:           slog.New(handler),
		ReadTimeout:      2 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		HTTPTimeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	}
	return srv.Addr().String(), handler, stop
}

func waitFor(t *testing.T, h *recHandler, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if recs := h.records(); hasMsg(recs, want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for event %q; got %v", want, msgs(h.records()))
}

func TestHelperAcceptingFullExchange(t *testing.T) {
	t.Parallel()

	addr, handler, stop := startTestServer(t, ProfileAccepting)
	defer stop()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // test only: helper cert is in-memory
		ServerName:         "probe.example",
	})
	if err != nil {
		t.Fatalf("tls dial: %v (events: %v)", err, msgs(handler.records()))
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: probe.example\r\n\r\n"); err != nil {
		_ = conn.Close()
		t.Fatalf("write request: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(resp), "200 OK") ||
		!strings.Contains(string(resp), "dpisect helper ok") {
		t.Errorf("response = %q, want 200 OK with body", resp)
	}

	waitFor(t, handler, "conn_closed")
	recs := handler.records()
	for _, want := range []string{
		"listening", "accept", "client_hello",
		"cert_served", "handshake_done", "http_request", "http_response",
	} {
		if !hasMsg(recs, want) {
			t.Errorf("missing event %q; got %v", want, msgs(recs))
		}
	}
	if v, ok := findAttr(recs, "client_hello", "sni"); !ok || v.String() != "probe.example" {
		t.Errorf("client_hello sni = %v (found=%v), want probe.example", v, ok)
	}
	if v, ok := findAttr(recs, "http_response", "status"); !ok || v.Int64() != 200 {
		t.Errorf("http_response status = %v (found=%v), want 200", v, ok)
	}
	if v, ok := findAttr(recs, "listening", "cert_sha256"); !ok || v.String() == "" {
		t.Errorf("listening must carry cert_sha256 for H07, found=%v", ok)
	}
}

func TestHelperRejectingSendsAlert(t *testing.T) {
	t.Parallel()

	addr, handler, stop := startTestServer(t, ProfileRejecting)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	hello, err := generator.BuildClientHello("blocked.example", [32]byte{1})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	alert := make([]byte, 7)
	if _, err := io.ReadFull(conn, alert); err != nil {
		t.Fatalf("read alert: %v", err)
	}
	if alert[0] != 0x15 {
		t.Errorf("record type = %#x, want 0x15 alert", alert[0])
	}
	if alert[5] != 0x02 || alert[6] != 0x28 {
		t.Errorf("alert = level %#x desc %#x, want fatal handshake_failure", alert[5], alert[6])
	}

	waitFor(t, handler, "conn_closed")
	recs := handler.records()
	for _, want := range []string{"client_hello", "tls_alert"} {
		if !hasMsg(recs, want) {
			t.Errorf("missing event %q; got %v", want, msgs(recs))
		}
	}
	if v, ok := findAttr(recs, "tls_alert", "direction"); !ok || v.String() != "server" {
		t.Errorf("tls_alert direction = %v (found=%v), want server", v, ok)
	}
	if v, ok := findAttr(recs, "client_hello", "sni"); !ok || v.String() != "blocked.example" {
		t.Errorf("client_hello sni = %v (found=%v), want blocked.example", v, ok)
	}
}

func TestHelperRejectsNonTLS(t *testing.T) {
	t.Parallel()

	addr, handler, stop := startTestServer(t, ProfileAccepting)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// ApplicationData record with empty payload: header parses, then
	// the record type check fails without blocking.
	if _, err := conn.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	_, _ = conn.Read(buf) // expect EOF, not a response
	_ = conn.Close()

	waitFor(t, handler, "conn_closed")
	recs := handler.records()
	if !hasMsg(recs, "parse_error") {
		t.Errorf("missing parse_error; got %v", msgs(recs))
	}
	if hasMsg(recs, "handshake_done") {
		t.Errorf("non-TLS input must not reach handshake_done; got %v", msgs(recs))
	}
}

func TestParseProfile(t *testing.T) {
	t.Parallel()

	if _, err := ParseProfile("accepting"); err != nil {
		t.Errorf("accepting: %v", err)
	}
	if _, err := ParseProfile("rejecting"); err != nil {
		t.Errorf("rejecting: %v", err)
	}
	if _, err := ParseProfile("weird"); err == nil {
		t.Error("weird: want error")
	}
}
