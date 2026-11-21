package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/relay"
	"github.com/victorcondackdev/webhook-relay-go/signature"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestReceiverWithRelay runs the real relay against the example receiver and
// replays a message: the receiver processes it once and acknowledges the
// duplicate.
func TestReceiverWithRelay(t *testing.T) {
	logs := &lockedBuf{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	sec, _ := signature.GenerateSecret()
	v := &signature.Verifier{Secrets: []signature.Secret{sec}}
	rcv := httptest.NewServer(newHandler(v, newDedup(time.Hour), logger))
	defer rcv.Close()

	eng, _ := relay.New(relay.Config{
		Store: relay.NewMemStore(),
		Guard: &relay.Guard{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, AllowHTTP: true},
	})
	eng.Start(context.Background())
	defer eng.Shutdown(context.Background())
	ctx := context.Background()
	ep, err := eng.CreateEndpoint(ctx, relay.EndpointSpec{URL: rcv.URL + "/webhooks", Secret: sec.String()})
	if err != nil {
		t.Fatal(err)
	}

	msg, _, _, _ := eng.Publish(ctx, relay.PublishInput{EventType: "pix.received", Payload: json.RawMessage(`{"amount":1500}`)})
	msg2, _, _, _ := eng.Publish(ctx, relay.PublishInput{EventType: "refund.created", Payload: json.RawMessage(`{}`)})
	waitLog(t, logs, `"msg":"payment event"`)
	waitLog(t, logs, `"msg":"event ignored"`)
	// Replay skips messages that are still pending, so let both settle.
	for _, id := range []string{msg.ID, msg2.ID} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			ds, _ := eng.Deliveries(ctx, id)
			if len(ds) == 1 && ds[0].State == relay.StateSucceeded {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("message %s not acknowledged", id)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	if n, err := eng.Replay(ctx, ep.ID, msg.CreatedAt); err != nil || n != 2 {
		t.Fatalf("Replay = %d, %v", n, err)
	}
	waitLog(t, logs, `"msg":"duplicate delivery ignored"`)
	if c := strings.Count(logs.String(), `"msg":"payment event"`); c != 1 {
		t.Fatalf("payment processed %d times", c)
	}
}

func waitLog(t *testing.T, l *lockedBuf, s string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(l.String(), s) {
		if time.Now().After(deadline) {
			t.Fatalf("log never contained %s:\n%s", s, l.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestReceiverRejects(t *testing.T) {
	sec, _ := signature.GenerateSecret()
	v := &signature.Verifier{Secrets: []signature.Secret{sec}}
	h := newHandler(v, newDedup(time.Hour), slog.New(slog.NewJSONHandler(io.Discard, nil)))
	send := func(body string, sign bool) int {
		req := httptest.NewRequest("POST", "/webhooks", strings.NewReader(body))
		if sign {
			signature.Signer{Secrets: []signature.Secret{sec}}.SetHeaders(req.Header, "msg_1x", time.Now(), []byte(body))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := send(`{"type":"pix.received"}`, false); c != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d", c)
	}
	if c := send(`not json`, true); c != http.StatusBadRequest {
		t.Fatalf("bad payload = %d", c)
	}
}

func TestDedupExpiry(t *testing.T) {
	d := newDedup(time.Minute)
	now := time.Unix(0, 0)
	d.now = func() time.Time { return now }
	if !d.firstTime("a") || d.firstTime("a") {
		t.Fatal("dedup")
	}
	now = now.Add(2 * time.Minute)
	if !d.firstTime("a") {
		t.Fatal("expired id still deduplicated")
	}
	for i := 0; i < 10_002; i++ {
		d.firstTime(string(rune(i)) + "x")
	}
	now = now.Add(2 * time.Minute)
	d.firstTime("trigger-sweep")
	if len(d.seen) > 2 {
		t.Fatalf("sweep left %d ids", len(d.seen))
	}
}
