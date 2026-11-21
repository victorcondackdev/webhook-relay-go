package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/relay"
	"github.com/victorcondackdev/webhook-relay-go/signature"
)

type harness struct {
	t      *testing.T
	api    *httptest.Server
	eng    *relay.Engine
	token  string
	status atomic.Int32 // status the merchant answers with
	hits   atomic.Int32
	last   atomic.Value // last request headers
	merch  *httptest.Server
}

func newHarness(t *testing.T, token string) *harness {
	h := &harness{t: t, token: token}
	h.status.Store(http.StatusOK)
	h.merch = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		h.last.Store(r.Header.Clone())
		w.WriteHeader(int(h.status.Load()))
	}))
	t.Cleanup(h.merch.Close)
	eng, err := relay.New(relay.Config{
		Store:   relay.NewMemStore(),
		Guard:   &relay.Guard{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, AllowHTTP: true},
		Backoff: relay.Schedule{Delays: []time.Duration{time.Millisecond}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng.Start(context.Background())
	t.Cleanup(func() { eng.Shutdown(context.Background()) })
	h.eng = eng
	h.api = httptest.NewServer(New(eng, Options{Token: token, MaxBodyBytes: 4096}))
	t.Cleanup(h.api.Close)
	return h
}

func (h *harness) do(method, path string, body any, hdr ...string) (*http.Response, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		buf, _ := json.Marshal(b)
		rd = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, h.api.URL+path, rd)
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func (h *harness) expect(method, path string, body any, want int, hdr ...string) map[string]any {
	h.t.Helper()
	resp, out := h.do(method, path, body, hdr...)
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s = %d, want %d: %v", method, path, resp.StatusCode, want, out)
	}
	if want >= 400 && resp.Header.Get("Content-Type") != "application/problem+json" {
		h.t.Fatalf("%s %s: error content type %q", method, path, resp.Header.Get("Content-Type"))
	}
	return out
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestEndToEndFlow(t *testing.T) {
	h := newHarness(t, "s3cret")

	ep := h.expect("POST", "/v1/endpoints", map[string]any{"url": h.merch.URL + "/webhooks", "event_types": []string{"pix.*"}, "description": "loja"}, http.StatusCreated)
	id := ep["id"].(string)
	secret, _ := ep["secret"].(string)
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("no secret on create: %v", ep)
	}
	got := h.expect("GET", "/v1/endpoints/"+id, nil, http.StatusOK)
	if _, leaked := got["secret"]; leaked {
		t.Fatal("secret returned by GET")
	}
	list := h.expect("GET", "/v1/endpoints", nil, http.StatusOK)
	if len(list["data"].([]any)) != 1 {
		t.Fatalf("list = %v", list)
	}
	sec := h.expect("GET", "/v1/endpoints/"+id+"/secret", nil, http.StatusOK)
	if keys := sec["keys"].([]any); len(keys) != 1 || keys[0].(map[string]any)["key"] != secret {
		t.Fatalf("secret endpoint = %v", sec)
	}

	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	msg := h.expect("POST", "/v1/messages", map[string]any{"event_type": "pix.received", "payload": map[string]any{"amount": 1500}}, http.StatusAccepted,
		"Idempotency-Key", "e2e-1", "traceparent", tp)
	mid := msg["id"].(string)
	if len(msg["deliveries"].([]any)) != 1 {
		t.Fatalf("deliveries = %v", msg)
	}
	again, _ := h.do("POST", "/v1/messages", map[string]any{"event_type": "pix.received", "payload": map[string]any{"amount": 1500}}, "Idempotency-Key", "e2e-1")
	if again.StatusCode != http.StatusOK || again.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("idempotent replay status %d", again.StatusCode)
	}
	h.expect("POST", "/v1/messages", map[string]any{"event_type": "pix.received", "payload": map[string]any{"amount": 9}}, http.StatusConflict, "Idempotency-Key", "e2e-1")
	h.expect("POST", "/v1/messages", map[string]any{"event_type": "pix.received", "payload": 1, "idempotency_key": "a"}, http.StatusBadRequest, "Idempotency-Key", "b")

	waitFor(t, func() bool { return h.hits.Load() == 1 })
	hdr := h.last.Load().(http.Header)
	v, _ := signature.NewVerifier(secret)
	if hdr.Get("webhook-id") != mid || hdr.Get("traceparent") != tp || v == nil {
		t.Fatalf("delivered headers = %v", hdr)
	}
	waitFor(t, func() bool {
		m := h.expect("GET", "/v1/messages/"+mid, nil, http.StatusOK)
		return m["deliveries"].([]any)[0].(map[string]any)["state"] == "succeeded"
	})
	atts := h.expect("GET", "/v1/messages/"+mid+"/attempts", nil, http.StatusOK)
	if a := atts["data"].([]any); len(a) != 1 || a[0].(map[string]any)["status_code"].(float64) != 200 {
		t.Fatalf("attempts = %v", atts)
	}

	// Rotation returns the new secret once.
	rot := h.expect("PATCH", "/v1/endpoints/"+id, map[string]any{"rotate_secret": true, "description": "loja 2"}, http.StatusOK)
	if rot["secret"] == secret || rot["secret"] == nil || rot["description"] != "loja 2" {
		t.Fatalf("rotation = %v", rot)
	}
	sec = h.expect("GET", "/v1/endpoints/"+id+"/secret", nil, http.StatusOK)
	if len(sec["keys"].([]any)) != 2 {
		t.Fatalf("keys after rotation = %v", sec)
	}

	// Make the merchant fail: the delivery lands in the DLQ.
	h.status.Store(http.StatusInternalServerError)
	m2 := h.expect("POST", "/v1/messages", map[string]any{"event_type": "pix.refunded", "payload": map[string]any{}}, http.StatusAccepted)
	did := m2["deliveries"].([]any)[0].(map[string]any)["id"].(string)
	var dead []any
	waitFor(t, func() bool {
		dead = h.expect("GET", "/v1/dlq?endpoint_id="+id+"&limit=10", nil, http.StatusOK)["data"].([]any)
		return len(dead) == 1
	})
	h.expect("GET", "/v1/dlq?limit=0", nil, http.StatusBadRequest)
	h.status.Store(http.StatusOK)
	h.expect("POST", "/v1/dlq/"+did+"/retry", nil, http.StatusAccepted)
	m2id := m2["id"].(string)
	waitFor(t, func() bool {
		m := h.expect("GET", "/v1/messages/"+m2id, nil, http.StatusOK)
		return m["deliveries"].([]any)[0].(map[string]any)["state"] == "succeeded"
	})
	if len(h.expect("GET", "/v1/dlq", nil, http.StatusOK)["data"].([]any)) != 0 {
		t.Fatal("DLQ not empty after retry")
	}
	h.expect("POST", "/v1/dlq/"+did+"/retry", nil, http.StatusConflict)
	h.expect("POST", "/v1/dlq/dlv_nope/retry", nil, http.StatusNotFound)

	// Replay everything since the beginning.
	before := h.hits.Load()
	rep := h.expect("POST", "/v1/endpoints/"+id+"/replay?since="+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), nil, http.StatusAccepted)
	if rep["scheduled"].(float64) != 2 {
		t.Fatalf("replay = %v", rep)
	}
	waitFor(t, func() bool { return h.hits.Load() == before+2 })
	h.expect("POST", "/v1/endpoints/"+id+"/replay?since=yesterday", nil, http.StatusBadRequest)
	h.expect("POST", "/v1/endpoints/"+id+"/replay", nil, http.StatusAccepted)

	// Disable, then delete.
	dis := h.expect("PATCH", "/v1/endpoints/"+id, map[string]any{"disabled": true}, http.StatusOK)
	if dis["disabled"] != true {
		t.Fatalf("disable = %v", dis)
	}
	h.expect("POST", "/v1/endpoints/"+id+"/replay", nil, http.StatusConflict)
	h.expect("DELETE", "/v1/endpoints/"+id, nil, http.StatusNoContent)
	h.expect("GET", "/v1/endpoints/"+id, nil, http.StatusNotFound)
	h.expect("DELETE", "/v1/endpoints/"+id, nil, http.StatusNotFound)
	h.expect("PATCH", "/v1/endpoints/"+id, map[string]any{}, http.StatusNotFound)
	h.expect("GET", "/v1/endpoints/"+id+"/secret", nil, http.StatusNotFound)
	h.expect("GET", "/v1/messages/msg_nope", nil, http.StatusNotFound)
	h.expect("GET", "/v1/messages/msg_nope/attempts", nil, http.StatusNotFound)
	h.expect("POST", "/v1/endpoints/ep_nope/replay", nil, http.StatusNotFound)
	// A message with no subscribers is accepted with no deliveries.
	none := h.expect("POST", "/v1/messages", map[string]any{"event_type": "nobody.cares"}, http.StatusAccepted)
	if len(none["deliveries"].([]any)) != 0 {
		t.Fatalf("deliveries = %v", none)
	}
	got = h.expect("GET", "/v1/messages/"+none["id"].(string), nil, http.StatusOK)
	if len(got["deliveries"].([]any)) != 0 {
		t.Fatal("deliveries of unrouted message")
	}
	if a := h.expect("GET", "/v1/messages/"+none["id"].(string)+"/attempts", nil, http.StatusOK)["data"].([]any); len(a) != 0 {
		t.Fatal("attempts of unrouted message")
	}
}

func TestErrorsAndAuth(t *testing.T) {
	h := newHarness(t, "tok")
	tests := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
		slug   string
	}{
		{"malformed json", "POST", "/v1/endpoints", "{", 400, "malformed-json"},
		{"unknown field", "POST", "/v1/endpoints", `{"url":"https://a.example","nope":1}`, 400, "malformed-json"},
		{"trailing data", "POST", "/v1/endpoints", `{"url":"https://a.example"} {}`, 400, "malformed-json"},
		{"too large", "POST", "/v1/messages", `{"event_type":"a","payload":"` + strings.Repeat("x", 5000) + `"}`, 413, "payload-too-large"},
		{"ssrf literal", "POST", "/v1/endpoints", map[string]any{"url": "https://169.254.169.254/latest"}, 422, "blocked-destination"},
		{"http scheme on https-only", "POST", "/v1/endpoints", map[string]any{"url": "ftp://a.example"}, 422, "invalid-request"},
		{"bad event type", "POST", "/v1/messages", map[string]any{"event_type": "has space"}, 422, "invalid-request"},
		{"unknown route", "GET", "/v2/nothing", nil, 404, "not-found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := h.expect(tt.method, tt.path, tt.body, tt.want)
			if out["type"] != problemBase+tt.slug || out["status"].(float64) != float64(tt.want) || out["title"] == "" {
				t.Fatalf("problem = %v", out)
			}
		})
	}

	req, _ := http.NewRequest("GET", h.api.URL+"/v1/endpoints", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	req.Header.Set("Authorization", "Bearer wrong")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("wrong token: %d", resp.StatusCode)
	}
	// Health and metrics are not behind the token.
	for _, p := range []string{"/healthz", "/metrics"} {
		resp, err := http.Get(h.api.URL + p)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, resp.StatusCode, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if p == "/metrics" && !strings.Contains(string(body), "webhook_queue_depth 0") {
			t.Fatalf("metrics body:\n%s", body)
		}
	}
}

func TestEd25519EndpointView(t *testing.T) {
	h := newHarness(t, "")
	ep := h.expect("POST", "/v1/endpoints", map[string]any{"url": h.merch.URL, "signing": "v1a"}, http.StatusCreated)
	pk, _ := ep["public_key"].(string)
	if !strings.HasPrefix(pk, "whpk_") || !strings.HasPrefix(ep["secret"].(string), "whsk_") {
		t.Fatalf("view = %v", ep)
	}
	got := h.expect("GET", "/v1/endpoints/"+ep["id"].(string), nil, http.StatusOK)
	if got["public_key"] != pk {
		t.Fatal("public key not shown on GET")
	}
	h.expect("POST", "/v1/messages", map[string]any{"event_type": "charge.paid", "payload": map[string]any{"id": "ch_1"}}, http.StatusAccepted)
	waitFor(t, func() bool { return h.hits.Load() == 1 })
	if hdr := h.last.Load().(http.Header); !strings.HasPrefix(hdr.Get("webhook-signature"), "v1a,") {
		t.Fatalf("signature = %q", hdr.Get("webhook-signature"))
	}
	if publicKey(relay.SigningEd25519, "garbage") != "" {
		t.Fatal("public key of garbage")
	}
}

func TestInternalErrorsAndPanics(t *testing.T) {
	s := &server{log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	s.fail(rec, errors.New("disk on fire"))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "disk on fire") {
		t.Fatalf("internal error leaked or wrong status: %d %s", rec.Code, rec.Body)
	}
	for err, code := range map[error]int{
		relay.ErrNotDead:          http.StatusConflict,
		relay.ErrEndpointDisabled: http.StatusConflict,
		relay.ErrPayloadTooLarge:  http.StatusRequestEntityTooLarge,
	} {
		rec := httptest.NewRecorder()
		s.fail(rec, err)
		if rec.Code != code {
			t.Errorf("%v -> %d, want %d", err, rec.Code, code)
		}
	}
	h := s.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic -> %d", rec.Code)
	}
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("ErrAbortHandler must propagate")
		}
	}()
	s.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}
