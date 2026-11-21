package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/signature"
	"github.com/victorcondackdev/webhook-relay-go/wal"
)

func TestDeliverySignedAndTraced(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{})
	ctx := context.Background()
	ep, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL + "/hook", EventTypes: []string{"pix.*"}})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL + "/other", EventTypes: []string{"charge.paid"}})

	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	msg, dlvs, created, err := e.Publish(ctx, PublishInput{
		EventType: "pix.received", Payload: json.RawMessage(`{"amount":1500,"txid":"E123"}`),
		TraceParent: tp, TraceState: "vendor=1",
	})
	if err != nil || !created {
		t.Fatal(err)
	}
	if len(dlvs) != 1 || dlvs[0].EndpointID != ep.ID {
		t.Fatalf("fan-out ignored filters: %+v (other endpoint %s)", dlvs, other.ID)
	}
	waitFor(t, "success", stateIs(e, dlvs[0].ID, StateSucceeded))

	r := srv.requests()[0]
	v, _ := signature.NewVerifier(ep.Keys[0].Key)
	if err := v.Verify(r.Header, r.Body); err != nil {
		t.Fatalf("receiver could not verify: %v", err)
	}
	if r.Header.Get("webhook-id") != msg.ID {
		t.Errorf("webhook-id = %q, want message id %q", r.Header.Get("webhook-id"), msg.ID)
	}
	if r.Header.Get("traceparent") != tp || r.Header.Get("tracestate") != "vendor=1" {
		t.Errorf("trace context not propagated: %v", r.Header)
	}
	if r.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(r.Header.Get("User-Agent"), "webhook-relay-go/") {
		t.Errorf("headers = %v", r.Header)
	}
	var env struct {
		Type      string          `json:"type"`
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil || env.Type != "pix.received" || string(env.Data) != `{"amount":1500,"txid":"E123"}` {
		t.Fatalf("body = %s (%v)", r.Body, err)
	}
	atts, _ := e.Attempts(ctx, msg.ID)
	if len(atts) != 1 || atts[0].StatusCode != 200 || atts[0].Outcome != OutcomeSuccess || atts[0].Response == "" || atts[0].Number != 1 {
		t.Fatalf("attempt log = %+v", atts)
	}
	if ds, _ := e.Deliveries(ctx, msg.ID); len(ds) != 1 {
		t.Fatal("Deliveries")
	}
	if _, err := e.Deliveries(ctx, "msg_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("Deliveries of missing message")
	}
	if m, _ := e.GetMessage(ctx, msg.ID); m.TraceParent != tp {
		t.Fatal("trace context not stored")
	}

	// Invalid trace context is dropped rather than forwarded.
	m2, d2, _, _ := e.Publish(ctx, PublishInput{EventType: "pix.sent", Payload: json.RawMessage(`{}`), TraceParent: "garbage", TraceState: "x"})
	waitFor(t, "second", stateIs(e, d2[0].ID, StateSucceeded))
	if m2.TraceParent != "" || m2.TraceState != "" {
		t.Fatal("invalid traceparent kept")
	}
}

func TestRetriesUntilSuccess(t *testing.T) {
	srv := newScriptServer(t, failTimes(3, http.StatusInternalServerError))
	e := newTestEngine(t, Config{Backoff: Schedule{Delays: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}}})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	msg, dlvs := publish(t, e, "charge.paid", map[string]string{"id": "ch_1"})
	waitFor(t, "success", stateIs(e, dlvs[0].ID, StateSucceeded))
	d := delivery(t, e, dlvs[0].ID)
	if d.Attempts != 4 || d.LastStatus != 200 {
		t.Fatalf("delivery = %+v", d)
	}
	atts, _ := e.Attempts(context.Background(), msg.ID)
	for i, a := range atts {
		want := OutcomeHTTP5xx
		if i == 3 {
			want = OutcomeSuccess
		}
		if a.Outcome != want || a.Number != i+1 {
			t.Fatalf("attempt %d = %+v", i, a)
		}
		if i < 3 && a.NextAt == nil {
			t.Fatalf("attempt %d has no next time", i)
		}
	}
	// The same webhook-id is used on every attempt.
	ids := map[string]bool{}
	for _, r := range srv.requests() {
		ids[r.Header.Get("webhook-id")] = true
	}
	if len(ids) != 1 {
		t.Fatalf("webhook-id changed across retries: %v", ids)
	}
}

// TestBackoffScheduleWithFakeClock checks the exact retry times against the
// schedule, using a fake clock and no jitter.
func TestBackoffScheduleWithFakeClock(t *testing.T) {
	clk := newFakeClock()
	srv := newScriptServer(t, always(http.StatusBadGateway))
	sched := []time.Duration{5 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	e := newTestEngine(t, Config{Clock: clk, Backoff: Schedule{Delays: sched}, Breaker: BreakerConfig{FailureThreshold: -1}})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	_, dlvs := publish(t, e, "pix.received", nil)
	id := dlvs[0].ID

	start := clk.Now()
	elapsed := time.Duration(0)
	for i, step := range sched {
		waitFor(t, fmt.Sprintf("attempt %d", i+1), attemptsAre(e, id, i+1))
		d := delivery(t, e, id)
		want := start.Add(elapsed + step)
		if !d.NextAttemptAt.Equal(want) {
			t.Fatalf("after attempt %d next = %v, want %v", i+1, d.NextAttemptAt, want)
		}
		waitFor(t, "timer armed", func() bool { return clk.hasTimerAt(want) })
		if srv.count() != i+1 {
			t.Fatalf("server saw %d requests before the timer fired, want %d", srv.count(), i+1)
		}
		clk.Advance(step - time.Nanosecond)
		time.Sleep(5 * time.Millisecond)
		if srv.count() != i+1 {
			t.Fatalf("retry %d fired early", i+1)
		}
		clk.Advance(time.Nanosecond)
		elapsed += step
	}
	waitFor(t, "dead letter", stateIs(e, id, StateDead))
	if d := delivery(t, e, id); d.Attempts != len(sched)+1 {
		t.Fatalf("attempts = %d", d.Attempts)
	}
	dead, _ := e.DeadLetters(context.Background(), "", 0)
	if len(dead) != 1 || dead[0].ID != id {
		t.Fatalf("DLQ = %+v", dead)
	}
}

func TestRetryAfterIsRespected(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		header  string
		wantOut Outcome
		wantIn  time.Duration
	}{
		{"429 seconds", http.StatusTooManyRequests, "120", OutcomeThrottled, 120 * time.Second},
		{"503 seconds", http.StatusServiceUnavailable, "30", OutcomeThrottled, 30 * time.Second},
		{"429 zero is clamped to 1s", http.StatusTooManyRequests, "0", OutcomeThrottled, time.Second},
		{"429 huge is capped", http.StatusTooManyRequests, "999999", OutcomeThrottled, time.Hour},
		{"429 without header uses schedule", http.StatusTooManyRequests, "", OutcomeThrottled, 7 * time.Second},
		{"503 without header is a 5xx", http.StatusServiceUnavailable, "", OutcomeHTTP5xx, 7 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clk := newFakeClock()
			srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
				h := http.Header{}
				if tt.header != "" {
					h.Set("Retry-After", tt.header)
				}
				return tt.status, h, 0
			})
			e := newTestEngine(t, Config{Clock: clk, MaxRetryAfter: time.Hour, Backoff: Schedule{Delays: []time.Duration{7 * time.Second}}})
			e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
			msg, dlvs := publish(t, e, "pix.received", nil)
			waitFor(t, "attempt", attemptsAre(e, dlvs[0].ID, 1))
			d := delivery(t, e, dlvs[0].ID)
			if got := d.NextAttemptAt.Sub(clk.Now()); got != tt.wantIn {
				t.Fatalf("next in %v, want %v", got, tt.wantIn)
			}
			atts, _ := e.Attempts(context.Background(), msg.ID)
			if atts[0].Outcome != tt.wantOut {
				t.Fatalf("outcome %s, want %s", atts[0].Outcome, tt.wantOut)
			}
		})
	}
}

func TestGoneDisablesEndpoint(t *testing.T) {
	release := make(chan struct{})
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		<-release // hold the first request until everything is queued
		return http.StatusGone, nil, 0
	})
	e := newTestEngine(t, Config{})
	ctx := context.Background()
	ep, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, Ordered: true})
	var ids []string
	for i := 0; i < 4; i++ {
		_, d := publish(t, e, "pix.received", map[string]int{"i": i})
		ids = append(ids, d[0].ID)
	}
	close(release)
	for _, id := range ids {
		waitFor(t, "dead letter "+id, stateIs(e, id, StateDead))
	}
	if srv.count() != 1 {
		t.Fatalf("server saw %d requests; after a 410 nothing else should be sent", srv.count())
	}
	got, _ := e.GetEndpoint(ctx, ep.ID)
	if !got.Disabled || !strings.Contains(got.DisabledReason, "410") {
		t.Fatalf("endpoint = %+v", got)
	}
	if d := delivery(t, e, ids[3]); !strings.Contains(d.LastError, "endpoint disabled") {
		t.Fatalf("queued delivery error = %q", d.LastError)
	}
	// New messages are not routed to a disabled endpoint, and DLQ retries
	// and replays are refused until it is re-enabled.
	if _, d := publish(t, e, "pix.received", nil); len(d) != 0 {
		t.Fatal("message routed to disabled endpoint")
	}
	if _, err := e.RetryDead(ctx, ids[0]); !errors.Is(err, ErrEndpointDisabled) {
		t.Fatalf("RetryDead on disabled endpoint: %v", err)
	}
	if _, err := e.Replay(ctx, ep.ID, time.Time{}); !errors.Is(err, ErrEndpointDisabled) {
		t.Fatalf("Replay on disabled endpoint: %v", err)
	}
}

// TestDisableWhileInFlight disables an endpoint through the API while a
// request to it is in flight: the in-flight delivery, once it fails, joins
// the rest of the queue in the DLQ instead of being retried.
func TestDisableWhileInFlight(t *testing.T) {
	release := make(chan struct{})
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		<-release
		return http.StatusInternalServerError, nil, 0
	})
	e := newTestEngine(t, Config{})
	ctx := context.Background()
	ep, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, Ordered: true})
	_, d1 := publish(t, e, "pix.received", nil)
	_, d2 := publish(t, e, "pix.received", nil)
	waitFor(t, "in flight", func() bool { return srv.count() == 1 })
	yes := true
	if _, err := e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "queued delivery dead", stateIs(e, d2[0].ID, StateDead))
	close(release)
	waitFor(t, "in-flight delivery dead", stateIs(e, d1[0].ID, StateDead))
	no := false
	e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{Disabled: &no})
	if st, _ := e.BreakerState(ep.ID); st != BreakerClosed {
		t.Fatal("breaker not reset on enable")
	}
}

func TestDeadLetterAndManualRetry(t *testing.T) {
	var healthy atomic.Bool
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		if healthy.Load() {
			return http.StatusAccepted, nil, 0
		}
		return http.StatusBadRequest, nil, 0
	})
	e := newTestEngine(t, Config{Backoff: Schedule{Delays: []time.Duration{time.Millisecond}}})
	ctx := context.Background()
	ep, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL})
	_, dlvs := publish(t, e, "charge.paid", nil)
	id := dlvs[0].ID
	waitFor(t, "dead", stateIs(e, id, StateDead))
	d := delivery(t, e, id)
	if d.Attempts != 2 || d.LastStatus != 400 {
		t.Fatalf("dead delivery = %+v", d)
	}
	if dead, _ := e.DeadLetters(ctx, ep.ID, 10); len(dead) != 1 {
		t.Fatal("not in DLQ")
	}
	if _, err := e.RetryDead(ctx, "dlv_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retry missing: %v", err)
	}

	healthy.Store(true)
	if _, err := e.RetryDead(ctx, id); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "success after retry", stateIs(e, id, StateSucceeded))
	if d := delivery(t, e, id); d.Attempts != 1 {
		t.Fatalf("manual retry must reset the attempt budget, attempts = %d", d.Attempts)
	}
	if _, err := e.RetryDead(ctx, id); !errors.Is(err, ErrNotDead) {
		t.Fatalf("retry of succeeded delivery: %v", err)
	}
}

func TestTimeoutIsRetried(t *testing.T) {
	srv := newScriptServer(t, func(n int, _ *http.Request) (int, http.Header, time.Duration) {
		if n == 1 {
			return http.StatusOK, nil, time.Second
		}
		return http.StatusOK, nil, 0
	})
	e := newTestEngine(t, Config{RequestTimeout: 50 * time.Millisecond})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	msg, dlvs := publish(t, e, "pix.received", nil)
	waitFor(t, "success", stateIs(e, dlvs[0].ID, StateSucceeded))
	atts, _ := e.Attempts(context.Background(), msg.ID)
	if len(atts) != 2 || atts[0].Outcome != OutcomeTimeout || atts[1].Outcome != OutcomeSuccess {
		t.Fatalf("attempts = %+v", atts)
	}
}

func TestNetworkErrorOutcome(t *testing.T) {
	srv := newScriptServer(t, nil)
	url := srv.URL
	srv.Close() // nothing listens any more
	e := newTestEngine(t, Config{Backoff: Schedule{}})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: url})
	msg, dlvs := publish(t, e, "pix.received", nil)
	waitFor(t, "dead", stateIs(e, dlvs[0].ID, StateDead))
	atts, _ := e.Attempts(context.Background(), msg.ID)
	if atts[0].Outcome != OutcomeNetwork || atts[0].Error == "" {
		t.Fatalf("attempt = %+v", atts[0])
	}
}

// TestCircuitBreaker checks that an open breaker stops spending attempts on
// a failing endpoint, lets a single probe through after the cool-down, and
// closes when the probe succeeds.
func TestCircuitBreaker(t *testing.T) {
	clk := newFakeClock()
	var healthy atomic.Bool
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		if healthy.Load() {
			return http.StatusOK, nil, 0
		}
		return http.StatusInternalServerError, nil, 0
	})
	e := newTestEngine(t, Config{
		Clock:   clk,
		Backoff: Schedule{Delays: []time.Duration{time.Second, time.Second, time.Second, time.Second, time.Second}},
		Breaker: BreakerConfig{FailureThreshold: 2, OpenFor: time.Minute},
	})
	ctx := context.Background()
	ep, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, MaxConcurrency: 1})
	var ids []string
	for i := 0; i < 5; i++ {
		_, d := publish(t, e, "pix.received", map[string]int{"i": i})
		ids = append(ids, d[0].ID)
	}
	waitFor(t, "breaker open", func() bool { st, _ := e.BreakerState(ep.ID); return st == BreakerOpen })
	time.Sleep(10 * time.Millisecond)
	if n := srv.count(); n != 2 {
		t.Fatalf("server saw %d requests, want exactly the 2 that tripped the breaker", n)
	}
	// Retries come due but the breaker is open: nothing is sent.
	clk.Advance(30 * time.Second)
	time.Sleep(10 * time.Millisecond)
	if n := srv.count(); n != 2 {
		t.Fatalf("open breaker let %d requests through", n-2)
	}

	healthy.Store(true)
	clk.Advance(30 * time.Second) // cool-down over: one probe, which succeeds
	for _, id := range ids {
		waitFor(t, "drain "+id, stateIs(e, id, StateSucceeded))
	}
	if st, _ := e.BreakerState(ep.ID); st != BreakerClosed {
		t.Fatalf("breaker = %v after successful probe", st)
	}
	if n := srv.count(); n != 7 {
		t.Fatalf("server saw %d requests, want 2 failures + 5 successes", n)
	}
	if _, ok := e.BreakerState("ep_nope"); ok {
		t.Fatal("breaker for unknown endpoint")
	}
}

func TestPerEndpointConcurrencyLimit(t *testing.T) {
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		return http.StatusOK, nil, 20 * time.Millisecond
	})
	fast := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{Workers: 16})
	ctx := context.Background()
	e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, MaxConcurrency: 2})
	e.CreateEndpoint(ctx, EndpointSpec{URL: fast.URL})
	var ids []string
	for i := 0; i < 12; i++ {
		_, ds := publish(t, e, "pix.received", map[string]int{"i": i})
		for _, d := range ds {
			ids = append(ids, d.ID)
		}
	}
	for _, id := range ids {
		waitFor(t, "delivered", stateIs(e, id, StateSucceeded))
	}
	srv.mu.Lock()
	maxIn := srv.maxIn
	srv.mu.Unlock()
	if maxIn != 2 {
		t.Fatalf("max concurrent requests = %d, want 2", maxIn)
	}
	// The slow endpoint must not starve the fast one: it finishes first.
	fr, sr := fast.requests(), srv.requests()
	if fr[len(fr)-1].At.After(sr[len(sr)-1].At) {
		t.Fatal("fast endpoint was held back by the slow one")
	}
}

func TestOrderedLane(t *testing.T) {
	// The first message ever seen fails twice; the others must wait behind it.
	var mu sync.Mutex
	head := ""
	srv := newScriptServer(t, func(n int, r *http.Request) (int, http.Header, time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		if head == "" {
			head = r.Header.Get("webhook-id")
		}
		if r.Header.Get("webhook-id") == head && n <= 2 {
			return http.StatusInternalServerError, nil, 0
		}
		return http.StatusOK, nil, 0
	})
	e := newTestEngine(t, Config{Workers: 8, Backoff: Schedule{Delays: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}}})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL, Ordered: true})
	var msgs []string
	var last string
	for i := 0; i < 6; i++ {
		m, d := publish(t, e, "pix.received", map[string]int{"i": i})
		msgs, last = append(msgs, m.ID), d[0].ID
	}
	waitFor(t, "all delivered", stateIs(e, last, StateSucceeded))
	var order []string
	for _, r := range srv.requests() {
		id := r.Header.Get("webhook-id")
		if len(order) == 0 || order[len(order)-1] != id {
			order = append(order, id)
		}
	}
	if fmt.Sprint(order) != fmt.Sprint(msgs) {
		t.Fatalf("delivery order %v, want %v", order, msgs)
	}
	if got := len(srv.requests()); got != 8 {
		t.Fatalf("requests = %d, want 3 for the head + 5", got)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.maxIn != 1 {
		t.Fatalf("ordered lane had %d concurrent requests", srv.maxIn)
	}
}

func TestRateLimit(t *testing.T) {
	clk := newFakeClock()
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{Clock: clk})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL, RateLimit: 1, Burst: 2})
	for i := 0; i < 5; i++ {
		publish(t, e, "pix.received", map[string]int{"i": i})
	}
	waitFor(t, "burst", func() bool { return srv.count() == 2 })
	time.Sleep(10 * time.Millisecond)
	if srv.count() != 2 {
		t.Fatalf("rate limit exceeded: %d requests at t=0", srv.count())
	}
	for want := 3; want <= 5; want++ {
		waitFor(t, "limiter timer", func() bool { return clk.hasTimerAt(clk.Now().Add(time.Second)) })
		clk.Advance(time.Second)
		waitFor(t, fmt.Sprintf("request %d", want), func() bool { return srv.count() == want })
	}
}

func TestIdempotentPublish(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{})
	ctx := context.Background()
	e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL})
	in := PublishInput{EventType: "charge.paid", Payload: json.RawMessage(`{"id":"ch_1"}`), IdempotencyKey: "charge-ch_1-paid"}
	m1, d1, c1, err := e.Publish(ctx, in)
	if err != nil || !c1 {
		t.Fatal(err)
	}
	m2, d2, c2, err := e.Publish(ctx, in)
	if err != nil || c2 || m2.ID != m1.ID || len(d2) != 1 || d2[0].ID != d1[0].ID {
		t.Fatalf("second publish = %v %v %v %v", m2.ID, d2, c2, err)
	}
	in.Payload = json.RawMessage(`{"id":"ch_2"}`)
	if _, _, _, err := e.Publish(ctx, in); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting reuse: %v", err)
	}
	waitFor(t, "delivered", stateIs(e, d1[0].ID, StateSucceeded))
	time.Sleep(10 * time.Millisecond)
	if srv.count() != 1 {
		t.Fatalf("idempotent publish delivered %d times", srv.count())
	}
}

func TestPublishValidation(t *testing.T) {
	e := newTestEngine(t, Config{MaxPayloadBytes: 32})
	ctx := context.Background()
	tests := []struct {
		in   PublishInput
		want error
	}{
		{PublishInput{EventType: "", Payload: json.RawMessage(`{}`)}, ErrInvalid},
		{PublishInput{EventType: "bad type", Payload: json.RawMessage(`{}`)}, ErrInvalid},
		{PublishInput{EventType: "ok", Payload: json.RawMessage(`{"a":`)}, ErrInvalid},
		{PublishInput{EventType: "ok", Payload: json.RawMessage(`"` + strings.Repeat("x", 40) + `"`)}, ErrPayloadTooLarge},
		{PublishInput{EventType: "ok", Payload: json.RawMessage(`{}`), IdempotencyKey: strings.Repeat("k", 256)}, ErrInvalid},
		{PublishInput{EventType: "ok"}, nil}, // empty payload becomes null
	}
	for _, tt := range tests {
		if _, _, _, err := e.Publish(ctx, tt.in); !errors.Is(err, tt.want) {
			t.Errorf("Publish(%+v) err = %v, want %v", tt.in.EventType, err, tt.want)
		}
	}
}

func TestReplay(t *testing.T) {
	clk := newFakeClock()
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{Clock: clk})
	ctx := context.Background()
	ep, _ := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, EventTypes: []string{"pix.*"}})
	for i := 0; i < 3; i++ {
		_, d := publish(t, e, "pix.received", map[string]int{"i": i})
		waitFor(t, "initial delivery", stateIs(e, d[0].ID, StateSucceeded))
		clk.Advance(time.Minute)
	}
	publish(t, e, "charge.paid", nil)          // not subscribed
	since := clk.Now().Add(-150 * time.Second) // the last two pix messages
	n, err := e.Replay(ctx, ep.ID, since)
	if err != nil || n != 2 {
		t.Fatalf("Replay = %d, %v", n, err)
	}
	waitFor(t, "replayed", func() bool { return srv.count() == 5 })
	if n, _ := e.Replay(ctx, ep.ID, clk.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("empty replay = %d", n)
	}
	if _, err := e.Replay(ctx, "ep_nope", since); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay unknown endpoint: %v", err)
	}
}

func TestEndpointLifecycleAndRotation(t *testing.T) {
	clk := newFakeClock()
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{Clock: clk, KeyRotationOverlap: time.Hour})
	ctx := context.Background()

	if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, Signing: "v9"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad scheme: %v", err)
	}
	if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, Secret: "whsec_short"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad secret: %v", err)
	}
	if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, EventTypes: []string{"bad filter"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad filter: %v", err)
	}
	if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, MaxConcurrency: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad concurrency: %v", err)
	}
	const fixed = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	ep, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL, Secret: fixed, Description: "merchant A"})
	if err != nil {
		t.Fatal(err)
	}
	oldKey := ep.Keys[0].Key

	desc, rate := "merchant A (prod)", 100.0
	ep, err = e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{Description: &desc, RateLimit: &rate, RotateSecret: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(ep.Keys) != 2 || ep.Keys[0].ExpiresAt == nil || ep.Keys[1].ExpiresAt != nil || ep.Description != desc {
		t.Fatalf("after rotation: %+v", ep)
	}
	newKey := ep.Keys[1].Key

	_, d := publish(t, e, "pix.received", nil)
	waitFor(t, "delivered", stateIs(e, d[0].ID, StateSucceeded))
	r := srv.requests()[0]
	for _, k := range []string{oldKey, newKey} {
		v, _ := signature.NewVerifier(k)
		v.Now = clk.Now
		if err := v.Verify(r.Header, r.Body); err != nil {
			t.Fatalf("receiver with %s… rejected during overlap: %v", k[:10], err)
		}
	}

	clk.Advance(2 * time.Hour) // overlap over: only the new key signs
	_, d = publish(t, e, "pix.received", nil)
	waitFor(t, "delivered", stateIs(e, d[0].ID, StateSucceeded))
	r = srv.requests()[1]
	if n := len(strings.Fields(r.Header.Get("webhook-signature"))); n != 1 {
		t.Fatalf("%d signatures after overlap", n)
	}
	oldV, _ := signature.NewVerifier(oldKey)
	oldV.Now = clk.Now
	if err := oldV.Verify(r.Header, r.Body); err == nil {
		t.Fatal("expired key still signing")
	}
	// A second rotation drops the expired key.
	ep, _ = e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{RotateSecret: true})
	if len(ep.Keys) != 2 || ep.Keys[0].Key != newKey {
		t.Fatalf("second rotation keys: %+v", ep.Keys)
	}

	disabled := true
	ep, _ = e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{Disabled: &disabled})
	if !ep.Disabled || ep.DisabledReason == "" {
		t.Fatal("not disabled")
	}
	disabled = false
	ep, _ = e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{Disabled: &disabled})
	if ep.Disabled || ep.DisabledReason != "" {
		t.Fatal("not re-enabled")
	}
	bad := "ftp://nope"
	if _, err := e.UpdateEndpoint(ctx, ep.ID, EndpointPatch{URL: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad URL patch: %v", err)
	}
	if _, err := e.UpdateEndpoint(ctx, "ep_nope", EndpointPatch{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("patch unknown endpoint")
	}
	if eps, _ := e.ListEndpoints(ctx); len(eps) != 1 {
		t.Fatalf("ListEndpoints = %d", len(eps))
	}
	if err := e.DeleteEndpoint(ctx, ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetEndpoint(ctx, ep.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("endpoint survived delete")
	}
	if err := e.DeleteEndpoint(ctx, ep.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete")
	}
}

func TestEd25519Endpoint(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	e := newTestEngine(t, Config{})
	ep, err := e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL, Signing: SigningEd25519})
	if err != nil {
		t.Fatal(err)
	}
	sk, err := signature.ParseSigningKey(ep.Keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	_, d := publish(t, e, "pix.received", nil)
	waitFor(t, "delivered", stateIs(e, d[0].ID, StateSucceeded))
	r := srv.requests()[0]
	v, _ := signature.NewVerifier(sk.Public().String())
	if err := v.Verify(r.Header, r.Body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Header.Get("webhook-signature"), "v1a,") {
		t.Fatal("not a v1a signature")
	}
	if _, err := e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL, Signing: SigningEd25519, Secret: "whsk_bad"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad ed25519 key: %v", err)
	}
}

func TestCorruptKeyIsDeadLettered(t *testing.T) {
	srv := newScriptServer(t, always(http.StatusOK))
	store := NewMemStore()
	e := newTestEngine(t, Config{Store: store})
	ep, _ := e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	ep.Keys = []EndpointKey{{Key: "whsec_!!!"}}
	store.PutEndpoint(context.Background(), ep)
	e.mu.Lock()
	e.laneLocked(ep)
	e.mu.Unlock()
	msg, d := publish(t, e, "pix.received", nil)
	waitFor(t, "dead", stateIs(e, d[0].ID, StateDead))
	atts, _ := e.Attempts(context.Background(), msg.ID)
	if atts[0].Outcome != OutcomeConfig || srv.count() != 0 {
		t.Fatalf("attempt = %+v", atts[0])
	}
}

func TestGracefulShutdownDrains(t *testing.T) {
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		return http.StatusOK, nil, 150 * time.Millisecond
	})
	e := newTestEngine(t, Config{})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	_, d := publish(t, e, "pix.received", nil)
	waitFor(t, "in flight", func() bool { return srv.count() == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := delivery(t, e, d[0].ID); got.State != StateSucceeded {
		t.Fatalf("in-flight delivery not drained: %+v", got)
	}
	if err := e.Shutdown(ctx); err != nil {
		t.Fatal("second shutdown:", err)
	}
}

func TestShutdownDeadlineLeavesDeliveryPending(t *testing.T) {
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		return http.StatusOK, nil, 5 * time.Second
	})
	e := newTestEngine(t, Config{})
	e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	_, d := publish(t, e, "pix.received", nil)
	waitFor(t, "in flight", func() bool { return srv.count() == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v", err)
	}
	got := delivery(t, e, d[0].ID)
	if got.State != StatePending || got.Attempts != 0 {
		t.Fatalf("abandoned delivery = %+v; want pending with no attempt counted", got)
	}
}

// TestRecoveryAfterRestart publishes while the merchant is down, stops the
// process, and checks that a new engine on the same WAL delivers everything.
func TestRecoveryAfterRestart(t *testing.T) {
	dir := t.TempDir()
	var healthy atomic.Bool
	srv := newScriptServer(t, func(int, *http.Request) (int, http.Header, time.Duration) {
		if healthy.Load() {
			return http.StatusOK, nil, 0
		}
		return http.StatusInternalServerError, nil, 0
	})
	open := func() *FileStore {
		s, err := OpenFileStore(FileStoreOptions{Dir: dir, Sync: wal.SyncAlways})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s1 := open()
	e1, _ := New(Config{Store: s1, Guard: &Guard{Allow: loopback, AllowHTTP: true}, Backoff: Schedule{Delays: []time.Duration{time.Hour}}, Breaker: BreakerConfig{FailureThreshold: -1}})
	e1.Start(context.Background())
	e1.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
	var ids []string
	for i := 0; i < 10; i++ {
		_, d := publish(t, e1, "pix.received", map[string]int{"i": i})
		ids = append(ids, d[0].ID)
	}
	for _, id := range ids {
		waitFor(t, "first attempt", attemptsAre(e1, id, 1))
	}
	e1.Shutdown(context.Background())
	s1.Close()

	healthy.Store(true)
	s2 := open()
	defer s2.Close()
	if s2.Recovery().Records == 0 {
		t.Fatal("nothing recovered")
	}
	// The retry is an hour away and a fresh engine honours the stored
	// schedule, so start it with a clock two hours ahead.
	clk := newFakeClock()
	clk.now = time.Now().Add(2 * time.Hour)
	e2 := newTestEngine(t, Config{Store: s2, Clock: clk})
	for _, id := range ids {
		waitFor(t, "recovered delivery", stateIs(e2, id, StateSucceeded))
	}
	if e2.QueueDepth() != 0 {
		t.Fatalf("queue depth %d", e2.QueueDepth())
	}
	// Sequence numbers continue after the recovered ones.
	_, d := publish(t, e2, "pix.received", nil)
	if d[0].Seq <= 10 {
		t.Fatalf("seq restarted: %d", d[0].Seq)
	}
}

// TestConcurrentProducers runs many producers against a file-backed engine
// with several endpoints and checks that every delivery arrives at least
// once and is recorded as succeeded exactly once. Run with -race.
func TestConcurrentProducers(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := newScriptServer(t, func(n int, r *http.Request) (int, http.Header, time.Duration) {
		mu.Lock()
		seen[r.URL.Path+" "+r.Header.Get("webhook-id")]++
		mu.Unlock()
		if n == 1 && r.URL.Path == "/flaky" {
			return http.StatusServiceUnavailable, nil, 0
		}
		return http.StatusOK, nil, 0
	})
	s, err := OpenFileStore(FileStoreOptions{Dir: t.TempDir(), Sync: wal.SyncNever})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	e := newTestEngine(t, Config{Store: s, Workers: 16, Breaker: BreakerConfig{FailureThreshold: -1}})
	ctx := context.Background()
	for _, path := range []string{"/a", "/b", "/flaky"} {
		if _, err := e.CreateEndpoint(ctx, EndpointSpec{URL: srv.URL + path, MaxConcurrency: 8}); err != nil {
			t.Fatal(err)
		}
	}
	const producers, per = 8, 50
	var wg sync.WaitGroup
	var all sync.Map
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				_, ds, _, err := e.Publish(ctx, PublishInput{EventType: "pix.received", Payload: json.RawMessage(fmt.Sprintf(`{"p":%d,"i":%d}`, p, i))})
				if err != nil {
					t.Error(err)
					return
				}
				for _, d := range ds {
					all.Store(d.ID, true)
				}
			}
		}(p)
	}
	// Readers race with the writers.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				var buf bytes.Buffer
				e.WriteMetrics(ctx, &buf)
				e.DeadLetters(ctx, "", 10)
			}
		}
	}()
	wg.Wait()
	waitFor(t, "all delivered", func() bool {
		ds, _ := s.ListDeliveries(ctx, DeliveryFilter{State: StateSucceeded})
		return len(ds) == producers*per*3
	})
	close(stop)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != producers*per*3 {
		t.Fatalf("receivers saw %d distinct (endpoint, message) pairs, want %d", len(seen), producers*per*3)
	}
	// Metrics are updated just after the store, so poll.
	waitFor(t, "metrics", func() bool {
		var buf bytes.Buffer
		e.WriteMetrics(ctx, &buf)
		return strings.Contains(buf.String(), fmt.Sprintf("webhook_deliveries_succeeded_total %d", producers*per*3))
	})
}

func TestNewAndStartErrors(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("missing store accepted")
	}
	if _, err := New(Config{Store: NewMemStore(), Backoff: Exponential{}}); err == nil {
		t.Fatal("zero attempts accepted")
	}
	e, _ := New(Config{Store: NewMemStore(), FollowRedirects: true, Transport: &http.Transport{}})
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatal("shutdown before start:", err)
	}
	e2 := newTestEngine(t, Config{})
	if err := e2.Start(context.Background()); err == nil {
		t.Fatal("double start accepted")
	}
	if e2.Metrics() == nil {
		t.Fatal("no metrics")
	}
	bad, _ := New(Config{Store: failingStore{NewMemStore()}})
	if err := bad.Start(context.Background()); err == nil {
		t.Fatal("store error not surfaced")
	}
}

type failingStore struct{ *MemStore }

func (failingStore) ListEndpoints(context.Context) ([]Endpoint, error) {
	return nil, errors.New("disk on fire")
}

func BenchmarkEndToEnd(b *testing.B) {
	srv := newScriptServer(b, always(http.StatusNoContent))
	for _, mode := range []string{"mem", "wal-fsync-never", "wal-fsync-always"} {
		b.Run(mode, func(b *testing.B) {
			var store Store = NewMemStore()
			switch mode {
			case "wal-fsync-never":
				fs, _ := OpenFileStore(FileStoreOptions{Dir: b.TempDir(), Sync: wal.SyncNever})
				defer fs.Close()
				store = fs
			case "wal-fsync-always":
				fs, _ := OpenFileStore(FileStoreOptions{Dir: b.TempDir(), Sync: wal.SyncAlways})
				defer fs.Close()
				store = fs
			}
			e := newTestEngine(b, Config{Store: store, Workers: 64, DefaultMaxConcurrency: 64})
			e.CreateEndpoint(context.Background(), EndpointSpec{URL: srv.URL})
			payload := json.RawMessage(`{"txid":"E12345678202611211234abcdefghij","amount":15000,"currency":"BRL"}`)
			b.ResetTimer()
			start := time.Now()
			var wg sync.WaitGroup
			const producers = 8
			for p := 0; p < producers; p++ {
				wg.Add(1)
				go func(n int) {
					defer wg.Done()
					for i := 0; i < n; i++ {
						e.Publish(context.Background(), PublishInput{EventType: "pix.received", Payload: payload})
					}
				}(b.N/producers + 1)
			}
			wg.Wait()
			total := (b.N/producers + 1) * producers
			waitFor(b, "drain", func() bool {
				e.metrics.mu.Lock()
				defer e.metrics.mu.Unlock()
				return e.metrics.succeeded >= uint64(total)
			})
			b.ReportMetric(float64(total)/time.Since(start).Seconds(), "deliveries/s")
		})
	}
}
