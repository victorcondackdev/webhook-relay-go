package relay

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestScheduleDelays(t *testing.T) {
	s := Schedule{Delays: DefaultSchedule}
	want := []time.Duration{5 * time.Second, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 5 * time.Hour, 10 * time.Hour, 10 * time.Hour}
	for i, w := range want {
		if got := s.Delay(i+1, nil); got != w {
			t.Errorf("Delay(%d) = %v, want %v", i+1, got, w)
		}
	}
	if s.MaxAttempts() != 8 {
		t.Errorf("MaxAttempts = %d", s.MaxAttempts())
	}
	if got := s.Delay(99, nil); got != 10*time.Hour {
		t.Errorf("past end = %v", got)
	}
	if got := s.Delay(0, nil); got != 5*time.Second {
		t.Errorf("attempt 0 = %v", got)
	}
	if got := (Schedule{}).Delay(1, nil); got != 0 {
		t.Errorf("empty schedule = %v", got)
	}

	jit := []struct {
		j    float64
		rnd  float64
		want time.Duration
	}{
		{0, 0.9, 100 * time.Second},
		{0.2, 0, 100 * time.Second},
		{0.2, 0.5, 90 * time.Second},
		{1, 0.25, 75 * time.Second}, // full jitter: uniform in [0, d]
		{1, 0.999, 100 * time.Millisecond},
		{5, 0.5, 50 * time.Second}, // clamped to full jitter
	}
	for _, tt := range jit {
		s := Schedule{Delays: []time.Duration{100 * time.Second}, Jitter: tt.j}
		got := s.Delay(1, func() float64 { return tt.rnd })
		if d := got - tt.want; d > time.Millisecond || d < -time.Millisecond {
			t.Errorf("jitter %v rnd %v = %v, want %v", tt.j, tt.rnd, got, tt.want)
		}
	}
}

func TestExponential(t *testing.T) {
	e := Exponential{Base: time.Second, Max: 10 * time.Second, Attempts: 6}
	want := []time.Duration{1, 2, 4, 8, 10, 10}
	for i, w := range want {
		if got := e.Delay(i+1, nil); got != w*time.Second {
			t.Errorf("Delay(%d) = %v", i+1, got)
		}
	}
	if e.Delay(0, nil) != time.Second || e.MaxAttempts() != 6 {
		t.Error("attempt 0 or max attempts")
	}
	full := Exponential{Base: time.Second, Jitter: 1}
	for i := 0; i < 100; i++ {
		if d := full.Delay(4, func() float64 { return float64(i) / 100 }); d < 0 || d > 8*time.Second {
			t.Fatalf("full jitter out of range: %v", d)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"120", 2 * time.Minute, true},
		{"0", 0, true},
		{"-1", 0, false},
		{"soon", 0, false},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{now.Add(-time.Hour).Format(http.TimeFormat), 0, true},
	}
	for _, tt := range tests {
		got, ok := ParseRetryAfter(tt.in, now)
		if got != tt.want || ok != tt.ok {
			t.Errorf("ParseRetryAfter(%q) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestBreakerStateMachine(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(BreakerConfig{FailureThreshold: 3, OpenFor: 10 * time.Second, MaxOpenFor: 25 * time.Second})
	type step struct {
		do      string // allow, fail, ok, advance, release
		d       time.Duration
		allowed bool
		state   BreakerState
	}
	steps := []step{
		{do: "allow", allowed: true, state: BreakerClosed},
		{do: "fail", state: BreakerClosed},
		{do: "fail", state: BreakerClosed},
		{do: "ok", state: BreakerClosed}, // success resets the count
		{do: "fail", state: BreakerClosed},
		{do: "fail", state: BreakerClosed},
		{do: "fail", state: BreakerOpen},
		{do: "allow", allowed: false, state: BreakerOpen},
		{do: "advance", d: 9 * time.Second, state: BreakerOpen},
		{do: "allow", allowed: false, state: BreakerOpen},
		{do: "advance", d: time.Second, state: BreakerHalfOpen},
		{do: "allow", allowed: true, state: BreakerHalfOpen},  // the probe
		{do: "allow", allowed: false, state: BreakerHalfOpen}, // only one probe
		{do: "fail", state: BreakerOpen},                      // probe failed: open for 20s
		{do: "advance", d: 19 * time.Second, state: BreakerOpen},
		{do: "advance", d: time.Second, state: BreakerHalfOpen},
		{do: "allow", allowed: true, state: BreakerHalfOpen},
		{do: "release", state: BreakerHalfOpen}, // abandoned probe frees the slot
		{do: "allow", allowed: true, state: BreakerHalfOpen},
		{do: "fail", state: BreakerOpen}, // open for min(40s, 25s)
		{do: "advance", d: 24 * time.Second, state: BreakerOpen},
		{do: "advance", d: time.Second, state: BreakerHalfOpen},
		{do: "allow", allowed: true, state: BreakerHalfOpen},
		{do: "ok", state: BreakerClosed},
		{do: "fail", state: BreakerClosed},
		{do: "fail", state: BreakerClosed},
		{do: "fail", state: BreakerOpen},
		{do: "advance", d: 10 * time.Second, state: BreakerHalfOpen}, // cool-down reset to 10s after close
	}
	for i, s := range steps {
		switch s.do {
		case "allow":
			ok, retry := b.Allow(now)
			if ok != s.allowed {
				t.Fatalf("step %d: Allow = %v, want %v", i, ok, s.allowed)
			}
			if !ok && b.State(now) == BreakerOpen && !retry.After(now) {
				t.Fatalf("step %d: retryAt %v not in the future", i, retry)
			}
		case "fail":
			b.Failure(now)
		case "ok":
			b.Success()
		case "advance":
			now = now.Add(s.d)
		case "release":
			b.Release()
		}
		if got := b.State(now); got != s.state {
			t.Fatalf("step %d (%s): state = %v, want %v", i, s.do, got, s.state)
		}
	}
	for st, name := range map[BreakerState]string{BreakerClosed: "closed", BreakerHalfOpen: "half_open", BreakerOpen: "open", 7: "unknown"} {
		if st.String() != name {
			t.Errorf("%d.String() = %q", st, st.String())
		}
	}

	off := NewBreaker(BreakerConfig{FailureThreshold: -1})
	for i := 0; i < 10; i++ {
		off.Failure(now)
	}
	if ok, _ := off.Allow(now); !ok {
		t.Fatal("disabled breaker rejected")
	}
}

func TestTokenBucket(t *testing.T) {
	now := time.Unix(0, 0)
	tb := NewTokenBucket(2, 3, now) // 2/s, burst 3
	for i := 0; i < 3; i++ {
		if ok, _ := tb.Take(now); !ok {
			t.Fatalf("burst token %d denied", i)
		}
	}
	ok, at := tb.Take(now)
	if ok || at != now.Add(500*time.Millisecond) {
		t.Fatalf("Take on empty = %v, %v", ok, at)
	}
	if ok, _ := tb.Take(now.Add(500 * time.Millisecond)); !ok {
		t.Fatal("token not refilled")
	}
	if ok, _ := tb.Take(now.Add(time.Hour)); !ok {
		t.Fatal("refill after long idle")
	}
	// Refill is capped at burst.
	n := 0
	for {
		if ok, _ := tb.Take(now.Add(time.Hour)); !ok {
			break
		}
		n++
	}
	if n != 2 {
		t.Fatalf("after idle: %d more tokens, want 2 (burst 3 minus the one taken)", n)
	}
	var nilBucket *TokenBucket
	if ok, _ := nilBucket.Take(now); !ok {
		t.Fatal("nil bucket must be unlimited")
	}
	if ok, _ := NewTokenBucket(0, 0, now).Take(now); !ok {
		t.Fatal("zero rate must be unlimited")
	}
	if tb := NewTokenBucket(2.5, 0, now); tb.burst != 3 {
		t.Fatalf("default burst = %v", tb.burst)
	}
}

func TestMetricsFormat(t *testing.T) {
	m := NewMetrics()
	m.observeAttempt(OutcomeSuccess, 3*time.Millisecond)
	m.observeAttempt(OutcomeHTTP5xx, 2*time.Second)
	m.observeSucceeded()
	m.observeDead(OutcomeTimeout)
	m.observePublished(4)
	var buf bytes.Buffer
	if err := m.WriteTo(&buf, Gauges{QueueDepth: 7, InFlight: 2, DeadLetter: 1, Breakers: map[string]BreakerState{"ep_b": BreakerOpen, "ep_a": BreakerClosed}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`# TYPE webhook_attempts_total counter`,
		`webhook_attempts_total{outcome="success"} 1`,
		`webhook_attempts_total{outcome="http_5xx"} 1`,
		`webhook_deliveries_succeeded_total 1`,
		`webhook_deliveries_failed_total{class="timeout"} 1`,
		`webhook_messages_published_total 4`,
		`webhook_attempt_duration_seconds_bucket{le="0.005"} 1`,
		`webhook_attempt_duration_seconds_bucket{le="2.5"} 2`,
		`webhook_attempt_duration_seconds_bucket{le="+Inf"} 2`,
		`webhook_attempt_duration_seconds_count 2`,
		`webhook_queue_depth 7`,
		`webhook_inflight_requests 2`,
		`webhook_dlq_depth 1`,
		"webhook_breaker_state{endpoint=\"ep_a\"} 0\nwebhook_breaker_state{endpoint=\"ep_b\"} 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("no trailing newline")
	}
}

func TestEndpointHelpers(t *testing.T) {
	ep := Endpoint{EventTypes: []string{"pix.*", "charge.paid"}}
	for ev, want := range map[string]bool{"pix.received": true, "pix.": true, "charge.paid": true, "charge.failed": false, "pi": false} {
		if ep.Accepts(ev) != want {
			t.Errorf("Accepts(%q) = %v", ev, !want)
		}
	}
	if !(Endpoint{}).Accepts("anything") || !(Endpoint{EventTypes: []string{"*"}}).Accepts("x") {
		t.Error("empty filter or * must accept all")
	}
	now := time.Unix(100, 0)
	past, future := now.Add(-time.Second), now.Add(time.Second)
	ep.Keys = []EndpointKey{{Key: "a", ExpiresAt: &past}, {Key: "b", ExpiresAt: &future}, {Key: "c"}}
	keys := ep.ActiveKeys(now)
	if len(keys) != 2 || keys[0].Key != "c" || keys[1].Key != "b" {
		t.Fatalf("ActiveKeys = %+v", keys)
	}
	if id := NewID("msg"); !strings.HasPrefix(id, "msg_") || len(id) != 36 {
		t.Fatalf("NewID = %q", id)
	}
	if truncate("héllo", 2) != "h…" || truncate("abc", 5) != "abc" {
		t.Error("truncate")
	}
	if sanitize([]byte("a\x00b\nc\xff")) != "ab\nc�" {
		t.Errorf("sanitize = %q", sanitize([]byte("a\x00b\nc\xff")))
	}
}
