package relay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced Clock.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	fc *fakeClock
	c  chan time.Time
	at time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{fc: f, c: make(chan time.Time, 1), at: f.now.Add(d)}
	if d <= 0 {
		t.c <- f.now
		return t
	}
	f.timers = append(f.timers, t)
	return t
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.fc.mu.Lock()
	defer t.fc.mu.Unlock()
	for i, x := range t.fc.timers {
		if x == t {
			t.fc.timers = append(t.fc.timers[:i], t.fc.timers[i+1:]...)
			return true
		}
	}
	return false
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	keep := f.timers[:0]
	for _, t := range f.timers {
		if !t.at.After(f.now) {
			t.c <- f.now
		} else {
			keep = append(keep, t)
		}
	}
	f.timers = keep
}

// hasTimerAt reports whether a timer is armed for exactly at.
func (f *fakeClock) hasTimerAt(at time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.timers {
		if t.at.Equal(at) {
			return true
		}
	}
	return false
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}

func testLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// newTestEngine starts an engine that may reach loopback over plain http.
func newTestEngine(t testing.TB, cfg Config) *Engine {
	t.Helper()
	if cfg.Store == nil {
		cfg.Store = NewMemStore()
	}
	if cfg.Guard == nil {
		cfg.Guard = &Guard{Allow: loopback, AllowHTTP: true}
	}
	if cfg.Workers == 0 {
		cfg.Workers = 8
	}
	if cfg.Logger == nil {
		cfg.Logger = testLogger()
	}
	if cfg.Backoff == nil {
		cfg.Backoff = Schedule{Delays: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}}
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.Shutdown(ctx)
	})
	return e
}

// received is one request seen by a scriptServer.
type received struct {
	Header http.Header
	Body   []byte
	At     time.Time
}

// scriptServer answers each request with respond(n, msgID), where n is the
// 1-based attempt number for that webhook-id.
type scriptServer struct {
	*httptest.Server
	mu       sync.Mutex
	perMsg   map[string]int
	reqs     []received
	inflight int
	maxIn    int
	respond  func(n int, r *http.Request) (status int, header http.Header, delay time.Duration)
}

func newScriptServer(t testing.TB, respond func(n int, r *http.Request) (int, http.Header, time.Duration)) *scriptServer {
	s := &scriptServer{perMsg: map[string]int{}, respond: respond}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		id := r.Header.Get("webhook-id")
		s.mu.Lock()
		s.perMsg[id]++
		n := s.perMsg[id]
		s.reqs = append(s.reqs, received{Header: r.Header.Clone(), Body: body, At: time.Now()})
		s.inflight++
		if s.inflight > s.maxIn {
			s.maxIn = s.inflight
		}
		s.mu.Unlock()
		defer func() { s.mu.Lock(); s.inflight--; s.mu.Unlock() }()
		status, h, delay := http.StatusNoContent, http.Header(nil), time.Duration(0)
		if s.respond != nil {
			status, h, delay = s.respond(n, r)
		}
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		for k, v := range h {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"ok":false,"note":"from test server"}`))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *scriptServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func (s *scriptServer) requests() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.reqs...)
}

func always(status int) func(int, *http.Request) (int, http.Header, time.Duration) {
	return func(int, *http.Request) (int, http.Header, time.Duration) { return status, nil, 0 }
}

func failTimes(n, status int) func(int, *http.Request) (int, http.Header, time.Duration) {
	return func(i int, _ *http.Request) (int, http.Header, time.Duration) {
		if i <= n {
			return status, nil, 0
		}
		return http.StatusOK, nil, 0
	}
}

func publish(t testing.TB, e *Engine, eventType string, payload any) (Message, []Delivery) {
	t.Helper()
	b, _ := json.Marshal(payload)
	msg, dlvs, _, err := e.Publish(context.Background(), PublishInput{EventType: eventType, Payload: b})
	if err != nil {
		t.Fatal(err)
	}
	return msg, dlvs
}

func delivery(t testing.TB, e *Engine, id string) Delivery {
	t.Helper()
	d, err := e.store.GetDelivery(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func stateIs(e *Engine, id string, st DeliveryState) func() bool {
	return func() bool {
		d, err := e.store.GetDelivery(context.Background(), id)
		return err == nil && d.State == st
	}
}

func attemptsAre(e *Engine, id string, n int) func() bool {
	return func() bool {
		d, err := e.store.GetDelivery(context.Background(), id)
		return err == nil && d.Attempts == n
	}
}
