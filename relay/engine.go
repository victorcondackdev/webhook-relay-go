// Package relay is a durable outbound webhook delivery engine.
//
// Producers publish messages; the engine fans each message out to every
// subscribed endpoint as a Delivery, persists it in a Store before
// acknowledging, and delivers it at least once with signed HTTP requests,
// retries on a backoff schedule, per-endpoint circuit breakers, concurrency
// and rate limits, SSRF protection and a dead-letter queue.
//
//	store, _ := relay.OpenFileStore(relay.FileStoreOptions{Dir: "/var/lib/relay"})
//	eng, _ := relay.New(relay.Config{Store: store})
//	eng.Start(ctx)
//	ep, _ := eng.CreateEndpoint(ctx, relay.EndpointSpec{URL: "https://merchant.example/webhooks"})
//	eng.Publish(ctx, relay.PublishInput{EventType: "pix.received", Payload: payload})
//	...
//	eng.Shutdown(ctx) // drains in-flight deliveries
package relay

import (
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/signature"
)

// Config configures an Engine. Only Store is required.
type Config struct {
	Store Store

	// Workers is the number of concurrent delivery requests across all
	// endpoints. Default 32.
	Workers int
	// Backoff defaults to Schedule{Delays: DefaultSchedule, Jitter: 0.2}.
	Backoff Backoff
	// RequestTimeout bounds each attempt, including reading the response
	// snippet. Default 15s.
	RequestTimeout time.Duration
	// MaxPayloadBytes bounds published payloads. Default 256 KiB.
	MaxPayloadBytes int
	// MaxResponseBytes is how much of each response body is kept in the
	// attempt log. Default 1 KiB.
	MaxResponseBytes int
	// MaxRetryAfter caps a receiver's Retry-After. Default 6h.
	MaxRetryAfter time.Duration
	// DefaultMaxConcurrency applies to endpoints that do not set their own.
	// Default 4.
	DefaultMaxConcurrency int
	// Breaker configures per-endpoint circuit breakers.
	Breaker BreakerConfig
	// Guard is the destination policy. Default: public addresses only, https
	// only.
	Guard *Guard
	// FollowRedirects enables following up to 3 redirects, each re-checked
	// by Guard. Default false: a 3xx is a failed attempt.
	FollowRedirects bool
	// Transport, if set, is cloned as the base HTTP transport (for custom
	// TLS roots, for example). Its Proxy and DialContext are always replaced
	// so every connection goes through Guard.
	Transport *http.Transport
	// KeyRotationOverlap is how long a replaced signing key keeps signing
	// alongside the new one. Default 24h.
	KeyRotationOverlap time.Duration
	// UserAgent defaults to "webhook-relay-go/0.1".
	UserAgent string

	Clock   Clock
	Rand    func() float64
	Logger  *slog.Logger
	Metrics *Metrics
}

const (
	minRetryAfter      = time.Second
	maxRedirects       = 3
	maxDrainBytes      = 64 << 10
	defaultUserAgent   = "webhook-relay-go/0.1"
	defaultMaxPayload  = 256 << 10
	defaultMaxResponse = 1 << 10
)

// Engine schedules and performs deliveries. Create it with New, then Start.
type Engine struct {
	cfg     Config
	store   Store
	client  *http.Client
	clock   Clock
	log     *slog.Logger
	metrics *Metrics
	backoff Backoff

	mu       sync.Mutex
	lanes    map[string]*lane
	order    []string
	rr       int
	idle     int
	queued   int
	inflight int
	seq      uint64
	stopping bool
	started  bool

	wake       chan struct{}
	work       chan *task
	stopCh     chan struct{}
	loopDone   chan struct{}
	workers    sync.WaitGroup
	reqCtx     context.Context
	cancelReqs context.CancelFunc
}

// New validates cfg and returns an engine that is not yet running.
func New(cfg Config) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("relay: Config.Store is required")
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 32
	}
	if cfg.Backoff == nil {
		cfg.Backoff = Schedule{Delays: DefaultSchedule, Jitter: 0.2}
	}
	if cfg.Backoff.MaxAttempts() < 1 {
		return nil, errors.New("relay: Backoff.MaxAttempts must be at least 1")
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 15 * time.Second
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = defaultMaxPayload
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponse
	}
	if cfg.MaxRetryAfter <= 0 {
		cfg.MaxRetryAfter = 6 * time.Hour
	}
	if cfg.DefaultMaxConcurrency <= 0 {
		cfg.DefaultMaxConcurrency = 4
	}
	if cfg.KeyRotationOverlap <= 0 {
		cfg.KeyRotationOverlap = 24 * time.Hour
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if cfg.Guard == nil {
		cfg.Guard = &Guard{}
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Float64
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(discard{}, nil))
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NewMetrics()
	}
	cfg.Breaker = cfg.Breaker.withDefaults()

	tr := &http.Transport{}
	if cfg.Transport != nil {
		tr = cfg.Transport.Clone()
	} else {
		tr.MaxIdleConns = 256
		tr.MaxIdleConnsPerHost = 16
		tr.IdleConnTimeout = 90 * time.Second
		tr.TLSHandshakeTimeout = 10 * time.Second
		tr.ForceAttemptHTTP2 = true
	}
	tr.Proxy = nil // a proxy would connect on our behalf and bypass the guard
	tr.DialContext = cfg.Guard.DialContext
	tr.DialTLSContext = nil
	client := &http.Client{Transport: tr}
	if cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return cfg.Guard.ValidateURL(req.URL.String())
		}
	} else {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	reqCtx, cancel := context.WithCancel(context.Background())
	return &Engine{
		cfg:        cfg,
		store:      cfg.Store,
		client:     client,
		clock:      cfg.Clock,
		log:        cfg.Logger,
		metrics:    cfg.Metrics,
		backoff:    cfg.Backoff,
		lanes:      map[string]*lane{},
		idle:       cfg.Workers,
		wake:       make(chan struct{}, 1),
		work:       make(chan *task),
		stopCh:     make(chan struct{}),
		loopDone:   make(chan struct{}),
		reqCtx:     reqCtx,
		cancelReqs: cancel,
	}, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Metrics returns the engine's metrics collector.
func (e *Engine) Metrics() *Metrics { return e.metrics }

// Start loads endpoints and pending deliveries from the store and starts the
// scheduler and workers.
func (e *Engine) Start(ctx context.Context) error {
	eps, err := e.store.ListEndpoints(ctx)
	if err != nil {
		return err
	}
	pending, err := e.store.ListDeliveries(ctx, DeliveryFilter{State: StatePending})
	if err != nil {
		return err
	}
	all, err := e.store.ListDeliveries(ctx, DeliveryFilter{})
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return errors.New("relay: engine already started")
	}
	e.started = true
	for _, ep := range eps {
		e.laneLocked(ep)
	}
	for _, d := range all {
		if d.Seq > e.seq {
			e.seq = d.Seq
		}
	}
	for _, d := range pending {
		e.enqueueLocked(d)
	}
	e.mu.Unlock()

	for i := 0; i < e.cfg.Workers; i++ {
		e.workers.Add(1)
		go e.worker()
	}
	go e.loop()
	e.log.Info("relay started", "workers", e.cfg.Workers, "recovered_pending", len(pending), "endpoints", len(eps))
	return nil
}

// Shutdown stops scheduling new attempts and waits for in-flight requests to
// finish. If ctx expires first, in-flight requests are cancelled; their
// deliveries stay pending (the attempt is not counted) and are retried on
// the next start. Shutdown does not close the store.
func (e *Engine) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.stopping || !e.started {
		e.stopping = true
		e.mu.Unlock()
		return nil
	}
	e.stopping = true
	inflight := e.inflight
	e.mu.Unlock()
	e.log.Info("relay draining", "inflight", inflight)

	close(e.stopCh)
	<-e.loopDone
	close(e.work)
	done := make(chan struct{})
	go func() { e.workers.Wait(); close(done) }()
	select {
	case <-done:
		e.cancelReqs()
		return nil
	case <-ctx.Done():
		e.cancelReqs()
		<-done
		return ctx.Err()
	}
}

// lane is the per-endpoint scheduling state.
type lane struct {
	ep       Endpoint
	breaker  *Breaker
	bucket   *TokenBucket
	pending  taskHeap
	inflight int
}

type task struct {
	d   Delivery
	idx int
}

// taskHeap orders an ordered lane by Seq and a parallel lane by due time.
type taskHeap struct {
	ordered bool
	items   []*task
}

func (h taskHeap) Len() int { return len(h.items) }
func (h taskHeap) Less(i, j int) bool {
	a, b := h.items[i].d, h.items[j].d
	if !h.ordered && !a.NextAttemptAt.Equal(b.NextAttemptAt) {
		return a.NextAttemptAt.Before(b.NextAttemptAt)
	}
	return a.Seq < b.Seq
}
func (h taskHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.items[i].idx, h.items[j].idx = i, j
}
func (h *taskHeap) Push(x any) { t := x.(*task); t.idx = len(h.items); h.items = append(h.items, t) }
func (h *taskHeap) Pop() any {
	n := len(h.items) - 1
	t := h.items[n]
	h.items[n] = nil
	h.items = h.items[:n]
	return t
}

func (e *Engine) laneLocked(ep Endpoint) *lane {
	l, ok := e.lanes[ep.ID]
	if !ok {
		l = &lane{breaker: NewBreaker(e.cfg.Breaker)}
		e.lanes[ep.ID] = l
		e.order = append(e.order, ep.ID)
	}
	if l.bucket == nil || l.ep.RateLimit != ep.RateLimit || l.ep.Burst != ep.Burst {
		l.bucket = nil
		if ep.RateLimit > 0 {
			l.bucket = NewTokenBucket(ep.RateLimit, ep.Burst, e.clock.Now())
		}
	}
	if l.pending.ordered != ep.Ordered {
		l.pending.ordered = ep.Ordered
		heap.Init(&l.pending)
	}
	l.ep = ep
	return l
}

func (e *Engine) removeLaneLocked(id string) {
	l, ok := e.lanes[id]
	if !ok {
		return
	}
	e.queued -= l.pending.Len()
	delete(e.lanes, id)
	for i, x := range e.order {
		if x == id {
			e.order = append(e.order[:i], e.order[i+1:]...)
			break
		}
	}
}

func (e *Engine) enqueueLocked(d Delivery) {
	l, ok := e.lanes[d.EndpointID]
	if !ok {
		return // endpoint deleted
	}
	heap.Push(&l.pending, &task{d: d})
	e.queued++
}

func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (l *lane) maxConcurrency(def int) int {
	if l.ep.Ordered {
		return 1
	}
	if l.ep.MaxConcurrency > 0 {
		return l.ep.MaxConcurrency
	}
	return def
}

// next pops the lane's next dispatchable task. When nothing can start now it
// returns the time worth waking up at (zero: wait for an event).
func (l *lane) next(now time.Time, defConc int) (*task, time.Time) {
	if l.ep.Disabled || l.pending.Len() == 0 || l.inflight >= l.maxConcurrency(defConc) {
		return nil, time.Time{}
	}
	head := l.pending.items[0]
	if head.d.NextAttemptAt.After(now) {
		return nil, head.d.NextAttemptAt
	}
	if ok, at := l.breaker.Allow(now); !ok {
		return nil, at
	}
	if ok, at := l.bucket.Take(now); !ok {
		l.breaker.Release()
		return nil, at
	}
	return heap.Pop(&l.pending).(*task), time.Time{}
}

func (e *Engine) loop() {
	defer close(e.loopDone)
	var timer Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		e.mu.Lock()
		if e.stopping {
			e.mu.Unlock()
			return
		}
		now := e.clock.Now()
		var batch []*task
		var wakeAt time.Time
		if n := len(e.order); n > 0 {
			for i := 0; i < n && e.idle > 0; i++ {
				l := e.lanes[e.order[(e.rr+i)%n]]
				for e.idle > 0 {
					t, at := l.next(now, e.cfg.DefaultMaxConcurrency)
					if t == nil {
						if !at.IsZero() && (wakeAt.IsZero() || at.Before(wakeAt)) {
							wakeAt = at
						}
						break
					}
					l.inflight++
					e.idle--
					e.inflight++
					e.queued--
					batch = append(batch, t)
				}
			}
			e.rr = (e.rr + 1) % n
		}
		e.mu.Unlock()

		for _, t := range batch {
			e.work <- t
		}
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		var tc <-chan time.Time
		if !wakeAt.IsZero() {
			timer = e.clock.NewTimer(wakeAt.Sub(now))
			tc = timer.C()
		}
		select {
		case <-e.wake:
		case <-tc:
		case <-e.stopCh:
			return
		}
	}
}

func (e *Engine) worker() {
	defer e.workers.Done()
	for t := range e.work {
		e.process(t)
	}
}

func (e *Engine) process(t *task) {
	e.mu.Lock()
	l := e.lanes[t.d.EndpointID]
	var ep Endpoint
	if l != nil {
		ep = l.ep
	}
	e.mu.Unlock()

	finish := func(requeue bool) {
		var orphan *Delivery
		e.mu.Lock()
		e.idle++
		e.inflight--
		if cur := e.lanes[t.d.EndpointID]; cur != nil {
			cur.inflight--
			if requeue && t.d.State == StatePending {
				if cur.ep.Disabled {
					// The endpoint was disabled while this request was in
					// flight: dead-letter it like the rest of its queue.
					d := t.d
					d.State, d.LastError = StateDead, "endpoint disabled: "+cur.ep.DisabledReason
					orphan = &d
				} else {
					heap.Push(&cur.pending, t)
					e.queued++
				}
			}
		}
		e.mu.Unlock()
		if orphan != nil {
			if err := e.store.PutDeliveries(context.Background(), *orphan); err != nil {
				e.log.Error("dead-letter delivery", "delivery_id", orphan.ID, "err", err)
			}
			e.metrics.observeDead(OutcomeGone)
		}
		e.signal()
	}
	if l == nil {
		finish(false)
		return
	}

	msg, err := e.store.GetMessage(e.reqCtx, t.d.MessageID)
	if err != nil {
		l.breaker.Release()
		e.log.Error("load message", "delivery_id", t.d.ID, "message_id", t.d.MessageID, "err", err)
		finish(false)
		return
	}

	att, retryAfter, hasRetryAfter := e.send(e.reqCtx, ep, msg, t.d)
	if e.reqCtx.Err() != nil {
		// Abandoned by shutdown: not an attempt. The delivery is still
		// pending in the store and is retried on the next start.
		l.breaker.Release()
		finish(false)
		return
	}
	now := e.clock.Now()
	d := t.d
	d.Attempts++
	d.LastStatus = att.StatusCode
	d.LastError = att.Error
	d.UpdatedAt = now

	disable := false
	switch att.Outcome {
	case OutcomeSuccess:
		l.breaker.Success()
		d.State = StateSucceeded
	case OutcomeGone:
		l.breaker.Release()
		d.State = StateDead
		disable = true
	case OutcomeBlocked, OutcomeConfig:
		// Retrying cannot help; dead-letter so an operator sees it.
		l.breaker.Release()
		d.State = StateDead
	default:
		l.breaker.Failure(now)
		if d.Attempts >= e.backoff.MaxAttempts() {
			d.State = StateDead
			break
		}
		delay := e.backoff.Delay(d.Attempts, e.cfg.Rand)
		if hasRetryAfter {
			delay = min(max(retryAfter, minRetryAfter), e.cfg.MaxRetryAfter)
		}
		d.NextAttemptAt = now.Add(delay)
		next := d.NextAttemptAt
		att.NextAt = &next
	}

	if err := e.store.RecordAttempt(context.Background(), att, d); err != nil {
		// The delivery stays pending in the store and will be retried after
		// a restart, which keeps the at-least-once guarantee.
		e.log.Error("record attempt", "delivery_id", d.ID, "err", err)
	}
	e.metrics.observeAttempt(att.Outcome, att.Duration)
	switch d.State {
	case StateSucceeded:
		e.metrics.observeSucceeded()
	case StateDead:
		e.metrics.observeDead(att.Outcome)
	}
	e.logAttempt(att, d)
	t.d = d
	if disable {
		// Disable before releasing the lane slot, so nothing else is
		// dispatched to an endpoint that told us it is gone.
		e.disableEndpoint(ep.ID, fmt.Sprintf("receiver returned 410 Gone at %s", now.UTC().Format(time.RFC3339)))
	}
	finish(true)
}

func (e *Engine) logAttempt(a Attempt, d Delivery) {
	level := slog.LevelInfo
	if a.Outcome != OutcomeSuccess {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("delivery_id", d.ID),
		slog.String("message_id", a.MessageID),
		slog.String("endpoint_id", a.EndpointID),
		slog.Int("attempt", a.Number),
		slog.String("outcome", string(a.Outcome)),
		slog.Int("status", a.StatusCode),
		slog.Duration("latency", a.Duration),
		slog.String("state", string(d.State)),
	}
	if a.Error != "" {
		attrs = append(attrs, slog.String("error", a.Error))
	}
	if a.NextAt != nil {
		attrs = append(attrs, slog.Time("next_attempt_at", *a.NextAt))
	}
	e.log.LogAttrs(context.Background(), level, "delivery attempt", attrs...)
}

// disableEndpoint marks the endpoint disabled and moves its pending
// deliveries to the dead-letter queue, from where they can be retried once
// the merchant fixes their side.
func (e *Engine) disableEndpoint(id, reason string) {
	ctx := context.Background()
	ep, err := e.store.GetEndpoint(ctx, id)
	if err != nil {
		return
	}
	if !ep.Disabled {
		ep.Disabled, ep.DisabledReason, ep.UpdatedAt = true, reason, e.clock.Now()
		if err := e.store.PutEndpoint(ctx, ep); err != nil {
			e.log.Error("disable endpoint", "endpoint_id", id, "err", err)
			return
		}
	}
	e.mu.Lock()
	var moved []Delivery
	if l := e.lanes[id]; l != nil {
		l.ep = ep
		for _, t := range l.pending.items {
			d := t.d
			d.State, d.LastError, d.UpdatedAt = StateDead, "endpoint disabled: "+reason, ep.UpdatedAt
			moved = append(moved, d)
		}
		e.queued -= l.pending.Len()
		l.pending.items = nil
	}
	e.mu.Unlock()
	if len(moved) > 0 {
		if err := e.store.PutDeliveries(ctx, moved...); err != nil {
			e.log.Error("dead-letter deliveries of disabled endpoint", "endpoint_id", id, "err", err)
		}
		for range moved {
			e.metrics.observeDead(OutcomeGone)
		}
	}
	e.log.Warn("endpoint disabled", "endpoint_id", id, "reason", reason, "dead_lettered", len(moved))
}

// PublishInput is a message to publish.
type PublishInput struct {
	EventType      string
	Payload        json.RawMessage
	IdempotencyKey string
	TraceParent    string // W3C traceparent of the producer, forwarded to receivers
	TraceState     string
}

var (
	eventTypeRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$`)
	traceparentRe = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

// Publish stores a message and one pending delivery per subscribed, enabled
// endpoint, then schedules them. When the store returns, the message is
// durable (subject to the store's sync policy). Publishing again with the
// same idempotency key returns the original message and created=false.
func (e *Engine) Publish(ctx context.Context, in PublishInput) (Message, []Delivery, bool, error) {
	if !eventTypeRe.MatchString(in.EventType) {
		return Message{}, nil, false, fmt.Errorf("%w: event_type must match %s", ErrInvalid, eventTypeRe)
	}
	if len(in.Payload) > e.cfg.MaxPayloadBytes {
		return Message{}, nil, false, fmt.Errorf("%w: %d bytes exceeds %d", ErrPayloadTooLarge, len(in.Payload), e.cfg.MaxPayloadBytes)
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage("null")
	}
	if !json.Valid(in.Payload) {
		return Message{}, nil, false, fmt.Errorf("%w: payload is not valid JSON", ErrInvalid)
	}
	if len(in.IdempotencyKey) > 255 {
		return Message{}, nil, false, fmt.Errorf("%w: idempotency key longer than 255 bytes", ErrInvalid)
	}
	if in.TraceParent != "" && !traceparentRe.MatchString(in.TraceParent) {
		in.TraceParent, in.TraceState = "", "" // invalid context is dropped, per W3C
	}
	eps, err := e.store.ListEndpoints(ctx)
	if err != nil {
		return Message{}, nil, false, err
	}
	now := e.clock.Now()
	msg := Message{
		ID:             NewID("msg"),
		EventType:      in.EventType,
		Payload:        in.Payload,
		IdempotencyKey: in.IdempotencyKey,
		TraceParent:    in.TraceParent,
		TraceState:     in.TraceState,
		CreatedAt:      now,
	}
	var dlvs []Delivery
	e.mu.Lock()
	for _, ep := range eps {
		if ep.Disabled || !ep.Accepts(in.EventType) {
			continue
		}
		e.seq++
		dlvs = append(dlvs, Delivery{
			ID: NewID("dlv"), MessageID: msg.ID, EndpointID: ep.ID, Seq: e.seq,
			State: StatePending, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now,
		})
	}
	e.mu.Unlock()

	existing, created, err := e.store.CreateMessage(ctx, msg, dlvs)
	if err != nil {
		return existing, nil, false, err
	}
	if !created {
		prev, err := e.store.ListDeliveries(ctx, DeliveryFilter{MessageID: existing.ID})
		return existing, prev, false, err
	}
	e.mu.Lock()
	for _, d := range dlvs {
		e.enqueueLocked(d)
	}
	e.mu.Unlock()
	e.metrics.observePublished(len(dlvs))
	e.signal()
	return msg, dlvs, true, nil
}

// GetMessage returns a message.
func (e *Engine) GetMessage(ctx context.Context, id string) (Message, error) {
	return e.store.GetMessage(ctx, id)
}

// Deliveries returns the deliveries of a message.
func (e *Engine) Deliveries(ctx context.Context, messageID string) ([]Delivery, error) {
	if _, err := e.store.GetMessage(ctx, messageID); err != nil {
		return nil, err
	}
	return e.store.ListDeliveries(ctx, DeliveryFilter{MessageID: messageID})
}

// Attempts returns the attempt log of a message.
func (e *Engine) Attempts(ctx context.Context, messageID string) ([]Attempt, error) {
	return e.store.ListAttempts(ctx, messageID)
}

// DeadLetters lists dead-lettered deliveries, optionally for one endpoint.
func (e *Engine) DeadLetters(ctx context.Context, endpointID string, limit int) ([]Delivery, error) {
	return e.store.ListDeliveries(ctx, DeliveryFilter{State: StateDead, EndpointID: endpointID, Limit: limit})
}

// RetryDead moves a dead-lettered delivery back to pending with a fresh
// attempt budget and schedules it immediately.
func (e *Engine) RetryDead(ctx context.Context, deliveryID string) (Delivery, error) {
	d, err := e.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return Delivery{}, err
	}
	if d.State != StateDead {
		return d, ErrNotDead
	}
	ep, err := e.store.GetEndpoint(ctx, d.EndpointID)
	if err != nil {
		return d, err
	}
	if ep.Disabled {
		return d, ErrEndpointDisabled
	}
	now := e.clock.Now()
	d.State, d.Attempts, d.NextAttemptAt, d.LastError, d.LastStatus, d.UpdatedAt = StatePending, 0, now, "", 0, now
	if err := e.store.PutDeliveries(ctx, d); err != nil {
		return d, err
	}
	e.mu.Lock()
	e.enqueueLocked(d)
	e.mu.Unlock()
	e.signal()
	return d, nil
}

// Replay creates new deliveries to an endpoint for every retained message
// created at or after since that the endpoint subscribes to, skipping
// messages that already have a pending delivery to it. It returns the
// number of deliveries scheduled.
func (e *Engine) Replay(ctx context.Context, endpointID string, since time.Time) (int, error) {
	ep, err := e.store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return 0, err
	}
	if ep.Disabled {
		return 0, ErrEndpointDisabled
	}
	msgs, err := e.store.ListMessages(ctx, since)
	if err != nil {
		return 0, err
	}
	pending, err := e.store.ListDeliveries(ctx, DeliveryFilter{EndpointID: endpointID, State: StatePending})
	if err != nil {
		return 0, err
	}
	busy := make(map[string]bool, len(pending))
	for _, d := range pending {
		busy[d.MessageID] = true
	}
	now := e.clock.Now()
	var dlvs []Delivery
	e.mu.Lock()
	for _, m := range msgs {
		if busy[m.ID] || !ep.Accepts(m.EventType) {
			continue
		}
		e.seq++
		dlvs = append(dlvs, Delivery{
			ID: NewID("dlv"), MessageID: m.ID, EndpointID: ep.ID, Seq: e.seq,
			State: StatePending, NextAttemptAt: now, CreatedAt: now, UpdatedAt: now,
		})
	}
	e.mu.Unlock()
	if len(dlvs) == 0 {
		return 0, nil
	}
	if err := e.store.PutDeliveries(ctx, dlvs...); err != nil {
		return 0, err
	}
	e.mu.Lock()
	for _, d := range dlvs {
		e.enqueueLocked(d)
	}
	e.mu.Unlock()
	e.signal()
	return len(dlvs), nil
}

// WriteMetrics renders metrics, including live gauges, in Prometheus format.
func (e *Engine) WriteMetrics(ctx context.Context, w interface{ Write([]byte) (int, error) }) error {
	dead, err := e.store.ListDeliveries(ctx, DeliveryFilter{State: StateDead})
	if err != nil {
		return err
	}
	now := e.clock.Now()
	e.mu.Lock()
	g := Gauges{QueueDepth: e.queued, InFlight: e.inflight, DeadLetter: len(dead), Breakers: make(map[string]BreakerState, len(e.lanes))}
	for id, l := range e.lanes {
		g.Breakers[id] = l.breaker.State(now)
	}
	e.mu.Unlock()
	return e.metrics.WriteTo(w, g)
}

// BreakerState returns the circuit breaker state of an endpoint.
func (e *Engine) BreakerState(endpointID string) (BreakerState, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.lanes[endpointID]
	if !ok {
		return BreakerClosed, false
	}
	return l.breaker.State(e.clock.Now()), true
}

// QueueDepth returns the number of pending deliveries not in flight.
func (e *Engine) QueueDepth() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.queued
}

func (e *Engine) signerFor(ep Endpoint, now time.Time) (signature.Signer, error) {
	var s signature.Signer
	for _, k := range ep.ActiveKeys(now) {
		switch ep.Signing {
		case SigningEd25519:
			sk, err := signature.ParseSigningKey(k.Key)
			if err != nil {
				return s, err
			}
			s.Keys = append(s.Keys, sk)
		default:
			sec, err := signature.ParseSecret(k.Key)
			if err != nil {
				return s, err
			}
			s.Secrets = append(s.Secrets, sec)
		}
	}
	if len(s.Keys)+len(s.Secrets) == 0 {
		return s, errors.New("endpoint has no active signing key")
	}
	return s, nil
}
