package relay

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Clock abstracts time so schedules, breakers and rate limits can be tested
// deterministically.
type Clock interface {
	Now() time.Time
	NewTimer(d time.Duration) Timer
}

// Timer is the subset of *time.Timer the engine uses.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

// SystemClock is the wall clock.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// NewTimer returns a real timer.
func (SystemClock) NewTimer(d time.Duration) Timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }
func (r realTimer) Stop() bool          { return r.t.Stop() }

// Backoff decides when a failed delivery is retried.
type Backoff interface {
	// Delay returns the wait after the given number of failed attempts
	// (attempt >= 1). rnd returns a uniform value in [0, 1).
	Delay(attempt int, rnd func() float64) time.Duration
	// MaxAttempts is the total number of attempts before dead-lettering.
	MaxAttempts() int
}

// DefaultSchedule is the retry schedule used when none is configured: an
// immediate first attempt, then retries after 5s, 5m, 30m, 2h, 5h, 10h and
// 10h, roughly 28 hours in total, before the delivery is dead-lettered.
var DefaultSchedule = []time.Duration{
	5 * time.Second, 5 * time.Minute, 30 * time.Minute,
	2 * time.Hour, 5 * time.Hour, 10 * time.Hour, 10 * time.Hour,
}

// Schedule is a fixed list of retry delays. Jitter in [0, 1] randomizes each
// delay d uniformly within [d*(1-Jitter), d]: 0 is no jitter, 1 is "full
// jitter" (uniform in [0, d]). The default schedule uses 0.2, so retries of
// many deliveries that failed together spread over the last fifth of each
// step instead of hitting the merchant in lockstep.
type Schedule struct {
	Delays []time.Duration
	Jitter float64
}

// Delay implements Backoff.
func (s Schedule) Delay(attempt int, rnd func() float64) time.Duration {
	if len(s.Delays) == 0 {
		return 0
	}
	i := attempt - 1
	if i < 0 {
		i = 0
	}
	if i >= len(s.Delays) {
		i = len(s.Delays) - 1
	}
	return jitter(s.Delays[i], s.Jitter, rnd)
}

// MaxAttempts implements Backoff.
func (s Schedule) MaxAttempts() int { return len(s.Delays) + 1 }

// Exponential is capped exponential backoff, Base*2^(attempt-1) up to Max,
// with the same Jitter semantics as Schedule (1 = full jitter).
type Exponential struct {
	Base     time.Duration
	Max      time.Duration
	Attempts int
	Jitter   float64
}

// Delay implements Backoff.
func (e Exponential) Delay(attempt int, rnd func() float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := float64(e.Base) * math.Pow(2, float64(attempt-1))
	if e.Max > 0 && d > float64(e.Max) {
		d = float64(e.Max)
	}
	return jitter(time.Duration(d), e.Jitter, rnd)
}

// MaxAttempts implements Backoff.
func (e Exponential) MaxAttempts() int { return e.Attempts }

func jitter(d time.Duration, j float64, rnd func() float64) time.Duration {
	if j <= 0 || rnd == nil {
		return d
	}
	if j > 1 {
		j = 1
	}
	return d - time.Duration(float64(d)*j*rnd())
}

// ParseRetryAfter interprets a Retry-After header (delta-seconds or an
// HTTP-date) relative to now. It returns false when the header is absent or
// invalid.
func ParseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// BreakerState is the state of a circuit breaker.
type BreakerState int

// Breaker states.
const (
	BreakerClosed BreakerState = iota
	BreakerHalfOpen
	BreakerOpen
)

func (s BreakerState) String() string {
	switch s {
	case BreakerClosed:
		return "closed"
	case BreakerHalfOpen:
		return "half_open"
	case BreakerOpen:
		return "open"
	}
	return "unknown"
}

// BreakerConfig configures per-endpoint circuit breakers.
type BreakerConfig struct {
	// FailureThreshold consecutive failures open the breaker. Default 5;
	// negative disables breakers.
	FailureThreshold int
	// OpenFor is the first cool-down before a probe is allowed. Each failed
	// probe doubles it, up to MaxOpenFor. Defaults 30s and 10m.
	OpenFor    time.Duration
	MaxOpenFor time.Duration
}

func (c BreakerConfig) withDefaults() BreakerConfig {
	if c.FailureThreshold == 0 {
		c.FailureThreshold = 5
	}
	if c.OpenFor <= 0 {
		c.OpenFor = 30 * time.Second
	}
	if c.MaxOpenFor <= 0 {
		c.MaxOpenFor = 10 * time.Minute
	}
	return c
}

// Breaker is a consecutive-failure circuit breaker. While open it rejects
// work, so the engine does not spend workers on an endpoint that is down;
// after the cool-down it lets exactly one probe through (half-open), and the
// probe's result closes or re-opens it.
type Breaker struct {
	cfg      BreakerConfig
	mu       sync.Mutex
	state    BreakerState
	failures int
	openFor  time.Duration
	until    time.Time
	probing  bool
}

// NewBreaker returns a closed breaker.
func NewBreaker(cfg BreakerConfig) *Breaker {
	cfg = cfg.withDefaults()
	return &Breaker{cfg: cfg, openFor: cfg.OpenFor}
}

// Allow reports whether a request may start now. When it returns false,
// retryAt is the earliest time to ask again (zero if a probe is in flight).
// A true result in the half-open state reserves the single probe slot; the
// caller must report its outcome with Success or Failure.
func (b *Breaker) Allow(now time.Time) (ok bool, retryAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg.FailureThreshold < 0 {
		return true, time.Time{}
	}
	switch b.state {
	case BreakerOpen:
		if now.Before(b.until) {
			return false, b.until
		}
		b.state = BreakerHalfOpen
		fallthrough
	case BreakerHalfOpen:
		if b.probing {
			return false, time.Time{}
		}
		b.probing = true
		return true, time.Time{}
	}
	return true, time.Time{}
}

// Success records a successful request.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state, b.failures, b.probing, b.openFor = BreakerClosed, 0, false, b.cfg.OpenFor
}

// Failure records a failed request at now.
func (b *Breaker) Failure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cfg.FailureThreshold < 0 {
		return
	}
	switch b.state {
	case BreakerHalfOpen:
		b.probing = false
		b.openFor *= 2
		if b.openFor > b.cfg.MaxOpenFor {
			b.openFor = b.cfg.MaxOpenFor
		}
		b.state, b.until = BreakerOpen, now.Add(b.openFor)
	case BreakerClosed:
		b.failures++
		if b.failures >= b.cfg.FailureThreshold {
			b.state, b.until = BreakerOpen, now.Add(b.openFor)
		}
	}
}

// Release frees a reserved probe slot without recording an outcome (for
// requests abandoned on shutdown).
func (b *Breaker) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probing = false
}

// State returns the current state as of now (an expired open breaker
// reports half-open).
func (b *Breaker) State(now time.Time) BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == BreakerOpen && !now.Before(b.until) {
		return BreakerHalfOpen
	}
	return b.state
}

// TokenBucket is a rate limiter refilled continuously at Rate tokens per
// second up to Burst tokens. A zero or negative rate means unlimited.
type TokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewTokenBucket returns a full bucket.
func NewTokenBucket(rate float64, burst int, now time.Time) *TokenBucket {
	if burst < 1 {
		burst = int(math.Max(1, math.Ceil(rate)))
	}
	return &TokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now}
}

// Take consumes a token if one is available. Otherwise it returns false and
// the time at which one will be.
func (tb *TokenBucket) Take(now time.Time) (bool, time.Time) {
	if tb == nil {
		return true, time.Time{}
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.rate <= 0 {
		return true, time.Time{}
	}
	if now.After(tb.last) {
		tb.tokens = math.Min(tb.burst, tb.tokens+now.Sub(tb.last).Seconds()*tb.rate)
		tb.last = now
	}
	if tb.tokens >= 1 {
		tb.tokens--
		return true, time.Time{}
	}
	wait := time.Duration(math.Ceil((1 - tb.tokens) / tb.rate * float64(time.Second)))
	return false, now.Add(wait)
}
