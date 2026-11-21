package relay

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Errors returned by the engine and stores. HTTP layers map them to status
// codes with errors.Is.
var (
	ErrNotFound            = errors.New("relay: not found")
	ErrIdempotencyConflict = errors.New("relay: idempotency key reused with a different request")
	ErrPayloadTooLarge     = errors.New("relay: payload too large")
	ErrInvalid             = errors.New("relay: invalid request")
	ErrBlockedDestination  = errors.New("relay: destination address is not allowed")
	ErrNotDead             = errors.New("relay: delivery is not dead-lettered")
	ErrEndpointDisabled    = errors.New("relay: endpoint is disabled")
)

// SigningScheme selects how deliveries to an endpoint are signed.
type SigningScheme string

// Signing schemes.
const (
	SigningHMAC    SigningScheme = "v1"  // HMAC-SHA256 with a whsec_ secret
	SigningEd25519 SigningScheme = "v1a" // ed25519 with a whsk_ key; receivers use whpk_
)

// EndpointKey is one signing secret (or key) of an endpoint. Several keys
// are active during a rotation; expired keys are ignored when signing.
type EndpointKey struct {
	Key       string     `json:"key"`                  // whsec_... or whsk_...
	CreatedAt time.Time  `json:"created_at"`           //
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil: no expiry
}

// Endpoint is a merchant URL subscribed to events.
type Endpoint struct {
	ID          string        `json:"id"`
	URL         string        `json:"url"`
	Description string        `json:"description,omitempty"`
	EventTypes  []string      `json:"event_types,omitempty"` // empty: all events; "pix.*" matches by prefix
	Signing     SigningScheme `json:"signing"`
	Keys        []EndpointKey `json:"keys"`

	// Ordered delivers messages to this endpoint one at a time in publish
	// order (a FIFO lane). A failing head message delays the ones behind it
	// until it succeeds or is dead-lettered.
	Ordered bool `json:"ordered"`
	// MaxConcurrency bounds in-flight requests to the endpoint (ignored, and
	// effectively 1, when Ordered). 0 means the engine default.
	MaxConcurrency int `json:"max_concurrency,omitempty"`
	// RateLimit is the sustained requests per second allowed; Burst is the
	// bucket size. 0 means unlimited.
	RateLimit float64 `json:"rate_limit,omitempty"`
	Burst     int     `json:"burst,omitempty"`

	Disabled       bool      `json:"disabled"`
	DisabledReason string    `json:"disabled_reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ActiveKeys returns the keys that have not expired at now, newest first.
func (e Endpoint) ActiveKeys(now time.Time) []EndpointKey {
	out := make([]EndpointKey, 0, len(e.Keys))
	for i := len(e.Keys) - 1; i >= 0; i-- {
		k := e.Keys[i]
		if k.ExpiresAt == nil || now.Before(*k.ExpiresAt) {
			out = append(out, k)
		}
	}
	return out
}

// Accepts reports whether the endpoint subscribes to eventType.
func (e Endpoint) Accepts(eventType string) bool {
	if len(e.EventTypes) == 0 {
		return true
	}
	for _, f := range e.EventTypes {
		if f == "*" || f == eventType {
			return true
		}
		if prefix, ok := strings.CutSuffix(f, "*"); ok && strings.HasPrefix(eventType, prefix) {
			return true
		}
	}
	return false
}

// Message is one published event. Its ID is sent as webhook-id on every
// attempt to every endpoint, so receivers can deduplicate on it.
type Message struct {
	ID             string          `json:"id"`
	EventType      string          `json:"event_type"`
	Payload        json.RawMessage `json:"payload"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
	TraceParent    string          `json:"traceparent,omitempty"`
	TraceState     string          `json:"tracestate,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

// DeliveryState is the lifecycle state of a Delivery.
type DeliveryState string

// Delivery states. Pending deliveries are owned by the scheduler; succeeded
// and dead are terminal (dead ones can be retried manually).
const (
	StatePending   DeliveryState = "pending"
	StateSucceeded DeliveryState = "succeeded"
	StateDead      DeliveryState = "dead"
)

// Delivery is the unit of work: one message to one endpoint.
type Delivery struct {
	ID            string        `json:"id"`
	MessageID     string        `json:"message_id"`
	EndpointID    string        `json:"endpoint_id"`
	Seq           uint64        `json:"seq"` // global publish order, used by ordered lanes
	State         DeliveryState `json:"state"`
	Attempts      int           `json:"attempts"`
	NextAttemptAt time.Time     `json:"next_attempt_at"`
	LastStatus    int           `json:"last_status,omitempty"`
	LastError     string        `json:"last_error,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// Outcome classifies an attempt. It is also the label used in metrics.
type Outcome string

// Attempt outcomes.
const (
	OutcomeSuccess   Outcome = "success"
	OutcomeHTTP4xx   Outcome = "http_4xx"
	OutcomeHTTP5xx   Outcome = "http_5xx"
	OutcomeThrottled Outcome = "throttled" // 429, or 503 with Retry-After
	OutcomeGone      Outcome = "gone"      // 410: endpoint disabled
	OutcomeRedirect  Outcome = "redirect"  // 3xx with redirects disabled
	OutcomeTimeout   Outcome = "timeout"
	OutcomeNetwork   Outcome = "network"
	OutcomeBlocked   Outcome = "blocked"      // SSRF guard refused the address
	OutcomeConfig    Outcome = "config_error" // endpoint cannot be signed for or addressed
)

// Attempt records one HTTP request made for a delivery.
type Attempt struct {
	ID         string        `json:"id"`
	DeliveryID string        `json:"delivery_id"`
	MessageID  string        `json:"message_id"`
	EndpointID string        `json:"endpoint_id"`
	Number     int           `json:"attempt"`
	StartedAt  time.Time     `json:"started_at"`
	Duration   time.Duration `json:"duration_ns"`
	StatusCode int           `json:"status_code,omitempty"`
	Outcome    Outcome       `json:"outcome"`
	Error      string        `json:"error,omitempty"`
	Response   string        `json:"response,omitempty"` // truncated body snippet
	NextAt     *time.Time    `json:"next_attempt_at,omitempty"`
}

// NewID returns a prefixed, roughly time-ordered random identifier, e.g.
// "msg_0192f3c1a2b4e5d6c7a8b9c0d1e2f3a4".
func NewID(prefix string) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	_, _ = rand.Read(b[6:])
	return prefix + "_" + hex.EncodeToString(b[:])
}
