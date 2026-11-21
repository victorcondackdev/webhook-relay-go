package relay

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// latencyBuckets are the upper bounds, in seconds, of the attempt latency
// histogram.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// Metrics collects delivery metrics and renders them in the Prometheus text
// exposition format (version 0.0.4) without a client library.
type Metrics struct {
	mu        sync.Mutex
	attempts  map[Outcome]uint64
	succeeded uint64
	dead      map[Outcome]uint64
	published uint64
	buckets   []uint64
	latSum    float64
	latCount  uint64
}

// NewMetrics returns an empty collector.
func NewMetrics() *Metrics {
	return &Metrics{
		attempts: map[Outcome]uint64{},
		dead:     map[Outcome]uint64{},
		buckets:  make([]uint64, len(latencyBuckets)),
	}
}

func (m *Metrics) observeAttempt(o Outcome, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts[o]++
	s := d.Seconds()
	for i, ub := range latencyBuckets {
		if s <= ub {
			m.buckets[i]++
		}
	}
	m.latSum += s
	m.latCount++
}

func (m *Metrics) observeSucceeded() {
	m.mu.Lock()
	m.succeeded++
	m.mu.Unlock()
}

func (m *Metrics) observeDead(o Outcome) {
	m.mu.Lock()
	m.dead[o]++
	m.mu.Unlock()
}

func (m *Metrics) observePublished(n int) {
	m.mu.Lock()
	m.published += uint64(n)
	m.mu.Unlock()
}

// Gauges are point-in-time values supplied by the engine at scrape time.
type Gauges struct {
	QueueDepth int                     // pending deliveries known to the scheduler
	InFlight   int                     // requests in progress
	DeadLetter int                     // deliveries in the DLQ
	Breakers   map[string]BreakerState // endpoint id -> state
}

// WriteTo writes all metrics in Prometheus text format.
func (m *Metrics) WriteTo(w io.Writer, g Gauges) error {
	var b strings.Builder
	m.mu.Lock()
	counter(&b, "webhook_messages_published_total", "Deliveries created by published messages.", nil, float64(m.published))

	help(&b, "webhook_attempts_total", "counter", "Delivery attempts by outcome.")
	for _, o := range sortedOutcomes(m.attempts) {
		sample(&b, "webhook_attempts_total", map[string]string{"outcome": string(o)}, float64(m.attempts[o]))
	}
	counter(&b, "webhook_deliveries_succeeded_total", "Deliveries acknowledged with a 2xx.", nil, float64(m.succeeded))
	help(&b, "webhook_deliveries_failed_total", "counter", "Deliveries dead-lettered, by the outcome of the last attempt.")
	for _, o := range sortedOutcomes(m.dead) {
		sample(&b, "webhook_deliveries_failed_total", map[string]string{"class": string(o)}, float64(m.dead[o]))
	}

	help(&b, "webhook_attempt_duration_seconds", "histogram", "Latency of delivery attempts.")
	for i, ub := range latencyBuckets {
		sample(&b, "webhook_attempt_duration_seconds_bucket", map[string]string{"le": trimFloat(ub)}, float64(m.buckets[i]))
	}
	sample(&b, "webhook_attempt_duration_seconds_bucket", map[string]string{"le": "+Inf"}, float64(m.latCount))
	sample(&b, "webhook_attempt_duration_seconds_sum", nil, m.latSum)
	sample(&b, "webhook_attempt_duration_seconds_count", nil, float64(m.latCount))
	m.mu.Unlock()

	gauge(&b, "webhook_queue_depth", "Pending deliveries waiting for an attempt.", float64(g.QueueDepth))
	gauge(&b, "webhook_inflight_requests", "Delivery requests in progress.", float64(g.InFlight))
	gauge(&b, "webhook_dlq_depth", "Deliveries in the dead-letter queue.", float64(g.DeadLetter))

	help(&b, "webhook_breaker_state", "gauge", "Circuit breaker state per endpoint: 0 closed, 1 half-open, 2 open.")
	ids := make([]string, 0, len(g.Breakers))
	for id := range g.Breakers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		sample(&b, "webhook_breaker_state", map[string]string{"endpoint": id}, float64(g.Breakers[id]))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func help(b *strings.Builder, name, typ, text string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, text, name, typ)
}

func counter(b *strings.Builder, name, text string, labels map[string]string, v float64) {
	help(b, name, "counter", text)
	sample(b, name, labels, v)
}

func gauge(b *strings.Builder, name, text string, v float64) {
	help(b, name, "gauge", text)
	sample(b, name, nil, v)
}

func sample(b *strings.Builder, name string, labels map[string]string, v float64) {
	b.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, "%s=%q", k, escapeLabel(labels[k]))
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(trimFloat(v))
	b.WriteByte('\n')
}

// escapeLabel pre-escapes newlines; %q handles backslashes and quotes.
func escapeLabel(s string) string { return strings.ReplaceAll(s, "\n", " ") }

func trimFloat(f float64) string { return strings.TrimSuffix(fmt.Sprintf("%g", f), ".0") }

func sortedOutcomes(m map[Outcome]uint64) []Outcome {
	out := make([]Outcome, 0, len(m))
	for o := range m {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
