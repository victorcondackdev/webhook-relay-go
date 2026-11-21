package relay

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// Store is the durable source of truth for endpoints, messages, deliveries
// and attempts. The engine keeps its scheduling index in memory and rebuilds
// it from ListDeliveries(StatePending) on startup, so a Store only has to
// persist state, not order work.
//
// Every method must be atomic: in particular CreateMessage stores a message
// and all of its deliveries, or nothing, and RecordAttempt stores the attempt
// together with the delivery's new state. A relational implementation maps
// each method to one transaction (see the README for a Postgres sketch).
type Store interface {
	PutEndpoint(ctx context.Context, ep Endpoint) error
	GetEndpoint(ctx context.Context, id string) (Endpoint, error)
	ListEndpoints(ctx context.Context) ([]Endpoint, error)
	// DeleteEndpoint removes the endpoint and all of its deliveries.
	DeleteEndpoint(ctx context.Context, id string) error

	// CreateMessage stores msg and its deliveries. If msg.IdempotencyKey is
	// set and already used, it stores nothing and returns the existing
	// message with created=false, or ErrIdempotencyConflict if the existing
	// message has a different event type or payload.
	CreateMessage(ctx context.Context, msg Message, dlvs []Delivery) (existing Message, created bool, err error)
	GetMessage(ctx context.Context, id string) (Message, error)
	// ListMessages returns messages created at or after since, oldest first.
	ListMessages(ctx context.Context, since time.Time) ([]Message, error)

	// PutDeliveries creates or replaces deliveries.
	PutDeliveries(ctx context.Context, dlvs ...Delivery) error
	GetDelivery(ctx context.Context, id string) (Delivery, error)
	// ListDeliveries returns matching deliveries ordered by Seq.
	ListDeliveries(ctx context.Context, f DeliveryFilter) ([]Delivery, error)

	// RecordAttempt appends a and stores d (the delivery after the attempt).
	RecordAttempt(ctx context.Context, a Attempt, d Delivery) error
	// ListAttempts returns the attempts of a message, oldest first.
	ListAttempts(ctx context.Context, messageID string) ([]Attempt, error)

	Close() error
}

// DeliveryFilter selects deliveries. Zero fields match everything.
type DeliveryFilter struct {
	State      DeliveryState
	EndpointID string
	MessageID  string
	Limit      int
}

func (f DeliveryFilter) match(d Delivery) bool {
	return (f.State == "" || d.State == f.State) &&
		(f.EndpointID == "" || d.EndpointID == f.EndpointID) &&
		(f.MessageID == "" || d.MessageID == f.MessageID)
}

// state is the in-memory model shared by MemStore and FileStore. It is not
// safe for concurrent use; callers hold a lock.
type state struct {
	endpoints  map[string]Endpoint
	messages   map[string]Message
	idem       map[string]string // idempotency key -> message id
	deliveries map[string]Delivery
	byMessage  map[string][]string // message id -> delivery ids
	attempts   map[string][]Attempt
}

func newState() *state {
	return &state{
		endpoints:  map[string]Endpoint{},
		messages:   map[string]Message{},
		idem:       map[string]string{},
		deliveries: map[string]Delivery{},
		byMessage:  map[string][]string{},
		attempts:   map[string][]Attempt{},
	}
}

func (s *state) putEndpoint(ep Endpoint) { s.endpoints[ep.ID] = ep }

func (s *state) deleteEndpoint(id string) {
	delete(s.endpoints, id)
	for did, d := range s.deliveries {
		if d.EndpointID == id {
			s.removeDelivery(did)
		}
	}
}

func (s *state) removeDelivery(id string) {
	d, ok := s.deliveries[id]
	if !ok {
		return
	}
	delete(s.deliveries, id)
	ids := s.byMessage[d.MessageID]
	for i, x := range ids {
		if x == id {
			s.byMessage[d.MessageID] = append(ids[:i:i], ids[i+1:]...)
			break
		}
	}
}

// checkIdempotency returns the existing message for msg's key, if any.
func (s *state) checkIdempotency(msg Message) (Message, bool, error) {
	if msg.IdempotencyKey == "" {
		return Message{}, false, nil
	}
	id, ok := s.idem[msg.IdempotencyKey]
	if !ok {
		return Message{}, false, nil
	}
	ex := s.messages[id]
	if ex.EventType != msg.EventType || !bytes.Equal(ex.Payload, msg.Payload) {
		return ex, true, ErrIdempotencyConflict
	}
	return ex, true, nil
}

func (s *state) putMessage(msg Message, dlvs []Delivery) {
	s.messages[msg.ID] = msg
	if msg.IdempotencyKey != "" {
		s.idem[msg.IdempotencyKey] = msg.ID
	}
	for _, d := range dlvs {
		s.putDelivery(d)
	}
}

func (s *state) putDelivery(d Delivery) {
	if _, ok := s.deliveries[d.ID]; !ok {
		s.byMessage[d.MessageID] = append(s.byMessage[d.MessageID], d.ID)
	}
	s.deliveries[d.ID] = d
}

func (s *state) recordAttempt(a Attempt, d Delivery) {
	s.attempts[a.MessageID] = append(s.attempts[a.MessageID], a)
	if _, ok := s.deliveries[d.ID]; ok { // endpoint may have been deleted meanwhile
		s.deliveries[d.ID] = d
	}
}

func (s *state) listEndpoints() []Endpoint {
	out := make([]Endpoint, 0, len(s.endpoints))
	for _, e := range s.endpoints {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *state) listMessages(since time.Time) []Message {
	var out []Message
	for _, m := range s.messages {
		if !m.CreatedAt.Before(since) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *state) listDeliveries(f DeliveryFilter) []Delivery {
	var out []Delivery
	if f.MessageID != "" {
		for _, id := range s.byMessage[f.MessageID] {
			if d := s.deliveries[id]; f.match(d) {
				out = append(out, d)
			}
		}
	} else {
		for _, d := range s.deliveries {
			if f.match(d) {
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].ID < out[j].ID
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// MemStore is a non-durable Store for tests and ephemeral deployments.
type MemStore struct {
	mu sync.RWMutex
	s  *state
}

var _ Store = (*MemStore)(nil)

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore { return &MemStore{s: newState()} }

// PutEndpoint implements Store.
func (m *MemStore) PutEndpoint(_ context.Context, ep Endpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s.putEndpoint(cloneEndpoint(ep))
	return nil
}

// GetEndpoint implements Store.
func (m *MemStore) GetEndpoint(_ context.Context, id string) (Endpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ep, ok := m.s.endpoints[id]
	if !ok {
		return Endpoint{}, ErrNotFound
	}
	return cloneEndpoint(ep), nil
}

// ListEndpoints implements Store.
func (m *MemStore) ListEndpoints(context.Context) ([]Endpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.s.listEndpoints(), nil
}

// DeleteEndpoint implements Store.
func (m *MemStore) DeleteEndpoint(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.s.endpoints[id]; !ok {
		return ErrNotFound
	}
	m.s.deleteEndpoint(id)
	return nil
}

// CreateMessage implements Store.
func (m *MemStore) CreateMessage(_ context.Context, msg Message, dlvs []Delivery) (Message, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ex, found, err := m.s.checkIdempotency(msg); found {
		return ex, false, err
	}
	m.s.putMessage(msg, dlvs)
	return msg, true, nil
}

// GetMessage implements Store.
func (m *MemStore) GetMessage(_ context.Context, id string) (Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	msg, ok := m.s.messages[id]
	if !ok {
		return Message{}, ErrNotFound
	}
	return msg, nil
}

// ListMessages implements Store.
func (m *MemStore) ListMessages(_ context.Context, since time.Time) ([]Message, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.s.listMessages(since), nil
}

// PutDeliveries implements Store.
func (m *MemStore) PutDeliveries(_ context.Context, dlvs ...Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range dlvs {
		m.s.putDelivery(d)
	}
	return nil
}

// GetDelivery implements Store.
func (m *MemStore) GetDelivery(_ context.Context, id string) (Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.s.deliveries[id]
	if !ok {
		return Delivery{}, ErrNotFound
	}
	return d, nil
}

// ListDeliveries implements Store.
func (m *MemStore) ListDeliveries(_ context.Context, f DeliveryFilter) ([]Delivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.s.listDeliveries(f), nil
}

// RecordAttempt implements Store.
func (m *MemStore) RecordAttempt(_ context.Context, a Attempt, d Delivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s.recordAttempt(a, d)
	return nil
}

// ListAttempts implements Store.
func (m *MemStore) ListAttempts(_ context.Context, messageID string) ([]Attempt, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.s.messages[messageID]; !ok {
		return nil, ErrNotFound
	}
	return append([]Attempt(nil), m.s.attempts[messageID]...), nil
}

// Close implements Store.
func (m *MemStore) Close() error { return nil }

func cloneEndpoint(ep Endpoint) Endpoint {
	ep.EventTypes = append([]string(nil), ep.EventTypes...)
	ep.Keys = append([]EndpointKey(nil), ep.Keys...)
	return ep
}
