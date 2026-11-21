package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/wal"
)

// FileStore is a durable Store backed by the write-ahead log in package wal.
//
// The full working set lives in memory (as in Redis with an append-only
// file, or Bitcask): every mutation is first appended to the log as one
// record and only then applied to memory, so the in-memory state is always a
// function of the log. On startup the log is replayed to rebuild it.
//
// Compact rewrites the live state into a fresh segment, framed by snapshot
// begin/end markers, and deletes older segments. A crash during compaction
// leaves an unterminated snapshot, which recovery discards; the older
// segments are only deleted after the end marker is on disk. Messages whose
// deliveries have all succeeded (acknowledged) are dropped by compaction once
// they are older than Retention; pending and dead-lettered work is always
// kept.
type FileStore struct {
	mu   sync.RWMutex
	s    *state
	log  *wal.Log
	opts FileStoreOptions

	lastSnapshot int64
	recovery     FileStoreRecovery
}

var _ Store = (*FileStore)(nil)

// FileStoreOptions configures a FileStore.
type FileStoreOptions struct {
	Dir          string
	Sync         wal.SyncPolicy
	SyncInterval time.Duration
	SegmentSize  int64
	// Retention is how long fully delivered messages (and their attempt
	// history, idempotency keys and replay eligibility) survive compaction.
	// Default 72h.
	Retention time.Duration
	// CompactMinBytes is the log size below which NeedsCompaction is always
	// false. Default 64 MiB.
	CompactMinBytes int64
	// Now is the clock used for retention. Default time.Now.
	Now func() time.Time
}

// FileStoreRecovery describes what OpenFileStore recovered.
type FileStoreRecovery struct {
	Records             int
	TruncatedBytes      int64
	DiscardedCompaction bool
}

type walRecord struct {
	Op         string     `json:"op"`
	ID         string     `json:"id,omitempty"`
	Endpoint   *Endpoint  `json:"endpoint,omitempty"`
	Message    *Message   `json:"message,omitempty"`
	Deliveries []Delivery `json:"deliveries,omitempty"`
	Attempt    *Attempt   `json:"attempt,omitempty"`
	Attempts   []Attempt  `json:"attempts,omitempty"`
}

const (
	opEndpointPut  = "endpoint.put"
	opEndpointDel  = "endpoint.delete"
	opMessagePut   = "message.put"
	opDeliveryPut  = "delivery.put"
	opAttempt      = "attempt"
	opSnapshotBeg  = "snapshot.begin"
	opSnapshotEnd  = "snapshot.end"
	defaultRetain  = 72 * time.Hour
	defaultCompact = 64 << 20
)

// OpenFileStore opens (or creates) a store in opts.Dir and recovers its state.
func OpenFileStore(opts FileStoreOptions) (*FileStore, error) {
	if opts.Retention <= 0 {
		opts.Retention = defaultRetain
	}
	if opts.CompactMinBytes <= 0 {
		opts.CompactMinBytes = defaultCompact
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	log, err := wal.Open(wal.Options{Dir: opts.Dir, Sync: opts.Sync, SyncInterval: opts.SyncInterval, SegmentSize: opts.SegmentSize})
	if err != nil {
		return nil, err
	}
	f := &FileStore{log: log, opts: opts}
	if err := f.recover(); err != nil {
		log.Close()
		return nil, err
	}
	return f, nil
}

func (f *FileStore) recover() error {
	cur := newState()
	var staging *state
	var snapPos wal.Position
	var snapSeg uint64
	records := 0
	err := f.log.Replay(func(pos wal.Position, data []byte) error {
		records++
		var rec walRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return fmt.Errorf("relay: undecodable wal record at %d:%d: %w", pos.Segment, pos.Offset, err)
		}
		switch rec.Op {
		case opSnapshotBeg:
			staging, snapPos = newState(), pos
		case opSnapshotEnd:
			if staging != nil {
				cur, staging, snapSeg = staging, nil, pos.Segment
			}
		default:
			target := cur
			if staging != nil {
				target = staging
			}
			apply(target, rec)
		}
		return nil
	})
	if err != nil {
		return err
	}
	f.recovery = FileStoreRecovery{Records: records, TruncatedBytes: f.log.Recovery().TruncatedBytes}
	if staging != nil {
		// The process died while writing a snapshot. The segments before it
		// are intact; drop the partial snapshot and continue appending.
		if err := f.log.TruncateAt(snapPos); err != nil {
			return err
		}
		f.recovery.DiscardedCompaction = true
	}
	if snapSeg > 0 {
		// The process may have died after finishing a snapshot but before
		// removing the segments it superseded.
		if err := f.log.RemoveBefore(snapSeg); err != nil {
			return err
		}
	}
	f.s = cur
	return nil
}

func apply(s *state, rec walRecord) {
	switch rec.Op {
	case opEndpointPut:
		if rec.Endpoint != nil {
			s.putEndpoint(*rec.Endpoint)
		}
	case opEndpointDel:
		s.deleteEndpoint(rec.ID)
	case opMessagePut:
		if rec.Message != nil {
			s.putMessage(*rec.Message, rec.Deliveries)
			if len(rec.Attempts) > 0 {
				s.attempts[rec.Message.ID] = rec.Attempts
			}
		}
	case opDeliveryPut:
		for _, d := range rec.Deliveries {
			s.putDelivery(d)
		}
	case opAttempt:
		if rec.Attempt != nil && len(rec.Deliveries) == 1 {
			s.recordAttempt(*rec.Attempt, rec.Deliveries[0])
		}
	}
}

// Recovery reports what was recovered when the store was opened.
func (f *FileStore) Recovery() FileStoreRecovery { return f.recovery }

// writeLocked appends rec to the log and, on success, applies it to memory.
// The caller holds f.mu and must call f.log.WaitSync(ticket) after releasing
// it; waiting outside the lock is what lets concurrent writers share an
// fsync. State applied here is visible to readers slightly before it is
// durable, but no caller is told a write succeeded until WaitSync returns,
// and the engine only schedules deliveries after that.
func (f *FileStore) writeLocked(rec walRecord) (uint64, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return 0, err
	}
	_, ticket, err := f.log.Write([][]byte{data})
	if err != nil {
		return 0, err
	}
	apply(f.s, rec)
	return ticket, nil
}

// commit is writeLocked plus locking and the durability wait.
func (f *FileStore) commit(rec walRecord) error {
	f.mu.Lock()
	ticket, err := f.writeLocked(rec)
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.log.WaitSync(ticket)
}

// PutEndpoint implements Store.
func (f *FileStore) PutEndpoint(_ context.Context, ep Endpoint) error {
	ep = cloneEndpoint(ep)
	return f.commit(walRecord{Op: opEndpointPut, Endpoint: &ep})
}

// GetEndpoint implements Store.
func (f *FileStore) GetEndpoint(_ context.Context, id string) (Endpoint, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	ep, ok := f.s.endpoints[id]
	if !ok {
		return Endpoint{}, ErrNotFound
	}
	return cloneEndpoint(ep), nil
}

// ListEndpoints implements Store.
func (f *FileStore) ListEndpoints(context.Context) ([]Endpoint, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.listEndpoints(), nil
}

// DeleteEndpoint implements Store.
func (f *FileStore) DeleteEndpoint(_ context.Context, id string) error {
	f.mu.Lock()
	if _, ok := f.s.endpoints[id]; !ok {
		f.mu.Unlock()
		return ErrNotFound
	}
	ticket, err := f.writeLocked(walRecord{Op: opEndpointDel, ID: id})
	f.mu.Unlock()
	if err != nil {
		return err
	}
	return f.log.WaitSync(ticket)
}

// CreateMessage implements Store.
func (f *FileStore) CreateMessage(_ context.Context, msg Message, dlvs []Delivery) (Message, bool, error) {
	f.mu.Lock()
	if ex, found, err := f.s.checkIdempotency(msg); found {
		f.mu.Unlock()
		return ex, false, err
	}
	ticket, err := f.writeLocked(walRecord{Op: opMessagePut, Message: &msg, Deliveries: dlvs})
	f.mu.Unlock()
	if err != nil {
		return Message{}, false, err
	}
	if err := f.log.WaitSync(ticket); err != nil {
		return Message{}, false, err
	}
	return msg, true, nil
}

// GetMessage implements Store.
func (f *FileStore) GetMessage(_ context.Context, id string) (Message, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	msg, ok := f.s.messages[id]
	if !ok {
		return Message{}, ErrNotFound
	}
	return msg, nil
}

// ListMessages implements Store.
func (f *FileStore) ListMessages(_ context.Context, since time.Time) ([]Message, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.listMessages(since), nil
}

// PutDeliveries implements Store.
func (f *FileStore) PutDeliveries(_ context.Context, dlvs ...Delivery) error {
	if len(dlvs) == 0 {
		return nil
	}
	return f.commit(walRecord{Op: opDeliveryPut, Deliveries: dlvs})
}

// GetDelivery implements Store.
func (f *FileStore) GetDelivery(_ context.Context, id string) (Delivery, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	d, ok := f.s.deliveries[id]
	if !ok {
		return Delivery{}, ErrNotFound
	}
	return d, nil
}

// ListDeliveries implements Store.
func (f *FileStore) ListDeliveries(_ context.Context, flt DeliveryFilter) ([]Delivery, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.listDeliveries(flt), nil
}

// RecordAttempt implements Store.
func (f *FileStore) RecordAttempt(_ context.Context, a Attempt, d Delivery) error {
	return f.commit(walRecord{Op: opAttempt, Attempt: &a, Deliveries: []Delivery{d}})
}

// ListAttempts implements Store.
func (f *FileStore) ListAttempts(_ context.Context, messageID string) ([]Attempt, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if _, ok := f.s.messages[messageID]; !ok {
		return nil, ErrNotFound
	}
	return append([]Attempt(nil), f.s.attempts[messageID]...), nil
}

// LogBytes returns the current size of the log on disk.
func (f *FileStore) LogBytes() int64 { return f.log.Size() }

// NeedsCompaction reports whether the log has grown past CompactMinBytes and
// to more than twice the size of the last snapshot.
func (f *FileStore) NeedsCompaction() bool {
	f.mu.RLock()
	last := f.lastSnapshot
	f.mu.RUnlock()
	size := f.log.Size()
	return size >= f.opts.CompactMinBytes && size > 2*last
}

// Compact rewrites the live state into a new segment and removes the old
// ones. Writers are blocked while the snapshot is written.
func (f *FileStore) Compact(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	cutoff := f.opts.Now().Add(-f.opts.Retention)
	recs := [][]byte{mustJSON(walRecord{Op: opSnapshotBeg})}
	live := newState()
	for _, ep := range f.s.listEndpoints() {
		ep := ep
		live.putEndpoint(ep)
		recs = append(recs, mustJSON(walRecord{Op: opEndpointPut, Endpoint: &ep}))
	}
	for _, msg := range f.s.listMessages(time.Time{}) {
		dlvs := f.s.listDeliveries(DeliveryFilter{MessageID: msg.ID})
		if msg.CreatedAt.Before(cutoff) && allSucceeded(dlvs) {
			continue // acknowledged and past retention
		}
		msg := msg
		atts := f.s.attempts[msg.ID]
		live.putMessage(msg, dlvs)
		if len(atts) > 0 {
			live.attempts[msg.ID] = atts
		}
		recs = append(recs, mustJSON(walRecord{Op: opMessagePut, Message: &msg, Deliveries: dlvs, Attempts: atts}))
	}
	recs = append(recs, mustJSON(walRecord{Op: opSnapshotEnd}))

	seg, err := f.log.Rotate()
	if err != nil {
		return err
	}
	if _, err := f.log.AppendBatch(recs); err != nil {
		return err // AppendBatch rolls back partial writes; old state stands
	}
	// From here on the log says the snapshot is the state.
	f.s = live
	if err := f.log.Sync(); err != nil {
		return err
	}
	if err := f.log.RemoveBefore(seg); err != nil {
		return err
	}
	f.lastSnapshot = f.log.Size()
	return nil
}

func allSucceeded(dlvs []Delivery) bool {
	for _, d := range dlvs {
		if d.State != StateSucceeded {
			return false
		}
	}
	return true
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only plain structs are marshaled here
	}
	return b
}

// Close flushes and closes the log.
func (f *FileStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.log.Close()
}
