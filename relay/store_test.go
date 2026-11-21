package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/victorcondackdev/webhook-relay-go/wal"
)

var t0 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func storeImpls(t *testing.T) map[string]func(t *testing.T) Store {
	return map[string]func(t *testing.T) Store{
		"mem": func(t *testing.T) Store { return NewMemStore() },
		"file": func(t *testing.T) Store {
			s, err := OpenFileStore(FileStoreOptions{Dir: t.TempDir(), Sync: wal.SyncNever})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	}
}

func TestStoreContract(t *testing.T) {
	for name, open := range storeImpls(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()

			ep1 := Endpoint{ID: "ep_1", URL: "https://a.example", EventTypes: []string{"pix.*"}, CreatedAt: t0}
			ep2 := Endpoint{ID: "ep_2", URL: "https://b.example", CreatedAt: t0.Add(time.Second)}
			for _, ep := range []Endpoint{ep2, ep1} {
				if err := s.PutEndpoint(ctx, ep); err != nil {
					t.Fatal(err)
				}
			}
			eps, _ := s.ListEndpoints(ctx)
			if len(eps) != 2 || eps[0].ID != "ep_1" {
				t.Fatalf("ListEndpoints = %+v", eps)
			}
			got, err := s.GetEndpoint(ctx, "ep_1")
			if err != nil || got.URL != ep1.URL {
				t.Fatalf("GetEndpoint = %+v, %v", got, err)
			}
			got.EventTypes[0] = "mutated"
			if again, _ := s.GetEndpoint(ctx, "ep_1"); again.EventTypes[0] != "pix.*" {
				t.Fatal("store returned an aliased endpoint")
			}
			if _, err := s.GetEndpoint(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("missing endpoint: %v", err)
			}

			msg := Message{ID: "msg_1", EventType: "pix.received", Payload: json.RawMessage(`{"a":1}`), IdempotencyKey: "k1", CreatedAt: t0}
			dlvs := []Delivery{
				{ID: "dlv_1", MessageID: "msg_1", EndpointID: "ep_1", Seq: 1, State: StatePending},
				{ID: "dlv_2", MessageID: "msg_1", EndpointID: "ep_2", Seq: 2, State: StatePending},
			}
			if _, created, err := s.CreateMessage(ctx, msg, dlvs); err != nil || !created {
				t.Fatalf("CreateMessage = %v, %v", created, err)
			}
			dup := msg
			dup.ID = "msg_dup"
			ex, created, err := s.CreateMessage(ctx, dup, []Delivery{{ID: "dlv_x", MessageID: "msg_dup", EndpointID: "ep_1"}})
			if err != nil || created || ex.ID != "msg_1" {
				t.Fatalf("idempotent CreateMessage = %+v, %v, %v", ex, created, err)
			}
			conflict := dup
			conflict.Payload = json.RawMessage(`{"a":2}`)
			if _, _, err := s.CreateMessage(ctx, conflict, nil); !errors.Is(err, ErrIdempotencyConflict) {
				t.Fatalf("conflict: %v", err)
			}
			if _, err := s.GetDelivery(ctx, "dlv_x"); !errors.Is(err, ErrNotFound) {
				t.Fatal("duplicate message stored deliveries")
			}
			msg2 := Message{ID: "msg_2", EventType: "charge.paid", Payload: json.RawMessage(`{}`), CreatedAt: t0.Add(time.Hour)}
			s.CreateMessage(ctx, msg2, []Delivery{{ID: "dlv_3", MessageID: "msg_2", EndpointID: "ep_2", Seq: 3, State: StatePending}})

			if m, err := s.GetMessage(ctx, "msg_2"); err != nil || m.EventType != "charge.paid" {
				t.Fatalf("GetMessage = %+v, %v", m, err)
			}
			if _, err := s.GetMessage(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatal("missing message")
			}
			if ms, _ := s.ListMessages(ctx, t0.Add(time.Minute)); len(ms) != 1 || ms[0].ID != "msg_2" {
				t.Fatalf("ListMessages since = %+v", ms)
			}
			if ms, _ := s.ListMessages(ctx, time.Time{}); len(ms) != 2 || ms[0].ID != "msg_1" {
				t.Fatalf("ListMessages all = %+v", ms)
			}

			d := dlvs[1]
			d.State, d.Attempts = StateDead, 3
			a := Attempt{ID: "att_1", DeliveryID: d.ID, MessageID: "msg_1", EndpointID: "ep_2", Number: 3, Outcome: OutcomeHTTP5xx}
			if err := s.RecordAttempt(ctx, a, d); err != nil {
				t.Fatal(err)
			}
			if atts, _ := s.ListAttempts(ctx, "msg_1"); len(atts) != 1 || atts[0].ID != "att_1" {
				t.Fatalf("ListAttempts = %+v", atts)
			}
			if _, err := s.ListAttempts(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatal("attempts of missing message")
			}

			filters := []struct {
				f    DeliveryFilter
				want []string
			}{
				{DeliveryFilter{}, []string{"dlv_1", "dlv_2", "dlv_3"}},
				{DeliveryFilter{State: StatePending}, []string{"dlv_1", "dlv_3"}},
				{DeliveryFilter{State: StateDead}, []string{"dlv_2"}},
				{DeliveryFilter{EndpointID: "ep_2"}, []string{"dlv_2", "dlv_3"}},
				{DeliveryFilter{MessageID: "msg_1"}, []string{"dlv_1", "dlv_2"}},
				{DeliveryFilter{MessageID: "msg_1", State: StatePending}, []string{"dlv_1"}},
				{DeliveryFilter{Limit: 1}, []string{"dlv_1"}},
			}
			for _, tt := range filters {
				ds, _ := s.ListDeliveries(ctx, tt.f)
				if ids := deliveryIDs(ds); fmt.Sprint(ids) != fmt.Sprint(tt.want) {
					t.Errorf("ListDeliveries(%+v) = %v, want %v", tt.f, ids, tt.want)
				}
			}

			d.State = StatePending
			if err := s.PutDeliveries(ctx, d); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.GetDelivery(ctx, d.ID); got.State != StatePending {
				t.Fatal("PutDeliveries did not update")
			}
			if err := s.PutDeliveries(ctx); err != nil {
				t.Fatal(err)
			}

			if err := s.DeleteEndpoint(ctx, "ep_2"); err != nil {
				t.Fatal(err)
			}
			if err := s.DeleteEndpoint(ctx, "ep_2"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("double delete: %v", err)
			}
			if ds, _ := s.ListDeliveries(ctx, DeliveryFilter{}); fmt.Sprint(deliveryIDs(ds)) != "[dlv_1]" {
				t.Fatalf("cascade delete left %v", deliveryIDs(ds))
			}
			// An attempt recorded after its endpoint was deleted must not
			// resurrect the delivery.
			s.RecordAttempt(ctx, Attempt{ID: "att_2", MessageID: "msg_2", DeliveryID: "dlv_3"}, Delivery{ID: "dlv_3", MessageID: "msg_2"})
			if _, err := s.GetDelivery(ctx, "dlv_3"); !errors.Is(err, ErrNotFound) {
				t.Fatal("deleted delivery resurrected")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func deliveryIDs(ds []Delivery) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.ID
	}
	return out
}

// digest renders a store's full state canonically so two states can be
// compared.
func digest(t *testing.T, s Store) string {
	t.Helper()
	ctx := context.Background()
	eps, _ := s.ListEndpoints(ctx)
	msgs, _ := s.ListMessages(ctx, time.Time{})
	dlvs, _ := s.ListDeliveries(ctx, DeliveryFilter{})
	var atts []Attempt
	for _, m := range msgs {
		a, _ := s.ListAttempts(ctx, m.ID)
		atts = append(atts, a...)
	}
	sort.Slice(atts, func(i, j int) bool { return atts[i].ID < atts[j].ID })
	b, _ := json.Marshal([]any{eps, msgs, dlvs, atts})
	return string(b)
}

// randomOps applies n random mutations to s and returns the digest after
// each one (index 0 is the empty state).
func randomOps(t *testing.T, s Store, rng *rand.Rand, n int) []string {
	ctx := context.Background()
	states := []string{digest(t, s)}
	var dlvIDs []string
	seq := uint64(0)
	for i := 0; i < n; i++ {
		switch op := rng.Intn(10); {
		case op == 0 || i < 2:
			s.PutEndpoint(ctx, Endpoint{ID: fmt.Sprintf("ep_%d", rng.Intn(3)), URL: "https://x.example", CreatedAt: t0})
		case op <= 4:
			id := fmt.Sprintf("msg_%d", i)
			seq++
			d := Delivery{ID: "dlv_" + id, MessageID: id, EndpointID: fmt.Sprintf("ep_%d", rng.Intn(3)), Seq: seq, State: StatePending}
			key := ""
			if rng.Intn(3) == 0 {
				key = fmt.Sprintf("key_%d", rng.Intn(5))
			}
			if _, created, _ := s.CreateMessage(ctx, Message{ID: id, EventType: "pix.received", Payload: json.RawMessage(`{"i":1}`), IdempotencyKey: key, CreatedAt: t0.Add(time.Duration(i) * time.Second)}, []Delivery{d}); created {
				dlvIDs = append(dlvIDs, d.ID)
			}
		case op <= 7 && len(dlvIDs) > 0:
			d, err := s.GetDelivery(ctx, dlvIDs[rng.Intn(len(dlvIDs))])
			if err != nil {
				continue
			}
			d.Attempts++
			d.State = []DeliveryState{StatePending, StateSucceeded, StateDead}[rng.Intn(3)]
			s.RecordAttempt(ctx, Attempt{ID: fmt.Sprintf("att_%d", i), DeliveryID: d.ID, MessageID: d.MessageID, Number: d.Attempts, Outcome: OutcomeHTTP5xx}, d)
		case op == 8 && len(dlvIDs) > 0:
			d, err := s.GetDelivery(ctx, dlvIDs[rng.Intn(len(dlvIDs))])
			if err != nil {
				continue
			}
			d.State = StatePending
			s.PutDeliveries(ctx, d)
		default:
			s.DeleteEndpoint(ctx, fmt.Sprintf("ep_%d", rng.Intn(3)))
		}
		states = append(states, digest(t, s))
	}
	return states
}

// TestFileStoreCrashRecovery writes a random history, cuts the newest
// segment at a random byte offset (a crash mid-write), and checks that the
// reopened store equals the state after some prefix of the history: no
// torn record is ever applied and nothing before the cut is lost.
func TestFileStoreCrashRecovery(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 60; iter++ {
		dir := t.TempDir()
		opts := FileStoreOptions{Dir: dir, Sync: wal.SyncNever, SegmentSize: 2048}
		s, err := OpenFileStore(opts)
		if err != nil {
			t.Fatal(err)
		}
		states := randomOps(t, s, rng, 10+rng.Intn(60))
		s.Close()

		segs, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
		sort.Strings(segs)
		last := segs[len(segs)-1]
		st, _ := os.Stat(last)
		cut := rng.Int63n(st.Size() + 1)
		os.Truncate(last, cut)

		s2, err := OpenFileStore(opts)
		if err != nil {
			t.Fatalf("iter %d: reopen after cut at %d/%d: %v", iter, cut, st.Size(), err)
		}
		got := digest(t, s2)
		match := -1
		for i := len(states) - 1; i >= 0; i-- {
			if states[i] == got {
				match = i
				break
			}
		}
		if match < 0 {
			t.Fatalf("iter %d: recovered state is not a prefix of the history", iter)
		}
		if cut == st.Size() && match != len(states)-1 {
			t.Fatalf("iter %d: lost data without any truncation", iter)
		}
		// The store keeps working after recovery.
		if err := s2.PutEndpoint(context.Background(), Endpoint{ID: "ep_after", CreatedAt: t0}); err != nil {
			t.Fatal(err)
		}
		s2.Close()
		s3, err := OpenFileStore(opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s3.GetEndpoint(context.Background(), "ep_after"); err != nil {
			t.Fatalf("iter %d: write after recovery lost", iter)
		}
		s3.Close()
	}
}

func TestFileStoreCompaction(t *testing.T) {
	dir := t.TempDir()
	now := t0.Add(100 * time.Hour)
	opts := FileStoreOptions{Dir: dir, Sync: wal.SyncAlways, Retention: 24 * time.Hour, CompactMinBytes: 1, Now: func() time.Time { return now }}
	s, err := OpenFileStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.PutEndpoint(ctx, Endpoint{ID: "ep_1", CreatedAt: t0})
	mk := func(id string, age time.Duration, st DeliveryState, key string) {
		m := Message{ID: id, EventType: "pix.received", Payload: json.RawMessage(`{}`), IdempotencyKey: key, CreatedAt: now.Add(-age)}
		d := Delivery{ID: "dlv_" + id, MessageID: id, EndpointID: "ep_1", State: StatePending}
		s.CreateMessage(ctx, m, []Delivery{d})
		for i := 0; i < 3; i++ { // history to compact away
			d.Attempts++
			s.RecordAttempt(ctx, Attempt{ID: fmt.Sprintf("att_%s_%d", id, i), MessageID: id, DeliveryID: d.ID}, d)
		}
		d.State = st
		s.RecordAttempt(ctx, Attempt{ID: "att_" + id + "_final", MessageID: id, DeliveryID: d.ID}, d)
	}
	mk("old_acked", 48*time.Hour, StateSucceeded, "k-old")
	mk("old_dead", 48*time.Hour, StateDead, "")
	mk("old_pending", 48*time.Hour, StatePending, "")
	mk("new_acked", time.Hour, StateSucceeded, "k-new")
	s.CreateMessage(ctx, Message{ID: "old_unrouted", EventType: "x", CreatedAt: now.Add(-48 * time.Hour)}, nil)

	if !s.NeedsCompaction() {
		t.Fatal("NeedsCompaction = false")
	}
	before := s.LogBytes()
	if err := s.Compact(ctx); err != nil {
		t.Fatal(err)
	}
	if s.LogBytes() >= before {
		t.Fatalf("log did not shrink: %d -> %d", before, s.LogBytes())
	}
	if s.NeedsCompaction() {
		t.Fatal("NeedsCompaction right after compaction")
	}
	check := func(s *FileStore) {
		t.Helper()
		for id, want := range map[string]bool{"old_acked": false, "old_unrouted": false, "old_dead": true, "old_pending": true, "new_acked": true} {
			_, err := s.GetMessage(ctx, id)
			if (err == nil) != want {
				t.Errorf("message %s kept=%v, want %v", id, err == nil, want)
			}
		}
		if atts, _ := s.ListAttempts(ctx, "new_acked"); len(atts) != 4 {
			t.Errorf("attempt history of retained message: %d", len(atts))
		}
		// The idempotency key of a compacted message is released; the one of
		// a retained message still deduplicates.
		if _, created, _ := s.CreateMessage(ctx, Message{ID: "again", EventType: "pix.received", Payload: json.RawMessage(`{}`), IdempotencyKey: "k-new"}, nil); created {
			t.Error("retained idempotency key not enforced")
		}
		if _, err := s.GetEndpoint(ctx, "ep_1"); err != nil {
			t.Error("endpoint lost in compaction")
		}
	}
	check(s)
	digestBefore := digest(t, s)
	s.Close()

	s2, err := OpenFileStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if digest(t, s2) != digestBefore {
		t.Fatalf("state after reopen differs from state after compaction\n%s\n%s", digest(t, s2), digestBefore)
	}
	check(s2)
	if segs, _ := filepath.Glob(filepath.Join(dir, "*.wal")); len(segs) != 1 {
		t.Fatalf("segments after compaction: %v", segs)
	}
	s2.Close()
}

// TestFileStoreInterruptedCompaction simulates a crash in the middle of
// writing a snapshot: the partial snapshot must be ignored and the previous
// state recovered in full.
func TestFileStoreInterruptedCompaction(t *testing.T) {
	dir := t.TempDir()
	opts := FileStoreOptions{Dir: dir, Sync: wal.SyncNever}
	s, _ := OpenFileStore(opts)
	states := randomOps(t, s, rand.New(rand.NewSource(1)), 40)
	want := states[len(states)-1]
	// Write what Compact writes, minus the end marker.
	s.log.Rotate()
	s.log.Append(mustJSON(walRecord{Op: opSnapshotBeg}))
	s.log.Append(mustJSON(walRecord{Op: opEndpointPut, Endpoint: &Endpoint{ID: "ep_partial"}}))
	s.Close()

	s2, err := OpenFileStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Recovery().DiscardedCompaction {
		t.Fatal("partial snapshot not detected")
	}
	if got := digest(t, s2); got != want {
		t.Fatal("state after interrupted compaction differs")
	}
	// New writes after recovery land after the truncation point and survive.
	s2.PutEndpoint(context.Background(), Endpoint{ID: "ep_new", CreatedAt: t0})
	s2.Close()
	s3, _ := OpenFileStore(opts)
	defer s3.Close()
	if _, err := s3.GetEndpoint(context.Background(), "ep_new"); err != nil {
		t.Fatal("write after discarded compaction lost")
	}
	if _, err := s3.GetEndpoint(context.Background(), "ep_partial"); err == nil {
		t.Fatal("partial snapshot applied")
	}
}

// TestFileStoreCompactionBeforeCleanup simulates a crash after the snapshot
// was complete but before the old segments were deleted.
func TestFileStoreCompactionBeforeCleanup(t *testing.T) {
	dir := t.TempDir()
	opts := FileStoreOptions{Dir: dir, Sync: wal.SyncNever, CompactMinBytes: 1}
	s, _ := OpenFileStore(opts)
	randomOps(t, s, rand.New(rand.NewSource(2)), 40)
	segs, _ := filepath.Glob(filepath.Join(dir, "*.wal"))
	old, _ := os.ReadFile(segs[0])
	if err := s.Compact(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := digest(t, s)
	s.Close()
	os.WriteFile(segs[0], old, 0o640) // the deletion "did not happen"

	s2, err := OpenFileStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if digest(t, s2) != want {
		t.Fatal("stale segment changed the recovered state")
	}
	if _, err := os.Stat(segs[0]); !os.IsNotExist(err) {
		t.Fatal("stale segment not removed on recovery")
	}
}

func TestFileStoreOpenErrors(t *testing.T) {
	if _, err := OpenFileStore(FileStoreOptions{}); err == nil {
		t.Fatal("empty dir accepted")
	}
	dir := t.TempDir()
	l, _ := wal.Open(wal.Options{Dir: dir})
	l.Append([]byte("not json"))
	l.Close()
	if _, err := OpenFileStore(FileStoreOptions{Dir: dir}); err == nil {
		t.Fatal("undecodable record accepted")
	}
}
