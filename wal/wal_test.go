package wal

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openT(t testing.TB, opts Options) *Log {
	t.Helper()
	l, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func readAll(t testing.TB, l *Log) [][]byte {
	t.Helper()
	var out [][]byte
	if err := l.Replay(func(_ Position, d []byte) error {
		out = append(out, append([]byte(nil), d...))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func record(i int) []byte {
	return []byte(fmt.Sprintf(`{"seq":%d,"pad":"%s"}`, i, bytes.Repeat([]byte{'x'}, i%37)))
}

func TestEncodeDecode(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("a"), bytes.Repeat([]byte("z"), 4096)} {
		enc := EncodeRecord(nil, data)
		got, n, err := DecodeRecord(enc)
		if err != nil || n != len(enc) || !bytes.Equal(got, data) {
			t.Fatalf("round trip %q: %v %d", data, err, n)
		}
	}
	enc := EncodeRecord(nil, []byte("hello"))
	tests := []struct {
		name string
		b    []byte
		want error
	}{
		{"empty", nil, ErrShortRecord},
		{"short header", enc[:5], ErrShortRecord},
		{"short body", enc[:len(enc)-1], ErrShortRecord},
		{"flipped data", flip(enc, len(enc)-1), ErrChecksum},
		{"flipped length", flip(enc, 0), ErrShortRecord},
		{"flipped crc", flip(enc, 5), ErrChecksum},
		{"huge length", []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}, ErrRecordTooLarge},
		{"zeros", make([]byte, 16), ErrChecksum},
	}
	for _, tt := range tests {
		if _, _, err := DecodeRecord(tt.b); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x40
	return c
}

func TestAppendReplayAcrossSegments(t *testing.T) {
	dir := t.TempDir()
	l := openT(t, Options{Dir: dir, SegmentSize: 256, Sync: SyncNever})
	var want [][]byte
	for i := 0; i < 100; i++ {
		want = append(want, record(i))
		if _, err := l.Append(record(i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.Segments()) < 5 {
		t.Fatalf("expected rotation, got %d segments", len(l.Segments()))
	}
	l.Close()

	l2 := openT(t, Options{Dir: dir, SegmentSize: 256})
	got := readAll(t, l2)
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("record %d = %q, want %q", i, got[i], want[i])
		}
	}
	if r := l2.Recovery(); r.Records != 100 || r.TruncatedBytes != 0 {
		t.Fatalf("recovery = %+v", r)
	}
	if _, err := l2.Append([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, l2); string(got[len(got)-1]) != "after" {
		t.Fatal("append after reopen lost")
	}
}

// TestTornWriteRecovery simulates a crash at every interesting point: the
// newest segment is cut at a random offset (and, half of the time, garbage is
// written past the cut, as a filesystem may leave after power loss). Recovery
// must return an exact prefix of what was written, never a corrupted record,
// and the log must accept appends afterwards.
func TestTornWriteRecovery(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 300; iter++ {
		dir := t.TempDir()
		l, err := Open(Options{Dir: dir, SegmentSize: 512, Sync: SyncNever})
		if err != nil {
			t.Fatal(err)
		}
		n := 1 + rng.Intn(60)
		var want [][]byte
		for i := 0; i < n; i++ {
			want = append(want, record(i))
			if _, err := l.Append(record(i)); err != nil {
				t.Fatal(err)
			}
		}
		segs := l.Segments()
		l.Close()

		last := l.path(segs[len(segs)-1])
		st, _ := os.Stat(last)
		cut := rng.Int63n(st.Size() + 1)
		if err := os.Truncate(last, cut); err != nil {
			t.Fatal(err)
		}
		if rng.Intn(2) == 0 {
			f, _ := os.OpenFile(last, os.O_WRONLY|os.O_APPEND, 0)
			junk := make([]byte, rng.Intn(40))
			rng.Read(junk)
			f.Write(junk)
			f.Close()
		}

		l2, err := Open(Options{Dir: dir, SegmentSize: 512, Sync: SyncNever})
		if err != nil {
			t.Fatalf("iter %d: open after cut %d: %v", iter, cut, err)
		}
		got := readAll(t, l2)
		if len(got) > len(want) {
			t.Fatalf("iter %d: recovered %d > written %d", iter, len(got), len(want))
		}
		for i := range got {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("iter %d: record %d corrupted: %q", iter, i, got[i])
			}
		}
		if _, err := l2.Append([]byte("tail")); err != nil {
			t.Fatal(err)
		}
		l2.Close()
		l3 := openT(t, Options{Dir: dir, SegmentSize: 512})
		got3 := readAll(t, l3)
		if len(got3) != len(got)+1 || string(got3[len(got3)-1]) != "tail" {
			t.Fatalf("iter %d: append after recovery not durable (%d vs %d)", iter, len(got3), len(got))
		}
		l3.Close()
	}
}

func TestMidLogCorruptionIsReported(t *testing.T) {
	dir := t.TempDir()
	l := openT(t, Options{Dir: dir, SegmentSize: 128})
	for i := 0; i < 20; i++ {
		l.Append(record(i))
	}
	segs := l.Segments()
	l.Close()
	first := l.path(segs[0])
	b, _ := os.ReadFile(first)
	b[headerSize+10] ^= 0xff
	os.WriteFile(first, b, 0o640)

	_, err := Open(Options{Dir: dir})
	var ce *CorruptError
	if !errors.As(err, &ce) || ce.Segment != segs[0] || !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v, want CorruptError in segment %d", err, segs[0])
	}
	if ce.Error() == "" {
		t.Fatal("empty error string")
	}

	// A bad magic is also corruption.
	os.WriteFile(first, []byte("NOTAWAL!"), 0o640)
	if _, err := Open(Options{Dir: dir}); !errors.As(err, &ce) {
		t.Fatalf("bad magic: err = %v", err)
	}
	// A short non-final segment too.
	os.WriteFile(first, []byte("WH"), 0o640)
	if _, err := Open(Options{Dir: dir}); !errors.As(err, &ce) {
		t.Fatalf("short segment: err = %v", err)
	}
}

func TestEmptyAndHeaderlessSegment(t *testing.T) {
	dir := t.TempDir()
	// Crash right after creating a segment file, before the magic hit disk.
	os.WriteFile(filepath.Join(dir, fmt.Sprintf("%020d.wal", 3)), []byte("WH"), 0o640)
	os.WriteFile(filepath.Join(dir, "README"), []byte("ignored"), 0o640)
	os.WriteFile(filepath.Join(dir, "junk.wal"), []byte("ignored"), 0o640)
	l := openT(t, Options{Dir: dir})
	if _, err := l.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	l.Close()
	l2 := openT(t, Options{Dir: dir})
	if got := readAll(t, l2); len(got) != 1 {
		t.Fatalf("got %d records", len(got))
	}
}

func TestRotateRemoveTruncate(t *testing.T) {
	dir := t.TempDir()
	l := openT(t, Options{Dir: dir})
	l.Append([]byte("old-1"))
	l.Append([]byte("old-2"))
	id, err := l.Rotate()
	if err != nil || id != 2 {
		t.Fatalf("Rotate = %d, %v", id, err)
	}
	pos, _ := l.Append([]byte("new-1"))
	if pos.Segment != 2 || pos.Offset != headerSize {
		t.Fatalf("pos = %+v", pos)
	}
	l.Append([]byte("new-2"))
	before := l.Size()
	if err := l.RemoveBefore(2); err != nil {
		t.Fatal(err)
	}
	if segs := l.Segments(); len(segs) != 1 || segs[0] != 2 {
		t.Fatalf("segments = %v", segs)
	}
	if l.Size() >= before {
		t.Fatal("size did not shrink")
	}
	pos2, _ := l.Append([]byte("new-3"))
	if err := l.TruncateAt(pos2); err != nil {
		t.Fatal(err)
	}
	if err := l.TruncateAt(Position{Segment: 1, Offset: 8}); err == nil {
		t.Fatal("truncate of inactive segment accepted")
	}
	if err := l.TruncateAt(Position{Segment: 2, Offset: 1 << 30}); err == nil {
		t.Fatal("out of range truncate accepted")
	}
	l.Append([]byte("new-4"))
	got := readAll(t, l)
	want := []string{"new-1", "new-2", "new-4"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Fatalf("got %q", got)
		}
	}
}

func TestSyncPolicies(t *testing.T) {
	for _, p := range []SyncPolicy{SyncAlways, SyncInterval, SyncNever} {
		t.Run(p.String(), func(t *testing.T) {
			l := openT(t, Options{Dir: t.TempDir(), Sync: p, SyncInterval: time.Millisecond})
			for i := 0; i < 10; i++ {
				if _, err := l.Append(record(i)); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(5 * time.Millisecond)
			if err := l.Sync(); err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal("double close:", err)
			}
			if _, err := l.Append(nil); !errors.Is(err, ErrClosed) {
				t.Fatalf("append after close: %v", err)
			}
			if _, err := l.Rotate(); !errors.Is(err, ErrClosed) {
				t.Fatalf("rotate after close: %v", err)
			}
			if err := l.Sync(); !errors.Is(err, ErrClosed) {
				t.Fatalf("sync after close: %v", err)
			}
		})
	}
	for in, want := range map[string]SyncPolicy{"always": SyncAlways, "": SyncAlways, "interval": SyncInterval, "never": SyncNever, "OFF": SyncNever} {
		if got, err := ParseSyncPolicy(in); err != nil || got != want {
			t.Errorf("ParseSyncPolicy(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseSyncPolicy("sometimes"); err == nil {
		t.Error("bad policy accepted")
	}
	if SyncPolicy(9).String() != "unknown" {
		t.Error("unknown policy name")
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("empty dir accepted")
	}
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o640)
	if _, err := Open(Options{Dir: f}); err == nil {
		t.Fatal("file as dir accepted")
	}
	l := openT(t, Options{Dir: t.TempDir()})
	if _, err := l.Append(make([]byte, MaxRecordSize+1)); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("oversized record: %v", err)
	}
	stop := errors.New("stop")
	l.Append([]byte("a"))
	if err := l.Replay(func(Position, []byte) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("replay error not propagated: %v", err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	for _, p := range []SyncPolicy{SyncInterval, SyncAlways} {
		t.Run(p.String(), func(t *testing.T) { testConcurrentAppends(t, p) })
	}
}

func testConcurrentAppends(t *testing.T, p SyncPolicy) {
	dir := t.TempDir()
	// Small segments force rotations while other writers wait for fsync.
	l := openT(t, Options{Dir: dir, SegmentSize: 4096, Sync: p, SyncInterval: time.Millisecond})
	var wg sync.WaitGroup
	const writers, per = 8, 200
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if _, err := l.Append([]byte(fmt.Sprintf("w%d-%d", w, i))); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	l.Close()
	l2 := openT(t, Options{Dir: dir})
	got := readAll(t, l2)
	if len(got) != writers*per {
		t.Fatalf("got %d records", len(got))
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[string(r)] = true
	}
	if len(seen) != writers*per {
		t.Fatal("duplicate or missing records")
	}
}

// FuzzDecodeRecord checks that the decoder never panics, never reads past
// its input, and accepts every record the encoder produces.
func FuzzDecodeRecord(f *testing.F) {
	f.Add(EncodeRecord(nil, []byte(`{"op":"delivery.put"}`)))
	f.Add(EncodeRecord(nil, nil))
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f})
	f.Add(make([]byte, 32))
	f.Fuzz(func(t *testing.T, b []byte) {
		data, n, err := DecodeRecord(b)
		if err != nil {
			if n != 0 || data != nil {
				t.Fatal("error with non-zero result")
			}
		} else {
			if n < headerSize || n > len(b) || len(data) != n-headerSize {
				t.Fatalf("bad n=%d len=%d", n, len(b))
			}
			if !bytes.Equal(EncodeRecord(nil, data), b[:n]) {
				t.Fatal("decoded record does not re-encode identically")
			}
		}
		if len(b) <= MaxRecordSize {
			enc := EncodeRecord(nil, b)
			got, m, err := DecodeRecord(enc)
			if err != nil || m != len(enc) || !bytes.Equal(got, b) {
				t.Fatalf("round trip failed: %v", err)
			}
		}
	})
}

// BenchmarkAppendParallel shows group commit: with SyncAlways, concurrent
// writers share fsyncs, so throughput scales with the number of writers.
func BenchmarkAppendParallel(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 512)
	l := openT(b, Options{Dir: b.TempDir(), Sync: SyncAlways})
	b.SetParallelism(16)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := l.Append(payload); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func TestWaitSyncAfterClose(t *testing.T) {
	l := openT(t, Options{Dir: t.TempDir(), Sync: SyncAlways})
	_, ticket, err := l.Write([][]byte{[]byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Close fsyncs, but a waiter that arrives later cannot know that.
	if err := l.WaitSync(ticket); err != nil && !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, _, err := l.Write([][]byte{make([]byte, MaxRecordSize+1)}); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatal(err)
	}
}

func BenchmarkAppend(b *testing.B) {
	payload := bytes.Repeat([]byte("x"), 512)
	for _, p := range []SyncPolicy{SyncNever, SyncInterval, SyncAlways} {
		b.Run("fsync="+p.String(), func(b *testing.B) {
			l := openT(b, Options{Dir: b.TempDir(), Sync: p})
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := l.Append(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
