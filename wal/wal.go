// Package wal implements an append-only, segmented write-ahead log with
// per-record CRC32-C checksums and crash recovery.
//
// On disk a log is a directory of segment files named by a zero-padded,
// monotonically increasing number:
//
//	00000000000000000001.wal
//	00000000000000000002.wal
//
// Each segment starts with an 8-byte magic header followed by records:
//
//	+-----------+-----------+------------------+
//	| len (u32) | crc (u32) | data (len bytes) |
//	+-----------+-----------+------------------+
//
// Integers are little-endian. crc is CRC32-C (Castagnoli) over the four length
// bytes followed by the data, so a corrupted length is detected as reliably as
// corrupted data.
//
// # Recovery
//
// Open scans every segment. A record that is incomplete or fails its checksum
// at the tail of the newest segment is the signature of a torn write (the
// process or machine died mid-append): the segment is truncated to the last
// good record and the log continues from there. The same condition in an
// older segment cannot be produced by a crash, because a segment is always
// fsynced before the next one is created, so Open reports it as a
// *CorruptError instead of silently dropping acknowledged data.
//
// # Durability
//
// SyncAlways fsyncs after every Append before returning, so an acknowledged
// append survives power loss. SyncInterval fsyncs in the background, bounding
// loss to one interval. SyncNever leaves flushing to the operating system,
// which survives process crashes but not power loss.
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyncPolicy controls when appended data is fsynced.
type SyncPolicy int

// Sync policies.
const (
	SyncAlways SyncPolicy = iota
	SyncInterval
	SyncNever
)

// String returns the policy name used in flags and logs.
func (p SyncPolicy) String() string {
	switch p {
	case SyncAlways:
		return "always"
	case SyncInterval:
		return "interval"
	case SyncNever:
		return "never"
	}
	return "unknown"
}

// ParseSyncPolicy parses "always", "interval" or "never".
func ParseSyncPolicy(s string) (SyncPolicy, error) {
	switch strings.ToLower(s) {
	case "always", "":
		return SyncAlways, nil
	case "interval":
		return SyncInterval, nil
	case "never", "off":
		return SyncNever, nil
	}
	return 0, fmt.Errorf("wal: unknown sync policy %q", s)
}

const (
	headerSize = 8
	segmentExt = ".wal"

	// MaxRecordSize bounds a single record. It also bounds how much memory a
	// corrupted length field can make the decoder try to allocate.
	MaxRecordSize = 64 << 20

	defaultSegmentSize  = 64 << 20
	defaultSyncInterval = 100 * time.Millisecond
)

var magic = [8]byte{'W', 'H', 'R', 'W', 'A', 'L', 0, 1}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Errors returned by the decoder and the log.
var (
	ErrShortRecord    = errors.New("wal: short record")
	ErrChecksum       = errors.New("wal: checksum mismatch")
	ErrRecordTooLarge = errors.New("wal: record too large")
	ErrClosed         = errors.New("wal: log closed")
)

// CorruptError reports corruption that cannot be explained by a torn write.
type CorruptError struct {
	Segment uint64
	Offset  int64
	Err     error
}

func (e *CorruptError) Error() string {
	return fmt.Sprintf("wal: segment %d corrupt at offset %d: %v", e.Segment, e.Offset, e.Err)
}

func (e *CorruptError) Unwrap() error { return e.Err }

// EncodeRecord appends the framed encoding of data to dst.
func EncodeRecord(dst, data []byte) []byte {
	var hdr [headerSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(data)))
	crc := crc32.Update(0, castagnoli, hdr[0:4])
	crc = crc32.Update(crc, castagnoli, data)
	binary.LittleEndian.PutUint32(hdr[4:8], crc)
	dst = append(dst, hdr[:]...)
	return append(dst, data...)
}

// DecodeRecord decodes the first record in b. It returns the record payload
// (aliasing b) and the number of bytes consumed. It never panics, whatever
// the input.
func DecodeRecord(b []byte) (data []byte, n int, err error) {
	if len(b) < headerSize {
		return nil, 0, ErrShortRecord
	}
	length := binary.LittleEndian.Uint32(b[0:4])
	if length > MaxRecordSize {
		return nil, 0, ErrRecordTooLarge
	}
	end := headerSize + int(length)
	if len(b) < end {
		return nil, 0, ErrShortRecord
	}
	crc := crc32.Update(0, castagnoli, b[0:4])
	crc = crc32.Update(crc, castagnoli, b[headerSize:end])
	if crc != binary.LittleEndian.Uint32(b[4:8]) {
		return nil, 0, ErrChecksum
	}
	return b[headerSize:end], end, nil
}

// Position identifies a record in the log.
type Position struct {
	Segment uint64
	Offset  int64
}

// Options configures a Log.
type Options struct {
	// Dir holds the segment files. It is created if missing.
	Dir string
	// SegmentSize is the size at which the active segment is rotated.
	// Default 64 MiB.
	SegmentSize int64
	// Sync is the fsync policy. Default SyncAlways.
	Sync SyncPolicy
	// SyncInterval is the background fsync period for SyncInterval.
	// Default 100ms.
	SyncInterval time.Duration
}

// RecoveryInfo describes what Open found on disk.
type RecoveryInfo struct {
	Segments       int
	Records        int
	TruncatedBytes int64 // bytes of torn tail discarded
}

// Log is a segmented write-ahead log. It is safe for concurrent use.
type Log struct {
	opts Options

	mu       sync.Mutex
	segments []uint64 // sorted ids of segments on disk
	active   *os.File
	activeID uint64
	size     int64  // size of active segment
	total    int64  // bytes across all segments
	written  uint64 // tickets issued by Write
	synced   uint64 // highest ticket known to be on stable storage
	syncMu   sync.Mutex
	closed   bool
	buf      []byte
	recovery RecoveryInfo

	stop chan struct{}
	done chan struct{}
}

// Open opens (or creates) the log in opts.Dir, validating every segment and
// truncating a torn tail. Use Replay to read the recovered records.
func Open(opts Options) (*Log, error) {
	if opts.Dir == "" {
		return nil, errors.New("wal: Dir is required")
	}
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = defaultSegmentSize
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = defaultSyncInterval
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	l := &Log{opts: opts}
	ids, err := listSegments(opts.Dir)
	if err != nil {
		return nil, err
	}
	l.segments = ids
	for i, id := range ids {
		last := i == len(ids)-1
		valid, records, size, err := l.scan(id, last)
		if err != nil {
			return nil, err
		}
		l.recovery.Records += records
		if last && valid < size {
			if err := os.Truncate(l.path(id), valid); err != nil {
				return nil, err
			}
			l.recovery.TruncatedBytes = size - valid
		}
		l.total += valid
	}
	l.recovery.Segments = len(ids)

	if len(ids) == 0 {
		if err := l.createSegment(1); err != nil {
			return nil, err
		}
	} else {
		last := ids[len(ids)-1]
		f, err := os.OpenFile(l.path(last), os.O_RDWR, 0o640)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if st.Size() < headerSize { // crash right after creating the segment
			if err := f.Truncate(0); err == nil {
				_, err = f.WriteAt(magic[:], 0)
			}
			if err != nil {
				f.Close()
				return nil, err
			}
			l.total += headerSize - st.Size()
			st, _ = f.Stat()
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, err
		}
		l.active, l.activeID, l.size = f, last, st.Size()
	}
	if opts.Sync == SyncInterval {
		l.stop, l.done = make(chan struct{}), make(chan struct{})
		go l.syncLoop()
	}
	return l, nil
}

// Recovery returns what Open found on disk.
func (l *Log) Recovery() RecoveryInfo { return l.recovery }

// scan validates segment id and returns the length of its valid prefix.
func (l *Log) scan(id uint64, last bool) (valid int64, records int, size int64, err error) {
	data, err := os.ReadFile(l.path(id))
	if err != nil {
		return 0, 0, 0, err
	}
	size = int64(len(data))
	if len(data) < headerSize {
		if last {
			return 0, 0, size, nil
		}
		return 0, 0, size, &CorruptError{Segment: id, Err: ErrShortRecord}
	}
	if [8]byte(data[:headerSize]) != magic {
		// In the newest segment a bad header followed by nothing decodable is
		// a torn segment creation; anything else is real corruption.
		if _, _, derr := DecodeRecord(data[headerSize:]); last && derr != nil {
			return 0, 0, size, nil
		}
		return 0, 0, size, &CorruptError{Segment: id, Err: errors.New("bad magic")}
	}
	off := headerSize
	for off < len(data) {
		_, n, derr := DecodeRecord(data[off:])
		if derr != nil {
			if last {
				return int64(off), records, size, nil
			}
			return 0, 0, size, &CorruptError{Segment: id, Offset: int64(off), Err: derr}
		}
		off += n
		records++
	}
	return int64(off), records, size, nil
}

// Replay calls fn for every record in log order. It must not be called
// concurrently with Append. The data slice is only valid during the call.
func (l *Log) Replay(fn func(pos Position, data []byte) error) error {
	l.mu.Lock()
	ids := append([]uint64(nil), l.segments...)
	l.mu.Unlock()
	for _, id := range ids {
		data, err := os.ReadFile(l.path(id))
		if err != nil {
			return err
		}
		off := headerSize
		for off < len(data) {
			rec, n, err := DecodeRecord(data[off:])
			if err != nil {
				return &CorruptError{Segment: id, Offset: int64(off), Err: err}
			}
			if err := fn(Position{Segment: id, Offset: int64(off)}, rec); err != nil {
				return err
			}
			off += n
		}
	}
	return nil
}

// Append writes one record and, under SyncAlways, fsyncs it before returning.
func (l *Log) Append(data []byte) (Position, error) {
	return l.AppendBatch([][]byte{data})
}

// AppendBatch writes several records with a single write and waits for them
// to be durable according to the sync policy. It returns the position of the
// first record.
func (l *Log) AppendBatch(records [][]byte) (Position, error) {
	pos, ticket, err := l.Write(records)
	if err != nil {
		return Position{}, err
	}
	return pos, l.WaitSync(ticket)
}

// Write appends records without waiting for durability and returns a ticket
// for WaitSync. Splitting the two lets a caller release its own locks before
// waiting, so that concurrent writers share one fsync (group commit).
func (l *Log) Write(records [][]byte) (Position, uint64, error) {
	for _, r := range records {
		if len(r) > MaxRecordSize {
			return Position{}, 0, ErrRecordTooLarge
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return Position{}, 0, ErrClosed
	}
	if l.size >= l.opts.SegmentSize {
		if err := l.rotateLocked(); err != nil {
			return Position{}, 0, err
		}
	}
	buf := l.buf[:0]
	for _, r := range records {
		buf = EncodeRecord(buf, r)
	}
	l.buf = buf
	pos := Position{Segment: l.activeID, Offset: l.size}
	if _, err := l.active.Write(buf); err != nil {
		// Never leave a partial record in the middle of the segment: a later
		// successful append would otherwise sit behind garbage.
		_ = l.active.Truncate(pos.Offset)
		_, _ = l.active.Seek(pos.Offset, io.SeekStart)
		return Position{}, 0, err
	}
	l.size += int64(len(buf))
	l.total += int64(len(buf))
	l.written++
	return pos, l.written, nil
}

// WaitSync blocks until the write identified by ticket is on stable
// storage. It returns immediately unless the policy is SyncAlways. Under
// SyncAlways one caller performs the fsync and every write that completed
// before it started is covered by it, so N concurrent writers cost about
// one fsync rather than N.
func (l *Log) WaitSync(ticket uint64) error {
	if l.opts.Sync != SyncAlways {
		return nil
	}
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	l.mu.Lock()
	if l.synced >= ticket {
		l.mu.Unlock()
		return nil
	}
	if l.closed {
		l.mu.Unlock()
		return ErrClosed
	}
	target, f := l.written, l.active
	l.mu.Unlock()

	err := f.Sync()

	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil && l.synced >= ticket {
		err = nil // the segment was rotated (and fsynced) under us
	}
	if err == nil && target > l.synced {
		l.synced = target
	}
	return err
}

// Rotate closes the active segment and starts a new one, returning its id.
// Records appended afterwards land in the new segment.
func (l *Log) Rotate() (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, ErrClosed
	}
	if err := l.rotateLocked(); err != nil {
		return 0, err
	}
	return l.activeID, nil
}

func (l *Log) rotateLocked() error {
	// Always fsync a segment before creating its successor, whatever the
	// policy: this is what makes mid-log corruption distinguishable from a
	// torn tail during recovery.
	if err := l.active.Sync(); err != nil {
		return err
	}
	l.synced = l.written
	if err := l.active.Close(); err != nil {
		return err
	}
	return l.createSegment(l.activeID + 1)
}

func (l *Log) createSegment(id uint64) error {
	f, err := os.OpenFile(l.path(id), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(magic[:]); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := syncDir(l.opts.Dir); err != nil {
		f.Close()
		return err
	}
	l.active, l.activeID, l.size = f, id, headerSize
	l.total += headerSize
	l.segments = append(l.segments, id)
	return nil
}

// RemoveBefore deletes every segment whose id is lower than id. It is used
// after a compaction has rewritten the live state into segment id.
func (l *Log) RemoveBefore(id uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.segments[:0]
	var firstErr error
	for _, s := range l.segments {
		if s >= id || s == l.activeID {
			keep = append(keep, s)
			continue
		}
		if st, err := os.Stat(l.path(s)); err == nil {
			l.total -= st.Size()
		}
		if err := os.Remove(l.path(s)); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	l.segments = keep
	if firstErr != nil {
		return firstErr
	}
	return syncDir(l.opts.Dir)
}

// TruncateAt discards every record at or after pos. pos must be in the
// active segment; it is used to drop an unfinished compaction found during
// recovery.
func (l *Log) TruncateAt(pos Position) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pos.Segment != l.activeID {
		return fmt.Errorf("wal: can only truncate the active segment %d, not %d", l.activeID, pos.Segment)
	}
	if pos.Offset < headerSize || pos.Offset > l.size {
		return fmt.Errorf("wal: truncate offset %d out of range", pos.Offset)
	}
	if err := l.active.Truncate(pos.Offset); err != nil {
		return err
	}
	if _, err := l.active.Seek(pos.Offset, io.SeekStart); err != nil {
		return err
	}
	l.total -= l.size - pos.Offset
	l.size = pos.Offset
	return l.active.Sync()
}

// Sync fsyncs the active segment.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if err := l.active.Sync(); err != nil {
		return err
	}
	l.synced = l.written
	return nil
}

// Size returns the total bytes across all segments.
func (l *Log) Size() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

// Segments returns the ids of the segments currently on disk.
func (l *Log) Segments() []uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]uint64(nil), l.segments...)
}

// Close fsyncs and closes the log.
func (l *Log) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	if l.stop != nil {
		close(l.stop)
		<-l.done
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.active.Sync()
	if cerr := l.active.Close(); err == nil {
		err = cerr
	}
	return err
}

func (l *Log) syncLoop() {
	defer close(l.done)
	t := time.NewTicker(l.opts.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.mu.Lock()
			if l.written > l.synced && !l.closed {
				if l.active.Sync() == nil {
					l.synced = l.written
				}
			}
			l.mu.Unlock()
		}
	}
}

func (l *Log) path(id uint64) string {
	return filepath.Join(l.opts.Dir, fmt.Sprintf("%020d%s", id, segmentExt))
}

func listSegments(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, segmentExt) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(name, segmentExt), 10, 64)
		if err != nil || id == 0 {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some filesystems do not support fsync on directories; that is not an
	// error worth failing an append for.
	_ = d.Sync()
	return nil
}
