// Package configstore is a small, durable key-value store for configuration, replicated over a gossip cluster: every
// node keeps all records in memory and in its own SQLite file, a change made on any node is pushed to the others of
// its group as it commits, and anti-entropy rounds repair whatever a push missed, so a node that was down or cut off
// catches up when it returns.
//
// Conflicts are settled per key, last writer wins: each written record carries a hybrid logical clock timestamp and
// the id of the node that wrote it, and the greater (timestamp, node id) pair wins everywhere. A delete leaves a
// tombstone that is kept for ever, so a node that missed the delete cannot bring the record back.
//
// It is meant for a few thousand records of a few KiB: every node holds every record in memory, and an anti-entropy
// round that finds a difference exchanges a summary of every key.
package configstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/paularlott/gossip"
	"github.com/paularlott/gossip/hlc"
	"github.com/paularlott/logger"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Limits on what a store accepts.
const (
	MaxKeyBytes   = 512
	MaxValueBytes = 1 << 20
	maxOrigin     = 128 // bytes of a record's Origin received from a peer
	// maxVersionAhead bounds how far ahead of this node's clock a peer's record may be stamped (the nodes' clocks are
	// synchronised; gossip refuses packets a minute off too). Witnessed, a version far ahead would be the floor of every
	// later write here and on every node it reaches, and win every edit and delete until the clocks caught up.
	maxVersionAhead = time.Minute
)

// Defaults of Options.
const (
	DefaultSyncInterval = 10 * time.Second
	DefaultPushTimeout  = time.Second
)

// lockTimeout is SQLite's busy_timeout: only this process writes the file, so it only matters if another program
// (a backup, the sqlite3 shell) holds a lock on it.
const lockTimeout = 5 * time.Second

var (
	// ErrClosed is returned by Update once the store is closed.
	ErrClosed = errors.New("configstore: closed")
	// ErrInvalidKey is returned by Update for a key that is empty, longer than MaxKeyBytes, not valid UTF-8 or
	// contains a NUL byte.
	ErrInvalidKey = errors.New("configstore: invalid key")
	// ErrValueTooLarge is returned by Update for a value longer than MaxValueBytes.
	ErrValueTooLarge = errors.New("configstore: value too large")
)

// Record is one key's latest state. Deleted records (tombstones) are kept forever, so a delete can never be undone by
// a node that missed it.
type Record struct {
	Key     string
	Value   []byte // nil when Deleted; never nil otherwise
	Version uint64 // hybrid logical clock timestamp (github.com/paularlott/gossip/hlc) of the write
	Origin  string // id of the node that wrote it
	Deleted bool
}

// newer reports whether r wins over o: a greater Version, or the same Version and a greater Origin.
func (r *Record) newer(o *Record) bool {
	return r.Version > o.Version || (r.Version == o.Version && r.Origin > o.Origin)
}

// size is roughly what r takes in a message, for chunking transfers.
func (r *Record) size() int { return len(r.Key) + len(r.Value) + len(r.Origin) + 24 }

// clone returns r with a copy of its value, for a caller that may modify it.
func (r Record) clone() Record {
	if r.Value != nil {
		r.Value = bytes.Clone(r.Value)
	}
	return r
}

// Options configure a Store.
type Options struct {
	// Path is the SQLite file. It and its directory are created if missing.
	Path string
	// Cluster replicates the store to the other nodes with a store; nil runs a single node without replication. The
	// caller creates, starts, joins and stops the cluster. A gossip node can carry one store.
	Cluster *gossip.Cluster
	// MsgBase is the first of the four gossip message types the store uses (MsgBase to MsgBase+3).
	// Default gossip.UserMsg+192.
	MsgBase gossip.MessageType
	// SyncInterval is how often the store runs an anti-entropy round with a random peer of the group. Default 10s.
	SyncInterval time.Duration
	// PushTimeout is how long Update waits for the peers to acknowledge the records it pushes to them. A peer that
	// does not never fails the write: anti-entropy brings it the records later. Default 1s.
	PushTimeout time.Duration
	// OnChange is called with the keys of records that changed, by local writes and by records received from peers.
	// It is called from one goroutine, never concurrently and never while the store holds a lock, so it may read and
	// update the store (but not close it); changes that arrive while it runs are coalesced into its next call.
	OnChange func(keys []string)
	Logger   logger.Logger
}

// Stats are a store's counters.
type Stats struct {
	Records     int       // live records
	Tombstones  int       // deleted records kept
	Peers       int       // other nodes of the group
	PeersSynced int       // of those, the ones whose last anti-entropy round completed
	LastSync    time.Time // when an anti-entropy round last completed; zero if none has
	Syncs       uint64    // anti-entropy rounds completed
	Repairs     uint64    // of those, the rounds that found the two nodes differed
	SyncErrors  uint64    // anti-entropy rounds that failed
	Pushes      uint64    // record messages sent to peers and acknowledged
	PushErrors  uint64    // record messages that failed or were not acknowledged in time
	Received    uint64    // records received from peers that changed this store
}

// Store is a replicated key-value store. Its methods are safe for concurrent use.
type Store struct {
	opts   Options
	log    logger.Logger
	db     *sql.DB
	clock  *hlc.Clock
	origin string
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup // the sync and notify loops
	pushes sync.WaitGroup // pushes of Update still running
	closed atomic.Bool

	// wmu serialises the writes, local and remote: it is held from reading the records a write depends on until the
	// write is in the database and in memory.
	wmu sync.Mutex

	mu         sync.RWMutex
	recs       map[string]Record
	keys       []string // every key in recs, sorted
	live       int      // records that are not tombstones
	digestOK   bool     // digestSum matches recs
	digestSum  []byte
	notifyKeys map[string]struct{} // changed keys OnChange has not been given yet

	notifyWake chan struct{}
	notifyStop chan struct{}

	// replication; c is nil for a single node
	c          *gossip.Cluster
	group      *gossip.NodeGroup
	msgRecords gossip.MessageType
	msgDigest  gossip.MessageType
	msgSummary gossip.MessageType
	msgFetch   gossip.MessageType
	syncWake   chan struct{}

	smu      sync.Mutex
	queue    []queued               // peers to sync with before the next random round
	synced   map[gossip.NodeID]bool // peers whose last round completed
	lastSync time.Time

	stats struct {
		syncs, repairs, syncErrors, pushes, pushErrors, received atomic.Uint64
	}
}

// Open opens (or creates) the store at o.Path, loads its records and, with o.Cluster, starts replicating.
func Open(o Options) (*Store, error) {
	if o.Path == "" {
		return nil, errors.New("configstore: no path")
	}
	if o.MsgBase == 0 {
		o.MsgBase = gossip.UserMsg + 192
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = DefaultSyncInterval
	}
	if o.PushTimeout <= 0 {
		o.PushTimeout = DefaultPushTimeout
	}
	if o.Logger == nil {
		o.Logger = logger.NewNullLogger()
	}
	if dir := filepath.Dir(o.Path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("configstore: %w", err)
		}
	}
	// The records may hold secrets: a new database is readable by its owner only, and SQLite gives its -wal and -shm
	// files the database file's permissions.
	if f, err := os.OpenFile(o.Path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
	} else if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("configstore: %w", err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(o.Path))
	if err != nil {
		return nil, fmt.Errorf("configstore: %w", err)
	}
	// One connection: every read is served from memory, and SQLite has one writer anyway.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Store{
		opts: o, log: o.Logger, db: db, clock: hlc.NewClock(), ctx: ctx, cancel: cancel,
		recs: make(map[string]Record), notifyKeys: make(map[string]struct{}),
		notifyWake: make(chan struct{}, 1), notifyStop: make(chan struct{}),
		c: o.Cluster, msgRecords: o.MsgBase, msgDigest: o.MsgBase + 1, msgSummary: o.MsgBase + 2, msgFetch: o.MsgBase + 3,
		syncWake: make(chan struct{}, 1), synced: make(map[gossip.NodeID]bool),
	}
	if err := s.load(ctx); err != nil {
		cancel()
		db.Close()
		return nil, fmt.Errorf("configstore: %s: %w", o.Path, err)
	}
	if s.c != nil {
		s.origin = s.c.LocalNode().ID.String()
		if err := s.startReplication(); err != nil {
			cancel()
			db.Close()
			return nil, err
		}
	}
	s.wg.Add(1)
	go s.notifyLoop()
	return s, nil
}

func sqliteDSN(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout("+strconv.FormatInt(lockTimeout.Milliseconds(), 10)+")")
	q.Add("_pragma", "journal_mode(WAL)")
	// FULL: a commit is on disk when it returns (NORMAL in WAL mode can lose the last commits to a power cut).
	q.Add("_pragma", "synchronous(FULL)")
	// Deleted and overwritten records (a tenant's HMAC secret) are zeroed in the file, not left in free pages.
	q.Add("_pragma", "secure_delete(ON)")
	q.Add("_txlock", "immediate")
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + strings.ReplaceAll(q.Encode(), "+", "%20")
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	name  TEXT PRIMARY KEY,
	value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS records (
	key     TEXT PRIMARY KEY,
	value   BLOB NOT NULL,
	version INTEGER NOT NULL,
	origin  TEXT NOT NULL,
	deleted INTEGER NOT NULL
) WITHOUT ROWID;
INSERT OR IGNORE INTO meta (name, value) VALUES ('schema', '1');
`

// load creates the tables if missing, reads every record into memory and sets the clock past every version, so
// that a write made now wins over every record the store holds.
func (s *Store) load(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE name = 'schema'`).Scan(&v); err != nil {
		return err
	}
	if v != "1" {
		return fmt.Errorf("unsupported schema version %q", v)
	}
	if s.c == nil {
		// A single node's origin is stable across restarts: a stored random id.
		id := newID()
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO meta (name, value) VALUES ('node_id', ?)`, id); err != nil {
			return err
		}
		if err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE name = 'node_id'`).Scan(&s.origin); err != nil {
			return err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key, value, version, origin, deleted FROM records`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r Record
		var version int64
		if err := rows.Scan(&r.Key, &r.Value, &version, &r.Origin, &r.Deleted); err != nil {
			return err
		}
		r.Version = uint64(version)
		normalize(&r)
		s.recs[r.Key] = r
		s.keys = append(s.keys, r.Key)
		if !r.Deleted {
			s.live++
		}
		s.clock.Witness(hlc.Timestamp(r.Version))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	slices.Sort(s.keys)
	return nil
}

// newID returns a random UUID (version 4).
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// normalize gives a tombstone a nil value and a live record a non-nil one.
func normalize(r *Record) {
	switch {
	case r.Deleted:
		r.Value = nil
	case r.Value == nil:
		r.Value = []byte{}
	}
}

func validKey(key string) error {
	if key == "" || len(key) > MaxKeyBytes || !utf8.ValidString(key) || strings.IndexByte(key, 0) >= 0 {
		return fmt.Errorf("%w: %q", ErrInvalidKey, key)
	}
	return nil
}

// NodeID returns the id this store writes its records with: the gossip node id, or for a single node a random id
// kept in the database.
func (s *Store) NodeID() string { return s.origin }

// Get returns the live record of key; false when there is none (or only a tombstone).
func (s *Store) Get(key string) (Record, bool) {
	s.mu.RLock()
	r, ok := s.recs[key]
	s.mu.RUnlock()
	if !ok || r.Deleted {
		return Record{}, false
	}
	return r.clone(), true
}

// List returns the live records whose key starts with prefix, sorted by key.
func (s *Store) List(prefix string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	s.scanLocked(prefix, func(r *Record) {
		if !r.Deleted {
			out = append(out, r.clone())
		}
	})
	return out
}

// scanLocked calls fn for every record (tombstones too) whose key starts with prefix, in key order. s.mu is held.
func (s *Store) scanLocked(prefix string, fn func(r *Record)) {
	i, _ := slices.BinarySearch(s.keys, prefix)
	for ; i < len(s.keys) && strings.HasPrefix(s.keys[i], prefix); i++ {
		r := s.recs[s.keys[i]]
		fn(&r)
	}
}

// Tx is the view of the store an Update function reads and writes through. Its reads see its own writes. A Tx must
// not be used after its function returns, nor from more than one goroutine.
type Tx struct {
	s      *Store
	writes map[string]Record // by key; Deleted for a delete
	err    error             // the first invalid Put or Delete
}

// Get returns the live record of key as the transaction sees it. Records the transaction wrote have no Version or
// Origin yet.
func (tx *Tx) Get(key string) (Record, bool) {
	if w, ok := tx.writes[key]; ok {
		if w.Deleted {
			return Record{}, false
		}
		return w.clone(), true
	}
	return tx.s.Get(key)
}

// List returns the live records whose key starts with prefix as the transaction sees them, sorted by key.
func (tx *Tx) List(prefix string) []Record {
	var out []Record
	tx.s.mu.RLock()
	tx.s.scanLocked(prefix, func(r *Record) {
		if _, written := tx.writes[r.Key]; !written && !r.Deleted {
			out = append(out, r.clone())
		}
	})
	tx.s.mu.RUnlock()
	for k, w := range tx.writes {
		if !w.Deleted && strings.HasPrefix(k, prefix) {
			out = append(out, w.clone())
		}
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// Put sets key to value (copied). An invalid key or a value over MaxValueBytes makes Update fail with nothing written.
func (tx *Tx) Put(key string, value []byte) {
	if err := validKey(key); err != nil {
		tx.fail(err)
		return
	}
	if len(value) > MaxValueBytes {
		tx.fail(fmt.Errorf("%w: %d bytes for %q", ErrValueTooLarge, len(value), key))
		return
	}
	v := make([]byte, len(value))
	copy(v, value)
	tx.writes[key] = Record{Key: key, Value: v}
}

// Delete removes key. Deleting a key with no live record does nothing.
func (tx *Tx) Delete(key string) {
	if err := validKey(key); err != nil {
		tx.fail(err)
		return
	}
	if _, ok := tx.s.Get(key); !ok {
		delete(tx.writes, key) // a key only this transaction put: no tombstone needed
		return
	}
	tx.writes[key] = Record{Key: key, Deleted: true}
}

func (tx *Tx) fail(err error) {
	if tx.err == nil {
		tx.err = err
	}
}

// Update runs fn under the store's write lock, so what fn reads cannot change before its writes commit. The Puts and
// Deletes of fn are written in one SQLite transaction, on disk before Update returns, or none of them if fn returns
// an error (which Update returns) or one of them was invalid. With a cluster, Update then pushes the written records
// to the other nodes of the group and waits for them, up to PushTimeout or until ctx is done; a peer that does not
// acknowledge them does not fail the write, and gets them from an anti-entropy round later.
func (s *Store) Update(ctx context.Context, fn func(tx *Tx) error) error {
	recs, err := s.write(ctx, fn)
	if err != nil || len(recs) == 0 || s.c == nil {
		return err
	}
	defer s.pushes.Done()
	s.push(ctx, recs)
	return nil
}

// write runs fn and commits its writes, returning the records written. With a cluster it counts the push to come in
// s.pushes, under wmu, so that Close (which takes wmu first) waits for it.
func (s *Store) write(ctx context.Context, fn func(tx *Tx) error) ([]Record, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return nil, ErrClosed
	}
	tx := &Tx{s: s, writes: make(map[string]Record)}
	err := fn(tx)
	if err == nil {
		err = tx.err
	}
	if err != nil || len(tx.writes) == 0 {
		return nil, err
	}
	recs := make([]Record, 0, len(tx.writes))
	for _, w := range tx.writes {
		recs = append(recs, w)
	}
	slices.SortFunc(recs, func(a, b Record) int { return strings.Compare(a.Key, b.Key) })
	for i := range recs {
		recs[i].Version = uint64(s.clock.Now())
		recs[i].Origin = s.origin
	}
	if err := s.persist(ctx, recs); err != nil {
		return nil, fmt.Errorf("configstore: %w", err)
	}
	s.apply(recs)
	if s.c != nil {
		s.pushes.Add(1)
	}
	return recs, nil
}

const upsert = `INSERT INTO records (key, value, version, origin, deleted) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value, version = excluded.version, origin = excluded.origin,
deleted = excluded.deleted`

// persist writes recs in one transaction. s.wmu is held.
func (s *Store) persist(ctx context.Context, recs []Record) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, upsert)
	if err != nil {
		return err
	}
	defer st.Close()
	for i := range recs {
		r := &recs[i]
		v := r.Value
		if v == nil {
			v = []byte{}
		}
		// The version goes in as int64, bit for bit: database/sql refuses a uint64 with the high bit set.
		if _, err := st.ExecContext(ctx, r.Key, v, int64(r.Version), r.Origin, r.Deleted); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// apply puts recs, just persisted, in memory and queues their keys for OnChange. s.wmu is held.
func (s *Store) apply(recs []Record) {
	s.mu.Lock()
	added := false
	for i := range recs {
		r := recs[i]
		if old, ok := s.recs[r.Key]; ok {
			if !old.Deleted {
				s.live--
			}
		} else {
			s.keys = append(s.keys, r.Key)
			added = true
		}
		if !r.Deleted {
			s.live++
		}
		s.recs[r.Key] = r
		s.notifyKeys[r.Key] = struct{}{}
	}
	if added {
		slices.Sort(s.keys)
	}
	s.digestOK = false
	s.mu.Unlock()
	select {
	case s.notifyWake <- struct{}{}:
	default:
	}
}

// merge applies the records received from a peer that win over what the store holds, in one transaction. It
// returns how many changed the store.
func (s *Store) merge(recs []Record) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return 0, ErrClosed
	}
	win := make(map[string]Record, len(recs))
	s.mu.RLock()
	for _, r := range recs {
		s.clock.Witness(hlc.Timestamp(r.Version)) // the next local write wins over every version seen
		if cur, ok := s.recs[r.Key]; ok && !r.newer(&cur) {
			continue
		}
		if w, ok := win[r.Key]; ok && !r.newer(&w) {
			continue
		}
		win[r.Key] = r
	}
	s.mu.RUnlock()
	if len(win) == 0 {
		return 0, nil
	}
	out := make([]Record, 0, len(win))
	for _, r := range win {
		out = append(out, r)
	}
	if err := s.persist(s.ctx, out); err != nil {
		return 0, err
	}
	s.apply(out)
	s.stats.received.Add(uint64(len(out)))
	return len(out), nil
}

// digest returns the number of records (tombstones too) and a hash of every key's key, version, origin and deleted
// flag, in key order: two stores with the same digest hold the same records.
func (s *Store) digest() (int, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.digestOK {
		h := sha256.New()
		var b [8]byte
		str := func(v string) {
			binary.BigEndian.PutUint32(b[:4], uint32(len(v)))
			h.Write(b[:4])
			h.Write([]byte(v))
		}
		for _, k := range s.keys {
			r := s.recs[k]
			str(k)
			binary.BigEndian.PutUint64(b[:], r.Version)
			h.Write(b[:])
			str(r.Origin)
			if r.Deleted {
				h.Write([]byte{1})
			} else {
				h.Write([]byte{0})
			}
		}
		s.digestSum, s.digestOK = h.Sum(nil), true
	}
	return len(s.keys), s.digestSum
}

// notifyLoop gives OnChange the keys that changed, until the store closes and what is left has been given.
func (s *Store) notifyLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.notifyWake:
			s.deliver()
		case <-s.notifyStop:
			s.deliver()
			return
		}
	}
}

func (s *Store) deliver() {
	s.mu.Lock()
	if len(s.notifyKeys) == 0 {
		s.mu.Unlock()
		return
	}
	keys := make([]string, 0, len(s.notifyKeys))
	for k := range s.notifyKeys {
		keys = append(keys, k)
	}
	clear(s.notifyKeys)
	s.mu.Unlock()
	if s.opts.OnChange != nil {
		slices.Sort(keys)
		s.opts.OnChange(keys)
	}
}

// Stats returns the store's counters.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	st := Stats{Records: s.live, Tombstones: len(s.keys) - s.live}
	s.mu.RUnlock()
	st.Syncs, st.Repairs, st.SyncErrors = s.stats.syncs.Load(), s.stats.repairs.Load(), s.stats.syncErrors.Load()
	st.Pushes, st.PushErrors, st.Received = s.stats.pushes.Load(), s.stats.pushErrors.Load(), s.stats.received.Load()
	if s.c != nil && !s.closed.Load() {
		peers := s.peers()
		st.Peers = len(peers)
		s.smu.Lock()
		for _, n := range peers {
			if s.synced[n.ID] {
				st.PeersSynced++
			}
		}
		s.smu.Unlock()
	}
	s.smu.Lock()
	st.LastSync = s.lastSync
	s.smu.Unlock()
	return st
}

// Close stops replication, waits for the writes and pushes under way and closes the database. Reads keep working on
// the records in memory; Update returns ErrClosed. Calling it again does nothing.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.cancel()
	if s.c != nil {
		s.stopReplication()
	}
	s.wmu.Lock() // the writes under way finish
	err := s.db.Close()
	s.wmu.Unlock()
	s.pushes.Wait()
	close(s.notifyStop)
	s.wg.Wait()
	return err
}
