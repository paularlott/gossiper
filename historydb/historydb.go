// Package historydb is a gossiper.HistoryStore in a SQLite file: a node's history survives a restart.
//
// Writes are batched as a group commit: one goroutine takes the updates saved since its last commit (up to maxBatch),
// inserts them and applies the deletes the hubs asked for in one transaction, and commits it with one sync. An idle
// store commits a lone update at once; under load a batch is what was saved while the previous one was syncing. A
// publisher waits only for the commit that holds its update. A commit that fails is retried until it succeeds or
// the store closes; meanwhile the store is not healthy (the hubs refuse publishes), and waiting publishers time out.
package historydb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/logger"
	"github.com/shamaton/msgpack/v3"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	maxBatch   = 1024                   // updates in one commit
	queueSize  = 8 * maxBatch           // updates waiting for a commit; Save leaves out what does not fit
	retryDelay = 100 * time.Millisecond // after a failed commit
	// vacuumEvery is how often the pages freed by deletes are given back to the file system (at most 8 MiB a time):
	// the history is a window that moves, so without it the file keeps its largest size.
	vacuumEvery = 5 * time.Second
	// dropTimeout bounds how long Drop waits for room in the queue.
	dropTimeout = 10 * time.Second
)

// ErrClosed is returned by Wait once the store is closed with the update not written.
var ErrClosed = errors.New("historydb: store closed")

// Store is a gossiper.HistoryStore in a SQLite file.
type Store struct {
	db     *sql.DB
	insert *sql.Stmt
	log    logger.Logger

	mu      sync.Mutex // orders the tickets in the queue; guards next and closed
	queue   chan item
	next    uint64
	closed  bool
	tmu     sync.Mutex       // guards trims (never held with mu)
	trims   map[string]bound // tenant -> keep from here
	stuck   atomic.Uint64    // updates not written: the queue was full
	failing atomic.Bool      // the last commit failed

	vacuumed  time.Time // last incremental vacuum; the run loop's
	committed atomic.Uint64
	notify    atomic.Pointer[chan struct{}] // closed and replaced at every commit
	stop      chan struct{}
	done      chan struct{}
}

// item is an update to write, or a tenant to drop (with no update).
type item struct {
	u      *gossiper.Update
	drop   string
	ticket uint64
}

// bound is the oldest update a tenant keeps.
type bound struct {
	stamp  uint64
	origin string
}

var _ gossiper.HistoryStore = (*Store)(nil)

// Open opens (creating it if needed) the store in the SQLite file at path. Close it after the hubs that use it.
func Open(path string, log logger.Logger) (*Store, error) {
	if log == nil {
		log = logger.NewNullLogger()
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "auto_vacuum(INCREMENTAL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2) // the writer, and Load (a tenant's hub may start while the others publish)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS history (
		tenant TEXT NOT NULL, stamp INTEGER NOT NULL, origin TEXT NOT NULL, data BLOB NOT NULL,
		PRIMARY KEY (tenant, stamp, origin)) WITHOUT ROWID`); err != nil {
		db.Close()
		return nil, fmt.Errorf("historydb: %s: %w", path, err)
	}
	ins, err := db.Prepare(`INSERT OR IGNORE INTO history (tenant, stamp, origin, data) VALUES (?, ?, ?, ?)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("historydb: %s: %w", path, err)
	}
	s := &Store{db: db, insert: ins, log: log, queue: make(chan item, queueSize), trims: map[string]bound{},
		stop: make(chan struct{}), done: make(chan struct{})}
	ch := make(chan struct{})
	s.notify.Store(&ch)
	go s.run()
	return s, nil
}

// Load implements gossiper.HistoryStore.
func (s *Store) Load(tenant string, fn func(*gossiper.Update)) error {
	rows, err := s.db.Query(`SELECT data FROM history WHERE tenant = ? ORDER BY stamp, origin`, tenant)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return err
		}
		var u gossiper.Update
		if err := msgpack.Unmarshal(b, &u); err != nil {
			s.log.Warn("historydb: an undecodable update is skipped", "tenant", tenant, "error", err.Error())
			continue
		}
		fn(&u)
	}
	return rows.Err()
}

// Save implements gossiper.HistoryStore. It returns 0 after Close, and when the queue is full.
func (s *Store) Save(u *gossiper.Update) uint64 {
	s.mu.Lock() // held while queueing, so tickets reach the queue in order
	defer s.mu.Unlock()
	if s.closed {
		return 0
	}
	select {
	case s.queue <- item{u: u, ticket: s.next + 1}:
	default:
		if s.stuck.Add(1) == 1 {
			s.log.Error("historydb: the history cannot be written fast enough; updates are not all stored")
		}
		return 0
	}
	s.next++
	return s.next
}

// Ready implements gossiper.HistoryStore: it returns once the last commit succeeded and the queue is less than half
// full (the other half is room for the saves of publishers that found it ready at once). It waits for a commit to
// wake it.
func (s *Store) Ready(ctx context.Context) error {
	for {
		ch := s.notify.Load()
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return ErrClosed
		}
		if !s.failing.Load() && len(s.queue) < cap(s.queue)/2 {
			return nil
		}
		select {
		case <-*ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return ErrClosed
		}
	}
}

// Unwritten returns how many updates were not stored because the store could not keep up.
func (s *Store) Unwritten() uint64 { return s.stuck.Load() }

// Wait implements gossiper.HistoryStore.
func (s *Store) Wait(ctx context.Context, ticket uint64) error {
	for {
		ch := s.notify.Load()
		if s.committed.Load() >= ticket {
			return nil
		}
		select {
		case <-*ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			if s.committed.Load() >= ticket {
				return nil
			}
			return ErrClosed
		}
	}
}

// Trim implements gossiper.HistoryStore: the delete goes with the next commit, in the same transaction as its inserts
// (so trimming as the history moves costs no commit of its own, and each delete is small).
func (s *Store) Trim(tenant string, stamp uint64, origin string) {
	s.tmu.Lock()
	s.trims[tenant] = bound{stamp: stamp, origin: origin}
	s.tmu.Unlock()
}

// Drop implements gossiper.HistoryStore: it goes in the queue with the updates, so that it deletes those saved
// before it and not those saved after (a tenant added again at once).
func (s *Store) Drop(ctx context.Context, tenant string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	t := time.NewTimer(dropTimeout)
	defer t.Stop()
	select {
	case s.queue <- item{drop: tenant, ticket: s.next + 1}:
	case <-t.C:
		s.mu.Unlock()
		return errors.New("historydb: the store is too far behind to drop a tenant")
	case <-ctx.Done():
		s.mu.Unlock()
		return ctx.Err()
	}
	s.next++
	ticket := s.next
	s.mu.Unlock()
	return s.Wait(ctx, ticket)
}

// run commits batches until Close, then what is left.
func (s *Store) run() {
	defer close(s.done)
	batch := make([]item, 0, maxBatch)
	for {
		select {
		case it := <-s.queue:
			batch = append(batch[:0], it)
		case <-s.stop:
			for { // what was saved before Close
				batch = batch[:0]
				for len(batch) < maxBatch && len(s.queue) > 0 {
					batch = append(batch, <-s.queue)
				}
				if len(batch) == 0 {
					s.commit(nil) // the last trims
					return
				}
				s.commitRetrying(batch, true)
			}
		}
		for len(batch) < maxBatch && len(s.queue) > 0 {
			batch = append(batch, <-s.queue)
		}
		s.commitRetrying(batch, false)
	}
}

// commitRetrying commits batch until it succeeds; once the store is closing it tries a few times only.
func (s *Store) commitRetrying(batch []item, closing bool) {
	for attempt := 0; ; attempt++ {
		err := s.commit(batch)
		s.failing.Store(err != nil)
		if err == nil {
			return
		}
		s.log.Error("historydb: writing the history failed; retrying", "error", err.Error(), "updates", len(batch))
		if closing && attempt >= 3 {
			return
		}
		select {
		case <-time.After(retryDelay):
		case <-s.stop:
			closing = true
		}
	}
}

// commit writes batch and the pending trims in one transaction, then wakes the waiters.
func (s *Store) commit(batch []item) (err error) {
	s.tmu.Lock()
	trims := s.trims
	s.trims = map[string]bound{}
	s.tmu.Unlock()
	defer func() {
		if err != nil { // the trims go with the next attempt
			s.tmu.Lock()
			for t, b := range trims {
				if _, newer := s.trims[t]; !newer {
					s.trims[t] = b
				}
			}
			s.tmu.Unlock()
		}
	}()
	var last uint64
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ins := tx.Stmt(s.insert)
	for _, it := range batch {
		switch {
		case it.u != nil:
			b, err := msgpack.Marshal(it.u)
			if err != nil {
				return err
			}
			if _, err := ins.Exec(it.u.Tenant, int64(it.u.Stamp), it.u.Origin, b); err != nil {
				return err
			}
		case it.drop != "":
			if _, err := tx.Exec(`DELETE FROM history WHERE tenant = ?`, it.drop); err != nil {
				return err
			}
		}
		last = it.ticket
	}
	for tenant, b := range trims {
		_, err = tx.Exec(`DELETE FROM history WHERE tenant = ? AND (stamp, origin) < (?, ?)`, // a range of the key
			tenant, int64(b.stamp), b.origin)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if time.Since(s.vacuumed) > vacuumEvery {
		s.vacuumed = time.Now()
		_, _ = s.db.Exec(`PRAGMA incremental_vacuum(2048)`)
	}
	if last > 0 {
		s.committed.Store(last)
		ch := make(chan struct{})
		close(*s.notify.Swap(&ch))
	}
	return nil
}

// Close writes what was saved and closes the file. Call it after the hubs that use the store are closed.
func (s *Store) Close() error {
	s.mu.Lock() // no Save is queueing once it is held: the run loop gets everything saved before
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	close(s.stop)
	<-s.done
	_, _ = s.db.Exec(`PRAGMA incremental_vacuum`)
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	s.insert.Close()
	return s.db.Close()
}
