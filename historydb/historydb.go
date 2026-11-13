// Package historydb is a gossiper.HistoryStore in a SQLite file: a node's history survives a restart.
//
// The history is in memory; the store keeps a copy. One goroutine collects the updates saved, and every flush
// interval writes them, with the deletes the hubs asked for, in one transaction and one sync. No publish waits for
// it: a crash loses what was saved since the last write, Close writes it all. A write that fails keeps its updates
// for the next one, up to maxPending.
package historydb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paularlott/gossiper"
	"github.com/paularlott/logger"
	"github.com/shamaton/msgpack/v3"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// DefaultFlush is how often a store writes what was saved, when Open is given no interval.
const DefaultFlush = time.Second

const (
	queueSize  = 8192                   // updates handed to the writer goroutine; Save leaves out what does not fit
	maxPending = 1 << 16                // updates collected for one write: more are written at once
	retryDelay = 100 * time.Millisecond // between the attempts of the last write, on Close
	// vacuumEvery is how often the pages freed by deletes are given back to the file system (at most 8 MiB a time):
	// the history is a window that moves, so without it the file keeps its largest size.
	vacuumEvery = 5 * time.Second
	// dropTimeout bounds how long Drop waits for room in the queue.
	dropTimeout = 10 * time.Second
)

// ErrClosed is returned by Drop once the store is closed.
var ErrClosed = errors.New("historydb: store closed")

// Store is a gossiper.HistoryStore in a SQLite file.
type Store struct {
	db     *sql.DB
	insert *sql.Stmt
	log    logger.Logger

	flush time.Duration

	mu       sync.Mutex // orders the tickets in the queue; guards next and closed
	queue    chan item
	next     uint64
	closed   bool
	tmu      sync.Mutex       // guards trims (never held with mu)
	trims    map[string]bound // tenant -> keep from here
	stuck    atomic.Uint64    // updates not written: the queue was full, or writes kept failing
	flushNow chan struct{}    // asks for a write at once (Drop)
	failed   time.Time        // when a failed write was last logged; the run loop's

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

// Open opens (creating it if needed) the store in the SQLite file at path, writing what is saved every flush
// (DefaultFlush when 0 or less). Close it after the hubs that use it.
func Open(path string, flush time.Duration, log logger.Logger) (*Store, error) {
	if log == nil {
		log = logger.NewNullLogger()
	}
	if flush <= 0 {
		flush = DefaultFlush
	}
	// It holds updates, private ones included: readable by this user only, as the tenants' database is.
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600); err == nil {
		f.Close()
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
	if err := checkSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("historydb: %s: %w", path, err)
	}
	ins, err := db.Prepare(`INSERT OR IGNORE INTO history (tenant, stamp, origin, data) VALUES (?, ?, ?, ?)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("historydb: %s: %w", path, err)
	}
	s := &Store{db: db, insert: ins, log: log, flush: flush, queue: make(chan item, queueSize), trims: map[string]bound{},
		flushNow: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	ch := make(chan struct{})
	s.notify.Store(&ch)
	go s.run()
	return s, nil
}

// schemaVersion is the layout of the file, kept in SQLite's user_version: a later version migrates from it.
const schemaVersion = 1

// checkSchema marks a new file with schemaVersion and refuses one written by a later version of gossiper.
func checkSchema(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch {
	case v == 0: // new (or written before versions were kept, with this layout)
		_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
		return err
	case v > schemaVersion:
		return fmt.Errorf("written by a later version of gossiper (schema %d, this one reads %d)", v, schemaVersion)
	}
	return nil
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

// Save implements gossiper.HistoryStore. After Close, and when the writer is far behind, it leaves u out.
func (s *Store) Save(u *gossiper.Update) {
	s.mu.Lock() // held while queueing, so tickets reach the queue in order
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.queue <- item{u: u, ticket: s.next + 1}:
		s.next++
	default:
		if s.stuck.Add(1) == 1 {
			s.log.Error("historydb: the history cannot be written fast enough; updates are not all stored")
		}
	}
}

// Unwritten returns how many updates were not stored because the store could not keep up.
func (s *Store) Unwritten() uint64 { return s.stuck.Load() }

// wait returns once the ticket's item is written, or with ctx's error.
func (s *Store) wait(ctx context.Context, ticket uint64) error {
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
	select { // written now, not at the next flush
	case s.flushNow <- struct{}{}:
	default:
	}
	return s.wait(ctx, ticket)
}

// run collects what is saved and writes it every flush interval (at once for a Drop, or when maxPending are
// waiting), until Close; then it writes what is left.
func (s *Store) run() {
	defer close(s.done)
	tick := time.NewTicker(s.flush)
	defer tick.Stop()
	var pending []item
	write := func(closing bool) {
		for len(s.queue) > 0 {
			pending = append(pending, <-s.queue)
		}
		if len(pending) == 0 && !s.trimsPending() {
			return
		}
		for attempt := 0; ; attempt++ {
			err := s.commit(pending)
			if err == nil {
				pending = pending[:0]
				return
			}
			if now := time.Now(); now.Sub(s.failed) > time.Minute { // once a minute, not every flush
				s.failed = now
				s.log.Error("historydb: writing the history failed; trying again", "error", err.Error(), "updates", len(pending))
			}
			if !closing || attempt >= 3 {
				break
			}
			time.Sleep(retryDelay)
		}
		if len(pending) > maxPending { // writes keep failing: keep the drops, give up the updates
			kept := pending[:0]
			for _, it := range pending {
				if it.u == nil {
					kept = append(kept, it)
				} else {
					s.stuck.Add(1)
				}
			}
			pending = kept
		}
	}
	for {
		select {
		case it := <-s.queue:
			if pending = append(pending, it); len(pending) >= maxPending {
				write(false)
			}
		case <-tick.C:
			write(false)
		case <-s.flushNow:
			write(false)
		case <-s.stop:
			write(true)
			return
		}
	}
}

// trimsPending reports whether hubs asked for deletes since the last write.
func (s *Store) trimsPending() bool {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return len(s.trims) > 0
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
