package configstore

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paularlott/gossip"
)

// metaKey is the gossip metadata key every node with a running store publishes, set to "on".
const metaKey = "gossiper.configstore"

const (
	// maxChunk bounds the bytes of records in one message (a single larger record goes alone, in at most
	// MaxValueBytes plus its key: far below gossip's default 4 MiB packet limit).
	maxChunk = 512 << 10
	// maxSummary bounds the bytes of one page of a summary.
	maxSummary = 256 << 10
	// requestTimeout bounds each request of an anti-entropy round.
	requestTimeout = 5 * time.Second
	// retryAfter is how long a sync with a node that just joined waits before it is tried again, after it failed;
	// it is tried syncAttempts times before the periodic rounds are left to repair what it missed.
	retryAfter   = time.Second
	syncAttempts = 3
)

// wireRecord is a Record in a message.
type wireRecord struct {
	K string `msgpack:"k"`
	V []byte `msgpack:"v,omitempty"`
	T uint64 `msgpack:"t"`
	O string `msgpack:"o"`
	D bool   `msgpack:"d,omitempty"`
}

// recordsMsg pushes records to a peer, which merges them and answers with an ack.
type recordsMsg struct {
	Records []wireRecord `msgpack:"r"`
}

// ack answers a recordsMsg. Err says that the receiver could not store the records.
type ack struct {
	Err string `msgpack:"e,omitempty"`
}

// digestReq asks a peer for the digest of its records.
type digestReq struct {
}

type digestResp struct {
	Count int    `msgpack:"c"`
	Hash  []byte `msgpack:"h"`
}

// summaryReq asks a peer for a page of its summary: the records after key After, in key order.
type summaryReq struct {
	After string `msgpack:"a,omitempty"`
}

// entry is a record in a summary, without its value. N is the value's size, for batching fetches.
type entry struct {
	K string `msgpack:"k"`
	T uint64 `msgpack:"t"`
	O string `msgpack:"o"`
	D bool   `msgpack:"d,omitempty"`
	N int    `msgpack:"n,omitempty"`
}

type summaryResp struct {
	Entries []entry `msgpack:"e"`
	More    bool    `msgpack:"m,omitempty"`
}

// fetchReq asks a peer for the records of Keys. It answers with as many as fit in maxChunk, in order.
type fetchReq struct {
	Keys []string `msgpack:"k"`
}

type fetchResp struct {
	Records []wireRecord `msgpack:"r"`
}

func toWire(recs []Record) []wireRecord {
	out := make([]wireRecord, len(recs))
	for i := range recs {
		r := &recs[i]
		out[i] = wireRecord{K: r.Key, V: r.Value, T: r.Version, O: r.Origin, D: r.Deleted}
	}
	return out
}

// fromWire returns the valid records of ws; a peer sending others is logged and they are dropped.
func (s *Store) fromWire(ws []wireRecord) []Record {
	out := make([]Record, 0, len(ws))
	for i := range ws {
		w := &ws[i]
		if validKey(w.K) != nil || len(w.V) > MaxValueBytes || w.O == "" || len(w.O) > maxOrigin || w.T == 0 {
			s.log.Warn("configstore: dropping an invalid record from a peer", "key", w.K, "origin", w.O)
			continue
		}
		r := Record{Key: w.K, Value: w.V, Version: w.T, Origin: w.O, Deleted: w.D}
		normalize(&r)
		out = append(out, r)
	}
	return out
}

// chunks splits recs into runs of at most maxChunk bytes (a larger record alone).
func chunks(recs []Record) [][]Record {
	var out [][]Record
	start, size := 0, 0
	for i := range recs {
		n := recs[i].size()
		if i > start && size+n > maxChunk {
			out = append(out, recs[start:i])
			start, size = i, 0
		}
		size += n
	}
	if start < len(recs) {
		out = append(out, recs[start:])
	}
	return out
}

// startReplication registers the store's handlers, announces it to the group and starts the anti-entropy loop.
func (s *Store) startReplication() error {
	handlers := []struct {
		t gossip.MessageType
		h gossip.ReplyHandler
	}{
		{s.msgRecords, s.handleRecords}, {s.msgDigest, s.handleDigest},
		{s.msgSummary, s.handleSummary}, {s.msgFetch, s.handleFetch},
	}
	for i, h := range handlers {
		if err := s.c.HandleFuncWithReply(h.t, h.h); err != nil {
			for _, done := range handlers[:i] {
				s.c.UnregisterMessageType(done.t)
			}
			return err
		}
	}
	// A node that joins the group (also one already there now, at startup) gets a round at once: a node that was
	// down catches up, and the others get what it wrote while cut off.
	s.group = gossip.NewNodeGroup(s.c, map[string]string{metaKey: "on"}, &gossip.NodeGroupOptions{
		OnNodeAdded: func(n *gossip.Node) {
			if n.ID != s.c.LocalNode().ID { // this node joins its own group too
				s.queueSync(n.ID, 0)
			}
		},
		OnNodeRemoved: func(n *gossip.Node) { s.forgetPeer(n.ID) },
	})
	s.c.LocalMetadata().SetString(metaKey, "on")
	s.wg.Add(1)
	go s.syncLoop()
	return nil
}

// stopReplication withdraws the store from the group and unregisters its handlers; the caller waits for the loop.
func (s *Store) stopReplication() {
	s.c.LocalMetadata().SetString(metaKey, "")
	for _, t := range []gossip.MessageType{s.msgRecords, s.msgDigest, s.msgSummary, s.msgFetch} {
		s.c.UnregisterMessageType(t)
	}
	s.group.Close()
}

// peers returns the other nodes of the group.
func (s *Store) peers() []*gossip.Node {
	return s.group.GetNodes([]gossip.NodeID{s.c.LocalNode().ID})
}

// push sends recs, just written, to every peer at once and waits for their acknowledgements, up to PushTimeout.
func (s *Store) push(ctx context.Context, recs []Record) {
	peers := s.peers()
	if len(peers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, s.opts.PushTimeout)
	defer cancel()
	defer context.AfterFunc(s.ctx, cancel)()
	var wg sync.WaitGroup
	for _, n := range peers {
		wg.Go(func() {
			if err := s.sendRecords(ctx, n, recs, 0); err != nil {
				s.log.Debug("configstore: push to peer failed", "peer", n.ID.String(), "error", err.Error())
			}
		})
	}
	wg.Wait()
}

// sendRecords sends recs to n in chunks, each acknowledged before the next; each chunk has perChunk to be
// acknowledged, when it is not zero.
func (s *Store) sendRecords(ctx context.Context, n *gossip.Node, recs []Record, perChunk time.Duration) error {
	for _, c := range chunks(recs) {
		cctx, cancel := ctx, context.CancelFunc(func() {})
		if perChunk > 0 {
			cctx, cancel = context.WithTimeout(ctx, perChunk)
		}
		var a ack
		err := s.c.SendToWithResponseContext(cctx, n, s.msgRecords, &recordsMsg{Records: toWire(c)}, &a)
		cancel()
		switch {
		case err != nil:
		case a.Err != "":
			err = errors.New(a.Err)
		}
		if err != nil {
			s.stats.pushErrors.Add(1)
			return err
		}
		s.stats.pushes.Add(1)
	}
	return nil
}

func (s *Store) handleRecords(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var m recordsMsg
	if err := p.Unmarshal(&m); err != nil {
		return nil, err
	}
	if _, err := s.merge(s.fromWire(m.Records)); err != nil {
		return &ack{Err: err.Error()}, nil
	}
	return &ack{}, nil
}

func (s *Store) handleDigest(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var req digestReq
	if err := p.Unmarshal(&req); err != nil {
		return nil, err
	}
	count, sum := s.digest()
	return &digestResp{Count: count, Hash: sum}, nil
}

func (s *Store) handleSummary(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var req summaryReq
	if err := p.Unmarshal(&req); err != nil {
		return nil, err
	}
	resp := &summaryResp{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, found := slices.BinarySearch(s.keys, req.After)
	if found {
		i++
	}
	size := 0
	for ; i < len(s.keys); i++ {
		r := s.recs[s.keys[i]]
		e := entry{K: r.Key, T: r.Version, O: r.Origin, D: r.Deleted, N: len(r.Value)}
		n := len(e.K) + len(e.O) + 24
		if len(resp.Entries) > 0 && size+n > maxSummary {
			resp.More = true
			break
		}
		size += n
		resp.Entries = append(resp.Entries, e)
	}
	return resp, nil
}

func (s *Store) handleFetch(_ *gossip.Node, p *gossip.Packet) (any, error) {
	var req fetchReq
	if err := p.Unmarshal(&req); err != nil {
		return nil, err
	}
	resp := &fetchResp{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	size := 0
	for _, k := range req.Keys {
		r, ok := s.recs[k]
		if !ok {
			continue
		}
		if len(resp.Records) > 0 && size+r.size() > maxChunk {
			break
		}
		size += r.size()
		resp.Records = append(resp.Records, wireRecord{K: r.Key, V: r.Value, T: r.Version, O: r.Origin, D: r.Deleted})
	}
	return resp, nil
}

// queued is a peer waiting for a round.
type queued struct {
	id       gossip.NodeID
	attempts int
	after    time.Time // not before
}

// queueSync asks the sync loop for a round with node id, after a delay.
func (s *Store) queueSync(id gossip.NodeID, attempts int) {
	s.smu.Lock()
	if !slices.ContainsFunc(s.queue, func(q queued) bool { return q.id == id }) {
		s.queue = append(s.queue, queued{id: id, attempts: attempts, after: time.Now().Add(time.Duration(attempts) * retryAfter)})
	}
	s.smu.Unlock()
	s.wakeSync()
}

func (s *Store) wakeSync() {
	select {
	case s.syncWake <- struct{}{}:
	default:
	}
}

// forgetPeer drops what the store knows of a node that left the group.
func (s *Store) forgetPeer(id gossip.NodeID) {
	s.smu.Lock()
	delete(s.synced, id)
	s.smu.Unlock()
}

// takeDue removes and returns the queued peers whose time has come, and when the next of the others is due (zero if
// none is left).
func (s *Store) takeDue(now time.Time) (due []queued, next time.Time) {
	s.smu.Lock()
	defer s.smu.Unlock()
	rest := s.queue[:0]
	for _, q := range s.queue {
		if q.after.After(now) {
			rest = append(rest, q)
			if next.IsZero() || q.after.Before(next) {
				next = q.after
			}
			continue
		}
		due = append(due, q)
	}
	s.queue = rest
	return due, next
}

// syncLoop runs an anti-entropy round with each node queued for one, and with a random peer every SyncInterval.
func (s *Store) syncLoop() {
	defer s.wg.Done()
	tick := time.NewTicker(s.opts.SyncInterval)
	defer tick.Stop()
	retry := time.NewTimer(time.Hour)
	defer retry.Stop()
	for {
		due, next := s.takeDue(time.Now())
		for _, q := range due {
			if s.ctx.Err() != nil {
				return
			}
			n := s.c.GetNode(q.id)
			if n == nil || !s.group.Contains(q.id) {
				continue
			}
			if s.syncWith(n) != nil && q.attempts+1 < syncAttempts {
				s.queueSync(q.id, q.attempts+1)
			}
		}
		if len(due) > 0 {
			continue // more may have been queued meanwhile
		}
		if !next.IsZero() {
			retry.Reset(time.Until(next))
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.syncWake:
		case <-retry.C:
		case <-tick.C:
			if n := s.randomPeer(); n != nil {
				_ = s.syncWith(n)
			}
		}
	}
}

// randomPeer returns a random alive peer of the group; nil when there is none.
func (s *Store) randomPeer() *gossip.Node {
	peers := slices.DeleteFunc(s.peers(), func(n *gossip.Node) bool { return !n.Alive() })
	if len(peers) == 0 {
		return nil
	}
	return peers[rand.IntN(len(peers))]
}

// syncWith runs an anti-entropy round with n and keeps count of it.
func (s *Store) syncWith(n *gossip.Node) error {
	err := s.syncPeer(n)
	s.smu.Lock()
	if err == nil {
		s.synced[n.ID] = true
		s.lastSync = time.Now()
	} else {
		delete(s.synced, n.ID)
	}
	s.smu.Unlock()
	if err != nil {
		if s.ctx.Err() == nil {
			s.stats.syncErrors.Add(1)
			s.log.Debug("configstore: sync with peer failed", "peer", n.ID.String(), "error", err.Error())
		}
		return err
	}
	s.stats.syncs.Add(1)
	return nil
}

// request sends req to n and waits up to requestTimeout for its answer in resp.
func (s *Store) request(n *gossip.Node, t gossip.MessageType, req, resp any) error {
	ctx, cancel := context.WithTimeout(s.ctx, requestTimeout)
	defer cancel()
	return s.c.SendToWithResponseContext(ctx, n, t, req, resp)
}

// syncPeer compares this store with n's: when their digests differ, it fetches n's summary, pulls the records n has
// that are newer or missing here and pushes the records this store has that are newer or missing there.
func (s *Store) syncPeer(n *gossip.Node) error {
	var d digestResp
	if err := s.request(n, s.msgDigest, &digestReq{}, &d); err != nil {
		return err
	}
	if count, sum := s.digest(); d.Count == count && bytes.Equal(d.Hash, sum) {
		return nil
	}
	s.stats.repairs.Add(1)

	remote := make(map[string]entry, d.Count)
	for after := ""; ; {
		var page summaryResp
		if err := s.request(n, s.msgSummary, &summaryReq{After: after}, &page); err != nil {
			return err
		}
		for _, e := range page.Entries {
			remote[e.K] = e
		}
		if !page.More || len(page.Entries) == 0 {
			break
		}
		after = page.Entries[len(page.Entries)-1].K
	}

	need, give := s.compare(remote)
	if err := s.pull(n, need); err != nil {
		return err
	}
	if len(give) > 0 {
		return s.sendRecords(s.ctx, n, give, requestTimeout)
	}
	return nil
}

// compare returns the entries of remote newer than this store's record or missing here, and this store's records
// newer than remote's entry or missing there, both in key order.
func (s *Store) compare(remote map[string]entry) (need []entry, give []Record) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, e := range remote {
		er := Record{Version: e.T, Origin: e.O}
		if cur, ok := s.recs[k]; !ok || er.newer(&cur) {
			need = append(need, e)
		}
	}
	for _, k := range s.keys {
		r := s.recs[k]
		if e, ok := remote[k]; !ok || r.newer(&Record{Version: e.T, Origin: e.O}) {
			give = append(give, r)
		}
	}
	slices.SortFunc(need, func(a, b entry) int { return strings.Compare(a.K, b.K) })
	return need, give
}

// pull fetches the records of need from n, in requests of about maxChunk bytes of records, and merges them. A record
// that grew since the summary may not fit its request: it is asked for again in the next.
func (s *Store) pull(n *gossip.Node, need []entry) error {
	for len(need) > 0 {
		var keys []string
		size := 0
		for _, e := range need {
			sz := len(e.K) + e.N + len(e.O) + 24
			if len(keys) > 0 && size+sz > maxChunk {
				break
			}
			size += sz
			keys = append(keys, e.K)
		}
		var f fetchResp
		if err := s.request(n, s.msgFetch, &fetchReq{Keys: keys}, &f); err != nil {
			return err
		}
		if len(f.Records) == 0 {
			return errors.New("configstore: peer sent none of the records asked for")
		}
		got := make(map[string]bool, len(f.Records))
		for i := range f.Records {
			got[f.Records[i].K] = true
		}
		if _, err := s.merge(s.fromWire(f.Records)); err != nil {
			return err
		}
		need = slices.DeleteFunc(need, func(e entry) bool { return got[e.K] })
	}
	return nil
}
