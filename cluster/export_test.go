package cluster

import "github.com/paularlott/gossip"

// Peers returns the other hubs of the group this node currently sends to.
func (t *Transport) Peers() []*gossip.Node { return t.peers() }

// EnqueueRaw queues raw for n as Publish queues an encoded update.
func (t *Transport) EnqueueRaw(n *gossip.Node, raw []byte) {
	if l := t.linkTo(n); l != nil {
		l.enqueue(item{raw: raw})
	}
}

// Received returns how many batches the node received from its peers and applied, and the updates in them.
func (t *Transport) Received() (batches, updates uint64) { return t.batches.Load(), t.batched.Load() }

// SetReady sets what Ready reports, and what the node tells a peer that copies its history.
func (t *Transport) SetReady(ready bool) { t.ready.Store(ready) }
