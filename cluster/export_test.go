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

// SetReady sets what Ready reports, and what the node tells a peer that copies its history.
func (t *Transport) SetReady(ready bool) { t.ready.Store(ready) }
