package gossiper

import (
	"cmp"
	"slices"
	"sync/atomic"
)

// budget is the memory the histories of several hubs may hold together (Tenants' HistoryBudget). Each history adds
// what it holds; when the sum goes over the limit, the owner sheds the largest histories first, down towards the size
// of the next largest, so a busy tenant gives up its oldest updates before a quiet one loses any.
type budget struct {
	limit int64
	used  atomic.Int64
	kick  chan struct{} // the sum went over the limit
}

func newBudget(limit int64) *budget {
	return &budget{limit: limit, kick: make(chan struct{}, 1)}
}

func (b *budget) add(n int64) {
	if b.used.Add(n) > b.limit && n > 0 {
		select {
		case b.kick <- struct{}{}:
		default:
		}
	}
}

// enforce sheds history from hubs() until the budget is kept, each time it goes over, until stop is closed: the
// largest histories are brought down to one level, the highest that frees enough.
func (b *budget) enforce(hubs func() map[string]*Hub, stop <-chan struct{}) {
	for {
		select {
		case <-b.kick:
		case <-stop:
			return
		}
		for excess := b.used.Load() - b.limit; excess > 0; excess = b.used.Load() - b.limit {
			if shedTo(hubs(), excess) == 0 {
				break
			}
		}
	}
}

// shedTo brings the largest of hubs' histories down to the level at which they free excess bytes between them, and
// returns how many they freed.
func shedTo(hubs map[string]*Hub, excess int64) int64 {
	type held struct {
		h    *Hub
		size int64
	}
	var all []held
	for _, h := range hubs {
		all = append(all, held{h, h.hist.size()})
	}
	slices.SortFunc(all, func(a, b held) int { return cmp.Compare(b.size, a.size) })
	var sum, level int64
	k := 0
	for k < len(all) {
		sum += all[k].size
		k++
		level = max(0, (sum-excess)/int64(k)) // the top k at one level free excess
		if k == len(all) || level >= all[k].size {
			break
		}
	}
	var freed int64
	for _, x := range all[:k] {
		freed += x.h.hist.shed(level)
	}
	return freed
}
