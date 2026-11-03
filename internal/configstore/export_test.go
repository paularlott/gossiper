package configstore

// Merge applies records as if a peer had sent them; it returns how many changed the store.
func (s *Store) Merge(recs []Record) (int, error) { return s.merge(recs) }

// MergeFromPeer applies records as received from a peer: checked as the wire's are, then merged.
func (s *Store) MergeFromPeer(recs []Record) (int, error) {
	ws := make([]wireRecord, len(recs))
	for i, r := range recs {
		ws[i] = wireRecord{K: r.Key, V: r.Value, T: r.Version, O: r.Origin, D: r.Deleted}
	}
	return s.merge(s.fromWire(ws))
}

// All returns every record, tombstones too, sorted by key.
func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	s.scanLocked("", func(r *Record) { out = append(out, r.clone()) })
	return out
}
