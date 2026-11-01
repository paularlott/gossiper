package configstore

// Merge applies records as if a peer had sent them; it returns how many changed the store.
func (s *Store) Merge(recs []Record) (int, error) { return s.merge(recs) }

// All returns every record, tombstones too, sorted by key.
func (s *Store) All() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	s.scanLocked("", func(r *Record) { out = append(out, r.clone()) })
	return out
}
