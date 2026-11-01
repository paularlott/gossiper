package gossiper

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	mrand "math/rand/v2"

	"github.com/paularlott/gossip/hlc"
)

// earliest is the reserved Last-Event-ID that asks for the whole history.
const earliest = "earliest"

// newEventID returns an event ID for an update stamped ts: a UUIDv7 URN whose timestamp is the stamp's, so IDs sort
// as the hub orders events. The 48-bit field holds the stamp's milliseconds; the 12 bits after the version hold its
// microseconds within the millisecond (10 bits) and the top 2 bits of its logical counter; the variant's 62 bits
// hold the counter's low 8 bits and 54 random bits.
func newEventID(ts hlc.Timestamp) string {
	t := ts.Time()
	ms := uint64(t.UnixMilli())
	us := uint64(t.Nanosecond()/1000) % 1000
	ctr := uint64(ts.Counter())

	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], ms<<16|0x7000|(us<<2|ctr>>8)&0x0fff)
	// The random bits make IDs unique, not secret: the runtime's generator (ChaCha8, per thread) gives them without
	// a system call per update.
	tail := (ctr&0xff)<<54 | mrand.Uint64()>>10
	binary.BigEndian.PutUint64(b[8:16], 0x8000000000000000|tail&0x3fffffffffffffff)
	return "urn:uuid:" + formatUUID(b)
}

// newSubscriberID returns a random (version 4) UUID URN for a subscriber.
func newSubscriberID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return "urn:uuid:" + formatUUID(b)
}

func formatUUID(b [16]byte) string {
	var s [36]byte
	hex.Encode(s[0:8], b[0:4])
	s[8] = '-'
	hex.Encode(s[9:13], b[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], b[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], b[8:10])
	s[23] = '-'
	hex.Encode(s[24:], b[10:])
	return string(s[:])
}
