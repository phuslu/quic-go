package congestion

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

func TestConnectionStatesRingBuffer(t *testing.T) {
	var s ConnectionStates
	sampler := &BandwidthSampler{}
	now := monotime.Now()

	if !s.Insert(5, now, 100, sampler) {
		t.Fatal("insert failed")
	}
	if s.Insert(5, now, 100, sampler) || s.Insert(4, now, 100, sampler) {
		t.Fatal("expected duplicate / old insert to fail")
	}
	// insert with a gap
	if !s.Insert(8, now, 200, sampler) {
		t.Fatal("insert failed")
	}
	if s.Get(6) != nil || s.Get(7) != nil || s.Get(9) != nil {
		t.Fatal("gap entries must be absent")
	}
	if st := s.Get(8); st == nil || st.size != 200 || st.packetNumber != 8 {
		t.Fatal("wrong entry")
	}
	// out of order removal
	if st, ok := s.Remove(8); !ok || st.size != 200 {
		t.Fatal("remove failed")
	}
	if _, ok := s.Remove(8); ok {
		t.Fatal("double remove")
	}
	if _, ok := s.Remove(5); !ok || s.length != 0 {
		t.Fatal("expected empty queue")
	}

	// wrap around and grow while keeping the oldest packet outstanding
	for pn := protocol.PacketNumber(10); pn < 1010; pn++ {
		if !s.Insert(pn, now, protocol.ByteCount(pn), sampler) {
			t.Fatal("insert failed")
		}
		if pn >= 20 && pn%3 != 0 {
			if _, ok := s.Remove(pn - 9); !ok && (pn-9)%3 != 0 {
				t.Fatalf("remove %d failed", pn-9)
			}
		}
	}
	if s.firstPacket != 10 {
		t.Fatalf("first packet: %d", s.firstPacket)
	}
	for pn := protocol.PacketNumber(10); pn < 1010; pn++ {
		if st := s.Get(pn); st != nil && st.size != protocol.ByteCount(pn) {
			t.Fatalf("corrupted entry %d", pn)
		}
	}
	if _, ok := s.Remove(10); !ok || s.firstPacket <= 10 {
		t.Fatal("front not advanced")
	}
}
