package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

// quic-go uses one packet number space for all encryption levels, starting at 0.
func TestBBRFirstPacketNumberZero(t *testing.T) {
	t.Run("ack", func(t *testing.T) {
		b := newAckEventTestSender(nil)
		now := monotime.Now()
		b.OnPacketSent(now, 0, 1200, true)
		ackTime := now.Add(10 * time.Millisecond)
		b.BeginAckEvent(ackTime)
		b.OnPacketAcked(0, 1200)
		b.EndAckEvent(1200, ackTime)
		require.Equal(t, int64(1), b.roundTripCount)
		require.Equal(t, protocol.PacketNumber(0), b.currentRoundTripEnd)
		require.Equal(t, 10*time.Millisecond, b.minRtt)
		require.Equal(t, b.initialCongestionWindow+1200, b.GetCongestionWindow())
	})

	t.Run("loss", func(t *testing.T) {
		b := newAckEventTestSender(nil)
		now := monotime.Now()
		b.OnPacketSent(now, 0, 1200, true)
		b.OnPacketSent(now, 1, 1200, true)
		b.OnPacketSent(now, 2, 1200, true)
		ackTime := now.Add(10 * time.Millisecond)
		b.BeginAckEvent(ackTime)
		b.OnCongestionEvent(0)
		b.OnPacketAcked(1, 3600)
		b.EndAckEvent(3600, ackTime)
		require.True(t, b.InRecovery())
		require.Equal(t, protocol.PacketNumber(2), b.endRecoveryAt)
	})
}

func TestBBRRemoveObsoletePackets(t *testing.T) {
	b := newAckEventTestSender(nil)
	now := monotime.Now()
	// Packet numbers 3 and 6 are skipped.
	for _, pn := range []protocol.PacketNumber{0, 1, 2, 4, 5, 7} {
		b.OnPacketSent(now, pn, 1200, true)
	}
	ackTime := now.Add(10 * time.Millisecond)
	b.BeginAckEvent(ackTime)
	b.OnPacketAcked(1, 7200)
	b.EndAckEvent(7200, ackTime)
	// 0 is obsolete, 1 was acknowledged, 2 is still outstanding.
	b.RemoveObsoletePackets(2)
	require.Equal(t, 4, b.sampler.connectionStats.numPresent)
	require.Equal(t, protocol.PacketNumber(2), b.sampler.connectionStats.firstPacket)
	// The front of the queue skips the gap.
	b.RemoveObsoletePackets(3)
	require.Equal(t, 3, b.sampler.connectionStats.numPresent)
	require.Equal(t, protocol.PacketNumber(4), b.sampler.connectionStats.firstPacket)
	// Packets that are still tracked can be acknowledged.
	b.BeginAckEvent(ackTime)
	b.OnPacketAcked(5, 3600)
	b.EndAckEvent(3600, ackTime)
	require.Equal(t, 2, b.sampler.connectionStats.numPresent)
	b.RemoveObsoletePackets(protocol.PacketNumber(1 << 62))
	require.Zero(t, b.sampler.connectionStats.numPresent)
	require.Zero(t, b.sampler.connectionStats.length)
	// New packets are tracked after the queue was emptied.
	b.OnPacketSent(now, 8, 1200, true)
	require.Equal(t, 1, b.sampler.connectionStats.numPresent)
	require.Equal(t, protocol.PacketNumber(8), b.sampler.connectionStats.firstPacket)
}

func TestBBRMinimumPacingRate(t *testing.T) {
	b := newAckEventTestSender(nil)
	b.pacingRate = 1
	require.Equal(t, BytesPerSecond, b.PacingRate())
	// The pacer divides by the rate in bytes per second.
	require.NotPanics(t, func() { b.TimeUntilSend() })
}

func TestBBRQlogPacingRate(t *testing.T) {
	var eventRecorder events.Recorder
	b := NewBBRSender(DefaultClock{}, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, false, &eventRecorder, BBROptions{})
	now := monotime.Now()
	for pn := protocol.PacketNumber(0); pn < 10; pn++ {
		b.OnPacketSent(now, pn, 1200, true)
	}
	eventRecorder.Clear()
	ackTime := now.Add(10 * time.Millisecond)
	b.BeginAckEvent(ackTime)
	for pn := protocol.PacketNumber(0); pn < 5; pn++ {
		b.OnPacketAcked(pn, 12000)
	}
	require.Empty(t, eventRecorder.Events(qlog.BBRPacingRateUpdated{}))
	b.EndAckEvent(12000, ackTime)
	require.Equal(t,
		[]qlogwriter.Event{qlog.BBRPacingRateUpdated{PacingRate: uint64(b.PacingRate())}},
		eventRecorder.Events(qlog.BBRPacingRateUpdated{}),
	)
	// An unchanged pacing rate is not logged again.
	b.BeginAckEvent(ackTime)
	b.OnPacketAcked(5, 6000)
	b.EndAckEvent(6000, ackTime)
	require.Len(t, eventRecorder.Events(qlog.BBRPacingRateUpdated{}), 1)
}
