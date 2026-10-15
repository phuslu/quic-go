package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

func newAckEventTestSender(stats *utils.ConnectionStats) *bbrSender {
	if stats == nil {
		stats = &utils.ConnectionStats{}
	}
	return NewBBRSender(DefaultClock{}, utils.NewRTTStats(), stats, 1200, false, nil, BBROptions{})
}

func TestBBRAckEventUpdatesModelOnce(t *testing.T) {
	stats := &utils.ConnectionStats{}
	b := newAckEventTestSender(stats)
	now := monotime.Now()
	b.minRtt, b.minRttTimestamp = 10*time.Millisecond, now
	b.maxBandwidth.Update(4_800_000, 1)
	b.bandwidthAtLastRound = 4_800_000
	b.roundsWithoutBandwidthGain = 2
	for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
		b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
	}

	ackTime := now.Add(10 * time.Millisecond)
	b.BeginAckEvent()
	for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
		b.OnPacketAcked(pn, 1200, 12000, ackTime)
		// Samples are taken immediately, but the model isn't updated yet.
		require.Equal(t, b.initialCongestionWindow, b.GetCongestionWindow())
		require.Equal(t, uint64(b.initialCongestionWindow), stats.CongestionWindow.Load())
		require.Equal(t, Bandwidth(4_800_000), b.BandwidthEstimate())
		require.Zero(t, b.roundTripCount)
	}
	require.Equal(t, protocol.ByteCount(12000), b.sampler.totalBytesAcked)
	require.Zero(t, b.bytesInFlight)
	b.EndAckEvent(12000, ackTime)

	// Later samples in this ACK double the bandwidth: the first, lower sample
	// must not count as a round without bandwidth growth.
	require.Equal(t, Bandwidth(9_600_000), b.BandwidthEstimate())
	require.True(t, b.InSlowStart())
	require.False(t, b.isAtFullBandwidth)
	require.Zero(t, b.roundsWithoutBandwidthGain)
	require.Equal(t, int64(1), b.roundTripCount)
	require.Equal(t, b.initialCongestionWindow+12000, b.GetCongestionWindow())
	require.Equal(t, uint64(b.GetCongestionWindow()), stats.CongestionWindow.Load())
	// The new aggregation epoch accounts for the whole ACK at once.
	require.Equal(t, protocol.ByteCount(12000), b.aggregationEpochBytes)
	require.Zero(t, b.maxAckHeight.GetBest())
	require.Equal(t, newBBRAckEvent(), b.ackEvent)

	// An ACK outside of an ACK event takes effect immediately.
	b.OnPacketSent(ackTime, 1200, 11, 1200, true)
	b.OnPacketAcked(11, 1200, 1200, now.Add(20*time.Millisecond))
	require.Equal(t, b.initialCongestionWindow+13200, b.GetCongestionWindow())
	require.Equal(t, int64(2), b.roundTripCount)
	require.Equal(t, newBBRAckEvent(), b.ackEvent)
}

func TestBBRAckEventSpansRoundBoundary(t *testing.T) {
	b := newAckEventTestSender(nil)
	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn <= 4; pn++ {
		b.OnPacketSent(now.Add(time.Duration(pn-1)*time.Millisecond), protocol.ByteCount(pn)*1200, pn, 1200, true)
	}
	b.currentRoundTripEnd, b.roundTripCount = 2, 7
	b.BeginAckEvent()
	for pn := protocol.PacketNumber(1); pn <= 4; pn++ {
		b.OnPacketAcked(pn, 1200, 4800, now.Add(10*time.Millisecond))
	}
	b.EndAckEvent(4800, now.Add(10*time.Millisecond))
	// The round is advanced once, by the largest acknowledged packet,
	// before the bandwidth sample is stamped with it.
	require.Equal(t, int64(8), b.roundTripCount)
	require.Equal(t, int64(8), b.maxBandwidth.estimates[0].time)
	require.Equal(t, protocol.PacketNumber(4), b.currentRoundTripEnd)
	require.Equal(t, 7*time.Millisecond, b.minRtt)
	require.Equal(t, protocol.ByteCount(4800), b.sampler.totalBytesAcked)
}

func TestBBRAckEventAppLimitedSamples(t *testing.T) {
	for _, tc := range []struct {
		name              string
		initial, expected Bandwidth
	}{
		{name: "ignore lower samples", initial: 4_800_000, expected: 4_800_000},
		{name: "accept higher samples", initial: 960_000, expected: 2_880_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newAckEventTestSender(nil)
			now := monotime.Now()
			b.maxBandwidth.Update(int64(tc.initial), 1)
			b.bandwidthAtLastRound = tc.initial
			b.roundsWithoutBandwidthGain = 2
			b.OnApplicationLimited()
			for pn := protocol.PacketNumber(1); pn <= 3; pn++ {
				b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
			}
			b.BeginAckEvent()
			for pn := protocol.PacketNumber(1); pn <= 3; pn++ {
				b.OnPacketAcked(pn, 1200, 3600, now.Add(10*time.Millisecond))
			}
			b.EndAckEvent(3600, now.Add(10*time.Millisecond))
			require.Equal(t, tc.expected, b.BandwidthEstimate())
			require.True(t, b.lastSampleIsAppLimited)
			require.False(t, b.hasNonAppLimitedSample)
			require.False(t, b.isAtFullBandwidth)
			require.Equal(t, int64(2), b.roundsWithoutBandwidthGain)
		})
	}
}

func TestBBRAckEventWithoutValidSamples(t *testing.T) {
	t.Run("obsolete packets", func(t *testing.T) {
		b := newAckEventTestSender(nil)
		now := monotime.Now()
		for pn := protocol.PacketNumber(1); pn <= 2; pn++ {
			b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
		}
		b.RemoveObsoletePackets(3)
		b.BeginAckEvent()
		b.OnPacketAcked(1, 1200, 2400, now.Add(10*time.Millisecond))
		b.OnPacketAcked(2, 1200, 2400, now.Add(10*time.Millisecond))
		b.EndAckEvent(2400, now.Add(10*time.Millisecond))
		require.Zero(t, b.roundTripCount)
		require.Zero(t, b.minRtt)
		require.Zero(t, b.sampler.connectionStats.numPresent)
		require.Equal(t, b.initialCongestionWindow, b.GetCongestionWindow())
	})

	t.Run("zero sampling interval", func(t *testing.T) {
		b := newAckEventTestSender(nil)
		now := monotime.Now()
		for pn := protocol.PacketNumber(1); pn <= 2; pn++ {
			b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
		}
		b.BeginAckEvent()
		b.OnPacketAcked(1, 1200, 2400, now)
		b.OnPacketAcked(2, 1200, 2400, now)
		b.EndAckEvent(2400, now)
		// Like quiche, packets without a bandwidth sample still count towards
		// the round trip and the congestion window.
		require.Equal(t, int64(1), b.roundTripCount)
		require.Zero(t, b.minRtt)
		require.Zero(t, b.BandwidthEstimate())
		require.Zero(t, b.bytesInFlight)
		require.Equal(t, b.initialCongestionWindow+2400, b.GetCongestionWindow())
	})
}

// A loss outside of an ACK event is a loss-only event of its own. Like in
// quiche, it doesn't enter recovery, and the next ACK event doesn't count it.
func TestBBRAckEventLossBeforeEvent(t *testing.T) {
	stats := &utils.ConnectionStats{}
	b := newAckEventTestSender(stats)
	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
		b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
	}
	recoveryWindow := b.recoveryWindow
	b.OnCongestionEvent(1, 1200, 12000)
	require.Equal(t, bbrRecoveryState(NOT_IN_RECOVERY), b.recoveryState)
	require.Equal(t, protocol.InvalidPacketNumber, b.endRecoveryAt)
	require.Equal(t, newBBRAckEvent(), b.ackEvent)

	b.BeginAckEvent()
	for pn := protocol.PacketNumber(2); pn <= 5; pn++ {
		b.OnPacketAcked(pn, 1200, 10800, now.Add(10*time.Millisecond))
	}
	b.EndAckEvent(10800, now.Add(10*time.Millisecond))
	require.Equal(t, protocol.ByteCount(6000), b.bytesInFlight)
	require.Equal(t, protocol.ByteCount(4800), b.sampler.totalBytesAcked)
	require.Equal(t, bbrRecoveryState(NOT_IN_RECOVERY), b.recoveryState)
	require.Equal(t, recoveryWindow, b.recoveryWindow)
	require.Equal(t, uint64(1), stats.PacketsLost.Load())
	require.Equal(t, uint64(1200), stats.BytesLost.Load())
	require.Equal(t, uint64(b.GetCongestionWindow()), stats.CongestionWindow.Load())
}

func TestBBRAckEventLossInEvent(t *testing.T) {
	stats := &utils.ConnectionStats{}
	b := newAckEventTestSender(stats)
	now := monotime.Now()
	for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
		b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
	}
	b.BeginAckEvent()
	b.OnCongestionEvent(1, 1200, 12000)
	b.OnCongestionEvent(2, 1200, 12000)
	// Losses are counted immediately, but recovery starts with the model update.
	require.Equal(t, uint64(2), stats.PacketsLost.Load())
	require.Equal(t, uint64(2400), stats.BytesLost.Load())
	require.Equal(t, bbrRecoveryState(NOT_IN_RECOVERY), b.recoveryState)
	for pn := protocol.PacketNumber(3); pn <= 5; pn++ {
		b.OnPacketAcked(pn, 1200, 12000, now.Add(10*time.Millisecond))
	}
	b.EndAckEvent(12000, now.Add(10*time.Millisecond))
	require.Equal(t, protocol.ByteCount(6000), b.bytesInFlight)
	require.Equal(t, bbrRecoveryState(CONSERVATION), b.recoveryState)
	require.Equal(t, protocol.PacketNumber(10), b.endRecoveryAt)
	// The recovery window starts at bytes in flight plus the bytes acknowledged by the event.
	require.Equal(t, protocol.ByteCount(6000+3600), b.recoveryWindow)
	require.Equal(t, uint64(b.GetCongestionWindow()), stats.CongestionWindow.Load())
}

// An event with only losses, e.g. from the loss detection timer, runs the
// model like quiche's OnCongestionEvent with empty acked_packets: no round
// trip and no recovery, but the gain cycle sees the losses, and the pacing
// rate and windows are recalculated.
func TestBBRAckEventOnlyLosses(t *testing.T) {
	b := newAckEventTestSender(nil)
	now := monotime.Now()
	b.mode = PROBE_BW
	b.isAtFullBandwidth = true
	b.minRtt, b.minRttTimestamp = 10*time.Millisecond, now
	b.maxBandwidth.Update(96_000_000, 1)
	b.cycleCurrentOffset, b.pacingGain = 0, PacingGain[0]
	b.lastCycleStart = now
	b.OnApplicationLimited()
	for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
		b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
	}
	recoveryWindow := b.recoveryWindow
	b.BeginAckEvent()
	b.OnCongestionEvent(1, 1200, 12000)
	b.OnCongestionEvent(2, 1200, 12000)
	b.EndAckEvent(12000, now.Add(20*time.Millisecond))
	require.Equal(t, bbrRecoveryState(NOT_IN_RECOVERY), b.recoveryState)
	require.Equal(t, protocol.InvalidPacketNumber, b.endRecoveryAt)
	require.Equal(t, recoveryWindow, b.recoveryWindow)
	require.Zero(t, b.roundTripCount)
	require.Equal(t, protocol.ByteCount(9600), b.bytesInFlight)
	// The 1.25 gain phase ends because of the losses, and the pacing rate follows.
	require.Equal(t, 1, b.cycleCurrentOffset)
	require.Equal(t, now.Add(20*time.Millisecond), b.lastCycleStart)
	require.Equal(t, Bandwidth(PacingGain[1]*96_000_000), b.pacingRate)
	// The send state of the largest lost packet is used.
	require.True(t, b.lastSampleIsAppLimited)
	require.Equal(t, newBBRAckEvent(), b.ackEvent)
}

// An ACK outside of an ACK event must produce the same state as an event
// containing just that ACK.
func TestBBRAckEventSinglePacketEquivalence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       bbrMode
		recovery   bool
		appLimited bool
	}{
		{name: "startup", mode: STARTUP},
		{name: "drain", mode: DRAIN},
		{name: "probe bandwidth", mode: PROBE_BW},
		{name: "probe RTT", mode: PROBE_RTT},
		{name: "recovery", mode: PROBE_BW, recovery: true},
		{name: "app limited", mode: STARTUP, appLimited: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := monotime.Now()
			newSender := func() *bbrSender {
				b := newAckEventTestSender(nil)
				b.mode = tc.mode
				b.isAtFullBandwidth = tc.mode != STARTUP
				b.minRtt, b.minRttTimestamp = 10*time.Millisecond, now
				b.maxBandwidth.Update(960_000, 1)
				b.lastCycleStart = now
				if tc.appLimited {
					b.OnApplicationLimited()
				}
				for pn := protocol.PacketNumber(1); pn <= 10; pn++ {
					b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
				}
				if tc.recovery {
					b.OnCongestionEvent(1, 1200, 12000)
				}
				return b
			}
			single, event := newSender(), newSender()
			ackTime := now.Add(10 * time.Millisecond)
			single.OnPacketAcked(2, 1200, single.bytesInFlight, ackTime)
			priorInFlight := event.bytesInFlight
			event.BeginAckEvent()
			event.OnPacketAcked(2, 1200, priorInFlight, ackTime)
			event.EndAckEvent(priorInFlight, ackTime)
			require.Equal(t, single, event)
		})
	}
}

// Losses detected by an ACK let the 1.25 gain phase end before the pipe is
// full, as in quiche's UpdateGainCyclePhase. Losses outside of the ACK event
// don't count for this ACK.
func TestBBRAckEventGainCycleLosses(t *testing.T) {
	for _, tc := range []struct {
		name            string
		lossBeforeEvent bool
		lossInEvent     bool
		advance         bool
		multiplePackets bool
	}{
		{name: "single packet without loss"},
		{name: "single packet with loss", lossInEvent: true, advance: true},
		{name: "multiple packets without loss", multiplePackets: true},
		{name: "multiple packets with loss", multiplePackets: true, lossInEvent: true, advance: true},
		{name: "loss before the event", multiplePackets: true, lossBeforeEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newAckEventTestSender(nil)
			now := monotime.Now()
			b.mode = PROBE_BW
			b.isAtFullBandwidth = true
			b.minRtt, b.minRttTimestamp = 10*time.Millisecond, now
			b.maxBandwidth.Update(96_000_000, 1)
			b.cycleCurrentOffset, b.pacingGain = 0, PacingGain[0]
			b.lastCycleStart = now
			for pn := protocol.PacketNumber(1); pn <= 4; pn++ {
				b.OnPacketSent(now, protocol.ByteCount(pn)*1200, pn, 1200, true)
			}
			if tc.lossBeforeEvent {
				b.OnCongestionEvent(1, 1200, 4800)
			}
			ackTime := now.Add(20 * time.Millisecond)
			b.BeginAckEvent()
			if tc.lossInEvent {
				b.OnCongestionEvent(1, 1200, 4800)
			}
			b.OnPacketAcked(2, 1200, 4800, ackTime)
			if tc.multiplePackets {
				b.OnPacketAcked(3, 1200, 4800, ackTime)
				b.OnPacketAcked(4, 1200, 4800, ackTime)
			}
			b.EndAckEvent(4800, ackTime)
			if tc.advance {
				require.Equal(t, 1, b.cycleCurrentOffset)
				require.Equal(t, ackTime, b.lastCycleStart)
			} else {
				require.Zero(t, b.cycleCurrentOffset)
				require.Equal(t, now, b.lastCycleStart)
			}
		})
	}
}
