package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/require"
)

func TestBBRSenderInterfaces(t *testing.T) {
	// Verify interface compliance
	var _ SendAlgorithm = &bbrSender{}
	var _ SendAlgorithmWithDebugInfos = &bbrSender{}
}

func TestBBRSenderInitialization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)

	require.NotNil(t, bbr)
	require.True(t, bbr.InSlowStart())
	require.Same(t, connStats, bbr.connStats)
	require.Equal(t, initialMaxDatagramSize, bbr.maxDatagramSize)
	require.Equal(t, initialMaxDatagramSize, bbr.pacer.maxDatagramSize)
	require.NotNil(t, bbr.sampler)
	require.NotNil(t, bbr.pacer)
	require.NotNil(t, bbr.maxBandwidth)
	require.NotNil(t, bbr.maxAckHeight)
}

func TestBBRStartupPhase(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	require.True(t, bbr.InSlowStart())
	require.False(t, bbr.InRecovery())
	require.Equal(t, DefaultHighGain, bbr.pacingGain)
}

func TestBBRDebugMethods(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Test debug interface methods
	require.True(t, bbr.InSlowStart())
	require.False(t, bbr.InRecovery())

	cwnd := bbr.GetCongestionWindow()
	require.Greater(t, cwnd, protocol.ByteCount(0))
	require.Equal(t, bbr.congestionWindow, cwnd)
}

func TestBBRPacketSendAndAck(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Send a packet
	packetNumber := protocol.PacketNumber(1)
	packetSize := protocol.ByteCount(1000)
	bytesInFlight := packetSize

	bbr.OnPacketSent((&clock).Now(), bytesInFlight, packetNumber, packetSize, true)
	require.Equal(t, packetNumber, bbr.lastSendPacket)

	// Advance time and ack the packet
	(&clock).Advance(50 * time.Millisecond)
	bytesInFlight = packetSize

	bbr.OnPacketAcked(packetNumber, packetSize, bytesInFlight, (&clock).Now())

	// Verify bandwidth estimate exists (may be zero if no valid sample)
	_ = bbr.BandwidthEstimate()
}

func TestBBRIgnoresNonAckElicitingPackets(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	bbr.OnPacketSent(clock.Now(), 1000, 1, 1000, true)
	require.Equal(t, protocol.PacketNumber(1), bbr.lastSendPacket)
	require.Equal(t, protocol.PacketNumber(1), bbr.sampler.lastSendPacket)
	require.Equal(t, protocol.ByteCount(1000), bbr.bytesInFlight)

	bbr.OnPacketSent(clock.Now(), 1000, 2, 50, false)
	require.Equal(t, protocol.PacketNumber(1), bbr.lastSendPacket)
	require.Equal(t, protocol.PacketNumber(1), bbr.sampler.lastSendPacket)
	require.Equal(t, protocol.ByteCount(1000), bbr.bytesInFlight)
}

func TestBBRTracksBytesInFlight(t *testing.T) {
	var clock mockClock
	clock.Advance(time.Millisecond)
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	bbr.OnPacketSent(clock.Now(), 1000, 1, 1000, true)
	require.Equal(t, protocol.ByteCount(1000), bbr.bytesInFlight)

	bbr.OnPacketSent(clock.Now(), 2000, 2, 1000, true)
	require.Equal(t, protocol.ByteCount(2000), bbr.bytesInFlight)

	clock.Advance(50 * time.Millisecond)
	bbr.OnPacketAcked(1, 1000, 2000, clock.Now())
	require.Equal(t, protocol.ByteCount(1000), bbr.bytesInFlight)

	bbr.OnCongestionEvent(2, 1000, 1000)
	require.Zero(t, bbr.bytesInFlight)

	bbr.OnPacketSent(clock.Now(), 1000, 3, 1000, true)
	require.Equal(t, protocol.ByteCount(1000), bbr.bytesInFlight)
	bbr.OnPacketDiscarded(3)
	require.Zero(t, bbr.bytesInFlight)
}

func TestBBRPacketLoss(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)

	// Send some packets
	for i := protocol.PacketNumber(1); i <= 10; i++ {
		bbr.OnPacketSent((&clock).Now(), protocol.ByteCount(i)*1000, i, 1000, true)
	}

	// Report a loss
	lostPacket := protocol.PacketNumber(5)
	lostBytes := protocol.ByteCount(1000)
	priorInFlight := protocol.ByteCount(10000)

	bbr.OnCongestionEvent(lostPacket, lostBytes, priorInFlight)

	require.Equal(t, uint64(1), connStats.PacketsLost.Load())
	require.Equal(t, uint64(lostBytes), connStats.BytesLost.Load())
	require.True(t, bbr.InRecovery())
}

func TestBBRToleratesSmallRandomLoss(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)

	const numPackets = 100
	for i := protocol.PacketNumber(1); i <= numPackets; i++ {
		bbr.OnPacketSent(clock.Now(), protocol.ByteCount(i)*initialMaxDatagramSize, i, initialMaxDatagramSize, true)
	}

	priorInFlight := protocol.ByteCount(numPackets) * initialMaxDatagramSize
	bbr.OnCongestionEvent(1, initialMaxDatagramSize, priorInFlight)

	require.Equal(t, uint64(1), connStats.PacketsLost.Load())
	require.Equal(t, uint64(initialMaxDatagramSize), connStats.BytesLost.Load())
	require.False(t, bbr.InRecovery())
	require.Equal(t, initialMaxDatagramSize, bbr.lossToleranceLostBytes)
}

func TestBBREntersRecoveryWhenRandomLossToleranceIsExceeded(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)

	const numPackets = 100
	for i := protocol.PacketNumber(1); i <= numPackets; i++ {
		bbr.OnPacketSent(clock.Now(), protocol.ByteCount(i)*initialMaxDatagramSize, i, initialMaxDatagramSize, true)
	}

	priorInFlight := protocol.ByteCount(numPackets) * initialMaxDatagramSize
	bbr.OnCongestionEvent(1, initialMaxDatagramSize, priorInFlight)
	require.False(t, bbr.InRecovery())

	bbr.OnCongestionEvent(2, initialMaxDatagramSize, priorInFlight)
	require.False(t, bbr.InRecovery())

	bbr.OnCongestionEvent(3, initialMaxDatagramSize, priorInFlight)
	require.True(t, bbr.InRecovery())
	require.Equal(t, uint64(3), connStats.PacketsLost.Load())
	require.Equal(t, uint64(3*initialMaxDatagramSize), connStats.BytesLost.Load())
}

func TestBBRUsesHigherRandomLossToleranceAtFullBandwidth(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)
	bbr.isAtFullBandwidth = true

	const numPackets = 100
	for i := protocol.PacketNumber(1); i <= numPackets; i++ {
		bbr.OnPacketSent(clock.Now(), protocol.ByteCount(i)*initialMaxDatagramSize, i, initialMaxDatagramSize, true)
	}

	priorInFlight := protocol.ByteCount(numPackets) * initialMaxDatagramSize
	bbr.OnCongestionEvent(1, initialMaxDatagramSize, priorInFlight)
	require.False(t, bbr.InRecovery())

	bbr.OnCongestionEvent(2, initialMaxDatagramSize, priorInFlight)
	require.False(t, bbr.InRecovery())

	bbr.OnCongestionEvent(3, initialMaxDatagramSize, priorInFlight)
	require.False(t, bbr.InRecovery())

	bbr.OnCongestionEvent(4, initialMaxDatagramSize, priorInFlight)
	require.True(t, bbr.InRecovery())
	require.Equal(t, uint64(4), connStats.PacketsLost.Load())
	require.Equal(t, uint64(4*initialMaxDatagramSize), connStats.BytesLost.Load())
}

func TestBBRDoesNotTolerateLossWithSmallInflight(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	const numPackets = 10
	for i := protocol.PacketNumber(1); i <= numPackets; i++ {
		bbr.OnPacketSent(clock.Now(), protocol.ByteCount(i)*initialMaxDatagramSize, i, initialMaxDatagramSize, true)
	}

	priorInFlight := protocol.ByteCount(numPackets) * initialMaxDatagramSize
	bbr.OnCongestionEvent(1, initialMaxDatagramSize, priorInFlight)

	require.True(t, bbr.InRecovery())
}

func TestBBRECNDoesNotDiscardBandwidthSample(t *testing.T) {
	var clock mockClock
	clock.Advance(time.Millisecond)
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize, false, nil)

	bbr.OnPacketSent(clock.Now(), initialMaxDatagramSize, 1, initialMaxDatagramSize, true)
	bbr.OnCongestionEvent(1, 0, initialMaxDatagramSize)
	require.Zero(t, connStats.PacketsLost.Load())
	require.Zero(t, connStats.BytesLost.Load())

	clock.Advance(50 * time.Millisecond)
	bbr.OnPacketAcked(1, initialMaxDatagramSize, initialMaxDatagramSize, clock.Now())

	require.Greater(t, bbr.BandwidthEstimate(), Bandwidth(0))
}

func TestBBRApplicationLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	require.False(t, bbr.sampler.isAppLimited)

	bbr.OnApplicationLimited()
	require.True(t, bbr.sampler.isAppLimited)
}

func TestBBRCanSend(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// With no bytes in flight, should be able to send
	require.True(t, bbr.CanSend(0))

	// With bytes in flight below CWND, should be able to send
	require.True(t, bbr.CanSend(bbr.GetCongestionWindow()-1))

	// With bytes in flight at or above CWND, should not be able to send
	require.False(t, bbr.CanSend(bbr.GetCongestionWindow()))
	require.False(t, bbr.CanSend(bbr.GetCongestionWindow()+1000))
}

func TestBBRSetMaxDatagramSize(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	newSize := protocol.ByteCount(1400)
	bbr.SetMaxDatagramSize(newSize)

	require.Equal(t, newSize, bbr.maxDatagramSize)
	require.Equal(t, 32*newSize, bbr.initialCongestionWindow)
	require.Equal(t, 32*newSize, bbr.congestionWindow)
	require.Equal(t, 4*newSize, bbr.minCongestionWindow)
	require.Equal(t, bbrMaxCongestionWindow(newSize), bbr.maxCongestionWindow)
	require.Equal(t, bbrMaxCongestionWindow(newSize), bbr.recoveryWindow)
}

func TestBBRSetMaxDatagramSizeCanDecrease(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(protocol.InitialPacketSize)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	newSize := protocol.ByteCount(protocol.MinInitialPacketSize)
	require.NotPanics(t, func() {
		bbr.SetMaxDatagramSize(newSize)
	})

	require.Equal(t, newSize, bbr.maxDatagramSize)
	require.Equal(t, 32*newSize, bbr.initialCongestionWindow)
	require.Equal(t, 32*newSize, bbr.congestionWindow)
	require.Equal(t, 4*newSize, bbr.minCongestionWindow)
	require.Equal(t, bbrMaxCongestionWindow(newSize), bbr.maxCongestionWindow)
	require.Equal(t, bbrMaxCongestionWindow(newSize), bbr.recoveryWindow)
}

func TestBBRMaxCongestionWindowSupportsHighBDP(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)
	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	const (
		bandwidth900Mbps = Bandwidth(900_000_000)
		rtt              = 120 * time.Millisecond
	)
	bdp := protocol.ByteCount(bandwidth900Mbps/BytesPerSecond) * protocol.ByteCount(rtt) / protocol.ByteCount(time.Second)

	require.GreaterOrEqual(t, bbr.maxCongestionWindow, bdp)
}

func TestBBRTimeUntilSend(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// TimeUntilSend should return a monotime value
	timeUntilSend := bbr.TimeUntilSend(0)
	require.GreaterOrEqual(t, timeUntilSend, monotime.Time(0))
}

func TestBBRHasPacingBudget(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Initially should have pacing budget
	hasBudget := bbr.HasPacingBudget((&clock).Now())
	// Budget status depends on pacer state, just verify it doesn't panic
	_ = hasBudget
}

func TestBBRModeTransitions(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Start in STARTUP
	require.True(t, bbr.InSlowStart())

	// Force full bandwidth detection
	bbr.isAtFullBandwidth = true
	bbr.MaybeExitStartupOrDrain((&clock).Now())

	// Should transition to DRAIN
	require.False(t, bbr.InSlowStart())

	// With no bytes in flight, should transition to PROBE_BW
	bbr.bytesInFlight = 0
	bbr.MaybeExitStartupOrDrain((&clock).Now())

	// Should be in PROBE_BW now (not in slow start, not in recovery)
	require.False(t, bbr.InSlowStart())
}

func TestBBRRecoveryState(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Send some packets first
	bbr.lastSendPacket = protocol.PacketNumber(10)

	// Initially not in recovery
	require.False(t, bbr.InRecovery())

	// Trigger recovery by reporting loss
	bbr.UpdateRecoveryState(protocol.PacketNumber(1), true, false)

	// Should enter recovery (CONSERVATION)
	require.True(t, bbr.InRecovery())

	// Advance to next round with no losses
	// This should transition to GROWTH but stay in recovery
	// because lastAckedPacket (2) < endRecoveryAt (10)
	bbr.UpdateRecoveryState(protocol.PacketNumber(2), false, true)

	// Should still be in recovery (GROWTH)
	require.True(t, bbr.InRecovery())

	// Exit recovery when we ack past endRecoveryAt
	bbr.UpdateRecoveryState(protocol.PacketNumber(11), false, false)

	// Should have exited recovery
	require.False(t, bbr.InRecovery())
}

func TestBBRRecoveryEndIsNotExtendedByAck(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	bbr.lastSendPacket = 10

	bbr.UpdateRecoveryState(5, true, false)
	require.True(t, bbr.InRecovery())
	require.Equal(t, protocol.PacketNumber(10), bbr.endRecoveryAt)

	bbr.lastSendPacket = 20
	bbr.UpdateRecoveryState(8, false, false)
	require.True(t, bbr.InRecovery())
	require.Equal(t, protocol.PacketNumber(10), bbr.endRecoveryAt)

	bbr.UpdateRecoveryState(11, false, false)
	require.False(t, bbr.InRecovery())
}

func TestBBRRecoveryDoesNotGrowCongestionWindow(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	bbr.maxBandwidth.Update(int64(Bandwidth(100_000_000)), 1)
	bbr.minRtt = 100 * time.Millisecond
	bbr.sampler.totalBytesAcked = bbr.initialCongestionWindow

	before := bbr.congestionWindow
	require.Greater(t, bbr.GetTargetCongestionWindow(bbr.congestionWindowGain), before+initialMaxDatagramSize)

	bbr.CalculateCongestionWindow(initialMaxDatagramSize, 0)
	require.Equal(t, before+initialMaxDatagramSize, bbr.congestionWindow)

	bbr.congestionWindow = before
	bbr.recoveryState = CONSERVATION
	bbr.CalculateCongestionWindow(initialMaxDatagramSize, 0)
	require.Equal(t, before, bbr.congestionWindow)
}

func TestBBRProbeRTTUsesCurrentMaxDatagramSize(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	bbr.mode = PROBE_RTT

	now := clock.Now()
	bbr.bytesInFlight = bbr.ProbeRttCongestionWindow() + bbr.maxDatagramSize
	bbr.MaybeEnterOrExitProbeRtt(now, false, false)
	require.True(t, bbr.exitProbeRttAt.IsZero())

	bbr.bytesInFlight = bbr.ProbeRttCongestionWindow() + bbr.maxDatagramSize - 1
	bbr.MaybeEnterOrExitProbeRtt(now, false, false)
	require.False(t, bbr.exitProbeRttAt.IsZero())
}

func TestBBRProbeRttCongestionWindowIsBasedOnBdp(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	bbr.maxBandwidth.Update(int64(Bandwidth(100_000_000)), 1) // 100 Mbit/s
	bbr.minRtt = 100 * time.Millisecond

	// PROBE_RTT keeps 0.75*BDP in flight instead of collapsing to the minimum window.
	require.Equal(t, bbr.GetTargetCongestionWindow(ModerateProbeRttMultiplier), bbr.ProbeRttCongestionWindow())
	require.Greater(t, bbr.ProbeRttCongestionWindow(), bbr.minCongestionWindow)
}

func TestBBROnApplicationLimitedIgnoredWhenCwndLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	bbr.bytesInFlight = bbr.GetCongestionWindow()
	bbr.OnApplicationLimited()
	require.False(t, bbr.appLimitedSinceLastProbeRtt)
	require.False(t, bbr.sampler.isAppLimited)

	bbr.bytesInFlight = 0
	bbr.OnApplicationLimited()
	require.True(t, bbr.appLimitedSinceLastProbeRtt)
	require.True(t, bbr.sampler.isAppLimited)
}

func TestBBRSkipsProbeRttIfRttSimilarWhileAppLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	// isolate the similar-RTT logic from the app-limited PROBE_RTT suppression
	bbr.probeRttDisabledIfAppLimited = false
	clock.Advance(time.Second)
	bbr.minRtt = 100 * time.Millisecond
	bbr.minRttTimestamp = clock.Now()
	bbr.OnApplicationLimited()
	require.True(t, bbr.appLimitedSinceLastProbeRtt)

	// A sample within 12.5% of the current min RTT extends the expiry
	// instead of triggering PROBE_RTT.
	clock.Advance(MinRttExpiry + time.Second)
	require.False(t, bbr.updateMinRtt(clock.Now(), 105*time.Millisecond))
	require.Equal(t, 100*time.Millisecond, bbr.minRtt)
	require.Equal(t, clock.Now(), bbr.minRttTimestamp)
	require.False(t, bbr.appLimitedSinceLastProbeRtt)

	// A sample well above the current min RTT lets the expiry fire.
	bbr.OnApplicationLimited()
	clock.Advance(MinRttExpiry + time.Second)
	require.True(t, bbr.updateMinRtt(clock.Now(), 130*time.Millisecond))
	require.Equal(t, 130*time.Millisecond, bbr.minRtt)
}

func TestBBRProbeRttDisabledIfAppLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	require.True(t, bbr.probeRttDisabledIfAppLimited)
	clock.Advance(time.Second)
	bbr.minRtt = 100 * time.Millisecond
	bbr.minRttTimestamp = clock.Now()
	bbr.OnApplicationLimited()
	require.True(t, bbr.appLimitedSinceLastProbeRtt)

	// While the connection was app-limited since the last PROBE_RTT,
	// min RTT expiry is extended even for samples well above the current min RTT.
	clock.Advance(MinRttExpiry + time.Second)
	require.False(t, bbr.updateMinRtt(clock.Now(), 130*time.Millisecond))
	require.Equal(t, 100*time.Millisecond, bbr.minRtt)
	require.Equal(t, clock.Now(), bbr.minRttTimestamp)
	require.False(t, bbr.appLimitedSinceLastProbeRtt)

	// Without an app-limited phase, the expiry fires as usual.
	clock.Advance(MinRttExpiry + time.Second)
	require.True(t, bbr.updateMinRtt(clock.Now(), 130*time.Millisecond))
	require.Equal(t, 130*time.Millisecond, bbr.minRtt)
}

func TestBBRDoesNotSkipProbeRttWhenNotAppLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	clock.Advance(time.Second)
	bbr.minRtt = 100 * time.Millisecond
	bbr.minRttTimestamp = clock.Now()

	// Without an app-limited phase since the last PROBE_RTT, a similar RTT
	// sample does not prevent the expiry: saturated connections still probe.
	clock.Advance(MinRttExpiry + time.Second)
	require.True(t, bbr.updateMinRtt(clock.Now(), 105*time.Millisecond))
	require.Equal(t, 105*time.Millisecond, bbr.minRtt)
}

func TestBBRRecoveryWindowFallbackUsesCurrentDatagramSize(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1400)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)
	bbr.recoveryState = CONSERVATION
	bbr.recoveryWindow = initialMaxDatagramSize / 2
	bbr.minCongestionWindow = 0

	bbr.CalculateRecoveryWindow(0, initialMaxDatagramSize)
	require.Equal(t, initialMaxDatagramSize, bbr.recoveryWindow)
}

func TestBBRGetTargetCongestionWindow(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// With no bandwidth estimate, should use initial congestion window
	targetCwnd := bbr.GetTargetCongestionWindow(1.0)
	require.GreaterOrEqual(t, targetCwnd, bbr.minCongestionWindow)

	// With a bandwidth estimate, should calculate BDP
	bbr.maxBandwidth.Update(1000000, 0) // 1 Mbps in bits/s
	bbr.minRtt = 100 * time.Millisecond

	targetCwnd = bbr.GetTargetCongestionWindow(1.0)
	require.Greater(t, targetCwnd, protocol.ByteCount(0))
	require.GreaterOrEqual(t, targetCwnd, bbr.minCongestionWindow)
}

func TestBBRAckAggregationAfterIdle(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// 1 Gbps bandwidth estimate
	bbr.maxBandwidth.Update(1e9, 1)
	bbr.roundTripCount = 1

	now := monotime.Now()
	bbr.aggregationEpochStartTime = now
	bbr.aggregationEpochBytes = 1200

	// The first ACK after a long idle period must not overflow the expected
	// bytes computation and poison the max ack height filter.
	excess := bbr.UpdateAckAggregationBytes(now.Add(5*time.Minute), 1200)
	require.Zero(t, excess)
	require.Zero(t, bbr.maxAckHeight.GetBest())
	// the epoch was reset
	require.Equal(t, now.Add(5*time.Minute), bbr.aggregationEpochStartTime)
	require.Equal(t, protocol.ByteCount(1200), bbr.aggregationEpochBytes)
}

func TestBBRAggregationEpochResetAfterQuiescence(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	now := monotime.Now()
	bbr.OnPacketSent(now, 1200, 0, 1200, true)
	require.Equal(t, now, bbr.aggregationEpochStartTime)

	bbr.aggregationEpochBytes = 5000

	// Sending with zero prior bytes in flight (i.e. resuming from quiescence)
	// resets the aggregation epoch.
	later := now.Add(time.Minute)
	bbr.OnPacketSent(later, 1200, 1, 1200, true)
	require.Equal(t, later, bbr.aggregationEpochStartTime)
	require.Zero(t, bbr.aggregationEpochBytes)
}

func TestBBRExpectedBytesAcked(t *testing.T) {
	// 1 Gbps for 100ms = 12.5 MB/s * 0.1s = 1.25 MB
	require.Equal(t, protocol.ByteCount(12_500_000), expectedBytesAcked(1e9*BitsPerSecond, 100*time.Millisecond))
	// long periods don't overflow
	require.Equal(t, protocol.ByteCount(125_000_000*3600), expectedBytesAcked(1e9*BitsPerSecond, time.Hour))
	require.Zero(t, expectedBytesAcked(1e9*BitsPerSecond, 0))
	require.Zero(t, expectedBytesAcked(0, time.Hour))
}

type recordingQlogger struct {
	events []qlogwriter.Event
}

func (r *recordingQlogger) RecordEvent(e qlogwriter.Event) { r.events = append(r.events, e) }
func (r *recordingQlogger) Close() error                   { return nil }

func (r *recordingQlogger) states(t *testing.T) []qlog.CongestionState {
	t.Helper()
	var states []qlog.CongestionState
	for _, e := range r.events {
		if s, ok := e.(qlog.CongestionStateUpdated); ok {
			states = append(states, s.State)
		}
	}
	return states
}

func TestBBRQlogStateTransitions(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	qlogger := &recordingQlogger{}

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, protocol.ByteCount(1200), false, qlogger)
	require.Equal(t, []qlog.CongestionState{qlog.CongestionStateSlowStart}, qlogger.states(t))

	now := monotime.Now()
	bbr.isAtFullBandwidth = true
	// keep bytes in flight above the target window, so DRAIN isn't exited immediately
	bbr.bytesInFlight = 10 * bbr.GetTargetCongestionWindow(1)
	bbr.MaybeExitStartupOrDrain(now)
	require.Equal(t, DRAIN, int(bbr.mode))
	bbr.bytesInFlight = 0
	bbr.MaybeExitStartupOrDrain(now)
	require.Equal(t, PROBE_BW, int(bbr.mode))
	require.Equal(t,
		[]qlog.CongestionState{qlog.CongestionStateSlowStart, qlog.CongestionStateCongestionAvoidance},
		qlogger.states(t),
	)

	// entering and leaving recovery is recorded as well
	bbr.lastSendPacket = 10
	bbr.UpdateRecoveryState(5, true, false)
	require.True(t, bbr.InRecovery())
	bbr.UpdateRecoveryState(11, false, false)
	require.False(t, bbr.InRecovery())
	require.Equal(t,
		[]qlog.CongestionState{
			qlog.CongestionStateSlowStart, qlog.CongestionStateCongestionAvoidance,
			qlog.CongestionStateRecovery, qlog.CongestionStateCongestionAvoidance,
		},
		qlogger.states(t),
	)
}

func TestBBRPacingRate(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, protocol.ByteCount(1200), false, nil)
	require.Zero(t, bbr.PacingRate())

	bbr.OnPacketSent(monotime.Now(), 1200, 0, 1200, true)
	require.Equal(t, bbr.pacingRate, bbr.PacingRate())
	require.NotZero(t, bbr.PacingRate())
}

// TestBBRStartupPacingInitialization verifies that BBR initializes pacing rate
// aggressively during startup, preventing the slow startup issue.
func TestBBRStartupPacingInitialization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Verify we're in startup mode
	require.True(t, bbr.InSlowStart())
	require.Equal(t, bbrMode(STARTUP), bbr.mode)
	require.Equal(t, DefaultHighGain, bbr.pacingGain)

	// Initial pacing rate should be 0 before any packets sent
	require.Equal(t, Bandwidth(0), bbr.pacingRate)

	// Send first packet - should initialize pacing rate using InitialRtt
	now := clock.Now()
	bbr.OnPacketSent(now, initialMaxDatagramSize, 1, initialMaxDatagramSize, true)

	// After first packet, pacing rate should be set and aggressive
	// Expected to be at least 8 Mbps (initialCongestionWindow / InitialRtt * pacingGain)
	require.Greater(t, bbr.pacingRate, Bandwidth(0), "Pacing rate should be initialized")
	require.Greater(t, bbr.pacingRate, Bandwidth(8*1024*1024), "Pacing rate should be aggressive (>8 Mbps)")

	// Verify pacer uses the aggressive pacing rate, not bandwidth estimate
	// (which would be 0 since no acks yet)
	require.Equal(t, Bandwidth(0), bbr.BandwidthEstimate())

	// Pacer should allow immediate sending with aggressive rate
	require.True(t, bbr.HasPacingBudget(now))
}

// TestBBRStartupPacingWithRTTSample verifies that pacing rate is updated
// when first RTT sample arrives and becomes more accurate.
func TestBBRStartupPacingWithRTTSample(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Send and ack first packet to get RTT sample
	clock.Advance(time.Millisecond)
	now := clock.Now()
	bbr.OnPacketSent(now, initialMaxDatagramSize, 1, initialMaxDatagramSize, true)

	// Simulate RTT of 40ms (realistic)
	rttSample := 40 * time.Millisecond
	clock.Advance(rttSample)
	rttStats.UpdateRTT(rttSample, 0)

	// Process ack
	bbr.OnPacketAcked(1, initialMaxDatagramSize, initialMaxDatagramSize, clock.Now())

	// Pacing rate should be updated based on actual RTT (40ms)
	// With 40ms RTT, should be significantly higher than with 100ms default
	// Expected to be at least 8 Mbps with aggressive startup gain
	require.Greater(t, bbr.pacingRate, Bandwidth(8*1024*1024), "Pacing rate should be aggressive with actual RTT (>8 Mbps)")
}

// TestBBRStartupPipeUtilization verifies that BBR fills the pipe during startup.
func TestBBRStartupPipeUtilization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Simulate sending packets to fill the pipe
	now := clock.Now()
	var bytesInFlight protocol.ByteCount
	packetNum := protocol.PacketNumber(0)

	// Should be able to send initial congestion window worth of data
	for bytesInFlight < bbr.initialCongestionWindow {
		require.True(t, bbr.CanSend(bytesInFlight), "Should be able to send up to initial CWND")

		packetNum++
		bytesInFlight += initialMaxDatagramSize
		bbr.OnPacketSent(now, bytesInFlight, packetNum, initialMaxDatagramSize, true)

		// Small time advance for pacing
		now = now.Add(time.Millisecond)
	}

	// Should have sent ~32 packets
	require.GreaterOrEqual(t, int(packetNum), 30)
	require.LessOrEqual(t, bytesInFlight, bbr.GetCongestionWindow()+initialMaxDatagramSize)
}

// TestBBRStartupBandwidthGrowth verifies that bandwidth estimate grows during startup.
func TestBBRStartupBandwidthGrowth(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)
	rtt := 40 * time.Millisecond

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, false, nil)

	// Simulate several round trips
	now := clock.Now()
	packetNum := protocol.PacketNumber(0)

	for round := 0; round < 5; round++ {
		// Send a burst of packets
		var bytesInFlight protocol.ByteCount
		sentInRound := protocol.ByteCount(0)

		for i := 0; i < 10; i++ {
			if bbr.CanSend(bytesInFlight) {
				packetNum++
				bytesInFlight += initialMaxDatagramSize
				sentInRound += initialMaxDatagramSize
				bbr.OnPacketSent(now, bytesInFlight, packetNum, initialMaxDatagramSize, true)
				now = now.Add(time.Millisecond)
			}
		}

		// Advance time for RTT
		clock.Advance(rtt)
		now = clock.Now()
		rttStats.UpdateRTT(rtt, 0)

		// Ack all packets from this round
		for i := protocol.ByteCount(0); i < sentInRound; i += initialMaxDatagramSize {
			bytesInFlight -= initialMaxDatagramSize
			bbr.OnPacketAcked(packetNum-protocol.PacketNumber(sentInRound/initialMaxDatagramSize)+protocol.PacketNumber(i/initialMaxDatagramSize)+1,
				initialMaxDatagramSize, bytesInFlight+initialMaxDatagramSize, now)
		}

		// Bandwidth should eventually be non-zero
		if round > 2 {
			require.Greater(t, bbr.BandwidthEstimate(), Bandwidth(0), "Should have bandwidth samples by round 3")
		}

		// CWND should grow during startup
		if round > 1 {
			require.Greater(t, bbr.congestionWindow, bbr.initialCongestionWindow, "CWND should grow during startup")
		}
	}

	// By round 5, should have some bandwidth estimate and CWND growth
	// (exact values depend on timing and packet scheduling)
	require.Greater(t, bbr.BandwidthEstimate(), Bandwidth(0), "Should have bandwidth estimate")
	require.Greater(t, bbr.congestionWindow, bbr.initialCongestionWindow, "CWND should have grown")
}
