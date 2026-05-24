package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

	require.True(t, bbr.InSlowStart())
	require.False(t, bbr.InRecovery())
	require.Equal(t, DefaultHighGain, bbr.pacingGain)
}

func TestBBRDebugMethods(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, connStats, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
	require.False(t, bbr.sampler.isAppLimited)

	bbr.OnApplicationLimited()
	require.True(t, bbr.sampler.isAppLimited)
}

func TestBBRCanSend(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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
	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

	// TimeUntilSend should return a monotime value
	timeUntilSend := bbr.TimeUntilSend(0)
	require.GreaterOrEqual(t, timeUntilSend, monotime.Time(0))
}

func TestBBRHasPacingBudget(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

	// Initially should have pacing budget
	hasBudget := bbr.HasPacingBudget((&clock).Now())
	// Budget status depends on pacer state, just verify it doesn't panic
	_ = hasBudget
}

func TestBBRModeTransitions(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
	bbr.mode = PROBE_RTT

	now := clock.Now()
	bbr.bytesInFlight = bbr.ProbeRttCongestionWindow() + bbr.maxDatagramSize
	bbr.MaybeEnterOrExitProbeRtt(now, false, false)
	require.True(t, bbr.exitProbeRttAt.IsZero())

	bbr.bytesInFlight = bbr.ProbeRttCongestionWindow() + bbr.maxDatagramSize - 1
	bbr.MaybeEnterOrExitProbeRtt(now, false, false)
	require.False(t, bbr.exitProbeRttAt.IsZero())
}

func TestBBRRecoveryWindowFallbackUsesCurrentDatagramSize(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1400)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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
