package congestion

import (
	"strconv"
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

func TestBBRSenderInterfaces(t *testing.T) {
	// Verify interface compliance
	var _ SendAlgorithm = &bbrSender{}
	var _ SendAlgorithmWithDebugInfos = &bbrSender{}
}

func TestBBRSenderInitialization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	require.NotNil(t, bbr)
	require.True(t, bbr.InSlowStart())
	require.Equal(t, initialMaxDatagramSize, bbr.maxDatagramSize)
	require.NotNil(t, bbr.sampler)
	require.NotNil(t, bbr.pacer)
	require.NotNil(t, bbr.maxBandwidth)
	require.NotNil(t, bbr.maxAckHeight)
}

func TestBBRStartupPhase(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	require.True(t, bbr.InSlowStart())
	require.False(t, bbr.InRecovery())
	require.Equal(t, DefaultHighGain, bbr.pacingGain)
}

func TestBBRDebugMethods(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})
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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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
	// Obsolete packets are dropped from the sampler, and the bytes in flight
	// are updated by the next call that passes them in.
	bbr.RemoveObsoletePackets(4)
	require.Zero(t, bbr.sampler.connectionStats.numPresent)
	require.True(t, bbr.CanSend(0))
	require.Zero(t, bbr.bytesInFlight)
}

func TestBBRPacketLoss(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	// Send some packets
	for i := protocol.PacketNumber(1); i <= 10; i++ {
		bbr.OnPacketSent((&clock).Now(), protocol.ByteCount(i)*1000, i, 1000, true)
	}

	// Report a loss
	lostPacket := protocol.PacketNumber(5)
	lostBytes := protocol.ByteCount(1000)
	priorInFlight := protocol.ByteCount(10000)

	bbr.OnCongestionEvent(lostPacket, lostBytes, priorInFlight)

	// In STARTUP, we might not enter recovery immediately
	// Just verify the method doesn't panic
}

func TestBBRECNDoesNotDiscardBandwidthSample(t *testing.T) {
	var clock mockClock
	clock.Advance(time.Millisecond)
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	bbr.OnPacketSent(clock.Now(), initialMaxDatagramSize, 1, initialMaxDatagramSize, true)
	bbr.OnCongestionEvent(1, 0, initialMaxDatagramSize)

	clock.Advance(50 * time.Millisecond)
	bbr.OnPacketAcked(1, initialMaxDatagramSize, initialMaxDatagramSize, clock.Now())

	require.Greater(t, bbr.BandwidthEstimate(), Bandwidth(0))
}

func TestBBRECNDoesNotEnterRecovery(t *testing.T) {
	bbr := newTestBBRSender(BBROptions{})
	bbr.lastSendPacket = 10
	bbr.OnCongestionEvent(5, 0, 12000)
	require.False(t, bbr.InRecovery())
	require.Equal(t, protocol.InvalidPacketNumber, bbr.endRecoveryAt)
	require.Equal(t, uint64(1), bbr.connStats.PacketsLost.Load())
}

func TestBBRAckAggregationAfterLongIdle(t *testing.T) {
	bbr := newTestBBRSender(BBROptions{})
	bbr.maxBandwidth.Update(int64(10_000_000_000), 2) // 10 Gbps
	start := monotime.Time(time.Second)
	bbr.aggregationEpochStartTime = start
	bbr.aggregationEpochBytes = 10000

	// 10 Gbps * 80s overflows an int64 when computed in nanoseconds.
	require.Zero(t, bbr.UpdateAckAggregationBytes(start.Add(80*time.Second), 1200))
	require.Zero(t, bbr.maxAckHeight.GetBest())
	require.Equal(t, protocol.ByteCount(1200), bbr.aggregationEpochBytes)
}

func TestBBRBytesInDuration(t *testing.T) {
	require.Zero(t, bytesInDuration(8*1000*1000, -time.Second))
	require.Equal(t, protocol.ByteCount(10000), bytesInDuration(8*1000*1000, 10*time.Millisecond))
	// overflows an int64 when computed in nanoseconds
	require.Equal(t, protocol.ByteCount(10_000_000_000), bytesInDuration(1_000_000_000, 80*time.Second))
	require.Equal(t, protocol.MaxByteCount, bytesInDuration(10_000_000_000, 80*time.Second))
	require.Equal(t, protocol.MaxByteCount, bytesInDuration(InfiniteBandwidth, time.Hour))
}

func TestBBRProbeRttExitsAtDeadline(t *testing.T) {
	bbr := newTestBBRSender(BBROptions{})
	bbr.isAtFullBandwidth = true
	bbr.mode = PROBE_RTT
	now := monotime.Time(10 * time.Second)
	bbr.exitProbeRttAt = now
	bbr.probeRttRoundPassed = true
	bbr.MaybeEnterOrExitProbeRtt(now, false, false)
	require.Equal(t, bbrMode(PROBE_BW), bbr.mode)
}

func TestBBRAckWithoutBandwidthSample(t *testing.T) {
	var clock mockClock
	clock.Advance(time.Millisecond)
	bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, nil, BBROptions{})
	cwnd := bbr.congestionWindow

	// An ACK received at the send time doesn't produce a bandwidth sample.
	bbr.OnPacketSent(clock.Now(), 1200, 1, 1200, true)
	bbr.OnPacketAcked(1, 1200, 1200, clock.Now())
	require.Zero(t, bbr.BandwidthEstimate())
	require.Zero(t, bbr.minRtt)
	// The packet still starts a round trip and grows the congestion window.
	require.Equal(t, int64(1), bbr.roundTripCount)
	require.Equal(t, cwnd+1200, bbr.congestionWindow)
	require.Zero(t, bbr.bytesInFlight)
}

func TestBBRApplicationLimited(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})
	require.False(t, bbr.sampler.isAppLimited)

	bbr.OnApplicationLimited()
	require.True(t, bbr.sampler.isAppLimited)
	require.True(t, bbr.appLimitedSinceLastProbeRtt)
}

func TestBBRApplicationLimitedIgnoredWhenCongestionLimited(t *testing.T) {
	bbr := newTestBBRSender(BBROptions{})
	bbr.bytesInFlight = bbr.GetCongestionWindow()

	bbr.OnApplicationLimited()
	require.False(t, bbr.sampler.isAppLimited)
	require.False(t, bbr.appLimitedSinceLastProbeRtt)
}

func TestBBRCanSend(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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
	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	// TimeUntilSend should return a monotime value
	timeUntilSend := bbr.TimeUntilSend(0)
	require.GreaterOrEqual(t, timeUntilSend, monotime.Time(0))
}

func TestBBRHasPacingBudget(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	// Initially should have pacing budget
	hasBudget := bbr.HasPacingBudget((&clock).Now())
	// Budget status depends on pacer state, just verify it doesn't panic
	_ = hasBudget
}

func TestBBRModeTransitions(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

func TestBBRQlogModeTransitions(t *testing.T) {
	clock := mockClock(monotime.Time(time.Second))
	var eventRecorder events.Recorder
	bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, &eventRecorder, BBROptions{})
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateStartup}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
	eventRecorder.Clear()

	// With nothing in flight, STARTUP goes through DRAIN to PROBE_BW at once.
	// Both transitions are logged.
	bbr.isAtFullBandwidth = true
	bbr.MaybeExitStartupOrDrain(clock.Now())
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CongestionStateUpdated{State: qlog.CongestionStateDrain},
			qlog.CongestionStateUpdated{State: qlog.CongestionStateProbeBW},
		},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
	eventRecorder.Clear()

	// staying in PROBE_BW doesn't log anything
	bbr.MaybeExitStartupOrDrain(clock.Now())
	bbr.MaybeEnterOrExitProbeRtt(clock.Now(), true, false)
	require.Empty(t, eventRecorder.Events(qlog.CongestionStateUpdated{}))

	// the min RTT expires
	bbr.MaybeEnterOrExitProbeRtt(clock.Now(), false, true)
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateProbeRTT}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
	eventRecorder.Clear()

	clock.Advance(ProbeRttTime + time.Millisecond)
	bbr.MaybeEnterOrExitProbeRtt(clock.Now(), true, false)
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateProbeBW}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
}

func TestBBRQlogRecoveryDoesNotChangeState(t *testing.T) {
	var eventRecorder events.Recorder
	clock := mockClock(monotime.Time(time.Second))
	bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, &eventRecorder, BBROptions{})
	eventRecorder.Clear()

	bbr.OnPacketSent(clock.Now(), 0, 1, 1200, true)
	bbr.OnPacketSent(clock.Now(), 1200, 2, 1200, true)
	clock.Advance(10 * time.Millisecond)
	bbr.BeginAckEvent()
	bbr.OnCongestionEvent(1, 1200, 2400)
	bbr.OnPacketAcked(2, 1200, 2400, clock.Now())
	bbr.EndAckEvent(2400, clock.Now())
	require.True(t, bbr.InRecovery())
	require.Empty(t, eventRecorder.Events(qlog.CongestionStateUpdated{}))
}

func TestBBRRecoveryState(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})
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

func TestBBROptionAppLimitedRecovery(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var clock mockClock
		bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, nil, BBROptions{AppLimitedRecovery: enabled})
		bbr.lastSendPacket = 10
		bbr.lastSampleIsAppLimited = true

		bbr.UpdateRecoveryState(1, true, false)
		require.True(t, bbr.InRecovery())
		require.Equal(t, enabled, bbr.isAppLimitedRecovery)
		require.Equal(t, enabled, bbr.sampler.isAppLimited)
	}
}

func TestBBROptionNoBytesAckedInStartupRecovery(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var clock mockClock
		bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, nil, BBROptions{NoBytesAckedInStartupRecovery: enabled})
		bbr.lastSendPacket = 10
		bbr.UpdateRecoveryState(1, true, false)
		require.True(t, bbr.InSlowStart())
		require.True(t, bbr.InRecovery())

		cwnd := bbr.congestionWindow
		bbr.CalculateCongestionWindow(1200, 0)
		if enabled {
			require.Equal(t, cwnd, bbr.congestionWindow)
		} else {
			require.Equal(t, cwnd+1200, bbr.congestionWindow)
		}
	}
}

func TestBBRApplicationLimitedWindowChecks(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mode           bbrMode
		recoveryWindow protocol.ByteCount
		inFlight       protocol.ByteCount
		opts           BBROptions
		appLimited     bool
	}{
		{name: "startup below cwnd", mode: STARTUP, inFlight: 38399, appLimited: true},
		{name: "startup at cwnd", mode: STARTUP, inFlight: 38400},
		{name: "probe bandwidth below cwnd", mode: PROBE_BW, inFlight: 38399, appLimited: true},
		{name: "probe bandwidth at cwnd", mode: PROBE_BW, inFlight: 38400},
		{name: "below recovery window", mode: PROBE_BW, recoveryWindow: 12000, inFlight: 11999, appLimited: true},
		{name: "at recovery window", mode: PROBE_BW, recoveryWindow: 12000, inFlight: 12000},
		{name: "cwnd below recovery window", mode: PROBE_BW, recoveryWindow: 48000, inFlight: 38400},
		{name: "rate based startup ignores recovery window", mode: STARTUP, recoveryWindow: 12000, inFlight: 12000, opts: BBROptions{RateBasedStartup: true}, appLimited: true},
		{name: "rate based probe bandwidth respects recovery window", mode: PROBE_BW, recoveryWindow: 12000, inFlight: 12000, opts: BBROptions{RateBasedStartup: true}},
		{name: "below probe RTT window", mode: PROBE_RTT, inFlight: 4799, appLimited: true},
		{name: "at probe RTT window", mode: PROBE_RTT, inFlight: 4800},
		{name: "probe RTT overrides recovery window", mode: PROBE_RTT, recoveryWindow: 2400, inFlight: 2400, appLimited: true},
		{name: "below probe RTT BDP window", mode: PROBE_RTT, inFlight: 7499, opts: BBROptions{ProbeRttBasedOnBdp: true}, appLimited: true},
		{name: "at probe RTT BDP window", mode: PROBE_RTT, inFlight: 7500, opts: BBROptions{ProbeRttBasedOnBdp: true}},
		{name: "flexible below pipe threshold", mode: STARTUP, inFlight: 14999, opts: BBROptions{FlexibleAppLimited: true}, appLimited: true},
		{name: "flexible at pipe threshold", mode: STARTUP, inFlight: 15000, opts: BBROptions{FlexibleAppLimited: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRSender(tc.opts)
			bbr.mode = tc.mode
			bbr.bytesInFlight = tc.inFlight
			if tc.recoveryWindow > 0 {
				bbr.recoveryState = CONSERVATION
				bbr.recoveryWindow = tc.recoveryWindow
			}
			bbr.sampler.lastSendPacket = 42
			bbr.sampler.endOfAppLimitedPhase = 11

			bbr.OnApplicationLimited()

			require.Equal(t, tc.appLimited, bbr.sampler.isAppLimited)
			require.Equal(t, tc.appLimited, bbr.appLimitedSinceLastProbeRtt)
			if tc.appLimited {
				require.Equal(t, protocol.PacketNumber(42), bbr.sampler.endOfAppLimitedPhase)
				// A second signal must cover the packets sent since the first one.
				bbr.sampler.lastSendPacket = 43
				bbr.OnApplicationLimited()
				require.Equal(t, protocol.PacketNumber(43), bbr.sampler.endOfAppLimitedPhase)
			} else {
				require.Equal(t, protocol.PacketNumber(11), bbr.sampler.endOfAppLimitedPhase)
			}
		})
	}
}

func TestBBROptionOneMSSConservation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var clock mockClock
		bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, nil, BBROptions{OneMSSConservation: enabled})
		bbr.lastSendPacket = 10
		bbr.UpdateRecoveryState(1, true, false)
		bbr.recoveryWindow = 10 * 1200
		bbr.bytesInFlight = 20 * 1200

		bbr.CalculateRecoveryWindow(0, 1200)
		if enabled {
			require.Equal(t, protocol.ByteCount(21*1200), bbr.recoveryWindow)
		} else {
			require.Equal(t, protocol.ByteCount(20*1200), bbr.recoveryWindow)
		}
	}
}

func TestBBRGetTargetCongestionWindow(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

func TestBBRConnectionStats(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	const size = protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, connStats, size, true, nil, BBROptions{})
	require.Equal(t, uint64(bbr.GetCongestionWindow()), connStats.CongestionWindow.Load())

	var bytesInFlight protocol.ByteCount
	for pn := protocol.PacketNumber(0); pn < 10; pn++ {
		bytesInFlight += size
		bbr.OnPacketSent(clock.Now(), bytesInFlight, pn, size, true)
	}
	clock.Advance(50 * time.Millisecond)
	rttStats.UpdateRTT(50*time.Millisecond, 0)
	for pn := protocol.PacketNumber(0); pn < 5; pn++ {
		bbr.OnPacketAcked(pn, size, bytesInFlight, clock.Now())
		bytesInFlight -= size
	}
	require.Equal(t, uint64(bbr.GetCongestionWindow()), connStats.CongestionWindow.Load())

	// A loss detected by an ACK puts BBR into recovery, which limits the
	// effective congestion window.
	bbr.BeginAckEvent()
	bbr.OnCongestionEvent(5, size, bytesInFlight)
	bbr.OnPacketAcked(6, size, bytesInFlight, clock.Now())
	bbr.EndAckEvent(bytesInFlight, clock.Now())
	bytesInFlight -= 2 * size
	require.True(t, bbr.InRecovery())
	require.Equal(t, uint64(1), connStats.PacketsLost.Load())
	require.Equal(t, uint64(size), connStats.BytesLost.Load())
	require.Equal(t, uint64(bbr.GetCongestionWindow()), connStats.CongestionWindow.Load())
	require.Less(t, connStats.CongestionWindow.Load(), uint64(bbr.congestionWindow))

	// ECN-CE marks are counted as congestion events without lost bytes, like in the Cubic sender.
	bbr.OnCongestionEvent(6, 0, bytesInFlight)
	require.Equal(t, uint64(2), connStats.PacketsLost.Load())
	require.Equal(t, uint64(size), connStats.BytesLost.Load())

	bbr.SetMaxDatagramSize(1400)
	require.Equal(t, uint64(bbr.GetCongestionWindow()), connStats.CongestionWindow.Load())
}

// newTestBBRSender returns a sender with a 1 MB/s bandwidth estimate and a 10ms
// min RTT, i.e. a BDP of 10000 bytes.
func newTestBBRSender(opts BBROptions) *bbrSender {
	clock := mockClock(monotime.Time(time.Second))
	bbr := NewBBRSender(&clock, utils.NewRTTStats(), &utils.ConnectionStats{}, 1200, true, nil, opts)
	bbr.maxBandwidth.Update(int64(8*1000*1000), 1)
	bbr.minRtt = 10 * time.Millisecond
	return bbr
}

func TestBBROptionFlexibleAppLimited(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{FlexibleAppLimited: enabled})
		// above 1.5*BDP, but below the congestion window
		bbr.bytesInFlight = 20000
		require.True(t, bbr.IsPipeSufficientlyFull())

		bbr.OnApplicationLimited()
		require.Equal(t, !enabled, bbr.sampler.isAppLimited)
		require.Equal(t, !enabled, bbr.appLimitedSinceLastProbeRtt)
	}
}

func TestBBROptionNumStartupRtts(t *testing.T) {
	require.Equal(t, RoundTripsWithoutGrowthBeforeExitingStartup, newTestBBRSender(BBROptions{}).numStartupRtts)

	for _, n := range []int64{1, 2} {
		bbr := newTestBBRSender(BBROptions{NumStartupRtts: n})
		bbr.bandwidthAtLastRound = bbr.BandwidthEstimate()
		for i := int64(1); i < n; i++ {
			bbr.CheckIfFullBandwidthReached()
			require.False(t, bbr.isAtFullBandwidth)
		}
		bbr.CheckIfFullBandwidthReached()
		require.True(t, bbr.isAtFullBandwidth)
	}
}

func TestBBROptionExitStartupOnLoss(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{ExitStartupOnLoss: enabled})
		bbr.lastSendPacket = 10
		bbr.UpdateRecoveryState(1, true, false)
		bbr.bandwidthAtLastRound = bbr.BandwidthEstimate()

		bbr.CheckIfFullBandwidthReached()
		require.Equal(t, enabled, bbr.isAtFullBandwidth)
	}
}

func TestBBROptionRateBasedStartup(t *testing.T) {
	for _, opts := range []BBROptions{{}, {RateBasedStartup: true}, {StartupRateReductionMultiplier: 1}} {
		enabled := opts != BBROptions{}
		bbr := newTestBBRSender(opts)
		require.Equal(t, enabled, bbr.rateBasedStartup)
		bbr.lastSendPacket = 10
		bbr.UpdateRecoveryState(1, true, false)
		bbr.CalculateRecoveryWindow(0, 0)
		require.True(t, bbr.InSlowStart())
		require.True(t, bbr.InRecovery())

		if enabled {
			require.Equal(t, bbr.congestionWindow, bbr.GetCongestionWindow())
		} else {
			require.Equal(t, bbr.minCongestionWindow, bbr.GetCongestionWindow())
		}
	}
}

func TestBBROptionStartupRateReduction(t *testing.T) {
	for _, multiplier := range []int64{0, 1, 2} {
		bbr := newTestBBRSender(BBROptions{StartupRateReductionMultiplier: multiplier})
		bbr.lastSendPacket = 10
		bbr.hasNonAppLimitedSample = true
		bbr.pacingRate = 1
		bbr.OnCongestionEvent(1, 3840, 0) // 10% of the initial congestion window
		// Like in quiche, only a loss detected by an ACK counts as detected loss.
		bbr.UpdateRecoveryState(2, true, false)
		bbr.CalculatePacingRate()

		bw := float64(bbr.BandwidthEstimate())
		switch multiplier {
		case 0:
			require.Equal(t, uint64(0), uint64(bbr.startupBytesLost))
			require.InDelta(t, DefaultHighGain*bw, float64(bbr.pacingRate), 1)
		default:
			require.Equal(t, protocol.ByteCount(3840), bbr.startupBytesLost)
			require.InDelta(t, (1-0.1*float64(multiplier))*DefaultHighGain*bw, float64(bbr.pacingRate), 1)
		}
	}
}

func TestBBROptionSlowerStartup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{SlowerStartup: enabled})
		bbr.lastSendPacket = 10
		bbr.UpdateRecoveryState(1, true, false)
		bbr.hasNonAppLimitedSample = true
		bbr.pacingRate = 1
		bbr.CalculatePacingRate()

		gain := DefaultHighGain
		if enabled {
			gain = StartupAfterLossGain
		}
		require.InDelta(t, gain*float64(bbr.BandwidthEstimate()), float64(bbr.pacingRate), 1)
	}
}

func TestBBROptionDrainToTarget(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{DrainToTarget: enabled})
		bbr.mode = PROBE_BW
		bbr.cycleCurrentOffset = 1
		bbr.pacingGain = PacingGain[1]
		bbr.bytesInFlight = 2 * bbr.GetTargetCongestionWindow(1)

		bbr.UpdateGainCyclePhase(monotime.Time(time.Second).Add(time.Second), 0, false)
		require.Equal(t, 2, bbr.cycleCurrentOffset)
		if enabled {
			require.Equal(t, PacingGain[1], bbr.pacingGain)
		} else {
			require.Equal(t, PacingGain[2], bbr.pacingGain)
		}
	}
}

func TestBBROptionProbeRttBasedOnBdp(t *testing.T) {
	bbr := newTestBBRSender(BBROptions{})
	require.Equal(t, bbr.minCongestionWindow, bbr.ProbeRttCongestionWindow())

	bbr = newTestBBRSender(BBROptions{ProbeRttBasedOnBdp: true})
	require.Equal(t, protocol.ByteCount(7500), bbr.ProbeRttCongestionWindow())
}

func TestBBROptionProbeRttSkipping(t *testing.T) {
	for _, tc := range []struct {
		name      string
		opts      BBROptions
		sampleRtt time.Duration
		extended  bool
	}{
		{name: "default", sampleRtt: 11 * time.Millisecond},
		{name: "disabled if app-limited", opts: BBROptions{ProbeRttDisabledIfAppLimited: true}, sampleRtt: 20 * time.Millisecond, extended: true},
		{name: "skipped if similar RTT", opts: BBROptions{ProbeRttSkippedIfSimilarRtt: true}, sampleRtt: 11 * time.Millisecond, extended: true},
		{name: "not skipped if RTT increased", opts: BBROptions{ProbeRttSkippedIfSimilarRtt: true}, sampleRtt: 20 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRSender(tc.opts)
			start := monotime.Time(time.Second)
			bbr.minRttTimestamp = start
			bbr.OnApplicationLimited()

			now := start.Add(MinRttExpiry + time.Millisecond)
			require.Equal(t, !tc.extended, bbr.updateMinRtt(now, tc.sampleRtt))
			require.Equal(t, now, bbr.minRttTimestamp)
			if tc.extended {
				require.Equal(t, 10*time.Millisecond, bbr.minRtt)
			} else {
				require.Equal(t, tc.sampleRtt, bbr.minRtt)
			}
		})
	}
}

func TestBBROptionEnableAckAggregationDuringStartup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{EnableAckAggregationDuringStartup: enabled})
		bbr.sampler.totalBytesAcked = bbr.initialCongestionWindow
		cwnd := bbr.congestionWindow
		require.Less(t, bbr.GetTargetCongestionWindow(bbr.congestionWindowGain), cwnd)

		bbr.CalculateCongestionWindow(1200, cwnd)
		if enabled {
			require.Equal(t, cwnd+1200, bbr.congestionWindow)
		} else {
			require.Equal(t, cwnd, bbr.congestionWindow)
		}
	}
}

func TestBBROptionExpireAckAggregationInStartup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		bbr := newTestBBRSender(BBROptions{ExpireAckAggregationInStartup: enabled})
		bbr.maxAckHeight.Update(5000, 1)

		bbr.CheckIfFullBandwidthReached()
		require.Equal(t, bbr.BandwidthEstimate(), bbr.bandwidthAtLastRound)
		if enabled {
			require.Zero(t, bbr.maxAckHeight.GetBest())
		} else {
			require.Equal(t, int64(5000), bbr.maxAckHeight.GetBest())
		}
	}
}

// TestBBRStartupPacingInitialization verifies that BBR uses the startup gain as
// a pacing fallback without storing it before the first bandwidth sample.
func TestBBRStartupPacingInitialization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

	// Verify we're in startup mode
	require.True(t, bbr.InSlowStart())
	require.Equal(t, bbrMode(STARTUP), bbr.mode)
	require.Equal(t, DefaultHighGain, bbr.pacingGain)

	// Initial pacing rate should be 0 before any packets sent
	require.Equal(t, Bandwidth(0), bbr.pacingRate)

	// Send first packet. The stored pacing rate is initialized from the first
	// bandwidth sample, not when the packet is sent.
	now := clock.Now()
	bbr.OnPacketSent(now, initialMaxDatagramSize, 1, initialMaxDatagramSize, true)

	require.Equal(t, Bandwidth(0), bbr.pacingRate)
	require.Equal(t, Bandwidth(0), bbr.BandwidthEstimate())
	initialRate := BandwidthFromDelta(bbr.initialCongestionWindow, bbr.GetMinRtt())
	require.Equal(t, Bandwidth(DefaultHighGain*float64(initialRate)), bbr.PacingRate())

	// The pacer uses the same high-gain fallback.
	require.True(t, bbr.HasPacingBudget(now))
}

func TestBBRUsesInitialRTTBeforeSample(t *testing.T) {
	var clock mockClock
	const initialRTT = 20 * time.Millisecond
	rttStats := utils.NewRTTStats()
	rttStats.SetInitialRTT(initialRTT)

	bbr := NewBBRSender(
		&clock,
		rttStats,
		&utils.ConnectionStats{},
		protocol.ByteCount(1200),
		true,
		nil,
		BBROptions{},
	)

	require.Equal(t, initialRTT, bbr.GetMinRtt())
	initialRate := BandwidthFromDelta(bbr.initialCongestionWindow, initialRTT)
	require.Equal(
		t,
		Bandwidth(DefaultHighGain*float64(initialRate)),
		bbr.PacingRate(),
	)
}

// TestBBRStartupPacingWithRTTSample verifies that pacing rate is updated
// when first RTT sample arrives and becomes more accurate.
func TestBBRStartupPacingWithRTTSample(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	require.Equal(
		t,
		BandwidthFromDelta(bbr.initialCongestionWindow, rttSample),
		bbr.pacingRate,
	)
}

// TestBBRStartupPipeUtilization verifies that BBR fills the pipe during startup.
func TestBBRStartupPipeUtilization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize, true, nil, BBROptions{})

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

func BenchmarkBBRSendAndAck(b *testing.B) {
	for _, inFlight := range []int{10, 100, 1000} {
		b.Run("in flight: "+strconv.Itoa(inFlight), func(b *testing.B) {
			b.ReportAllocs()
			rttStats := utils.NewRTTStats()
			bbr := NewBBRSender(DefaultClock{}, rttStats, &utils.ConnectionStats{}, 1200, false, nil, BBROptions{})
			now := monotime.Now()
			var sent, acked protocol.PacketNumber
			var bytesInFlight protocol.ByteCount
			for b.Loop() {
				now = now.Add(10 * time.Microsecond)
				bytesInFlight += 1200
				bbr.OnPacketSent(now, bytesInFlight, sent, 1200, true)
				sent++
				if int(sent-acked) > inFlight {
					prior := bytesInFlight
					bytesInFlight -= 1200
					bbr.OnPacketAcked(acked, 1200, prior, now)
					acked++
				}
			}
		})
	}
}

// Keep the concrete sender opaque so this benchmark retains interface dispatch.
//
//go:noinline
func benchmarkAppLimitedNotifier(b *bbrSender) interface{ OnApplicationLimited() } {
	return b
}

func BenchmarkBBROnApplicationLimited(b *testing.B) {
	for _, tc := range []struct {
		name     string
		mode     bbrMode
		recovery bool
		inFlight int64
		opts     BBROptions
	}{
		{name: "startup", mode: STARTUP, inFlight: 1200},
		{name: "probe_bw", mode: PROBE_BW, inFlight: 1200},
		{name: "congestion_limited", mode: PROBE_BW, inFlight: 38400},
		{name: "recovery", mode: PROBE_BW, recovery: true, inFlight: 2400},
		{name: "recovery_limited", mode: PROBE_BW, recovery: true, inFlight: 12000},
		{name: "rate_based_startup", mode: STARTUP, recovery: true, inFlight: 12000, opts: BBROptions{RateBasedStartup: true}},
		{name: "probe_rtt", mode: PROBE_RTT, inFlight: 1200},
		{name: "probe_rtt_limited", mode: PROBE_RTT, inFlight: 4800},
		{name: "flexible", mode: STARTUP, inFlight: 12000, opts: BBROptions{FlexibleAppLimited: true}},
		{name: "flexible_full", mode: STARTUP, inFlight: 15000, opts: BBROptions{FlexibleAppLimited: true}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			sender := newTestBBRSender(tc.opts)
			sender.mode = tc.mode
			sender.bytesInFlight = protocol.ByteCount(tc.inFlight)
			if tc.recovery {
				sender.recoveryState = CONSERVATION
				sender.recoveryWindow = 12000
			}
			notifier := benchmarkAppLimitedNotifier(sender)
			b.ReportAllocs()
			for b.Loop() {
				notifier.OnApplicationLimited()
			}
		})
	}
}
