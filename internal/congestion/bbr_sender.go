package congestion

// src from https://quiche.googlesource.com/quiche.git/+/66dea072431f94095dfc3dd2743cb94ef365f7ef/quic/core/congestion_control/bbr_sender.cc

import (
	"math"
	"math/rand"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

var (
	// Default initial rtt used before any samples are received.
	InitialRtt = 100 * time.Millisecond

	// The gain used for the STARTUP, equal to 2/ln(2).
	DefaultHighGain = 2.885

	// The gain used in STARTUP after loss has been detected.
	// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
	// in measured bandwidth.
	StartupAfterLossGain = 1.5

	// The cycle of gains used during the PROBE_BW stage.
	PacingGain = []float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

	// The length of the gain cycle.
	GainCycleLength = len(PacingGain)

	// The size of the bandwidth filter window, in round-trips.
	BandwidthWindowSize = GainCycleLength + 2

	// The time after which the current min_rtt value expires.
	MinRttExpiry = 10 * time.Second

	// The minimum time the connection can spend in PROBE_RTT mode.
	ProbeRttTime = time.Millisecond * 200

	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	StartupGrowthTarget                         = 1.25
	RoundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Coefficient of target congestion window to use when basing PROBE_RTT on BDP.
	ModerateProbeRttMultiplier = 0.75

	// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
	// we don't need to enter PROBE_RTT.
	SimilarMinRttThreshold = 1.125

	// Congestion window gain for QUIC BBR during PROBE_BW phase.
	DefaultCongestionWindowGainConst = 2.0
)

func bbrMinimumCongestionWindow(maxDatagramSize protocol.ByteCount) protocol.ByteCount {
	return 4 * maxDatagramSize
}

func bbrMaxCongestionWindow(maxDatagramSize protocol.ByteCount) protocol.ByteCount {
	return protocol.ByteCount(protocol.MaxOutstandingSentPackets) * maxDatagramSize
}

type bbrMode int

const (
	// Startup phase of the connection.
	STARTUP = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	DRAIN
	// Cruising mode.
	PROBE_BW
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	PROBE_RTT
)

type bbrRecoveryState int

const (
	// Do not limit.
	NOT_IN_RECOVERY = iota

	// Allow an extra outstanding byte for each byte acknowledged.
	CONSERVATION

	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	GROWTH
)

const (
	bbrLossToleranceNumerator     = 2
	bbrFullBandwidthLossTolerance = 3
	bbrLossToleranceDenominator   = 100
	bbrLossToleranceMinPackets    = 16
)

type bbrSender struct {
	mode      bbrMode
	clock     Clock
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	// Pacer for pacing packets
	pacer *pacer
	// Maximum datagram size
	maxDatagramSize protocol.ByteCount
	// Track bytes in flight (passed as parameter in interface methods)
	bytesInFlight protocol.ByteCount
	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *BandwidthSampler
	// The number of the round trips that have occurred during the connection.
	roundTripCount int64
	// The packet number of the most recently sent packet.
	lastSendPacket protocol.PacketNumber
	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber
	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *WindowedFilter
	// Tracks the maximum number of bytes acked faster than the sending rate.
	maxAckHeight *WindowedFilter
	// The time this aggregation started and the number of bytes acked during it.
	aggregationEpochStartTime monotime.Time
	aggregationEpochBytes     protocol.ByteCount
	// Minimum RTT estimate.  Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp monotime.Time
	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount
	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount
	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount
	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount
	// The pacing gain applied during the STARTUP phase.
	highGain float64
	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64
	// The pacing gain applied during the DRAIN phase.
	drainGain float64
	// The current pacing rate of the connection.
	pacingRate Bandwidth
	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64
	// The gain used for the congestion window during PROBE_BW.  Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConst float64
	// The number of RTTs to stay in STARTUP mode.  Defaults to 3.
	numStartupRtts int64
	// If true, exit startup if 1RTT has passed with no bandwidth increase and
	// the connection is in recovery.
	exitStartupOnLoss bool
	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart monotime.Time
	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth
	// Set to true upon exiting quiescence.
	exitingQuiescence bool
	// Time at which PROBE_RTT has to be exited.  Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt monotime.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool
	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool
	// Indicates whether any non app-limited samples have been recorded.
	hasNoAppLimitedSample bool
	// Indicates app-limited calls should be ignored as long as there's
	// enough data inflight to see more bandwidth when necessary.
	flexibleAppLimited bool
	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode.  A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount
	// If true, consider all samples in recovery app-limited.
	isAppLimitedRecovery bool
	// Loss tolerance state for distinguishing isolated random loss from congestion.
	lossToleranceRoundEnd    protocol.PacketNumber
	lossToleranceLostBytes   protocol.ByteCount
	lossToleranceInFlightMax protocol.ByteCount
	// When true, pace at 1.5x and disable packet conservation in STARTUP.
	slowerStartup bool
	// When true, disables packet conservation in STARTUP.
	rateBasedStartup bool
	// When non-zero, decreases the rate in STARTUP by the total number of bytes
	// lost in STARTUP divided by CWND.
	startupRateReductionMultiplier int64
	// Sum of bytes lost in STARTUP.
	startupBytesLost protocol.ByteCount
	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool
	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool
	// If true, use a CWND of 0.75*BDP during probe_rtt instead of 4 packets.
	probeRttBasedOnBdp bool
	// If true, skip probe_rtt and update the timestamp of the existing min_rtt to
	// now if min_rtt over the last cycle is within 12.5% of the current min_rtt.
	// Even if the min_rtt is 12.5% too low, the 25% gain cycling and 2x CWND gain
	// should overcome an overly small min_rtt.
	probeRttSkippedIfSimilarRtt bool
	// If true, disable PROBE_RTT entirely as long as the connection was recently
	// app limited.
	probeRttDisabledIfAppLimited bool
	appLimitedSinceLastProbeRtt  bool
	minRttSinceLastProbeRtt      time.Duration
	// Latched value of --quic_always_get_bw_sample_when_acked.
	alwaysGetBwSampleWhenAcked bool

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

func NewBBRSender(clock Clock, rttStats *utils.RTTStats, connStats *utils.ConnectionStats, initialMaxDatagramSize protocol.ByteCount, _ bool, qlogger qlogwriter.Recorder) *bbrSender {
	initialCongestionWindow := 32 * initialMaxDatagramSize
	maxCongestionWindow := bbrMaxCongestionWindow(initialMaxDatagramSize)

	b := &bbrSender{
		rttStats:                     rttStats,
		connStats:                    connStats,
		mode:                         STARTUP,
		clock:                        clock,
		sampler:                      NewBandwidthSampler(),
		maxBandwidth:                 NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		maxAckHeight:                 NewWindowedFilter(int64(BandwidthWindowSize), MaxFilter),
		congestionWindow:             initialCongestionWindow,
		initialCongestionWindow:      initialCongestionWindow,
		maxCongestionWindow:          maxCongestionWindow,
		minCongestionWindow:          bbrMinimumCongestionWindow(initialMaxDatagramSize),
		highGain:                     DefaultHighGain,
		highCwndGain:                 DefaultHighGain,
		drainGain:                    1.0 / DefaultHighGain,
		pacingGain:                   DefaultHighGain,
		congestionWindowGain:         DefaultHighGain,
		congestionWindowGainConst:    DefaultCongestionWindowGainConst,
		numStartupRtts:               RoundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:                NOT_IN_RECOVERY,
		recoveryWindow:               maxCongestionWindow,
		lossToleranceRoundEnd:        protocol.InvalidPacketNumber,
		minRttSinceLastProbeRtt:      InfiniteRTT,
		maxDatagramSize:              initialMaxDatagramSize,
		probeRttBasedOnBdp:           true,
		probeRttSkippedIfSimilarRtt:  true,
		probeRttDisabledIfAppLimited: true,
		qlogger:                      qlogger,
	}
	if b.qlogger != nil {
		b.lastState = qlog.CongestionStateSlowStart
		b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: b.lastState})
	}

	// Initialize pacer with pacing rate function (not raw bandwidth estimate)
	// The pacing rate includes the pacing gain and handles startup properly
	b.pacer = newExactPacer(func() Bandwidth {
		if b.pacingRate > 0 {
			return b.pacingRate
		}
		// Fallback to bandwidth estimate if pacing rate not set yet
		return b.BandwidthEstimate()
	})
	b.pacer.SetMaxDatagramSize(initialMaxDatagramSize)

	return b
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	b.bytesInFlight = bytesInFlight
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.bytesInFlight = bytesInFlight
	if !isRetransmittable {
		b.pacer.SentPacket(sentTime, bytes)
		return
	}
	b.lastSendPacket = packetNumber

	priorBytesInFlight := protocol.ByteCount(0)
	if bytesInFlight > bytes {
		priorBytesInFlight = bytesInFlight - bytes
	}
	if priorBytesInFlight == 0 && b.sampler.isAppLimited {
		b.exitingQuiescence = true
	}

	// Reset the ack aggregation epoch when resuming from quiescence. The epoch
	// would otherwise span the entire idle period, and the first ACK received
	// afterwards would be measured against a hugely inflated (or overflowed)
	// expected number of acked bytes.
	if b.aggregationEpochStartTime.IsZero() || priorBytesInFlight == 0 {
		b.aggregationEpochStartTime = sentTime
		b.aggregationEpochBytes = 0
	}

	// Initialize pacing rate on first packet if not already set
	if b.pacingRate == 0 {
		b.CalculatePacingRate()
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, priorBytesInFlight, true)
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	b.bytesInFlight = bytesInFlight
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	if b.mode == PROBE_RTT {
		return b.ProbeRttCongestionWindow()
	}

	if b.InRecovery() && !(b.rateBasedStartup && b.mode == STARTUP) {
		return min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

func (b *bbrSender) MaybeExitSlowStart() {
	// BBR does not use traditional slow start exit
}

func (b *bbrSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	totalBytesAckedBefore := b.sampler.totalBytesAcked

	// Get bandwidth sample
	bandwidthSample := b.sampler.OnPacketAcked(eventTime, number)
	bytesAcked := b.sampler.totalBytesAcked - totalBytesAckedBefore
	b.onBytesRemovedFromFlight(bytesAcked)
	if !bandwidthSample.stateAtSend.isValid {
		// Packet was never sent or already processed
		return
	}

	// Debug logging for startup performance issues
	if b.mode == STARTUP && b.roundTripCount < 20 {
		_ = bandwidthSample // Placeholder for potential debug logging
		// In production, you could log: RTT=%d, BW=%d Mbps, CWND=%d, Round=%d, Mode=%d
		// eventTime, bandwidthSample.bandwidth/125000, b.congestionWindow, b.roundTripCount, b.mode
	}

	b.lastSampleIsAppLimited = bandwidthSample.stateAtSend.isAppLimited
	if !bandwidthSample.stateAtSend.isAppLimited {
		b.hasNoAppLimitedSample = true
	}

	// Advance round trip counter first, so that maxBandwidth and maxAckHeight
	// are stamped with the correct (already-incremented) roundTripCount.
	// Quiche processes UpdateRoundTripCounter before UpdateBandwidthAndMinRtt.
	isRoundStart := b.UpdateRoundTripCounter(number)

	// Update min RTT
	minRttExpired := false
	if bandwidthSample.rtt > 0 {
		minRttExpired = b.updateMinRtt(eventTime, bandwidthSample.rtt)
	}

	// Update bandwidth estimate
	if !bandwidthSample.stateAtSend.isAppLimited || bandwidthSample.bandwidth > b.BandwidthEstimate() {
		b.maxBandwidth.Update(int64(bandwidthSample.bandwidth), b.roundTripCount)
	}

	// Update state machine
	b.UpdateRecoveryState(number, false, isRoundStart)

	excessAcked := b.UpdateAckAggregationBytes(eventTime, bytesAcked)

	// Phase-specific updates
	if b.mode == PROBE_BW {
		b.UpdateGainCyclePhase(eventTime, priorInFlight, false)
	}

	if isRoundStart && !b.isAtFullBandwidth {
		b.CheckIfFullBandwidthReached()
	}

	b.MaybeExitStartupOrDrain(eventTime)
	b.MaybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Recalculate windows
	b.CalculatePacingRate()
	b.CalculateCongestionWindow(bytesAcked, excessAcked)
	b.CalculateRecoveryWindow(bytesAcked, 0)
}

func (b *bbrSender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	shouldEnterRecovery := lostBytes == 0
	if lostBytes > 0 {
		b.connStats.PacketsLost.Add(1)
		b.connStats.BytesLost.Add(uint64(lostBytes))
		b.sampler.OnPacketLost(number)
		b.onBytesRemovedFromFlight(lostBytes)
		shouldEnterRecovery = b.shouldEnterRecoveryForLoss(number, lostBytes, priorInFlight)
	}
	if b.mode == STARTUP && b.startupRateReductionMultiplier != 0 {
		b.startupBytesLost += lostBytes
	}

	if !shouldEnterRecovery {
		return
	}
	b.UpdateRecoveryState(number, true, false)

	// Recalculate recovery window
	b.CalculateRecoveryWindow(0, lostBytes)
}

func (b *bbrSender) shouldEnterRecoveryForLoss(number protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) bool {
	if b.InRecovery() {
		return true
	}
	if priorInFlight <= 0 || priorInFlight < bbrLossToleranceMinPackets*b.maxDatagramSize {
		return true
	}
	if b.lossToleranceRoundEnd == protocol.InvalidPacketNumber || number > b.lossToleranceRoundEnd {
		b.lossToleranceRoundEnd = b.lastSendPacket
		b.lossToleranceLostBytes = 0
		b.lossToleranceInFlightMax = 0
	}
	b.lossToleranceLostBytes += lostBytes
	b.lossToleranceInFlightMax = max(b.lossToleranceInFlightMax, priorInFlight)
	tolerance := bbrLossToleranceNumerator
	if b.isAtFullBandwidth {
		tolerance = bbrFullBandwidthLossTolerance
	}
	return b.lossToleranceLostBytes*bbrLossToleranceDenominator > b.lossToleranceInFlightMax*protocol.ByteCount(tolerance)
}

func (b *bbrSender) OnPacketDiscarded(number protocol.PacketNumber) {
	b.onBytesRemovedFromFlight(b.sampler.OnPacketDiscarded(number))
}

func (b *bbrSender) OnApplicationLimited() {
	if b.bytesInFlight >= b.GetCongestionWindow() {
		return
	}
	b.appLimitedSinceLastProbeRtt = true
	b.sampler.OnAppLimited()
}

func (b *bbrSender) onBytesRemovedFromFlight(bytes protocol.ByteCount) {
	if bytes >= b.bytesInFlight {
		b.bytesInFlight = 0
		return
	}
	b.bytesInFlight -= bytes
}

func (b *bbrSender) SetMaxDatagramSize(size protocol.ByteCount) {
	cwndIsInitial := b.congestionWindow == b.initialCongestionWindow
	cwndIsMin := b.congestionWindow == b.minCongestionWindow
	recoveryWindowIsMax := b.recoveryWindow == b.maxCongestionWindow
	recoveryWindowIsMin := b.recoveryWindow == b.minCongestionWindow

	b.maxDatagramSize = size
	b.initialCongestionWindow = 32 * size
	b.maxCongestionWindow = bbrMaxCongestionWindow(size)
	b.minCongestionWindow = bbrMinimumCongestionWindow(size)

	if cwndIsInitial {
		b.congestionWindow = b.initialCongestionWindow
	} else if cwndIsMin {
		b.congestionWindow = b.minCongestionWindow
	} else {
		b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
	}

	if recoveryWindowIsMax {
		b.recoveryWindow = b.maxCongestionWindow
	} else if recoveryWindowIsMin {
		b.recoveryWindow = b.minCongestionWindow
	} else {
		b.recoveryWindow = min(b.recoveryWindow, b.maxCongestionWindow)
	}

	b.pacer.SetMaxDatagramSize(size)
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// BBR does not react to retransmission timeouts
}

// Debug interface methods
func (b *bbrSender) InSlowStart() bool {
	return b.mode == STARTUP
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != NOT_IN_RECOVERY
}

func (b *bbrSender) BandwidthEstimate() Bandwidth {
	return Bandwidth(b.maxBandwidth.GetBest())
}

// PacingRate returns the current pacing rate.
func (b *bbrSender) PacingRate() Bandwidth {
	return b.pacingRate
}

func (b *bbrSender) currentQlogState() qlog.CongestionState {
	if b.InRecovery() {
		return qlog.CongestionStateRecovery
	}
	if b.mode == STARTUP {
		return qlog.CongestionStateSlowStart
	}
	return qlog.CongestionStateCongestionAvoidance
}

func (b *bbrSender) maybeQlogStateChange(state qlog.CongestionState) {
	if b.qlogger == nil || state == b.lastState {
		return
	}
	b.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})
	b.lastState = state
}

func (b *bbrSender) ShouldSendProbingPacket() bool {
	if b.pacingGain <= 1 {
		return false
	}
	if b.flexibleAppLimited {
		return !b.IsPipeSufficientlyFull()
	}
	return true
}

func (b *bbrSender) IsPipeSufficientlyFull() bool {
	if b.mode == STARTUP {
		return b.bytesInFlight >= b.GetTargetCongestionWindow(1.5)
	}
	if b.pacingGain > 1 {
		return b.bytesInFlight >= b.GetTargetCongestionWindow(b.pacingGain)
	}
	return b.bytesInFlight >= b.GetTargetCongestionWindow(1.1)
}

func (b *bbrSender) UpdateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == 0 || lastAckedPacket > b.currentRoundTripEnd {
		b.currentRoundTripEnd = b.lastSendPacket
		b.roundTripCount++
		return true
	}
	return false
}

func (b *bbrSender) updateMinRtt(now monotime.Time, sampleRtt time.Duration) bool {
	b.minRttSinceLastProbeRtt = minRtt(b.minRttSinceLastProbeRtt, sampleRtt)

	// Do not expire min_rtt if none was ever available.
	minRttExpired := b.minRtt > 0 && (now.Sub(b.minRttTimestamp) > MinRttExpiry)

	if minRttExpired || sampleRtt < b.minRtt || b.minRtt == 0 {
		if minRttExpired && b.ShouldExtendMinRttExpiry() {
			minRttExpired = false
		} else {
			b.minRtt = sampleRtt
		}
		b.minRttTimestamp = now
		// Reset since_last_probe_rtt fields.
		b.minRttSinceLastProbeRtt = InfiniteRTT
		b.appLimitedSinceLastProbeRtt = false
	}

	return minRttExpired
}

func (b *bbrSender) ShouldExtendMinRttExpiry() bool {
	if b.probeRttDisabledIfAppLimited && b.appLimitedSinceLastProbeRtt {
		return true
	}

	minRttIncreasedSinceLastProbe := b.minRttSinceLastProbeRtt > time.Duration(float64(b.minRtt)*SimilarMinRttThreshold)
	if b.probeRttSkippedIfSimilarRtt && b.appLimitedSinceLastProbeRtt && !minRttIncreasedSinceLastProbe {
		return true
	}

	return false
}

func (b *bbrSender) UpdateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	if hasLosses {
		b.endRecoveryAt = b.lastSendPacket
	}
	switch b.recoveryState {
	case NOT_IN_RECOVERY:
		if hasLosses {
			b.recoveryState = CONSERVATION
			b.recoveryWindow = 0
			b.currentRoundTripEnd = b.lastSendPacket
			if false && b.lastSampleIsAppLimited {
				b.isAppLimitedRecovery = true
			}
		}
	case CONSERVATION:
		if isRoundStart {
			b.recoveryState = GROWTH
		}
		fallthrough
	case GROWTH:
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = NOT_IN_RECOVERY
			b.isAppLimitedRecovery = false
		}
	}

	if b.recoveryState != NOT_IN_RECOVERY && b.isAppLimitedRecovery {
		b.sampler.OnAppLimited()
	}
	b.maybeQlogStateChange(b.currentQlogState())
}

func (b *bbrSender) UpdateAckAggregationBytes(ackTime monotime.Time, ackedBytes protocol.ByteCount) protocol.ByteCount {
	// Compute how many bytes are expected to be delivered, assuming max bandwidth is correct.
	timeDelta := ackTime.Sub(b.aggregationEpochStartTime)
	expectedAckedBytes := expectedBytesAcked(Bandwidth(b.maxBandwidth.GetBest()), timeDelta)

	// Reset the current aggregation epoch as soon as the ack arrival rate is less
	// than or equal to the max bandwidth.
	if b.aggregationEpochBytes <= expectedAckedBytes {
		b.aggregationEpochBytes = ackedBytes
		b.aggregationEpochStartTime = ackTime
		return 0
	}

	// Compute how many extra bytes were delivered vs max bandwidth.
	b.aggregationEpochBytes += ackedBytes
	b.maxAckHeight.Update(int64(b.aggregationEpochBytes-expectedAckedBytes), b.roundTripCount)
	return b.aggregationEpochBytes - expectedAckedBytes
}

// expectedBytesAcked computes how many bytes are expected to be delivered at the
// given bandwidth (in bits/s) during the given period. In contrast to a naive
// bandwidth * period multiplication, it doesn't overflow for the long periods
// that occur when the first ACK arrives after an extended idle phase.
func expectedBytesAcked(bw Bandwidth, period time.Duration) protocol.ByteCount {
	if period <= 0 {
		return 0
	}
	bytesPerSecond := int64(bw / BytesPerSecond)
	if bytesPerSecond == 0 {
		return 0
	}
	seconds := int64(period / time.Second)
	nanos := int64(period % time.Second)
	var frac int64
	if bytesPerSecond <= math.MaxInt64/int64(time.Second) {
		frac = bytesPerSecond * nanos / int64(time.Second)
	} else {
		frac = bytesPerSecond / int64(time.Second) * nanos
	}
	if seconds > 0 && bytesPerSecond > (math.MaxInt64-frac)/seconds {
		return protocol.MaxByteCount
	}
	return protocol.ByteCount(bytesPerSecond*seconds + frac)
}

func (b *bbrSender) UpdateGainCyclePhase(now monotime.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	bytesInFlight := b.bytesInFlight
	shouldAdvanceGainCycling := now.Sub(b.lastCycleStart) > b.GetMinRtt()

	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.GetTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	if b.pacingGain < 1.0 && bytesInFlight <= b.GetTargetCongestionWindow(1.0) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % GainCycleLength
		b.lastCycleStart = now
		if b.drainToTarget && b.pacingGain < 1.0 && PacingGain[b.cycleCurrentOffset] == 1.0 &&
			bytesInFlight > b.GetTargetCongestionWindow(1.0) {
			return
		}
		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) GetTargetCongestionWindow(gain float64) protocol.ByteCount {
	// BandwidthEstimate() is in bits/second; divide by BytesPerSecond (8) to get bytes/second.
	// BDP (bytes) = RTT (nanoseconds) × bandwidth (bytes/s) / nanoseconds_per_second
	bdp := protocol.ByteCount(b.GetMinRtt()) * protocol.ByteCount(b.BandwidthEstimate()/BytesPerSecond) / protocol.ByteCount(time.Second)
	congestionWindow := protocol.ByteCount(gain * float64(bdp))

	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) CheckIfFullBandwidthReached() {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * StartupGrowthTarget)
	if b.BandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.BandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			b.maxAckHeight.Reset(0, b.roundTripCount)
		}
		return
	}
	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts || (b.exitStartupOnLoss && b.InRecovery()) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) MaybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == STARTUP && b.isAtFullBandwidth {
		b.OnExitStartup(now)
		b.mode = DRAIN
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
		b.maybeQlogStateChange(b.currentQlogState())
	}
	if b.mode == DRAIN && b.bytesInFlight <= b.GetTargetCongestionWindow(1) {
		b.EnterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) EnterProbeBandwidthMode(now monotime.Time) {
	b.mode = PROBE_BW
	b.congestionWindowGain = b.congestionWindowGainConst

	b.cycleCurrentOffset = rand.Int() % (GainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = PacingGain[b.cycleCurrentOffset]
	b.maybeQlogStateChange(b.currentQlogState())
}

func (b *bbrSender) MaybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != PROBE_RTT {
		if b.InSlowStart() {
			b.OnExitStartup(now)
		}
		b.mode = PROBE_RTT
		b.pacingGain = 1.0
		b.exitProbeRttAt = monotime.Time(0)
		b.maybeQlogStateChange(b.currentQlogState())
	}

	if b.mode == PROBE_RTT {
		b.sampler.OnAppLimited()
		if b.exitProbeRttAt.IsZero() {
			if b.bytesInFlight < b.ProbeRttCongestionWindow()+b.maxDatagramSize {
				b.exitProbeRttAt = now.Add(ProbeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.After(b.exitProbeRttAt) && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.EnterStartupMode(now)
				} else {
					b.EnterProbeBandwidthMode(now)
				}
			}
		}
	}
	b.exitingQuiescence = false
}

func (b *bbrSender) ProbeRttCongestionWindow() protocol.ByteCount {
	if b.probeRttBasedOnBdp {
		return b.GetTargetCongestionWindow(ModerateProbeRttMultiplier)
	}
	return b.minCongestionWindow
}

func (b *bbrSender) EnterStartupMode(now monotime.Time) {
	b.mode = STARTUP
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
	b.maybeQlogStateChange(b.currentQlogState())
}

func (b *bbrSender) OnExitStartup(now monotime.Time) {
	// Could add statistics tracking here
}

func (b *bbrSender) CalculatePacingRate() {
	bwEstimate := b.BandwidthEstimate()

	// Initialize pacing rate early in the connection
	if b.pacingRate == 0 {
		rtt := b.rttStats.MinRTT()
		if rtt == 0 {
			// Use initial RTT estimate if no samples yet
			rtt = InitialRtt
		}
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, rtt)
		// Apply startup gain to initial pacing rate
		b.pacingRate = Bandwidth(b.pacingGain * float64(b.pacingRate))
		return
	}

	if bwEstimate == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(bwEstimate))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	hasEverDetectedLoss := b.endRecoveryAt > 0
	if b.slowerStartup && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth(StartupAfterLossGain * float64(b.BandwidthEstimate()))
		return
	}

	if b.startupRateReductionMultiplier != 0 && hasEverDetectedLoss && b.hasNoAppLimitedSample {
		b.pacingRate = Bandwidth((1.0 - (float64(b.startupBytesLost) * float64(b.startupRateReductionMultiplier) / float64(b.congestionWindow))) * float64(targetRate))
		b.pacingRate = max(b.pacingRate, Bandwidth(StartupGrowthTarget*float64(b.BandwidthEstimate())))
		return
	}

	b.pacingRate = max(b.pacingRate, targetRate)
}

func (b *bbrSender) CalculateCongestionWindow(ackedBytes, excessAcked protocol.ByteCount) {
	if b.mode == PROBE_RTT {
		return
	}

	targetWindow := b.GetTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		targetWindow += protocol.ByteCount(b.maxAckHeight.GetBest())
	} else if b.enableAckAggregationDuringStartup {
		targetWindow += excessAcked
	}

	addBytesAcked := !b.InRecovery() || (b.rateBasedStartup && b.mode == STARTUP)
	if b.isAtFullBandwidth {
		if addBytesAcked {
			b.congestionWindow = min(targetWindow, b.congestionWindow+ackedBytes)
		} else {
			b.congestionWindow = min(targetWindow, b.congestionWindow)
		}
	} else if addBytesAcked && (b.congestionWindow < targetWindow || b.sampler.totalBytesAcked < b.initialCongestionWindow) {
		b.congestionWindow += ackedBytes
	}

	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) CalculateRecoveryWindow(ackedBytes, lostBytes protocol.ByteCount) {
	if b.rateBasedStartup && b.mode == STARTUP {
		return
	}

	if b.recoveryState == NOT_IN_RECOVERY {
		return
	}

	if b.recoveryWindow == 0 {
		b.recoveryWindow = max(b.bytesInFlight+ackedBytes, b.minCongestionWindow)
		return
	}

	if b.recoveryWindow >= lostBytes {
		b.recoveryWindow -= lostBytes
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	if b.recoveryState == GROWTH {
		b.recoveryWindow += ackedBytes
	}

	b.recoveryWindow = max(b.recoveryWindow, b.bytesInFlight+ackedBytes)
	b.recoveryWindow = max(b.recoveryWindow, b.minCongestionWindow)
}

func (b *bbrSender) GetMinRtt() time.Duration {
	if b.minRtt > 0 {
		return b.minRtt
	}
	return InitialRtt
}

func minRtt(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

var (
	InfiniteRTT = time.Duration(math.MaxInt64)
)

var (
	InfiniteBandwidth = Bandwidth(math.MaxUint64)
)

// SendTimeState is a subset of ConnectionStateOnSentPacket which is returned
// to the caller when the packet is acked or lost.
type SendTimeState struct {
	// Whether other states in this object is valid.
	isValid bool
	// Whether the sender is app limited at the time the packet was sent.
	// App limited bandwidth sample might be artificially low because the sender
	// did not have enough data to send in order to saturate the link.
	isAppLimited bool
	// Total number of sent bytes at the time the packet was sent.
	// Includes the packet itself.
	totalBytesSent protocol.ByteCount
	// Total number of acked bytes at the time the packet was sent.
	totalBytesAcked protocol.ByteCount
	// Total number of lost bytes at the time the packet was sent.
	totalBytesLost protocol.ByteCount
}

// ConnectionStateOnSentPacket represents the information about a sent packet
// and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
type ConnectionStateOnSentPacket struct {
	packetNumber protocol.PacketNumber
	// Time at which the packet is sent.
	sendTime monotime.Time
	// Size of the packet.
	size protocol.ByteCount
	// The value of |totalBytesSentAtLastAckedPacket| at the time the
	// packet was sent.
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	// The value of |lastAckedPacketSentTime| at the time the packet was
	// sent.
	lastAckedPacketSentTime monotime.Time
	// The value of |lastAckedPacketAckTime| at the time the packet was
	// sent.
	lastAckedPacketAckTime monotime.Time
	// Send time states that are returned to the congestion controller when the
	// packet is acked or lost.
	sendTimeState SendTimeState
}

// BandwidthSample
type BandwidthSample struct {
	// The bandwidth at that particular sample. Zero if no valid bandwidth sample
	// is available.
	bandwidth Bandwidth
	// The RTT measurement at this particular sample.  Zero if no RTT sample is
	// available.  Does not correct for delayed ack time.
	rtt time.Duration
	// States captured when the packet was sent.
	stateAtSend SendTimeState
}

func NewBandwidthSample() *BandwidthSample {
	return &BandwidthSample{
		// FIXME: the default value of original code is zero.
		rtt: InfiniteRTT,
	}
}

// BandwidthSampler keeps track of sent and acknowledged packets and outputs a
// bandwidth sample for every packet acknowledged. The samples are taken for
// individual packets, and are not filtered; the consumer has to filter the
// bandwidth samples itself. In certain cases, the sampler will locally severely
// underestimate the bandwidth, hence a maximum filter with a size of at least
// one RTT is recommended.
//
// This class bases its samples on the slope of two curves: the number of bytes
// sent over time, and the number of bytes acknowledged as received over time.
// It produces a sample of both slopes for every packet that gets acknowledged,
// based on a slope between two points on each of the corresponding curves. Note
// that due to the packet loss, the number of bytes on each curve might get
// further and further away from each other, meaning that it is not feasible to
// compare byte values coming from different curves with each other.
//
// The obvious points for measuring slope sample are the ones corresponding to
// the packet that was just acknowledged. Let us denote them as S_1 (point at
// which the current packet was sent) and A_1 (point at which the current packet
// was acknowledged). However, taking a slope requires two points on each line,
// so estimating bandwidth requires picking a packet in the past with respect to
// which the slope is measured.
//
// For that purpose, BandwidthSampler always keeps track of the most recently
// acknowledged packet, and records it together with every outgoing packet.
// When a packet gets acknowledged (A_1), it has not only information about when
// it itself was sent (S_1), but also the information about the latest
// acknowledged packet right before it was sent (S_0 and A_0).
//
// Based on that data, send and ack rate are estimated as:
//
//	send_rate = (bytes(S_1) - bytes(S_0)) / (time(S_1) - time(S_0))
//	ack_rate = (bytes(A_1) - bytes(A_0)) / (time(A_1) - time(A_0))
//
// Here, the ack rate is intuitively the rate we want to treat as bandwidth.
// However, in certain cases (e.g. ack compression) the ack rate at a point may
// end up higher than the rate at which the data was originally sent, which is
// not indicative of the real bandwidth. Hence, we use the send rate as an upper
// bound, and the sample value is
//
//	rate_sample = min(send_rate, ack_rate)
//
// An important edge case handled by the sampler is tracking the app-limited
// samples. There are multiple meaning of "app-limited" used interchangeably,
// hence it is important to understand and to be able to distinguish between
// them.
//
// Meaning 1: connection state. The connection is said to be app-limited when
// there is no outstanding data to send. This means that certain bandwidth
// samples in the future would not be an accurate indication of the link
// capacity, and it is important to inform consumer about that. Whenever
// connection becomes app-limited, the sampler is notified via OnAppLimited()
// method.
//
// Meaning 2: a phase in the bandwidth sampler. As soon as the bandwidth
// sampler becomes notified about the connection being app-limited, it enters
// app-limited phase. In that phase, all *sent* packets are marked as
// app-limited. Note that the connection itself does not have to be
// app-limited during the app-limited phase, and in fact it will not be
// (otherwise how would it send packets?). The boolean flag below indicates
// whether the sampler is in that phase.
//
// Meaning 3: a flag on the sent packet and on the sample. If a sent packet is
// sent during the app-limited phase, the resulting sample related to the
// packet will be marked as app-limited.
//
// With the terminology issue out of the way, let us consider the question of
// what kind of situation it addresses.
//
// Consider a scenario where we first send packets 1 to 20 at a regular
// bandwidth, and then immediately run out of data. After a few seconds, we send
// packets 21 to 60, and only receive ack for 21 between sending packets 40 and
// 41. In this case, when we sample bandwidth for packets 21 to 40, the S_0/A_0
// we use to compute the slope is going to be packet 20, a few seconds apart
// from the current packet, hence the resulting estimate would be extremely low
// and not indicative of anything. Only at packet 41 the S_0/A_0 will become 21,
// meaning that the bandwidth sample would exclude the quiescence.
//
// Based on the analysis of that scenario, we implement the following rule: once
// OnAppLimited() is called, all sent packets will produce app-limited samples
// up until an ack for a packet that was sent after OnAppLimited() was called.
// Note that while the scenario above is not the only scenario when the
// connection is app-limited, the approach works in other cases too.
type BandwidthSampler struct {
	// The total number of congestion controlled bytes sent during the connection.
	totalBytesSent protocol.ByteCount
	// The total number of congestion controlled bytes which were acknowledged.
	totalBytesAcked protocol.ByteCount
	// The total number of congestion controlled bytes which were lost.
	totalBytesLost protocol.ByteCount
	// The value of |totalBytesSent| at the time the last acknowledged packet
	// was sent. Valid only when |lastAckedPacketSentTime| is valid.
	totalBytesSentAtLastAckedPacket protocol.ByteCount
	// The time at which the last acknowledged packet was sent. Set to
	// zero value if no valid timestamp is available.
	lastAckedPacketSentTime monotime.Time
	// The time at which the most recent packet was acknowledged.
	lastAckedPacketAckTime monotime.Time
	// The most recently sent packet.
	lastSendPacket protocol.PacketNumber
	// Indicates whether the bandwidth sampler is currently in an app-limited
	// phase.
	isAppLimited bool
	// The packet that will be acknowledged after this one will cause the sampler
	// to exit the app-limited phase.
	endOfAppLimitedPhase protocol.PacketNumber
	// Record of the connection state at the point where each packet in flight was
	// sent, indexed by the packet number.
	connectionStats *ConnectionStates
}

func NewBandwidthSampler() *BandwidthSampler {
	return &BandwidthSampler{
		connectionStats: &ConnectionStates{
			stats: make(map[protocol.PacketNumber]*ConnectionStateOnSentPacket),
		},
	}
}

// OnPacketSent Inputs the sent packet information into the sampler. Assumes that all
// packets are sent in order. The information about the packet will not be
// released from the sampler until it the packet is either acknowledged or
// declared lost.
func (s *BandwidthSampler) OnPacketSent(sentTime monotime.Time, lastSentPacket protocol.PacketNumber, sentBytes, bytesInFlight protocol.ByteCount, hasRetransmittableData bool) {
	s.lastSendPacket = lastSentPacket

	if !hasRetransmittableData {
		return
	}

	s.totalBytesSent += sentBytes

	// If there are no packets in flight, the time at which the new transmission
	// opens can be treated as the A_0 point for the purpose of bandwidth
	// sampling. This underestimates bandwidth to some extent, and produces some
	// artificially low samples for most packets in flight, but it provides with
	// samples at important points where we would not have them otherwise, most
	// importantly at the beginning of the connection.
	if bytesInFlight == 0 {
		s.lastAckedPacketAckTime = sentTime
		s.totalBytesSentAtLastAckedPacket = s.totalBytesSent

		// In this situation ack compression is not a concern, set send rate to
		// effectively infinite.
		s.lastAckedPacketSentTime = sentTime
	}

	s.connectionStats.Insert(lastSentPacket, sentTime, sentBytes, s)
}

// OnPacketAcked Notifies the sampler that the |lastAckedPacket| is acknowledged. Returns a
// bandwidth sample. If no bandwidth sample is available,
// QuicBandwidth::Zero() is returned.
func (s *BandwidthSampler) OnPacketAcked(ackTime monotime.Time, lastAckedPacket protocol.PacketNumber) *BandwidthSample {
	sentPacketState := s.connectionStats.Get(lastAckedPacket)
	if sentPacketState == nil {
		return NewBandwidthSample()
	}

	sample := s.onPacketAckedInner(ackTime, lastAckedPacket, sentPacketState)
	s.connectionStats.Remove(lastAckedPacket)

	return sample
}

// onPacketAckedInner Handles the actual bandwidth calculations, whereas the outer method handles
// retrieving and removing |sentPacket|.
func (s *BandwidthSampler) onPacketAckedInner(ackTime monotime.Time, lastAckedPacket protocol.PacketNumber, sentPacket *ConnectionStateOnSentPacket) *BandwidthSample {
	s.totalBytesAcked += sentPacket.size

	s.totalBytesSentAtLastAckedPacket = sentPacket.sendTimeState.totalBytesSent
	s.lastAckedPacketSentTime = sentPacket.sendTime
	s.lastAckedPacketAckTime = ackTime

	// Exit app-limited phase once a packet that was sent while the connection is
	// not app-limited is acknowledged.
	if s.isAppLimited && lastAckedPacket > s.endOfAppLimitedPhase {
		s.isAppLimited = false
	}

	// There might have been no packets acknowledged at the moment when the
	// current packet was sent. In that case, there is no bandwidth sample to
	// make.
	if sentPacket.lastAckedPacketSentTime.IsZero() {
		return NewBandwidthSample()
	}

	// Infinite rate indicates that the sampler is supposed to discard the
	// current send rate sample and use only the ack rate.
	sendRate := InfiniteBandwidth
	if sentPacket.sendTime.After(sentPacket.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(sentPacket.sendTimeState.totalBytesSent-sentPacket.totalBytesSentAtLastAckedPacket, sentPacket.sendTime.Sub(sentPacket.lastAckedPacketSentTime))
	}

	// During the slope calculation, ensure that ack time of the current packet is
	// always larger than the time of the previous packet, otherwise division by
	// zero or integer underflow can occur.
	if !ackTime.After(sentPacket.lastAckedPacketAckTime) {
		// TODO(wub): Compare this code count before and after fixing clock jitter
		// issue.
		// if sentPacket.lastAckedPacketAckTime.Equal(sentPacket.sendTime) {
		// This is the 1st packet after quiescense.
		// QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 1, 2);
		// } else {
		//   QUIC_CODE_COUNT_N(quic_prev_ack_time_larger_than_current_ack_time, 2, 2);
		// }

		return NewBandwidthSample()
	}

	ackRate := BandwidthFromDelta(s.totalBytesAcked-sentPacket.sendTimeState.totalBytesAcked,
		ackTime.Sub(sentPacket.lastAckedPacketAckTime))

	// Note: this sample does not account for delayed acknowledgement time.  This
	// means that the RTT measurements here can be artificially high, especially
	// on low bandwidth connections.
	sample := &BandwidthSample{
		bandwidth: minBandwidth(sendRate, ackRate),
		rtt:       ackTime.Sub(sentPacket.sendTime),
	}

	SentPacketToSendTimeState(sentPacket, &sample.stateAtSend)
	return sample
}

// OnPacketLost Informs the sampler that a packet is considered lost and it should no
// longer keep track of it.
func (s *BandwidthSampler) OnPacketLost(packetNumber protocol.PacketNumber) SendTimeState {
	ok, sentPacket := s.connectionStats.Remove(packetNumber)
	sendTimeState := SendTimeState{
		isValid: ok,
	}
	if sentPacket != nil {
		s.totalBytesLost += sentPacket.size
		SentPacketToSendTimeState(sentPacket, &sendTimeState)
	}

	return sendTimeState
}

func (s *BandwidthSampler) OnPacketDiscarded(packetNumber protocol.PacketNumber) protocol.ByteCount {
	_, sentPacket := s.connectionStats.Remove(packetNumber)
	if sentPacket != nil {
		return sentPacket.size
	}
	return 0
}

// OnAppLimited Informs the sampler that the connection is currently app-limited, causing
// the sampler to enter the app-limited phase.  The phase will expire by
// itself.
func (s *BandwidthSampler) OnAppLimited() {
	s.isAppLimited = true
	s.endOfAppLimitedPhase = s.lastSendPacket
}

// SentPacketToSendTimeState Copy a subset of the (private) ConnectionStateOnSentPacket to the (public)
// SendTimeState. Always set send_time_state->is_valid to true.
func SentPacketToSendTimeState(sentPacket *ConnectionStateOnSentPacket, sendTimeState *SendTimeState) {
	sendTimeState.isAppLimited = sentPacket.sendTimeState.isAppLimited
	sendTimeState.totalBytesSent = sentPacket.sendTimeState.totalBytesSent
	sendTimeState.totalBytesAcked = sentPacket.sendTimeState.totalBytesAcked
	sendTimeState.totalBytesLost = sentPacket.sendTimeState.totalBytesLost
	sendTimeState.isValid = true
}

// ConnectionStates Record of the connection state at the point where each packet in flight was
// sent, indexed by the packet number.
// FIXME: using LinkedList replace map to fast remove all the packets lower than the specified packet number.
type ConnectionStates struct {
	stats map[protocol.PacketNumber]*ConnectionStateOnSentPacket
}

func (s *ConnectionStates) Insert(packetNumber protocol.PacketNumber, sentTime monotime.Time, bytes protocol.ByteCount, sampler *BandwidthSampler) bool {
	if _, ok := s.stats[packetNumber]; ok {
		return false
	}

	s.stats[packetNumber] = NewConnectionStateOnSentPacket(packetNumber, sentTime, bytes, sampler)
	return true
}

func (s *ConnectionStates) Get(packetNumber protocol.PacketNumber) *ConnectionStateOnSentPacket {
	return s.stats[packetNumber]
}

func (s *ConnectionStates) Remove(packetNumber protocol.PacketNumber) (bool, *ConnectionStateOnSentPacket) {
	state, ok := s.stats[packetNumber]
	if ok {
		delete(s.stats, packetNumber)
	}
	return ok, state
}

func NewConnectionStateOnSentPacket(packetNumber protocol.PacketNumber, sentTime monotime.Time, bytes protocol.ByteCount, sampler *BandwidthSampler) *ConnectionStateOnSentPacket {
	return &ConnectionStateOnSentPacket{
		packetNumber:                    packetNumber,
		sendTime:                        sentTime,
		size:                            bytes,
		lastAckedPacketSentTime:         sampler.lastAckedPacketSentTime,
		lastAckedPacketAckTime:          sampler.lastAckedPacketAckTime,
		totalBytesSentAtLastAckedPacket: sampler.totalBytesSentAtLastAckedPacket,
		sendTimeState: SendTimeState{
			isValid:         true,
			isAppLimited:    sampler.isAppLimited,
			totalBytesSent:  sampler.totalBytesSent,
			totalBytesAcked: sampler.totalBytesAcked,
			totalBytesLost:  sampler.totalBytesLost,
		},
	}
}

func minBandwidth(a, b Bandwidth) Bandwidth {
	if a < b {
		return a
	}
	return b
}

// newExactPacer creates a pacer that paces at exactly the rate returned by getBandwidth.
// Rate-based congestion controllers (like BBR) apply their own pacing gain to the rate.
// Adding headroom on top of that rate would create a standing queue while cruising in
// PROBE_BW, and prevent the queue from draining in the DRAIN and PROBE_RTT phases.
func newExactPacer(getBandwidth func() Bandwidth) *pacer {
	return newPacerWithBandwidthFunc(func() uint64 {
		// Bandwidth is in bits/s. We need the value in bytes/s.
		return uint64(getBandwidth() / BytesPerSecond)
	})
}

func newPacerWithBandwidthFunc(adjustedBandwidth func() uint64) *pacer {
	p := &pacer{
		maxDatagramSize:   initialMaxDatagramSize,
		adjustedBandwidth: adjustedBandwidth,
	}
	p.budgetAtLastSent = p.maxBurstSize()
	return p
}

// WindowedFilter Use the following to construct a windowed filter object of type T.
// For example, a min filter using QuicTime as the time type:
//
//	WindowedFilter<T, MinFilter<T>, QuicTime, QuicTime::Delta> ObjectName;
//
// A max filter using 64-bit integers as the time type:
//
//	WindowedFilter<T, MaxFilter<T>, uint64_t, int64_t> ObjectName;
//
// Specifically, this template takes four arguments:
//  1. T -- type of the measurement that is being filtered.
//  2. Compare -- MinFilter<T> or MaxFilter<T>, depending on the type of filter
//     desired.
//  3. TimeT -- the type used to represent timestamps.
//  4. TimeDeltaT -- the type used to represent continuous time intervals between
//     two timestamps.  Has to be the type of (a - b) if both |a| and |b| are
//     of type TimeT.
type WindowedFilter struct {
	// Time length of window.
	windowLength int64
	estimates    []Sample
	comparator   func(int64, int64) bool
}

type Sample struct {
	sample int64
	time   int64
}

// Compares two values and returns true if the first is greater than or equal
// to the second.
func MaxFilter(a, b int64) bool {
	return a >= b
}

// Compares two values and returns true if the first is less than or equal
// to the second.
func MinFilter(a, b int64) bool {
	return a <= b
}

func NewWindowedFilter(windowLength int64, comparator func(int64, int64) bool) *WindowedFilter {
	return &WindowedFilter{
		windowLength: windowLength,
		estimates:    make([]Sample, 3),
		comparator:   comparator,
	}
}

// Changes the window length.  Does not update any current samples.
func (f *WindowedFilter) SetWindowLength(windowLength int64) {
	f.windowLength = windowLength
}

func (f *WindowedFilter) GetBest() int64 {
	return f.estimates[0].sample
}

func (f *WindowedFilter) GetSecondBest() int64 {
	return f.estimates[1].sample
}

func (f *WindowedFilter) GetThirdBest() int64 {
	return f.estimates[2].sample
}

func (f *WindowedFilter) Update(sample int64, time int64) {
	if f.estimates[0].time == 0 || f.comparator(sample, f.estimates[0].sample) || (time-f.estimates[2].time) > f.windowLength {
		f.Reset(sample, time)
		return
	}

	if f.comparator(sample, f.estimates[1].sample) {
		f.estimates[1].sample = sample
		f.estimates[1].time = time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	} else if f.comparator(sample, f.estimates[2].sample) {
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	}

	// Expire and update estimates as necessary.
	if time-f.estimates[0].time > f.windowLength {
		// The best estimate hasn't been updated for an entire window, so promote
		// second and third best estimates.
		f.estimates[0].sample = f.estimates[1].sample
		f.estimates[0].time = f.estimates[1].time
		f.estimates[1].sample = f.estimates[2].sample
		f.estimates[1].time = f.estimates[2].time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
		// Need to iterate one more time. Check if the new best estimate is
		// outside the window as well, since it may also have been recorded a
		// long time ago. Don't need to iterate once more since we cover that
		// case at the beginning of the method.
		if time-f.estimates[0].time > f.windowLength {
			f.estimates[0].sample = f.estimates[1].sample
			f.estimates[0].time = f.estimates[1].time
			f.estimates[1].sample = f.estimates[2].sample
			f.estimates[1].time = f.estimates[2].time
		}
		return
	}
	if f.estimates[1].sample == f.estimates[0].sample && time-f.estimates[1].time > f.windowLength>>2 {
		// A quarter of the window has passed without a better sample, so the
		// second-best estimate is taken from the second quarter of the window.
		f.estimates[1].sample = sample
		f.estimates[1].time = time
		f.estimates[2].sample = sample
		f.estimates[2].time = time
		return
	}

	if f.estimates[2].sample == f.estimates[1].sample && time-f.estimates[2].time > f.windowLength>>1 {
		// We've passed a half of the window without a better estimate, so take
		// a third-best estimate from the second half of the window.
		f.estimates[2].sample = sample
		f.estimates[2].time = time
	}
}

func (f *WindowedFilter) Reset(newSample int64, newTime int64) {
	f.estimates[0].sample = newSample
	f.estimates[0].time = newTime
	f.estimates[1].sample = newSample
	f.estimates[1].time = newTime
	f.estimates[2].sample = newSample
	f.estimates[2].time = newTime
}
