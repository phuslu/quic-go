package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"github.com/stretchr/testify/require"
)

// TestBBRStartupPacingInitialization verifies that BBR initializes pacing rate
// aggressively during startup, preventing the slow startup issue.
func TestBBRStartupPacingInitialization(t *testing.T) {
	var clock mockClock
	rttStats := utils.NewRTTStats()
	initialMaxDatagramSize := protocol.ByteCount(1200)

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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

	bbr := NewBBRSender(&clock, rttStats, &utils.ConnectionStats{}, initialMaxDatagramSize)

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
