package congestion

import (
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

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
