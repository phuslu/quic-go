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
			bbr := NewBBRSender(DefaultClock{}, rttStats, &utils.ConnectionStats{}, 1200, false, nil)
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
