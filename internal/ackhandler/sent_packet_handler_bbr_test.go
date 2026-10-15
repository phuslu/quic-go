package ackhandler

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

type ackRecordingSender struct {
	congestion.SendAlgorithmWithDebugInfos
	events        []string
	priorInFlight []protocol.ByteCount
	ackTimes      []monotime.Time
}

func (s *ackRecordingSender) OnPacketAcked(pn protocol.PacketNumber, size, priorInFlight protocol.ByteCount, now monotime.Time) {
	s.events = append(s.events, fmt.Sprintf("ack:%d", pn))
	s.priorInFlight = append(s.priorInFlight, priorInFlight)
	s.ackTimes = append(s.ackTimes, now)
	s.SendAlgorithmWithDebugInfos.OnPacketAcked(pn, size, priorInFlight, now)
}

func (s *ackRecordingSender) OnCongestionEvent(pn protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	s.events = append(s.events, fmt.Sprintf("loss:%d", pn))
	s.priorInFlight = append(s.priorInFlight, priorInFlight)
	s.SendAlgorithmWithDebugInfos.OnCongestionEvent(pn, lostBytes, priorInFlight)
}

func (s *ackRecordingSender) OnPacketDiscarded(pn protocol.PacketNumber) {
	s.SendAlgorithmWithDebugInfos.(interface{ OnPacketDiscarded(protocol.PacketNumber) }).OnPacketDiscarded(pn)
}

type ackEventRecordingSender struct{ *ackRecordingSender }

func (s *ackEventRecordingSender) BeginAckEvent() {
	s.events = append(s.events, "begin")
	s.SendAlgorithmWithDebugInfos.(congestionEventer).BeginAckEvent()
}

func (s *ackEventRecordingSender) RemoveObsoletePackets(leastUnacked protocol.PacketNumber) {
	if leastUnacked == math.MaxInt64 {
		s.events = append(s.events, "obsolete:max")
	} else {
		s.events = append(s.events, fmt.Sprintf("obsolete:%d", leastUnacked))
	}
	s.SendAlgorithmWithDebugInfos.(congestionEventer).RemoveObsoletePackets(leastUnacked)
}

func (s *ackEventRecordingSender) EndAckEvent(priorInFlight protocol.ByteCount, now monotime.Time) {
	s.events = append(s.events, "end")
	s.priorInFlight = append(s.priorInFlight, priorInFlight)
	s.ackTimes = append(s.ackTimes, now)
	s.SendAlgorithmWithDebugInfos.(congestionEventer).EndAckEvent(priorInFlight, now)
}

func TestSentPacketHandlerAckEvent(t *testing.T) {
	for _, tc := range []struct {
		name          string
		packets       []string
		ackFrom       int
		discardFirst  bool
		withoutEvents bool
		events        []string
	}{
		{name: "single packet", packets: []string{"data"}, events: []string{"begin", "ack:#0", "end", "obsolete:max"}},
		{name: "multiple packets", packets: []string{"data", "data"}, events: []string{"begin", "ack:#0", "ack:#1", "end", "obsolete:max"}},
		{name: "sender without ACK events", packets: []string{"data", "data"}, withoutEvents: true, events: []string{"ack:#0", "ack:#1"}},
		{name: "path probes", packets: []string{"probe", "data", "probe"}, events: []string{"begin", "ack:#1", "end", "obsolete:max"}},
		{name: "only path probes", packets: []string{"probe", "probe"}, events: []string{"begin", "end", "obsolete:max"}},
		{name: "ack-only packets and path probes", packets: []string{"ack", "data", "probe", "ack", "data", "probe"}, events: []string{"begin", "ack:#1", "ack:#4", "end", "obsolete:max"}},
		{name: "packet declared lost by a PTO probe", packets: []string{"data", "data", "data"}, discardFirst: true, events: []string{"begin", "ack:#1", "ack:#2", "end", "obsolete:max"}},
		{name: "losses detected by the ACK", packets: []string{"data", "data", "data", "data", "data"}, ackFrom: 1, events: []string{"begin", "loss:#0", "ack:#1", "ack:#2", "ack:#3", "ack:#4", "end", "obsolete:max"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
			sender := &ackRecordingSender{SendAlgorithmWithDebugInfos: h.congestion}
			if tc.withoutEvents {
				h.congestion = sender
			} else {
				h.congestion = &ackEventRecordingSender{sender}
			}
			now := monotime.Now()
			var pns []protocol.PacketNumber
			for _, kind := range tc.packets {
				pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
				var frames []Frame
				if kind != "ack" {
					frames = []Frame{{Frame: &wire.PingFrame{}}}
				}
				h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, frames, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, kind == "probe")
				pns = append(pns, pn)
			}
			if tc.discardFirst {
				require.True(t, h.QueueProbePacket(protocol.PacketNumberSpaceAppData))
			}
			priorInFlight := h.bytesInFlight
			ackTime := now.Add(10 * time.Millisecond)
			ack := &wire.AckFrame{AckRanges: ackRanges(slices.Clone(pns[tc.ackFrom:])...)} // ackRanges sorts in place
			_, err := h.ReceivedAck(ack, protocol.Encryption1RTT, ackTime)
			require.NoError(t, err)
			// Packet numbers are skipped randomly, so refer to packets by the order they were sent in.
			for i, ev := range sender.events {
				for j, pn := range pns {
					sender.events[i] = strings.Replace(sender.events[i], fmt.Sprintf(":%d", pn), fmt.Sprintf(":#%d", j), 1)
					if sender.events[i] != ev {
						break
					}
				}
			}
			require.Equal(t, tc.events, sender.events)
			for _, prior := range sender.priorInFlight {
				require.Equal(t, priorInFlight, prior)
			}
			for _, at := range sender.ackTimes {
				require.Equal(t, ackTime, at)
			}
			require.Zero(t, h.bytesInFlight)

			// A duplicate ACK has nothing to report.
			sender.events = nil
			_, err = h.ReceivedAck(ack, protocol.Encryption1RTT, ackTime.Add(time.Millisecond))
			require.NoError(t, err)
			if tc.withoutEvents {
				require.Empty(t, sender.events)
			} else {
				require.Equal(t, []string{"begin", "end", "obsolete:max"}, sender.events)
			}
		})
	}
}

// The BBR sender only publishes the congestion window at the end of the ACK
// event, so the metrics must be logged after it.
func TestSentPacketHandlerAckEventQlogMetrics(t *testing.T) {
	var eventRecorder events.Recorder
	stats := &utils.ConnectionStats{}
	h := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), stats, true, false, nil, protocol.PerspectiveClient, &eventRecorder, utils.DefaultLogger).(*sentPacketHandler)
	now := monotime.Now()
	var pns []protocol.PacketNumber
	for range 10 {
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		pns = append(pns, pn)
	}
	eventRecorder.Clear()
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pns...)}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	cwnd := h.congestion.GetCongestionWindow()
	require.Equal(t, uint64(cwnd), stats.CongestionWindow.Load())
	var lastLogged int
	for _, ev := range eventRecorder.Events(qlog.MetricsUpdated{}) {
		if m := ev.(qlog.MetricsUpdated); m.CongestionWindow != 0 {
			lastLogged = m.CongestionWindow
		}
	}
	require.Equal(t, int(cwnd), lastLogged)
}

// Like TestSentPacketHandlerCongestionAcrossPacketNumberSpaces, for the BBR
// sender, which doesn't log recovery as a congestion state.
func TestSentPacketHandlerBBRRecoveryAcrossPacketNumberSpaces(t *testing.T) {
	sph := NewSentPacketHandler(
		0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false,
		nil, protocol.PerspectiveServer, nil, utils.DefaultLogger,
	).(*sentPacketHandler)
	var packets packetTracker
	now := monotime.Now()
	sendPacket := func(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel.PacketNumberSpace())
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{packets.NewPingFrame(pn)}, encLevel, protocol.ECNNon, 1200, false, false)
		return pn
	}
	ackPacket := func(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) {
		_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn)}, encLevel, now.Add(time.Millisecond))
		require.NoError(t, err)
	}

	for range 5 {
		sendPacket(protocol.EncryptionInitial)
	}
	handshakePN := sendPacket(protocol.EncryptionHandshake)
	appDataPN := sendPacket(protocol.Encryption1RTT)

	ackPacket(4, protocol.EncryptionInitial)
	require.True(t, sph.congestion.InRecovery())
	// ACKs for packets sent before the loss was detected don't end recovery,
	// even when they belong to another packet number space.
	ackPacket(handshakePN, protocol.EncryptionHandshake)
	ackPacket(appDataPN, protocol.Encryption1RTT)
	require.True(t, sph.congestion.InRecovery())

	now = now.Add(2 * time.Millisecond)
	ackPacket(sendPacket(protocol.Encryption1RTT), protocol.Encryption1RTT)
	require.False(t, sph.congestion.InRecovery())
	require.Equal(t, []protocol.PacketNumber{0, 1}, packets.Lost)
}

// Packets of a dropped packet number space are neither acknowledged nor
// declared lost: the BBR sender stops tracking them with the next ACK.
func TestSentPacketHandlerBBRObsoletePackets(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	sender := &ackEventRecordingSender{&ackRecordingSender{SendAlgorithmWithDebugInfos: sph.congestion}}
	sph.congestion = sender
	now := monotime.Now()
	send := func(encLevel protocol.EncryptionLevel) protocol.PacketNumber {
		pn := sph.PopPacketNumber(encLevel.PacketNumberSpace())
		sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, encLevel, protocol.ECNNon, 1200, false, false)
		return pn
	}
	send(protocol.EncryptionInitial)
	send(protocol.EncryptionInitial)
	pn1 := send(protocol.Encryption1RTT)
	pn2 := send(protocol.Encryption1RTT)
	sph.DropPackets(protocol.EncryptionInitial, now)
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn1)}, protocol.Encryption1RTT, now.Add(10*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, []string{"begin", fmt.Sprintf("ack:%d", pn1), "end", fmt.Sprintf("obsolete:%d", pn2)}, sender.events)
}

func TestSentPacketHandlerBBRQlogAndMigration(t *testing.T) {
	var eventRecorder events.Recorder
	opts := congestion.BBROptions{ProbeRttBasedOnBdp: true}
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, &eventRecorder, utils.DefaultLogger, opts).(*sentPacketHandler)
	// The Cubic sender created by the upstream constructor is replaced without a trace.
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateStartup}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
	require.Len(t, eventRecorder.Events(qlog.RecoveryParametersSet{}), 1)
	require.Equal(t, &eventRecorder, sph.qlogger)

	eventRecorder.Clear()
	sph.MigratedPath(monotime.Now(), 1300)
	require.Equal(t,
		[]qlogwriter.Event{qlog.CongestionStateUpdated{State: qlog.CongestionStateStartup}},
		eventRecorder.Events(qlog.CongestionStateUpdated{}),
	)
	require.Equal(t, &eventRecorder, sph.qlogger)
	require.Equal(t, opts, sph.congestion.(interface{ Options() congestion.BBROptions }).Options())
	require.Equal(t, 32*protocol.ByteCount(1300), sph.congestion.GetCongestionWindow())

	// Without qlog, no recorder is installed.
	sph = NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	require.Nil(t, sph.qlogger)
	sph.MigratedPath(monotime.Now(), 1300)
	require.Nil(t, sph.qlogger)
}

// All packets declared lost by the loss detection timer are reported as one
// event. Like in quiche, a loss-only event doesn't start recovery.
func TestSentPacketHandlerBBRLossDetectionTimeout(t *testing.T) {
	sph := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger).(*sentPacketHandler)
	sender := &ackEventRecordingSender{&ackRecordingSender{SendAlgorithmWithDebugInfos: sph.congestion}}
	sph.congestion = sender
	now := monotime.Now()
	send := func(t monotime.Time) protocol.PacketNumber {
		pn := sph.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		sph.SentPacket(t, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
		return pn
	}
	pn1 := send(now)
	pn2 := send(now)
	pn3 := send(now.Add(time.Millisecond))
	// Acknowledging the 3rd packet doesn't reach the packet threshold for the
	// first two, but arms the loss timer for them.
	_, err := sph.ReceivedAck(&wire.AckFrame{AckRanges: ackRanges(pn3)}, protocol.Encryption1RTT, now.Add(50*time.Millisecond))
	require.NoError(t, err)
	require.Equal(t, []string{"begin", fmt.Sprintf("ack:%d", pn3), "end", fmt.Sprintf("obsolete:%d", pn1)}, sender.events)
	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)

	sender.events = nil
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Equal(t, []string{"begin", fmt.Sprintf("loss:%d", pn1), fmt.Sprintf("loss:%d", pn2), "end", "obsolete:max"}, sender.events)
	require.False(t, sph.congestion.InRecovery())
	require.Zero(t, sph.bytesInFlight)
}
