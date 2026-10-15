package ackhandler

import (
	"math"

	"github.com/quic-go/quic-go/internal/congestion"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// This file replaces the Cubic sender with the BBR sender. To keep the changes
// to the upstream code minimal, the upstream NewSentPacketHandler, ReceivedAck,
// OnLossDetectionTimeout and MigratedPath are renamed, and wrapped by the
// functions below.

// congestionEventer is implemented by congestion controllers that update their
// model once per ACK frame or loss detection timeout, instead of once per
// acknowledged or lost packet.
type congestionEventer interface {
	BeginAckEvent()
	EndAckEvent(priorInFlight protocol.ByteCount, eventTime monotime.Time)
	// RemoveObsoletePackets stops tracking packets below leastUnacked,
	// which were neither acknowledged nor declared lost.
	RemoveObsoletePackets(leastUnacked protocol.PacketNumber)
}

// NewSentPacketHandler creates a new sentPacketHandler using the BBR sender.
func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
	bbrOptions ...congestion.BBROptions,
) SentPacketHandler {
	var opts congestion.BBROptions
	if len(bbrOptions) > 0 {
		opts = bbrOptions[0]
	}
	h := newSentPacketHandler(
		initialPN,
		initialMaxDatagramSize,
		rttStats,
		connStats,
		clientAddressValidated,
		enableECN,
		ignorePacketsBelow,
		pers,
		withoutCubicState(qlogger),
		logger,
	).(*sentPacketHandler)
	h.qlogger = qlogger
	h.congestion = h.newBBRSender(initialMaxDatagramSize, opts)
	return h
}

func (h *sentPacketHandler) newBBRSender(initialMaxDatagramSize protocol.ByteCount, opts congestion.BBROptions) congestion.SendAlgorithmWithDebugInfos {
	return congestion.NewBBRSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
		opts,
	)
}

// cubicStateFilter drops the slow start state that the Cubic sender logs when
// it is created, since it is replaced by the BBR sender right away.
type cubicStateFilter struct{ qlogwriter.Recorder }

func (r cubicStateFilter) RecordEvent(ev qlogwriter.Event) {
	if e, ok := ev.(qlog.CongestionStateUpdated); ok && e.State == qlog.CongestionStateSlowStart {
		return
	}
	r.Recorder.RecordEvent(ev)
}

func withoutCubicState(qlogger qlogwriter.Recorder) qlogwriter.Recorder {
	if qlogger == nil {
		return nil
	}
	return cubicStateFilter{qlogger}
}

// ReceivedAck wraps receivedAck in an ACK event, so that the congestion controller
// sees the losses and acknowledged packets of one ACK frame as a single event.
func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	ev, ok := h.congestion.(congestionEventer)
	if !ok {
		return h.receivedAck(ack, encLevel, rcvTime)
	}
	ev.BeginAckEvent()
	priorInFlight := h.bytesInFlight
	acked1RTTPacket, err := h.receivedAck(ack, encLevel, rcvTime)
	ev.EndAckEvent(priorInFlight, rcvTime)
	ev.RemoveObsoletePackets(h.leastUnacked())
	// receivedAck logs the metrics before the model is updated.
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	return acked1RTTPacket, err
}

// OnLossDetectionTimeout wraps onLossDetectionTimeout in an event, so that the
// congestion controller sees all packets declared lost by the timer as a
// single event.
func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	ev, ok := h.congestion.(congestionEventer)
	if !ok {
		return h.onLossDetectionTimeout(now)
	}
	ev.BeginAckEvent()
	priorInFlight := h.bytesInFlight
	err := h.onLossDetectionTimeout(now)
	ev.EndAckEvent(priorInFlight, now)
	ev.RemoveObsoletePackets(h.leastUnacked())
	// onLossDetectionTimeout logs the metrics before the model is updated.
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	return err
}

// leastUnacked returns the first packet number that is still tracked. Packets
// below it that the congestion controller still tracks were dropped without
// being acknowledged or declared lost, e.g. when their packet number space was
// dropped, or a PTO probe declared them lost.
func (h *sentPacketHandler) leastUnacked() protocol.PacketNumber {
	if pn := h.hist.FirstPacketNumber(); pn != protocol.InvalidPacketNumber {
		return pn
	}
	return math.MaxInt64
}

// MigratedPath resets the congestion controller to a new BBR sender with the same options.
func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	var opts congestion.BBROptions
	if s, ok := h.congestion.(interface{ Options() congestion.BBROptions }); ok {
		opts = s.Options()
	}
	qlogger := h.qlogger
	h.qlogger = withoutCubicState(qlogger)
	h.migratedPath(now, initialMaxDatagramSize)
	h.qlogger = qlogger
	h.congestion = h.newBBRSender(initialMaxDatagramSize, opts)
}

// OnApplicationLimited is called when the connection has no more data to send.
func (h *sentPacketHandler) OnApplicationLimited() {
	if appLimited, ok := h.congestion.(interface{ OnApplicationLimited() }); ok {
		appLimited.OnApplicationLimited()
	}
}
