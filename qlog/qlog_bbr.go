package qlog

import (
	"time"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

const (
	// CongestionStateStartup is the startup phase of BBR.
	CongestionStateStartup CongestionState = "startup"
	// CongestionStateDrain is the drain phase of BBR.
	CongestionStateDrain CongestionState = "drain"
	// CongestionStateProbeBW is the bandwidth probing phase of BBR.
	CongestionStateProbeBW CongestionState = "probe_bw"
	// CongestionStateProbeRTT is the RTT probing phase of BBR.
	CongestionStateProbeRTT CongestionState = "probe_rtt"
)

// BBRPacingRateUpdated logs a BBR pacing rate change as part of the
// recovery:metrics_updated event.
type BBRPacingRateUpdated struct {
	// PacingRate is the pacing rate in bits per second.
	PacingRate uint64
}

func (e BBRPacingRateUpdated) Name() string { return "recovery:metrics_updated" }

func (e BBRPacingRateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.PacingRate != 0 {
		h.WriteToken(jsontext.String("pacing_rate"))
		h.WriteToken(jsontext.Uint(e.PacingRate))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
