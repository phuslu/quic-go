package quic

import "github.com/quic-go/quic-go/internal/congestion"

// BBROptions configures the local BBRv1 congestion controller.
// The zero value uses the default BBRv1 configuration.
type BBROptions = congestion.BBROptions
