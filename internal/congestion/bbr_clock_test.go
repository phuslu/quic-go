package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
)

type mockClock monotime.Time

func (c *mockClock) Now() monotime.Time {
	return monotime.Time(*c)
}

func (c *mockClock) Advance(d time.Duration) {
	*c = mockClock(monotime.Time(*c).Add(d))
}
