package quic

import (
	"bytes"
	"testing"
	"testing/synctest"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type appLimitedSentPacketHandler struct {
	*mockackhandler.MockSentPacketHandler
	appLimited int
}

func (h *appLimitedSentPacketHandler) OnApplicationLimited() { h.appLimited++ }

// The connection runs out of data after packing some packets of a GSO batch.
// It is application-limited, even though it sends the batch.
func TestConnectionGSOBatchApplicationLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		sph := &appLimitedSentPacketHandler{MockSentPacketHandler: mockackhandler.NewMockSentPacketHandler(mockCtrl)}
		tc := newServerTestConnection(t,
			mockCtrl,
			nil,
			true,
			connectionOptHandshakeConfirmed(),
			connectionOptSentPacketHandler(sph),
		)

		sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny).AnyTimes()
		sph.EXPECT().TimeUntilSend().AnyTimes()
		sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
		sph.EXPECT().ECNMode(gomock.Any()).Return(protocol.ECT1).AnyTimes()

		maxPacketSize := tc.conn.maxPacketSize()
		var expectedData []byte
		for i := range 2 {
			data := bytes.Repeat([]byte{byte(i)}, int(maxPacketSize))
			expectedData = append(expectedData, data...)
			tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(buffer *packetBuffer, count protocol.ByteCount, t monotime.Time, version protocol.Version) (shortHeaderPacket, error) {
					buffer.Data = append(buffer.Data, data...)
					return shortHeaderPacket{PacketNumber: protocol.PacketNumber(i)}, nil
				},
			)
		}
		done := make(chan struct{})
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)
		tc.sendConn.EXPECT().Write(expectedData, uint16(maxPacketSize), protocol.ECT1).DoAndReturn(
			func([]byte, uint16, protocol.ECN) error { close(done); return nil },
		)

		errChan := make(chan error, 1)
		go func() { errChan <- tc.conn.run() }()
		tc.conn.scheduleSending()
		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("should have sent a packet")
		}
		require.Equal(t, 1, sph.appLimited)

		// test teardown
		tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		tc.conn.destroy(nil)
		synctest.Wait()
		select {
		case err := <-errChan:
			require.NoError(t, err)
		default:
			t.Fatal("should have timed out")
		}
	})
}
