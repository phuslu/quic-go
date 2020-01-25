package self_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/phuslu/quic-go"
	quicproxy "github.com/phuslu/quic-go/integrationtests/tools/proxy"
	"github.com/phuslu/quic-go/internal/protocol"
	"github.com/phuslu/quic-go/internal/wire"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("0-RTT", func() {
	const rtt = 50 * time.Millisecond
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			runCountingProxy := func(serverPort int) (*quicproxy.QuicProxy, *uint32) {
				var num0RTTPackets uint32 // to be used as an atomic
				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							atomic.AddUint32(&num0RTTPackets, 1)
						}
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())

				return proxy, &num0RTTPackets
			}

			dialAndReceiveSessionTicket := func(ln quic.EarlyListener, proxyPort int) *tls.Config {
				// dial the first session in order to receive a session ticket
				go func() {
					defer GinkgoRecover()
					_, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
				}()

				clientConf := getTLSClientConfig()
				gets := make(chan string, 100)
				puts := make(chan string, 100)
				clientConf.ClientSessionCache = newClientSessionCache(gets, puts)
				sess, err := quic.DialAddr(
					fmt.Sprintf("localhost:%d", proxyPort),
					clientConf,
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				Eventually(puts).Should(Receive())
				// received the session ticket. We're done here.
				Expect(sess.Close()).To(Succeed())
				return clientConf
			}

			transfer0RTTData := func(ln quic.EarlyListener, proxyPort int, clientConf *tls.Config, testdata []byte) {
				// now dial the second session, and use 0-RTT to send some data
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(testdata))
					close(done)
				}()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxyPort),
					clientConf,
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(testdata)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())
				Eventually(done).Should(BeClosed())
			}

			It("transfers 0-RTT data", func() {
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					getTLSConfig(),
					&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
					},
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				clientConf := dialAndReceiveSessionTicket(ln, proxy.LocalPort())
				transfer0RTTData(ln, proxy.LocalPort(), clientConf, PRData)

				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).ToNot(BeZero())
			})

			// Test that data intended to be sent with 1-RTT protection is not sent in 0-RTT packets.
			It("waits until a session until the handshake is done", func() {
				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					getTLSConfig(),
					&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
					},
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()

				proxy, num0RTTPackets := runCountingProxy(ln.Addr().(*net.UDPAddr).Port)
				defer proxy.Close()

				clientConf := dialAndReceiveSessionTicket(ln, proxy.LocalPort())

				zeroRTTData := GeneratePRData(2 * 1100) // 2 packets
				oneRTTData := PRData

				// now dial the second session, and use 0-RTT to send some data
				done := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())
					str, err := sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err := ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(zeroRTTData))
					str, err = sess.AcceptUniStream(context.Background())
					Expect(err).ToNot(HaveOccurred())
					data, err = ioutil.ReadAll(str)
					Expect(err).ToNot(HaveOccurred())
					Expect(data).To(Equal(oneRTTData))
					close(done)
				}()

				sess, err := quic.DialAddrEarly(
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					clientConf,
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				sent0RTT := make(chan struct{})
				go func() {
					defer GinkgoRecover()
					defer close(sent0RTT)
					str, err := sess.OpenUniStream()
					Expect(err).ToNot(HaveOccurred())
					_, err = str.Write(zeroRTTData)
					Expect(err).ToNot(HaveOccurred())
					Expect(str.Close()).To(Succeed())
				}()
				Eventually(sent0RTT).Should(BeClosed())

				// wait for the handshake to complete
				Eventually(sess.HandshakeComplete().Done()).Should(BeClosed())
				str, err := sess.OpenUniStream()
				Expect(err).ToNot(HaveOccurred())
				_, err = str.Write(PRData)
				Expect(err).ToNot(HaveOccurred())
				Expect(str.Close()).To(Succeed())

				Eventually(done).Should(BeClosed())

				num0RTT := atomic.LoadUint32(num0RTTPackets)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets.", num0RTT)
				Expect(num0RTT).To(Or(BeEquivalentTo(2), BeEquivalentTo(3))) // the FIN might be sent in a separate packet
			})

			It("transfers 0-RTT data, when 0-RTT packets are lost", func() {
				var (
					num0RTTPackets uint32 // to be used as an atomic
					num0RTTDropped uint32
				)

				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					getTLSConfig(),
					&quic.Config{
						Versions:    []protocol.VersionNumber{version},
						AcceptToken: func(_ net.Addr, _ *quic.Token) bool { return true },
					},
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				serverPort := ln.Addr().(*net.UDPAddr).Port

				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							atomic.AddUint32(&num0RTTPackets, 1)
						}
						return rtt / 2
					},
					DropPacket: func(_ quicproxy.Direction, data []byte) bool {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							// drop 25% of the 0-RTT packets
							drop := mrand.Intn(4) == 0
							if drop {
								atomic.AddUint32(&num0RTTDropped, 1)
							}
							return drop
						}
						return false
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				clientConf := dialAndReceiveSessionTicket(ln, proxy.LocalPort())
				transfer0RTTData(ln, proxy.LocalPort(), clientConf, PRData)

				num0RTT := atomic.LoadUint32(&num0RTTPackets)
				numDropped := atomic.LoadUint32(&num0RTTDropped)
				fmt.Fprintf(GinkgoWriter, "Sent %d 0-RTT packets. Dropped %d of those.", num0RTT, numDropped)
				Expect(numDropped).ToNot(BeZero())
				Expect(num0RTT).ToNot(BeZero())
			})

			It("retransmits all 0-RTT data when the server performs a Retry", func() {
				var mutex sync.Mutex
				var firstConnID, secondConnID protocol.ConnectionID
				var firstCounter, secondCounter int

				ln, err := quic.ListenAddrEarly(
					"localhost:0",
					getTLSConfig(),
					&quic.Config{Versions: []protocol.VersionNumber{version}},
				)
				Expect(err).ToNot(HaveOccurred())
				defer ln.Close()
				serverPort := ln.Addr().(*net.UDPAddr).Port

				proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
						hdr, _, _, err := wire.ParsePacket(data, 0)
						Expect(err).ToNot(HaveOccurred())
						if hdr.Type == protocol.PacketType0RTT {
							connID := hdr.DestConnectionID
							mutex.Lock()
							defer mutex.Unlock()
							if firstConnID == nil {
								firstConnID = connID
								firstCounter++
							} else if firstConnID != nil && firstConnID.Equal(connID) {
								Expect(secondConnID).To(BeNil())
								firstCounter++
							} else if secondConnID == nil {
								secondConnID = connID
								secondCounter++
							} else if secondConnID != nil && secondConnID.Equal(connID) {
								secondCounter++
							} else {
								Fail("received 3 connection IDs on 0-RTT packets")
							}
						}
						return rtt / 2
					},
				})
				Expect(err).ToNot(HaveOccurred())
				defer proxy.Close()

				clientConf := dialAndReceiveSessionTicket(ln, proxy.LocalPort())
				transfer0RTTData(ln, proxy.LocalPort(), clientConf, GeneratePRData(5*1100)) // ~5 packets

				mutex.Lock()
				defer mutex.Unlock()
				Expect(firstCounter).To(BeNumerically("~", 5, 1)) // the FIN bit might be sent extra
				Expect(secondCounter).To(Equal(firstCounter))
			})
		})
	}
})
