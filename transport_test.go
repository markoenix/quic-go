package quic

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	mocklogging "github.com/quic-go/quic-go/internal/mocks/logging"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/logging"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Transport", func() {
	type packetToRead struct {
		addr net.Addr
		data []byte
		err  error
	}

	getPacketWithPacketType := func(connID protocol.ConnectionID, t protocol.PacketType, length protocol.ByteCount) []byte {
		b, err := (&wire.ExtendedHeader{
			Header: wire.Header{
				Type:             t,
				DestConnectionID: connID,
				Length:           length,
				Version:          protocol.Version1,
			},
			PacketNumberLen: protocol.PacketNumberLen2,
		}).Append(nil, protocol.Version1)
		Expect(err).ToNot(HaveOccurred())
		return b
	}

	getPacket := func(connID protocol.ConnectionID) []byte {
		return getPacketWithPacketType(connID, protocol.PacketTypeHandshake, 2)
	}

	newMockPacketConn := func(packetChan <-chan packetToRead) net.PacketConn {
		conn := NewMockPacketConn(mockCtrl)
		conn.EXPECT().LocalAddr().Return(&net.UDPAddr{}).AnyTimes()
		conn.EXPECT().ReadFrom(gomock.Any()).DoAndReturn(func(b []byte) (int, net.Addr, error) {
			p, ok := <-packetChan
			if !ok {
				return 0, nil, errors.New("closed")
			}
			return copy(b, p.data), p.addr, p.err
		}).AnyTimes()
		// for shutdown
		conn.EXPECT().SetReadDeadline(gomock.Any()).AnyTimes()
		return conn
	}

	It("handles packets for different packet handlers on the same packet conn", func() {
		packetChan := make(chan packetToRead)
		tr := &Transport{Conn: newMockPacketConn(packetChan)}
		tr.init(&Config{})
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm
		connID1 := protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8})
		connID2 := protocol.ParseConnectionID([]byte{8, 7, 6, 5, 4, 3, 2, 1})

		handled := make(chan struct{}, 2)
		phm.EXPECT().Get(connID1).DoAndReturn(func(protocol.ConnectionID) (packetHandler, bool) {
			h := NewMockPacketHandler(mockCtrl)
			h.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				defer GinkgoRecover()
				connID, err := wire.ParseConnectionID(p.data, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(connID).To(Equal(connID1))
				handled <- struct{}{}
			})
			return h, true
		})
		phm.EXPECT().Get(connID2).DoAndReturn(func(protocol.ConnectionID) (packetHandler, bool) {
			h := NewMockPacketHandler(mockCtrl)
			h.EXPECT().handlePacket(gomock.Any()).Do(func(p *receivedPacket) {
				defer GinkgoRecover()
				connID, err := wire.ParseConnectionID(p.data, 0)
				Expect(err).ToNot(HaveOccurred())
				Expect(connID).To(Equal(connID2))
				handled <- struct{}{}
			})
			return h, true
		})

		packetChan <- packetToRead{data: getPacket(connID1)}
		packetChan <- packetToRead{data: getPacket(connID2)}

		Eventually(handled).Should(Receive())
		Eventually(handled).Should(Receive())

		// shutdown
		close(packetChan)
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	})

	It("closes listeners", func() {
		packetChan := make(chan packetToRead)
		tr := &Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		ln, err := tr.Listen(&tls.Config{}, nil)
		Expect(err).ToNot(HaveOccurred())
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.handlerMap = phm

		phm.EXPECT().CloseServer()
		Expect(ln.Close()).To(Succeed())

		// shutdown
		close(packetChan)
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	})

	It("drops unparseable packets", func() {
		addr := &net.UDPAddr{IP: net.IPv4(9, 8, 7, 6), Port: 1234}
		packetChan := make(chan packetToRead)
		tracer := mocklogging.NewMockTracer(mockCtrl)
		tr := &Transport{
			Conn:               newMockPacketConn(packetChan),
			ConnectionIDLength: 10,
		}
		tr.init(&Config{Tracer: tracer})
		dropped := make(chan struct{})
		tracer.EXPECT().DroppedPacket(addr, logging.PacketTypeNotDetermined, protocol.ByteCount(4), logging.PacketDropHeaderParseError).Do(func(net.Addr, logging.PacketType, protocol.ByteCount, logging.PacketDropReason) { close(dropped) })
		packetChan <- packetToRead{
			addr: addr,
			data: []byte{0, 1, 2, 3},
		}
		Eventually(dropped).Should(BeClosed())

		// shutdown
		close(packetChan)
		tr.Close()
	})

	It("closes when reading from the conn fails", func() {
		packetChan := make(chan packetToRead)
		tr := Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.init(&Config{})
		tr.handlerMap = phm

		done := make(chan struct{})
		phm.EXPECT().Close(gomock.Any()).Do(func(error) { close(done) })
		packetChan <- packetToRead{err: errors.New("read failed")}
		Eventually(done).Should(BeClosed())

		// shutdown
		close(packetChan)
		tr.Close()
	})

	It("continues listening after temporary errors", func() {
		packetChan := make(chan packetToRead)
		tr := Transport{Conn: newMockPacketConn(packetChan)}
		defer tr.Close()
		phm := NewMockPacketHandlerManager(mockCtrl)
		tr.init(&Config{})
		tr.handlerMap = phm

		tempErr := deadlineError{}
		Expect(tempErr.Temporary()).To(BeTrue())
		packetChan <- packetToRead{err: tempErr}
		// don't expect any calls to phm.Close
		time.Sleep(50 * time.Millisecond)

		// shutdown
		close(packetChan)
		phm.EXPECT().Close(gomock.Any())
		tr.Close()
	})
})
