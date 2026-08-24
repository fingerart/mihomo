package outbound

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/buf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type testICMPStack struct {
	ipStack
	local       []netip.Addr
	mtu         int
	conn        net.Conn
	network     string
	source      netip.Addr
	destination netip.Addr
}

func (s *testICMPStack) LocalAddresses() []netip.Addr {
	return s.local
}

func (s *testICMPStack) DialIP(_ context.Context, network string, source, destination netip.Addr) (net.Conn, error) {
	s.network = network
	s.source = source
	s.destination = destination
	return s.conn, nil
}

func (s *testICMPStack) MTU() (int, error) { return s.mtu, nil }

type testICMPWriter struct {
	packets chan []byte
}

func (w *testICMPWriter) WritePacket(packet []byte) error {
	w.packets <- append([]byte(nil), packet...)
	return nil
}

type testICMPDialerAdapter struct {
	*Base
	connection C.ICMPConnection
	closed     chan struct{}
}

func (a *testICMPDialerAdapter) DialICMP(context.Context, *C.Metadata, C.ICMPWriter, time.Duration) (C.ICMPConnection, error) {
	return a.connection, nil
}

func (a *testICMPDialerAdapter) Close() error {
	if a.closed != nil {
		close(a.closed)
	}
	return nil
}

type testClosedICMPConnection struct {
	closed bool
}

func (*testClosedICMPConnection) WritePacket(*buf.Buffer) error { return nil }

func (c *testClosedICMPConnection) Close() error {
	c.closed = true
	return nil
}

func (c *testClosedICMPConnection) IsClosed() bool { return c.closed }

func TestAutoCloseProxyAdapterDoesNotAdvertiseUnsupportedICMP(t *testing.T) {
	wrapped := NewAutoCloseProxyAdapter(NewBase(BaseOption{Name: "no-icmp-test"}))
	if _, ok := wrapped.(C.ICMPDialer); ok {
		t.Fatal("auto-close proxy adapter advertised unsupported ICMP capability")
	}
}

func TestAutoCloseProxyAdapterKeepsICMPAdapterAlive(t *testing.T) {
	connection, underlyingConnection, adapterClosed := newAutoCloseICMPConnection(t)
	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
		select {
		case <-adapterClosed:
			t.Fatal("auto-close proxy adapter closed while its ICMP connection was active")
		default:
		}
	}
	runtime.KeepAlive(connection)

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !underlyingConnection.IsClosed() {
		t.Fatal("wrapped ICMP connection did not close the underlying connection")
	}
	connection = nil
	deadline := time.After(time.Second)
	for {
		runtime.GC()
		select {
		case <-adapterClosed:
			return
		case <-deadline:
			t.Fatal("auto-close proxy adapter remained alive after its ICMP connection was released")
		default:
			runtime.Gosched()
		}
	}
}

func newAutoCloseICMPConnection(t *testing.T) (C.ICMPConnection, *testClosedICMPConnection, <-chan struct{}) {
	t.Helper()
	adapterClosed := make(chan struct{})
	underlyingConnection := &testClosedICMPConnection{}
	wrapped := NewAutoCloseProxyAdapter(&testICMPDialerAdapter{
		Base:       NewBase(BaseOption{Name: "icmp-lifetime-test"}),
		connection: underlyingConnection,
		closed:     adapterClosed,
	})
	dialer, ok := wrapped.(C.ICMPDialer)
	if !ok {
		t.Fatal("auto-close proxy adapter hid ICMP dialer capability")
	}
	connection, err := dialer.DialICMP(context.Background(), &C.Metadata{}, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return connection, underlyingConnection, adapterClosed
}

func TestSingMuxAndAutoClosePreserveICMPDialer(t *testing.T) {
	underlyingConnection := &testClosedICMPConnection{}
	muxed, err := NewSingMux(SingMuxOption{}, &testICMPDialerAdapter{
		Base:       NewBase(BaseOption{Name: "smux-icmp-test"}),
		connection: underlyingConnection,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapped := NewAutoCloseProxyAdapter(muxed)
	t.Cleanup(func() { _ = wrapped.Close() })
	dialer, ok := wrapped.(C.ICMPDialer)
	if !ok {
		t.Fatal("SingMux hid ICMP dialer capability")
	}
	connection, err := dialer.DialICMP(context.Background(), &C.Metadata{}, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !underlyingConnection.IsClosed() {
		t.Fatal("SingMux ICMP connection did not close the underlying connection")
	}
}

func TestSingMuxDoesNotAdvertiseUnsupportedICMP(t *testing.T) {
	wrapped, err := NewSingMux(SingMuxOption{}, NewBase(BaseOption{Name: "smux-no-icmp-test"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wrapped.Close() })
	if _, ok := wrapped.(C.ICMPDialer); ok {
		t.Fatal("SingMux advertised unsupported ICMP capability")
	}
}

func TestICMPStackConnectionRewritesIPv4Packets(t *testing.T) {
	stackConn, peerConn := net.Pipe()
	defer peerConn.Close()
	stack := &testICMPStack{
		local: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		mtu:   4096,
		conn:  stackConn,
	}
	writer := &testICMPWriter{packets: make(chan []byte, 1)}
	metadata := &C.Metadata{
		NetWork: C.ICMP,
		SrcIP:   netip.MustParseAddr("192.0.2.10"),
		DstIP:   netip.MustParseAddr("1.1.1.1"),
	}

	connection, err := newICMPStackConnection(context.Background(), stack, metadata, writer, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if stack.network != "ip4:icmp" || stack.source != netip.MustParseAddr("10.0.0.2") || stack.destination != metadata.DstIP {
		t.Fatalf("unexpected dial: %s %s -> %s", stack.network, stack.source, stack.destination)
	}

	request := testIPv4ICMPPacket(t, metadata.SrcIP, metadata.DstIP, ipv4.ICMPTypeEcho)
	forwarded := make(chan []byte, 1)
	go func() {
		packet := make([]byte, len(request))
		_, err := io.ReadFull(peerConn, packet)
		if err != nil {
			forwarded <- nil
			return
		}
		forwarded <- packet
	}()
	requestBuffer := buf.As(request).ToOwned()
	if err := connection.WritePacket(requestBuffer); err != nil {
		t.Fatal(err)
	}
	if requestBuffer.Len() != 0 {
		t.Fatal("ICMP connection did not release the request buffer")
	}
	packet := <-forwarded
	if packet == nil {
		t.Fatal("failed to read forwarded packet")
	}
	if got := netip.AddrFrom4([4]byte(packet[12:16])); got != stack.source {
		t.Fatalf("unexpected forwarded source: %s", got)
	}
	if !validInternetChecksum(packet[:ipv4.HeaderLen]) || !validInternetChecksum(packet[ipv4.HeaderLen:]) {
		t.Fatal("invalid forwarded IPv4 or ICMP checksum")
	}

	reply := testIPv4ICMPPacketOfSize(t, metadata.DstIP, stack.source, ipv4.ICMPTypeEchoReply, 3000)
	if _, err := peerConn.Write(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-writer.packets:
		if len(packet) != len(reply) {
			t.Fatalf("unexpected reply size: %d, want %d", len(packet), len(reply))
		}
		if got := netip.AddrFrom4([4]byte(packet[16:20])); got != metadata.SrcIP {
			t.Fatalf("unexpected reply destination: %s", got)
		}
		if !validInternetChecksum(packet[:ipv4.HeaderLen]) || !validInternetChecksum(packet[ipv4.HeaderLen:]) {
			t.Fatal("invalid rewritten IPv4 or ICMP checksum")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rewritten reply")
	}

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !connection.IsClosed() {
		t.Fatal("expected closed connection")
	}
}

func TestICMPStackConnectionRewritesIPv6Packets(t *testing.T) {
	stackConn, peerConn := net.Pipe()
	defer peerConn.Close()
	stack := &testICMPStack{
		local: []netip.Addr{netip.MustParseAddr("fd00::2")},
		mtu:   4096,
		conn:  stackConn,
	}
	writer := &testICMPWriter{packets: make(chan []byte, 1)}
	metadata := &C.Metadata{
		NetWork: C.ICMP,
		SrcIP:   netip.MustParseAddr("2001:db8::10"),
		DstIP:   netip.MustParseAddr("2606:4700:4700::1111"),
	}

	connection, err := newICMPStackConnection(context.Background(), stack, metadata, writer, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if stack.network != "ip6:ipv6-icmp" || stack.source != netip.MustParseAddr("fd00::2") || stack.destination != metadata.DstIP {
		t.Fatalf("unexpected dial: %s %s -> %s", stack.network, stack.source, stack.destination)
	}

	request := testIPv6ICMPPacket(t, metadata.SrcIP, metadata.DstIP, ipv6.ICMPTypeEchoRequest)
	forwarded := make(chan []byte, 1)
	go func() {
		packet := make([]byte, len(request))
		_, err := io.ReadFull(peerConn, packet)
		if err != nil {
			forwarded <- nil
			return
		}
		forwarded <- packet
	}()
	if err := connection.WritePacket(buf.As(request).ToOwned()); err != nil {
		t.Fatal(err)
	}
	packet := <-forwarded
	if packet == nil {
		t.Fatal("failed to read forwarded packet")
	}
	if got := netip.AddrFrom16([16]byte(packet[8:24])); got != stack.source {
		t.Fatalf("unexpected forwarded source: %s", got)
	}
	if !validICMPv6Checksum(packet) {
		t.Fatal("invalid forwarded ICMPv6 checksum")
	}

	reply := testIPv6ICMPPacket(t, metadata.DstIP, stack.source, ipv6.ICMPTypeEchoReply)
	if _, err := peerConn.Write(reply); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-writer.packets:
		if got := netip.AddrFrom16([16]byte(packet[24:40])); got != metadata.SrcIP {
			t.Fatalf("unexpected reply destination: %s", got)
		}
		if !validICMPv6Checksum(packet) {
			t.Fatal("invalid rewritten ICMPv6 checksum")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rewritten reply")
	}
}

func testIPv4ICMPPacket(t *testing.T, source, destination netip.Addr, messageType ipv4.ICMPType) []byte {
	return testIPv4ICMPPacketOfSize(t, source, destination, messageType, ipv4.HeaderLen+8+len("mihomo"))
}

func testIPv4ICMPPacketOfSize(t *testing.T, source, destination netip.Addr, messageType ipv4.ICMPType, size int) []byte {
	t.Helper()
	payload, err := (&icmp.Message{
		Type: messageType,
		Code: 0,
		Body: &icmp.Echo{ID: 7, Seq: 1, Data: make([]byte, size-ipv4.HeaderLen-8)},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := (&ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(payload),
		TTL:      64,
		Protocol: 1,
		Src:      net.IP(source.AsSlice()),
		Dst:      net.IP(destination.AsSlice()),
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return append(header, payload...)
}

func testIPv6ICMPPacket(t *testing.T, source, destination netip.Addr, messageType ipv6.ICMPType) []byte {
	t.Helper()
	sourceIP := net.IP(source.AsSlice())
	destinationIP := net.IP(destination.AsSlice())
	payload, err := (&icmp.Message{
		Type: messageType,
		Code: 0,
		Body: &icmp.Echo{ID: 7, Seq: 1, Data: []byte("mihomo")},
	}).Marshal(icmp.IPv6PseudoHeader(sourceIP, destinationIP))
	if err != nil {
		t.Fatal(err)
	}
	ipHeader := make([]byte, ipv6.HeaderLen)
	ipHeader[0] = 6 << 4
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(len(payload)))
	ipHeader[6] = 58
	ipHeader[7] = 64
	copy(ipHeader[8:24], sourceIP)
	copy(ipHeader[24:40], destinationIP)
	return append(ipHeader, payload...)
}

func validICMPv6Checksum(packet []byte) bool {
	pseudoHeader := icmp.IPv6PseudoHeader(net.IP(packet[8:24]), net.IP(packet[24:40]))
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(packet)-ipv6.HeaderLen))
	checksumData := make([]byte, 0, len(pseudoHeader)+len(packet)-ipv6.HeaderLen)
	checksumData = append(checksumData, pseudoHeader...)
	checksumData = append(checksumData, packet[ipv6.HeaderLen:]...)
	return validInternetChecksum(checksumData)
}

func validInternetChecksum(data []byte) bool {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = uint32(uint16(sum)) + sum>>16
	}
	return uint16(sum) == 0xffff
}
