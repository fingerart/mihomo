package outbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type mipsForwardTestTCPResult struct {
	connection net.Conn
	metadata   M.Metadata
}

type mipsForwardTestUDPResult struct {
	key      netip.AddrPort
	payload  []byte
	metadata M.Metadata
	writer   N.PacketWriter
}

type mipsForwardTestICMPResult struct {
	source      netip.Addr
	destination netip.Addr
	timeout     time.Duration
	connection  *mipsForwardTestICMPConnection
}

type mipsForwardTestHandler struct {
	tcp       chan mipsForwardTestTCPResult
	udp       chan mipsForwardTestUDPResult
	icmp      chan mipsForwardTestICMPResult
	icmpInput chan []byte
	icmpReply []byte
	icmpErr   error
}

type wireGuardForwardTestTCPUDPHandler struct{}

func (*wireGuardForwardTestTCPUDPHandler) NewConnection(_ context.Context, connection net.Conn, _ M.Metadata) error {
	return connection.Close()
}

func (*wireGuardForwardTestTCPUDPHandler) NewPacket(_ context.Context, _ netip.AddrPort, packet *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
	packet.Release()
}

func (h *mipsForwardTestHandler) NewConnection(_ context.Context, connection net.Conn, metadata M.Metadata) error {
	h.tcp <- mipsForwardTestTCPResult{connection: connection, metadata: metadata}
	return nil
}

func (h *mipsForwardTestHandler) NewPacket(_ context.Context, key netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	payload := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	h.udp <- mipsForwardTestUDPResult{
		key:      key,
		payload:  payload,
		metadata: metadata,
		writer:   init(nil),
	}
}

func (h *mipsForwardTestHandler) NewICMPConnection(_ context.Context, source, destination netip.Addr, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	if h.icmpErr != nil {
		return nil, h.icmpErr
	}
	connection := &mipsForwardTestICMPConnection{writer: writer, input: h.icmpInput, reply: h.icmpReply}
	h.icmp <- mipsForwardTestICMPResult{source: source, destination: destination, timeout: timeout, connection: connection}
	return connection, nil
}

type mipsForwardTestICMPConnection struct {
	writer C.ICMPWriter
	input  chan []byte
	reply  []byte
	closed atomic.Bool
}

func (c *mipsForwardTestICMPConnection) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	c.input <- append([]byte(nil), packet.Bytes()...)
	return c.writer.WritePacket(c.reply)
}

func (c *mipsForwardTestICMPConnection) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *mipsForwardTestICMPConnection) IsClosed() bool {
	return c.closed.Load()
}

func newMIPSForwardTestStack(t *testing.T, address netip.Addr, promiscuous bool) ipStack {
	t.Helper()
	stack, err := newIPStack(
		IPStackOption{Mode: ipStackMips},
		[]netip.Prefix{netip.PrefixFrom(address, address.BitLen())},
		1400,
		promiscuous,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = stack.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	return stack
}

func bridgeMIPSForwardTestStacks(left, right ipStack) {
	copyPackets := func(source, target ipStack) {
		buffers := make([][]byte, source.BatchSize())
		sizes := make([]int, len(buffers))
		for index := range buffers {
			buffers[index] = make([]byte, 2048)
		}
		for {
			count, err := source.Read(buffers, sizes, 0)
			if err != nil {
				return
			}
			packets := make([][]byte, count)
			for index := 0; index < count; index++ {
				packets[index] = buffers[index][:sizes[index]]
			}
			if _, err = target.Write(packets, 0); err != nil {
				return
			}
		}
	}
	go copyPackets(left, right)
	go copyPackets(right, left)
}

func registerMIPSForwardTestHandler(t *testing.T, stack ipStack, handler wireguard.ForwardHandler) {
	t.Helper()
	forwarder, ok := stack.(wireguard.RegisterForward)
	if !ok {
		t.Fatal("MIPS stack does not implement inbound forwarding")
	}
	if err := forwarder.RegisterForward(wireguard.ForwardOptions{Handler: handler}); err != nil {
		t.Fatal(err)
	}
}

func TestMIPSInboundForwardsTCP(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.10")
	serverAddress := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddrPort("198.51.100.20:8080")
	client := newMIPSForwardTestStack(t, clientAddress, false)
	server := newMIPSForwardTestStack(t, serverAddress, true)
	bridgeMIPSForwardTestStacks(client, server)

	handler := &mipsForwardTestHandler{tcp: make(chan mipsForwardTestTCPResult, 1)}
	registerMIPSForwardTestHandler(t, server, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientConnection, err := client.DialTCP(ctx, "tcp4", netip.AddrPort{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()

	var forwarded mipsForwardTestTCPResult
	select {
	case forwarded = <-handler.tcp:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer forwarded.connection.Close()
	if forwarded.metadata.Source.Addr != clientAddress || forwarded.metadata.Destination.AddrPort() != target {
		t.Fatalf("forwarded TCP metadata = %+v", forwarded.metadata)
	}
	if forwarded.metadata.Source.Port != uint16(clientConnection.LocalAddr().(*net.TCPAddr).Port) {
		t.Fatalf("forwarded TCP source port = %d, want %d", forwarded.metadata.Source.Port, clientConnection.LocalAddr().(*net.TCPAddr).Port)
	}

	request := []byte("mips inbound tcp")
	if _, err = clientConnection.Write(request); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(request))
	if _, err = io.ReadFull(forwarded.connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, request) {
		t.Fatalf("forwarded TCP payload = %q", received)
	}
}

func TestMIPSInboundForwardsUDPReply(t *testing.T) {
	clientAddress := netip.MustParseAddr("192.0.2.30")
	serverAddress := netip.MustParseAddr("192.0.2.1")
	target := netip.MustParseAddrPort("198.51.100.40:5353")
	client := newMIPSForwardTestStack(t, clientAddress, false)
	server := newMIPSForwardTestStack(t, serverAddress, true)
	bridgeMIPSForwardTestStacks(client, server)

	handler := &mipsForwardTestHandler{udp: make(chan mipsForwardTestUDPResult, 1)}
	registerMIPSForwardTestHandler(t, server, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientConnection, err := client.DialUDP(ctx, "udp4", netip.AddrPort{}, target)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	if err = clientConnection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	request := []byte("mips inbound udp")
	if _, err = clientConnection.Write(request); err != nil {
		t.Fatal(err)
	}

	var forwarded mipsForwardTestUDPResult
	select {
	case forwarded = <-handler.udp:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	clientSource := clientConnection.LocalAddr().(*net.UDPAddr).AddrPort()
	if forwarded.key != clientSource || forwarded.metadata.Source.AddrPort() != clientSource || forwarded.metadata.Destination.AddrPort() != target {
		t.Fatalf("forwarded UDP key/metadata = %s %+v", forwarded.key, forwarded.metadata)
	}
	if !bytes.Equal(forwarded.payload, request) {
		t.Fatalf("forwarded UDP payload = %q", forwarded.payload)
	}
	reply := []byte("mips inbound udp reply")
	if err = forwarded.writer.WritePacket(buf.As(reply).ToOwned(), M.SocksaddrFrom(target.Addr(), target.Port())); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(reply))
	n, err := clientConnection.Read(received)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received[:n], reply) {
		t.Fatalf("forwarded UDP reply = %q", received[:n])
	}
}

func TestMIPSInboundForwardsICMPPacketAndReply(t *testing.T) {
	serverAddress := netip.MustParseAddr("192.0.2.1")
	source := netip.MustParseAddr("192.0.2.50")
	destination := netip.MustParseAddr("198.51.100.60")
	server := newMIPSForwardTestStack(t, serverAddress, true)
	device, err := newWireguardDevice(server)
	if err != nil {
		t.Fatal(err)
	}
	request := makeMIPSForwardTestEchoPacket(t, source, destination, false)
	reply := makeMIPSForwardTestEchoPacket(t, destination, source, true)
	handler := &mipsForwardTestHandler{
		icmp:      make(chan mipsForwardTestICMPResult, 1),
		icmpInput: make(chan []byte, 1),
		icmpReply: reply,
	}
	const timeout = 17 * time.Second
	if err = device.RegisterInboundForward(handler, timeout); err != nil {
		t.Fatal(err)
	}

	if _, err = device.Write([][]byte{request}, 0); err != nil {
		t.Fatal(err)
	}
	var session mipsForwardTestICMPResult
	select {
	case session = <-handler.icmp:
		if session.source != source || session.destination != destination || session.timeout != timeout {
			t.Fatalf("forwarded ICMP session = %+v", session)
		}
	case <-time.After(time.Second):
		t.Fatal("ICMP session was not forwarded")
	}
	select {
	case input := <-handler.icmpInput:
		if !bytes.Equal(input, request) {
			t.Fatalf("forwarded ICMP packet = %x", input)
		}
	case <-time.After(time.Second):
		t.Fatal("ICMP packet was not forwarded")
	}
	if _, err = device.Write([][]byte{request}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case input := <-handler.icmpInput:
		if !bytes.Equal(input, request) {
			t.Fatalf("reused ICMP session packet = %x", input)
		}
	case <-time.After(time.Second):
		t.Fatal("second ICMP packet was not forwarded")
	}
	select {
	case session := <-handler.icmp:
		t.Fatalf("ICMP session was not reused: %+v", session)
	default:
	}
	fragments := fragmentMIPSForwardTestIPv4Packet(t, request)
	for _, fragment := range fragments {
		if _, err = device.Write([][]byte{fragment}, 0); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case input := <-handler.icmpInput:
		parsed, parseErr := mipstack.ParseIPPacket(input)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		message, messageErr := parsed.ICMPMessage()
		if messageErr != nil || !message.IsEchoRequest() || parsed.Source != source || parsed.Destination != destination {
			t.Fatalf("reassembled ICMP packet = %+v, %v", parsed, messageErr)
		}
	case <-time.After(time.Second):
		t.Fatal("fragmented ICMP packet was not reassembled")
	}

	outbound := make(chan []byte, 1)
	go func() {
		buffers := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		count, err := server.Read(buffers, sizes, 0)
		if err == nil && count == 1 {
			outbound <- append([]byte(nil), buffers[0][:sizes[0]]...)
		}
	}()
	select {
	case packet := <-outbound:
		parsed, err := mipstack.ParseIPPacket(packet)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Source != destination || parsed.Destination != source || parsed.Protocol != mipstack.ProtocolICMPv4 {
			t.Fatalf("forwarded ICMP reply packet = %+v", parsed)
		}
		message, err := parsed.ICMPMessage()
		if err != nil {
			t.Fatal(err)
		}
		identifier, sequence, payload, ok := message.Echo()
		if !ok || !message.IsEchoReply() || identifier != 7 || sequence != 11 || string(payload) != "mips icmp" {
			t.Fatalf("forwarded ICMP reply message = %+v", message)
		}
	case <-time.After(time.Second):
		t.Fatal("ICMP reply was not written to MIPS")
	}
	if err = device.Close(); err != nil {
		t.Fatal(err)
	}
	if !session.connection.closed.Load() {
		t.Fatal("closing MIPS did not close the forwarded ICMP session")
	}
}

func TestWireGuardICMPInboundRejectsReset(t *testing.T) {
	serverAddress := netip.MustParseAddr("192.0.2.1")
	source := netip.MustParseAddr("192.0.2.70")
	destination := netip.MustParseAddr("198.51.100.80")
	server := newMIPSForwardTestStack(t, serverAddress, true)
	device, err := newWireguardDevice(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	if err = device.RegisterInboundForward(&mipsForwardTestHandler{icmpErr: tun.ErrReset}, time.Second); err != nil {
		t.Fatal(err)
	}
	request := makeMIPSForwardTestEchoPacket(t, source, destination, false)
	if _, err = device.Write([][]byte{request}, 0); err != nil {
		t.Fatal(err)
	}

	outbound := make(chan []byte, 1)
	go func() {
		buffers := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		count, readErr := device.Read(buffers, sizes, 0)
		if readErr == nil && count == 1 {
			outbound <- append([]byte(nil), buffers[0][:sizes[0]]...)
		}
	}()
	select {
	case packet := <-outbound:
		parsed, parseErr := mipstack.ParseIPPacket(packet)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		message, messageErr := parsed.ICMPMessage()
		if messageErr != nil || message.Type != mipstack.ICMPv4TypeDestinationUnreachable || message.Code != mipstack.ICMPv4DestinationUnreachableCodeHost {
			t.Fatalf("ICMP rejection = %+v, %v", message, messageErr)
		}
	case <-time.After(time.Second):
		t.Fatal("ICMP reset did not emit a rejection")
	}
}

func TestWireGuardInboundWritesMixedICMPAndUDPBatch(t *testing.T) {
	serverAddress := netip.MustParseAddr("192.0.2.1")
	sourceAddress := netip.MustParseAddr("192.0.2.90")
	icmpDestination := netip.MustParseAddr("198.51.100.91")
	server := newMIPSForwardTestStack(t, serverAddress, true)
	device, err := newWireguardDevice(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = device.Close() })
	handler := &mipsForwardTestHandler{
		udp:       make(chan mipsForwardTestUDPResult, 1),
		icmp:      make(chan mipsForwardTestICMPResult, 1),
		icmpInput: make(chan []byte, 1),
		icmpReply: makeMIPSForwardTestEchoPacket(t, icmpDestination, sourceAddress, true),
	}
	if err = device.RegisterInboundForward(handler, time.Second); err != nil {
		t.Fatal(err)
	}
	icmpRequest := makeMIPSForwardTestEchoPacket(t, sourceAddress, icmpDestination, false)
	udpRequest := makeMIPSForwardTestUDPPacket(
		t,
		netip.AddrPortFrom(sourceAddress, 42000),
		netip.MustParseAddrPort("198.51.100.92:53"),
		[]byte("mixed batch"),
	)
	written, err := device.Write([][]byte{icmpRequest, udpRequest}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if written != 2 {
		t.Fatalf("mixed batch written = %d, want 2", written)
	}
	select {
	case <-handler.icmpInput:
	case <-time.After(time.Second):
		t.Fatal("mixed batch ICMP packet was not forwarded")
	}
	select {
	case <-handler.udp:
	case <-time.After(time.Second):
		t.Fatal("mixed batch UDP packet was not forwarded")
	}
}

func TestWireGuardInboundRejectsRegistrationAfterClose(t *testing.T) {
	stack := newMIPSForwardTestStack(t, netip.MustParseAddr("192.0.2.1"), true)
	device, err := newWireguardDevice(stack)
	if err != nil {
		t.Fatal(err)
	}
	if err = device.Close(); err != nil {
		t.Fatal(err)
	}
	handler := &wireGuardForwardTestTCPUDPHandler{}
	if err = device.RegisterInboundForward(handler, time.Second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("register after close error = %v", err)
	}
}

func makeMIPSForwardTestEchoPacket(t *testing.T, source, destination netip.Addr, reply bool) []byte {
	t.Helper()
	message := mipstack.ICMPMessage{Source: source, Destination: destination}
	var err error
	if reply {
		err = message.SetEchoReply(7, 11, []byte("mips icmp"))
	} else {
		err = message.SetEchoRequest(7, 11, []byte("mips icmp"))
	}
	if err != nil {
		t.Fatal(err)
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := (mipstack.IPPacket{
		Source:      source,
		Destination: destination,
		Protocol:    mipstack.ProtocolICMPv4,
		HopLimit:    64,
		Payload:     payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func makeMIPSForwardTestUDPPacket(t *testing.T, source, destination netip.AddrPort, payload []byte) []byte {
	t.Helper()
	datagram, err := (mipstack.UDPDatagram{
		Source:      source,
		Destination: destination,
		Payload:     payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := (mipstack.IPPacket{
		Source:      source.Addr(),
		Destination: destination.Addr(),
		Protocol:    mipstack.ProtocolUDP,
		HopLimit:    64,
		Payload:     datagram,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func fragmentMIPSForwardTestIPv4Packet(t *testing.T, packet []byte) [][]byte {
	t.Helper()
	parsed, err := mipstack.ParseIPPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Payload) <= 8 {
		t.Fatal("test packet is too small to fragment")
	}
	first := parsed
	first.Identification = 41
	first.MoreFragments = true
	first.Payload = parsed.Payload[:8]
	second := parsed
	second.Identification = 41
	second.FragmentOffset = 8
	second.Payload = parsed.Payload[8:]
	fragments := make([][]byte, 2)
	fragments[0], err = first.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fragments[1], err = second.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return fragments
}

var _ wireguard.ForwardHandler = (*mipsForwardTestHandler)(nil)
var _ wireGuardICMPForwardHandler = (*mipsForwardTestHandler)(nil)
