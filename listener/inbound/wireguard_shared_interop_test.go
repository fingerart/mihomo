//go:build with_gvisor

package inbound_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	LI "github.com/metacubex/mihomo/listener/inbound"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/sing/common/buf"
)

type sharedWireGuardTunnel struct {
	*TestTunnel
	proxy    C.Proxy
	metadata chan C.Metadata
}

func (t *sharedWireGuardTunnel) ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	t.metadata <- *metadata
	return t.proxy, nil, nil
}

type sharedWireGuardEchoAdapter struct {
	*outbound.Base
}

func (a *sharedWireGuardEchoAdapter) DialICMP(_ context.Context, _ *C.Metadata, writer C.ICMPWriter, _ time.Duration) (C.ICMPConnection, error) {
	return &sharedWireGuardEchoConnection{writer: writer}, nil
}

type sharedWireGuardEchoConnection struct {
	writer C.ICMPWriter
}

func (c *sharedWireGuardEchoConnection) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	response := append([]byte(nil), packet.Bytes()...)
	ipHeader := header.IPv4(response)
	source := ipHeader.SourceAddress()
	ipHeader.SetSourceAddress(ipHeader.DestinationAddress())
	ipHeader.SetDestinationAddress(source)
	ipHeader.SetChecksum(0)
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	icmpHeader := header.ICMPv4(ipHeader.Payload())
	icmpHeader.SetType(header.ICMPv4EchoReply)
	icmpHeader.SetChecksum(0)
	icmpHeader.SetChecksum(header.ICMPv4Checksum(icmpHeader, 0))
	return c.writer.WritePacket(response)
}

func (*sharedWireGuardEchoConnection) Close() error   { return nil }
func (*sharedWireGuardEchoConnection) IsClosed() bool { return false }

type sharedWireGuardReplyWriter struct {
	packets chan []byte
}

func (w *sharedWireGuardReplyWriter) WritePacket(packet []byte) error {
	w.packets <- append([]byte(nil), packet...)
	return nil
}

func sharedWireGuardKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(privateKey.Bytes()), base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func sharedWireGuardEchoRequest(source, destination netip.Addr) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+4)
	ipHeader := header.IPv4(packet)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     sharedWireGuardAddressFromAddr(source),
		DstAddr:     sharedWireGuardAddressFromAddr(destination),
	})
	icmpHeader := header.ICMPv4(ipHeader.Payload())
	icmpHeader.SetType(header.ICMPv4Echo)
	icmpHeader.SetChecksum(header.ICMPv4Checksum(icmpHeader, 0))
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	return packet
}

func sharedWireGuardAddressFromAddr(address netip.Addr) tcpip.Address {
	if address.Is4() {
		return tcpip.AddrFrom4(address.As4())
	}
	return tcpip.AddrFrom16(address.As16())
}

func TestWireGuardProxySharesDeviceWithInboundTraffic(t *testing.T) {
	serverPrivateKey, serverPublicKey := sharedWireGuardKeyPair(t)
	clientPrivateKey, clientPublicKey := sharedWireGuardKeyPair(t)
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	if err = probe.Close(); err != nil {
		t.Fatal(err)
	}

	const (
		tcpPayload = "wireguard-inbound"
		udpPayload = "wireguard-inbound-udp"
	)
	localService, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = localService.Close() })
	localServiceResult := make(chan error, 1)
	go func() {
		connection, acceptErr := localService.Accept()
		if acceptErr != nil {
			localServiceResult <- acceptErr
			return
		}
		defer connection.Close()
		request := make([]byte, len(tcpPayload))
		if _, acceptErr = io.ReadFull(connection, request); acceptErr == nil {
			_, acceptErr = connection.Write(request)
		}
		localServiceResult <- acceptErr
	}()
	localPacketService, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = localPacketService.Close() })
	localPacketServiceResult := make(chan error, 1)
	go func() {
		packet := make([]byte, len(udpPayload))
		n, source, packetErr := localPacketService.ReadFromUDP(packet)
		if packetErr == nil {
			_, packetErr = localPacketService.WriteToUDP(packet[:n], source)
		}
		localPacketServiceResult <- packetErr
	}()

	tcpMetadata := make(chan C.Metadata, 1)
	localMetadata := make(chan C.Metadata, 1)
	localPacketMetadata := make(chan C.Metadata, 1)
	localPacketResult := make(chan error, 1)
	direct := outbound.NewDirect()
	serverAddress := netip.MustParseAddr("10.0.0.1")
	baseTunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			if metadata.DstIP == serverAddress {
				localMetadata <- *metadata
				remote, dialErr := direct.DialContext(context.Background(), metadata)
				if dialErr != nil {
					localServiceResult <- dialErr
					return
				}
				defer remote.Close()
				N.Relay(conn, remote)
				return
			}
			tcpMetadata <- *metadata
			request := make([]byte, len(tcpPayload))
			if _, err := io.ReadFull(conn, request); err != nil {
				return
			}
			_, _ = conn.Write(request)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			go func() {
				defer packet.Drop()
				localPacketMetadata <- *metadata
				dialMetadata := metadata.Clone()
				connection, packetErr := direct.ListenPacketContext(context.Background(), dialMetadata)
				if packetErr == nil && dialMetadata.DstIP != serverAddress {
					packetErr = fmt.Errorf("DIRECT changed routed destination to %s", dialMetadata.DstIP)
				}
				if packetErr == nil {
					defer connection.Close()
					packetErr = connection.SetDeadline(time.Now().Add(time.Second))
				}
				if packetErr == nil {
					_, packetErr = connection.WriteTo(packet.Data(), dialMetadata.UDPAddr())
				}
				response := make([]byte, len(udpPayload))
				var n int
				var responseSource net.Addr
				if packetErr == nil {
					n, responseSource, packetErr = connection.ReadFrom(response)
				}
				if packetErr == nil {
					expectedSource := netip.AddrPortFrom(serverAddress, metadata.DstPort).String()
					if responseSource.String() != expectedSource {
						packetErr = fmt.Errorf("DIRECT returned local UDP source %s, expected %s", responseSource, expectedSource)
					}
				}
				if packetErr == nil {
					_, packetErr = packet.WriteBack(response[:n], responseSource)
				}
				localPacketResult <- packetErr
			}()
		},
		CloseFn: func() error { return nil },
	}
	echoAdapter := &sharedWireGuardEchoAdapter{Base: outbound.NewBase(outbound.BaseOption{
		Name: "icmp-echo",
		Type: C.Direct,
	})}
	tunnel := &sharedWireGuardTunnel{
		TestTunnel: baseTunnel,
		proxy:      A.NewProxy(echoAdapter),
		metadata:   make(chan C.Metadata, 1),
	}
	t.Cleanup(func() { _ = tunnel.Close() })

	server, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wg-server",
		Ip:         "10.0.0.1/24",
		PrivateKey: serverPrivateKey,
		UDP:        true,
		Inbound:    true,
		Listen:     "127.0.0.1",
		ListenPort: int(port),
		IPStack:    outbound.IPStackOption{Mode: "gvisor"},
		Peers: []outbound.WireGuardPeerOption{{
			Name:       "client",
			PublicKey:  clientPublicKey,
			AllowedIPs: []string{"10.0.0.2/32"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverListener, err := LI.NewVPN(server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverListener.Close() })
	if err = serverListener.Listen(tunnel); err != nil {
		t.Fatal(err)
	}

	client, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wg-client",
		Ip:         "10.0.0.2/24",
		PrivateKey: clientPrivateKey,
		UDP:        true,
		IPStack:    outbound.IPStackOption{Mode: "gvisor"},
		Peers: []outbound.WireGuardPeerOption{{
			Server:     "127.0.0.1",
			Port:       int(port),
			PublicKey:  serverPublicKey,
			AllowedIPs: []string{"10.0.0.0/24", "1.2.3.4/32"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	originalSource := netip.MustParseAddr("192.0.2.10")
	destination := netip.MustParseAddr("10.0.0.3")
	replyWriter := &sharedWireGuardReplyWriter{packets: make(chan []byte, 1)}
	connection, err := client.DialICMP(context.Background(), &C.Metadata{
		NetWork: C.ICMP,
		SrcIP:   originalSource,
		DstIP:   destination,
	}, replyWriter, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	request := sharedWireGuardEchoRequest(originalSource, destination)
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if err = connection.WritePacket(buf.As(request).ToOwned()); err != nil {
			t.Fatal(err)
		}
		select {
		case packet := <-replyWriter.packets:
			ipHeader := header.IPv4(packet)
			if got := netip.AddrFrom4(ipHeader.DestinationAddress().As4()); got != originalSource {
				t.Fatalf("unexpected reply destination: %s", got)
			}
			goto receivedReply
		case <-retry.C:
		case <-deadline.C:
			t.Fatal("timed out waiting for ICMP reply through shared WireGuard device")
		}
	}

receivedReply:

	select {
	case metadata := <-tunnel.metadata:
		if metadata.Type != C.WIREGUARD || metadata.InName != "wg-server" || metadata.InUser != "client" {
			t.Fatalf("unexpected inbound metadata: %+v", metadata)
		}
		if metadata.SrcIP != netip.MustParseAddr("10.0.0.2") || metadata.DstIP != destination {
			t.Fatalf("unexpected routed addresses: %+v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard inbound did not reach rule resolution")
	}

	tcpConnection, err := client.DialContext(context.Background(), &C.Metadata{
		NetWork: C.TCP,
		DstIP:   remoteAddr,
		DstPort: 80,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpConnection.Close() })
	if err = tcpConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = tcpConnection.Write([]byte(tcpPayload)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(tcpPayload))
	if _, err = io.ReadFull(tcpConnection, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != tcpPayload {
		t.Fatalf("unexpected TCP reply: %q", reply)
	}

	select {
	case metadata := <-tcpMetadata:
		if metadata.Type != C.WIREGUARD || metadata.InName != "wg-server" || metadata.InUser != "client" {
			t.Fatalf("unexpected TCP inbound metadata: %+v", metadata)
		}
		if metadata.SrcIP != netip.MustParseAddr("10.0.0.2") || metadata.DstIP != remoteAddr {
			t.Fatalf("unexpected TCP routed addresses: %+v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard TCP inbound did not reach rule resolution")
	}

	localConnection, err := client.DialContext(context.Background(), &C.Metadata{
		NetWork: C.TCP,
		DstIP:   serverAddress,
		DstPort: localService.Addr().(*net.TCPAddr).AddrPort().Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = localConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = localConnection.Write([]byte(tcpPayload)); err != nil {
		t.Fatal(err)
	}
	reply = make([]byte, len(tcpPayload))
	if _, err = io.ReadFull(localConnection, reply); err != nil {
		t.Fatal(err)
	}
	if err = localConnection.Close(); err != nil {
		t.Fatal(err)
	}
	if string(reply) != tcpPayload {
		t.Fatalf("unexpected local service reply: %q", reply)
	}
	select {
	case metadata := <-localMetadata:
		if metadata.DstIP != serverAddress {
			t.Fatalf("local service routing lost the original destination: %+v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard local service traffic did not reach rule resolution")
	}
	select {
	case err = <-localServiceResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard local service did not complete")
	}

	packetConnection, err := client.ListenPacketContext(context.Background(), &C.Metadata{
		NetWork: C.UDP,
		DstIP:   serverAddress,
		DstPort: localPacketService.LocalAddr().(*net.UDPAddr).AddrPort().Port(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConnection.Close() })
	if err = packetConnection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packetDestination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(serverAddress, localPacketService.LocalAddr().(*net.UDPAddr).AddrPort().Port()))
	if _, err = packetConnection.WriteTo([]byte(udpPayload), packetDestination); err != nil {
		t.Fatal(err)
	}
	packetReply := make([]byte, len(udpPayload))
	n, source, err := packetConnection.ReadFrom(packetReply)
	if err != nil {
		t.Fatal(err)
	}
	if string(packetReply[:n]) != udpPayload || source.String() != packetDestination.String() {
		t.Fatalf("unexpected local UDP service reply %q from %s", packetReply[:n], source)
	}
	select {
	case metadata := <-localPacketMetadata:
		if metadata.DstIP != serverAddress {
			t.Fatalf("local UDP service routing lost the original destination: %+v", metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard local UDP service traffic did not reach rule resolution")
	}
	for name, result := range map[string]<-chan error{
		"local UDP forwarding": localPacketResult,
		"local UDP service":    localPacketServiceResult,
	} {
		select {
		case err = <-result:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not complete", name)
		}
	}
}

func TestWireGuardInboundReportsListenPortConflict(t *testing.T) {
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	port := occupied.LocalAddr().(*net.UDPAddr).AddrPort().Port()

	privateKey, _ := sharedWireGuardKeyPair(t)
	_, peerPublicKey := sharedWireGuardKeyPair(t)
	adapter, err := outbound.NewWireGuard(outbound.WireGuardOption{
		Name:       "wg-conflict",
		Ip:         "10.0.0.1/24",
		PrivateKey: privateKey,
		UDP:        true,
		Inbound:    true,
		Listen:     "127.0.0.1",
		ListenPort: int(port),
		IPStack:    outbound.IPStackOption{Mode: "gvisor"},
		Peers: []outbound.WireGuardPeerOption{{
			PublicKey:  peerPublicKey,
			AllowedIPs: []string{"10.0.0.2/32"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := LI.NewVPN(adapter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { _ = tunnel.Close() })

	if err = listener.Listen(tunnel); err == nil {
		t.Fatal("expected occupied WireGuard listen port to fail")
	}
	if err = occupied.Close(); err != nil {
		t.Fatal(err)
	}
	if err = listener.Listen(tunnel); err != nil {
		t.Fatalf("retry after releasing WireGuard listen port: %v", err)
	}
}
