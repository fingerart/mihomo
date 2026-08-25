package proxydialer

import (
	"context"
	"net"
	"net/netip"
	"testing"

	M "github.com/metacubex/sing/common/metadata"
)

type listenAddressTestDialer struct {
	network  string
	address  string
	addrPort netip.AddrPort
}

func (*listenAddressTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (d *listenAddressTestDialer) ListenPacket(_ context.Context, network, address string, addrPort netip.AddrPort) (net.PacketConn, error) {
	d.network = network
	d.address = address
	d.addrPort = addrPort
	return net.ListenUDP(network, net.UDPAddrFromAddrPort(addrPort))
}

func TestSingDialerListensOnExplicitLocalAddress(t *testing.T) {
	baseDialer := &listenAddressTestDialer{}
	dialer := NewSingDialer(baseDialer)
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 0)
	packetConn, err := dialer.ListenPacketAddress(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })

	if baseDialer.network != "udp4" || baseDialer.address != "127.0.0.1:0" || baseDialer.addrPort != destination.AddrPort() {
		t.Fatalf("unexpected listen call: %s %s %s", baseDialer.network, baseDialer.address, baseDialer.addrPort)
	}
}
