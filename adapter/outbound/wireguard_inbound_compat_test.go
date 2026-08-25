package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

type delayedWireGuardBindDialer struct {
	started    chan struct{}
	release    chan struct{}
	packetConn net.PacketConn
}

func (*delayedWireGuardBindDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, net.ErrClosed
}

func (d *delayedWireGuardBindDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	close(d.started)
	<-d.release
	return d.packetConn, nil
}

func (d *delayedWireGuardBindDialer) ListenPacketAddress(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.ListenPacket(ctx, destination)
}

func compatTestWireGuardKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func compatTestWireGuardOption() WireGuardOption {
	return WireGuardOption{
		Name:       "wg-outbound",
		Ip:         "10.0.0.1/32",
		PrivateKey: compatTestWireGuardKey(1),
		UDP:        true,
		IPStack:    IPStackOption{Mode: ipStackMips},
		Peers: []WireGuardPeerOption{{
			Server:     "127.0.0.1",
			Port:       51820,
			PublicKey:  compatTestWireGuardKey(33),
			AllowedIPs: []string{"0.0.0.0/0"},
		}},
	}
}

func TestWireGuardOutboundOnlySupportsMIPS(t *testing.T) {
	tests := []struct {
		name              string
		listen            string
		listenPort        int
		wantListenAddress string
	}{
		{name: "default"},
		{name: "fixed port", listenPort: 51820, wantListenAddress: "0.0.0.0"},
		{name: "listen address", listen: "127.0.0.1", wantListenAddress: "127.0.0.1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			option := compatTestWireGuardOption()
			option.Listen = test.listen
			option.ListenPort = test.listenPort
			adapter, err := NewWireGuard(option)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = adapter.Close() })
			if _, enabled := adapter.InboundOption(); enabled {
				t.Fatal("outbound-only WireGuard unexpectedly enabled inbound")
			}
			if test.wantListenAddress != "" && adapter.listenAddress.String() != test.wantListenAddress {
				t.Fatalf("listen address = %s, want %s", adapter.listenAddress, test.wantListenAddress)
			}
		})
	}
}

func TestWireGuardInboundSupportsMIPS(t *testing.T) {
	option := compatTestWireGuardOption()
	option.Inbound = true
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	handler := &mipsForwardTestHandler{udp: make(chan mipsForwardTestUDPResult, 1)}
	if err = adapter.tunDevice.RegisterInboundForward(handler, time.Minute); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("10.0.0.2:42000")
	destination := netip.MustParseAddrPort("198.51.100.10:53")
	packet := makeMIPSForwardTestUDPPacket(t, source, destination, []byte("wireguard mips inbound"))
	if _, err = adapter.tunDevice.Write([][]byte{packet}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case forwarded := <-handler.udp:
		if forwarded.metadata.Source.AddrPort() != source || forwarded.metadata.Destination.AddrPort() != destination {
			t.Fatalf("forwarded UDP metadata = %+v", forwarded.metadata)
		}
	case <-time.After(time.Second):
		t.Fatal("WireGuard MIPS stack did not admit a nonlocal inbound packet")
	}
}

func TestWireGuardBindCloseUnblocksWaitersAndRejectsInFlightOpen(t *testing.T) {
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	delayed := &delayedWireGuardBindDialer{
		started:    make(chan struct{}),
		release:    make(chan struct{}),
		packetConn: packetConn,
	}
	dialer := newWireGuardBindDialer(delayed, netip.AddrPort{})
	openResult := make(chan error, 1)
	go func() {
		connection, listenErr := dialer.ListenPacket(context.Background(), M.Socksaddr{})
		if connection != nil {
			_ = connection.Close()
		}
		openResult <- listenErr
	}()
	<-delayed.started
	waitResult := make(chan error, 1)
	go func() { waitResult <- dialer.WaitOpen(context.Background()) }()

	dialer.Close()
	select {
	case waitErr := <-waitResult:
		if !errors.Is(waitErr, net.ErrClosed) {
			t.Fatalf("wait after close error = %v", waitErr)
		}
	case <-time.After(time.Second):
		t.Fatal("bind close did not unblock waiter")
	}

	close(delayed.release)
	if listenErr := <-openResult; !errors.Is(listenErr, net.ErrClosed) {
		t.Fatalf("in-flight listen after close error = %v", listenErr)
	}
	if dialer.LocalAddr() != nil {
		t.Fatalf("closed bind exposed local address %v", dialer.LocalAddr())
	}
}
