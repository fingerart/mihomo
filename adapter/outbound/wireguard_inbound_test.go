//go:build with_gvisor

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

type inboundTestSocketDialer struct {
	connected   atomic.Int32
	unconnected atomic.Int32
}

func (d *inboundTestSocketDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.connected.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (d *inboundTestSocketDialer) ListenPacket(ctx context.Context, network, address string, _ netip.AddrPort) (net.PacketConn, error) {
	d.unconnected.Add(1)
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func inboundTestWireGuardKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func inboundTestWireGuardOption() WireGuardOption {
	return WireGuardOption{
		Name:       "wg-node",
		Ip:         "10.0.0.1/24",
		PrivateKey: inboundTestWireGuardKey(1),
		UDP:        true,
		Inbound:    true,
		Listen:     "127.0.0.1",
		ListenPort: 51820,
		IPStack:    IPStackOption{Mode: ipStackGVisor},
		Peers: []WireGuardPeerOption{{
			Name:       "phone",
			PublicKey:  inboundTestWireGuardKey(33),
			AllowedIPs: []string{"10.0.0.2/32"},
		}},
	}
}

func TestWireGuardExposesInboundFromOutboundInstance(t *testing.T) {
	adapter, err := NewWireGuard(inboundTestWireGuardOption())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	option, enabled := adapter.InboundOption()
	if !enabled {
		t.Fatal("expected inbound capability")
	}
	if option.Name != adapter.Name() || option.ListenAddress.String() != "127.0.0.1:51820" {
		t.Fatalf("unexpected inbound option: %+v", option)
	}
}

func TestWireGuardAllowsPassivePeerWithoutFixedListenPort(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Listen = ""
	option.ListenPort = 0
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	adapter.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	config, err := adapter.genIpcConf(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(config, "listen_port=") || strings.Contains(config, "endpoint=") {
		t.Fatalf("unexpected fixed endpoint in passive IPC config:\n%s", config)
	}
}

func TestWireGuardAllowsActiveAndPassivePeersOnSharedEphemeralSocket(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Listen = ""
	option.ListenPort = 0
	option.Peers = []WireGuardPeerOption{
		{
			Name:       "active",
			Server:     "127.0.0.1",
			Port:       51820,
			PublicKey:  inboundTestWireGuardKey(33),
			AllowedIPs: []string{"10.0.0.2/32"},
		},
		{
			Name:       "passive",
			PublicKey:  inboundTestWireGuardKey(65),
			AllowedIPs: []string{"10.0.0.3/32"},
		},
	}
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	adapter.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	config, err := adapter.genIpcConf(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(config, "public_key="); got != 2 {
		t.Fatalf("expected two peers in IPC config, got %d:\n%s", got, config)
	}
	if got := strings.Count(config, "endpoint="); got != 1 {
		t.Fatalf("expected only the active peer endpoint, got %d:\n%s", got, config)
	}
}

func TestWireGuardInboundUsesUnconnectedEphemeralSocket(t *testing.T) {
	endpoint, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })

	dialer := &inboundTestSocketDialer{}
	option := inboundTestWireGuardOption()
	option.Listen = ""
	option.ListenPort = 0
	option.DialerForAPI = dialer
	option.Peers[0].Server = "127.0.0.1"
	option.Peers[0].Port = int(endpoint.LocalAddr().(*net.UDPAddr).AddrPort().Port())
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	if err = adapter.init(context.Background()); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && dialer.connected.Load() == 0 && dialer.unconnected.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if dialer.unconnected.Load() == 0 || dialer.connected.Load() != 0 {
		t.Fatalf("inbound WireGuard used connected=%d unconnected=%d UDP sockets", dialer.connected.Load(), dialer.unconnected.Load())
	}
	localAddress := M.SocksaddrFromNet(adapter.InboundAddress())
	if !localAddress.IsValid() || localAddress.Port == 0 {
		t.Fatalf("inbound WireGuard did not expose its ephemeral UDP address: %v", adapter.InboundAddress())
	}
}

func TestWireGuardInboundHonorsListenAddressWithEphemeralPort(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.ListenPort = 0
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = adapter.init(ctx); err != nil {
		t.Fatal(err)
	}
	localAddress := M.SocksaddrFromNet(adapter.InboundAddress())
	if localAddress.Addr != netip.MustParseAddr("127.0.0.1") || localAddress.Port == 0 {
		t.Fatalf("inbound WireGuard listen address = %v", adapter.InboundAddress())
	}
}

func TestWireGuardIPCAllowsPassivePeer(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.PersistentKeepalive = 25
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	adapter.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)

	config, err := adapter.genIpcConf(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "listen_port=51820\n") {
		t.Fatalf("listen port is missing from IPC config:\n%s", config)
	}
	if strings.Contains(config, "endpoint=") {
		t.Fatalf("passive peer unexpectedly has an endpoint:\n%s", config)
	}
	if !strings.Contains(config, "allowed_ip=10.0.0.2/32\n") {
		t.Fatalf("allowed IP is missing from IPC config:\n%s", config)
	}
	if !strings.Contains(config, "persistent_keepalive_interval=25\n") {
		t.Fatalf("persistent keepalive is missing from passive peer:\n%s", config)
	}
	if got := adapter.peerName(netip.MustParseAddr("10.0.0.2")); got != "phone" {
		t.Fatalf("unexpected inbound peer name: %q", got)
	}
}

func TestWireGuardIPCAllowsLegacyActivePeerWithListener(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Peers = nil
	option.WireGuardPeerOption = WireGuardPeerOption{
		Server:    "127.0.0.1",
		Port:      51821,
		PublicKey: inboundTestWireGuardKey(33),
	}
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	adapter.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)

	config, err := adapter.genIpcConf(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "endpoint=127.0.0.1:51821\n") {
		t.Fatalf("legacy peer endpoint is missing from IPC config:\n%s", config)
	}
}

func TestWireGuardRejectsPartialPeerEndpoint(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Peers[0].Server = "127.0.0.1"
	_, err := NewWireGuard(option)
	if err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Fatalf("expected endpoint validation error, got %v", err)
	}
}

func TestWireGuardInboundAutoSelectsGVisor(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.IPStack = IPStackOption{}
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	if _, enabled := adapter.InboundOption(); !enabled {
		t.Fatal("auto gVisor mode did not enable inbound")
	}
}

func TestWireGuardInboundRejectsDialerProxy(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.DialerProxy = "upstream"
	_, err := NewWireGuard(option)
	if err == nil || !strings.Contains(err.Error(), "dialer-proxy") {
		t.Fatalf("expected dialer-proxy compatibility error, got %v", err)
	}
}

func TestWireGuardAutomaticInboundAllowsDialerProxy(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Listen = ""
	option.ListenPort = 0
	option.DialerProxy = "upstream"
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	if adapter.listenAddress.IsValid() {
		t.Fatalf("automatic inbound unexpectedly became an explicit IPv4 bind: %s", adapter.listenAddress)
	}
}

func TestWireGuardRegisterInboundRequiresInboundOption(t *testing.T) {
	option := inboundTestWireGuardOption()
	option.Inbound = false
	option.Listen = ""
	option.ListenPort = 0
	adapter, err := NewWireGuard(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	if err = adapter.RegisterInbound(nil, 0); !errors.Is(err, C.ErrNotSupport) {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}
