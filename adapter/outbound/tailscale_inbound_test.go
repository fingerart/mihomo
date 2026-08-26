//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/tailscale/client/tailscale/apitype"
	"github.com/metacubex/tailscale/tailcfg"
)

type tailscaleForwardTestTCPResult struct {
	connection net.Conn
	metadata   M.Metadata
}

type tailscaleForwardTestUDPResult struct {
	key      netip.AddrPort
	payload  []byte
	metadata M.Metadata
	writer   N.PacketWriter
}

type tailscaleForwardTestHandler struct {
	tcp chan tailscaleForwardTestTCPResult
	udp chan tailscaleForwardTestUDPResult
}

func (h *tailscaleForwardTestHandler) NewConnection(_ context.Context, connection net.Conn, metadata M.Metadata) error {
	h.tcp <- tailscaleForwardTestTCPResult{connection: connection, metadata: metadata}
	return nil
}

func (h *tailscaleForwardTestHandler) NewPacket(_ context.Context, key netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	payload := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	h.udp <- tailscaleForwardTestUDPResult{
		key:      key,
		payload:  payload,
		metadata: metadata,
		writer:   init(nil),
	}
}

type tailscaleForwardTestPacketConn struct {
	packet    []byte
	writes    chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
	closedCh  chan struct{}
}

func (c *tailscaleForwardTestPacketConn) Read(payload []byte) (int, error) {
	if c.packet == nil {
		<-c.closedCh
		return 0, net.ErrClosed
	}
	n := copy(payload, c.packet)
	c.packet = nil
	return n, nil
}

func (c *tailscaleForwardTestPacketConn) Write(payload []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writes <- append([]byte(nil), payload...)
	return len(payload), nil
}

func (c *tailscaleForwardTestPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, err := c.Read(payload)
	return n, c.RemoteAddr(), err
}

func (c *tailscaleForwardTestPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return c.Write(payload)
}

func (c *tailscaleForwardTestPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
	})
	return nil
}

func (*tailscaleForwardTestPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(100, 64, 0, 2), Port: 8080}
}

func (*tailscaleForwardTestPacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1234}
}

func (*tailscaleForwardTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*tailscaleForwardTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*tailscaleForwardTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestTailscaleInboundCapability(t *testing.T) {
	disabled, err := NewTailscale(TailscaleOption{
		Name:     "tailscale-disabled",
		StateDir: "test-tailscale-disabled",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disabled.Close() })
	if disabled.VPNInbound() != nil {
		t.Fatal("inbound capability is enabled by default")
	}

	enabled, err := NewTailscale(TailscaleOption{
		Name:     "tailscale-enabled",
		StateDir: "test-tailscale-enabled",
		Inbound:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = enabled.Close() })
	if enabled.VPNInbound() == nil {
		t.Fatal("inbound capability is missing")
	}
	option := enabled.VPNInboundOption()
	if option.Name != enabled.Name() || option.Type != C.TAILSCALE {
		t.Fatalf("unexpected inbound option: %+v", option)
	}
	if option.SourceUser == nil {
		t.Fatal("Tailscale peer identity resolver is missing")
	}
}

func TestTailscaleWhoIsName(t *testing.T) {
	whoIs := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{ComputedName: "phone"},
		UserProfile: &tailcfg.UserProfile{LoginName: "owner@example.com"},
	}
	if got := tailscaleWhoIsName(whoIs); got != "phone" {
		t.Fatalf("unexpected node identity: %q", got)
	}
	whoIs.Node.ComputedName = ""
	if got := tailscaleWhoIsName(whoIs); got != "owner@example.com" {
		t.Fatalf("unexpected user identity fallback: %q", got)
	}
}

func TestTailscaleInboundForwardsTCP(t *testing.T) {
	source := netip.MustParseAddrPort("100.64.0.1:1234")
	destination := netip.MustParseAddrPort("100.64.0.2:8080")
	handler := &tailscaleForwardTestHandler{tcp: make(chan tailscaleForwardTestTCPResult, 1)}
	adapter := &Tailscale{ctx: context.Background()}
	forward, intercept := adapter.newFallbackTCPHandler(handler)(source, destination)
	if !intercept || forward == nil {
		t.Fatal("TCP flow was not intercepted")
	}
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	forward(server)

	result := <-handler.tcp
	if result.connection != server || result.metadata.Source.AddrPort() != source || result.metadata.Destination.AddrPort() != destination {
		t.Fatalf("unexpected TCP forwarding result: %+v", result)
	}
}

func TestTailscaleInboundForwardsUDP(t *testing.T) {
	source := netip.MustParseAddrPort("100.64.0.1:1234")
	destination := netip.MustParseAddrPort("100.64.0.2:8080")
	handler := &tailscaleForwardTestHandler{udp: make(chan tailscaleForwardTestUDPResult, 1)}
	adapter := &Tailscale{ctx: context.Background()}
	forward, intercept := adapter.newFallbackUDPHandler(handler)(source, destination)
	if !intercept || forward == nil {
		t.Fatal("UDP flow was not intercepted")
	}
	connection := &tailscaleForwardTestPacketConn{
		packet:   []byte("request"),
		writes:   make(chan []byte, 1),
		closedCh: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		forward(connection)
		close(done)
	}()

	result := <-handler.udp
	if !result.key.IsValid() || string(result.payload) != "request" || result.metadata.Source.AddrPort() != source || result.metadata.Destination.AddrPort() != destination {
		t.Fatalf("unexpected UDP forwarding result: %+v", result)
	}
	reply := buf.As([]byte("response")).ToOwned()
	if err := result.writer.WritePacket(reply, M.SocksaddrFromNetIP(destination)); err != nil {
		t.Fatal(err)
	}
	if got := string(<-connection.writes); got != "response" {
		t.Fatalf("unexpected UDP reply: %q", got)
	}
	if connection.closed.Load() {
		t.Fatal("UDP flow closed while it was still active")
	}
	_ = connection.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP forwarding did not exit after the flow closed")
	}
}

func TestTailscaleInboundSeparatesUDPFlows(t *testing.T) {
	source := netip.MustParseAddrPort("100.64.0.1:1234")
	destinations := []netip.AddrPort{
		netip.MustParseAddrPort("100.64.0.2:8080"),
		netip.MustParseAddrPort("100.64.0.2:8081"),
	}
	handler := &tailscaleForwardTestHandler{udp: make(chan tailscaleForwardTestUDPResult, len(destinations))}
	adapter := &Tailscale{ctx: context.Background()}
	connections := make([]*tailscaleForwardTestPacketConn, 0, len(destinations))
	for _, destination := range destinations {
		forward, intercept := adapter.newFallbackUDPHandler(handler)(source, destination)
		if !intercept || forward == nil {
			t.Fatal("UDP flow was not intercepted")
		}
		connection := &tailscaleForwardTestPacketConn{
			packet:   []byte("request"),
			writes:   make(chan []byte, 1),
			closedCh: make(chan struct{}),
		}
		connections = append(connections, connection)
		go forward(connection)
	}
	t.Cleanup(func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	})

	first := <-handler.udp
	second := <-handler.udp
	if first.key == second.key {
		t.Fatalf("distinct connected UDP flows shared NAT key %s", first.key)
	}
}

func TestTailscaleInboundUDPIdleTimeout(t *testing.T) {
	connection := &tailscaleForwardTestPacketConn{
		writes:   make(chan []byte, 1),
		closedCh: make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		forwardTailscaleUDP(
			context.Background(),
			&tailscaleForwardTestHandler{},
			connection,
			netip.MustParseAddrPort("100.64.0.1:1234"),
			tailscaleInboundMetadata(
				netip.MustParseAddrPort("100.64.0.1:1234"),
				netip.MustParseAddrPort("100.64.0.2:8080"),
			),
			10*time.Millisecond,
		)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle UDP flow was not closed")
	}
	if !connection.closed.Load() {
		t.Fatal("idle UDP connection remains open")
	}
}
