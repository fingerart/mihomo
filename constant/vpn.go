package constant

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type VPNInboundOption struct {
	Name          string
	Type          Type
	ListenAddress netip.AddrPort
	LocalPrefixes []netip.Prefix
	SourceUser    func(netip.Addr) string
}

// VPNInbound exposes network-layer traffic from a proxy that owns virtual
// addresses and peers, such as WireGuard or Tailscale.
type VPNInbound interface {
	VPNInboundOption() VPNInboundOption
	StartVPNInbound(handler VPNForwardHandler, icmpTimeout time.Duration) error
	VPNInboundAddress() net.Addr
	Close() error
}

// VPNInboundProvider is an optional capability implemented by VPN proxies.
type VPNInboundProvider interface {
	VPNInbound() VPNInbound
}

type VPNForwardHandler interface {
	N.TCPConnectionHandler
	NewPacket(ctx context.Context, key netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter)
}

type VPNICMPForwardHandler interface {
	NewICMPConnection(ctx context.Context, source, destination netip.Addr, writer ICMPWriter, timeout time.Duration) (ICMPConnection, error)
}
