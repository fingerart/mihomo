package inbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	A "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/listener/sing_tun"

	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type wireGuardConfig struct {
	listener *WireGuard
}

func (c wireGuardConfig) Name() string {
	return c.listener.Name()
}

func (c wireGuardConfig) Equal(other C.InboundConfig) bool {
	otherConfig, ok := other.(wireGuardConfig)
	return ok && c.listener == otherConfig.listener
}

type WireGuard struct {
	adapter *outbound.WireGuard
	option  outbound.WireGuardInboundOption
}

func NewWireGuard(adapter *outbound.WireGuard) (*WireGuard, error) {
	option, enabled := adapter.InboundOption()
	if !enabled {
		return nil, C.ErrNotSupport
	}
	return &WireGuard{adapter: adapter, option: option}, nil
}

func (l *WireGuard) Name() string {
	return l.option.Name
}

func (l *WireGuard) Config() C.InboundConfig {
	return wireGuardConfig{listener: l}
}

func (l *WireGuard) RawAddress() string {
	return l.option.ListenAddress.String()
}

func (l *WireGuard) Address() string {
	if address := l.adapter.InboundAddress(); address != nil {
		return address.String()
	}
	return l.RawAddress()
}

func (l *WireGuard) Listen(tunnel C.Tunnel) error {
	baseHandler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:     tunnel,
		Type:       C.WIREGUARD,
		Additions:  []A.Addition{A.WithInName(l.Name())},
		UDPTimeout: sing.UDPTimeout,
	})
	if err != nil {
		return err
	}
	inet4Address := make([]netip.Prefix, 0, len(l.option.LocalPrefixes))
	inet6Address := make([]netip.Prefix, 0, len(l.option.LocalPrefixes))
	for _, prefix := range l.option.LocalPrefixes {
		if prefix.Addr().Is4() {
			inet4Address = append(inet4Address, netip.PrefixFrom(prefix.Addr(), 32))
		} else {
			inet6Address = append(inet6Address, netip.PrefixFrom(prefix.Addr(), 128))
		}
	}
	handler := &wireGuardForwardHandler{
		ListenerHandler: &sing_tun.ListenerHandler{
			ListenerHandler: baseHandler,
			Inet4Address:    inet4Address,
			Inet6Address:    inet6Address,
			SourceAdditions: func(source netip.Addr) []A.Addition {
				name := l.option.PeerName(source)
				if name == "" {
					return nil
				}
				return []A.Addition{A.WithInUser(name)}
			},
		},
		peerName: l.option.PeerName,
	}
	return l.adapter.RegisterInbound(handler, sing.ICMPTimeout)
}

func (l *WireGuard) Close() error {
	return l.adapter.Close()
}

type wireGuardForwardHandler struct {
	*sing_tun.ListenerHandler
	peerName func(netip.Addr) string
}

func (h *wireGuardForwardHandler) withPeer(ctx context.Context, source netip.Addr) context.Context {
	if !source.IsValid() {
		return ctx
	}
	name := h.peerName(source.Unmap())
	if name == "" {
		return ctx
	}
	return sing.WithAdditions(ctx, A.WithInUser(name))
}

func (h *wireGuardForwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return h.ListenerHandler.NewConnection(h.withPeer(ctx, metadata.Source.Addr), conn, metadata)
}

func (h *wireGuardForwardHandler) NewPacket(ctx context.Context, key netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	h.ListenerHandler.NewPacket(h.withPeer(ctx, metadata.Source.Addr), key, packet, metadata, init)
}

func (h *wireGuardForwardHandler) NewICMPConnection(ctx context.Context, source, destination netip.Addr, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	return h.PrepareConnection(
		N.NetworkICMP,
		M.SocksaddrFrom(source, 0),
		M.SocksaddrFrom(destination, 0),
		writer,
		timeout,
	)
}

var (
	_ C.InboundListener        = (*WireGuard)(nil)
	_ wireguard.ForwardHandler = (*wireGuardForwardHandler)(nil)
)
