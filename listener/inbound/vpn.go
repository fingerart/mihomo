package inbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	A "github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/listener/sing_tun"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type vpnConfig struct {
	listener *VPN
}

func (c vpnConfig) Name() string {
	return c.listener.Name()
}

func (c vpnConfig) Equal(other C.InboundConfig) bool {
	otherConfig, ok := other.(vpnConfig)
	return ok && c.listener == otherConfig.listener
}

type VPN struct {
	adapter C.VPNInbound
	option  C.VPNInboundOption
}

func NewVPN(adapter C.VPNInbound) (*VPN, error) {
	if adapter == nil {
		return nil, C.ErrNotSupport
	}
	return &VPN{adapter: adapter, option: adapter.VPNInboundOption()}, nil
}

func (l *VPN) Name() string {
	return l.option.Name
}

func (l *VPN) Config() C.InboundConfig {
	return vpnConfig{listener: l}
}

func (l *VPN) RawAddress() string {
	return l.option.ListenAddress.String()
}

func (l *VPN) Address() string {
	if address := l.adapter.VPNInboundAddress(); address != nil {
		return address.String()
	}
	return l.RawAddress()
}

func (l *VPN) Listen(tunnel C.Tunnel) error {
	baseHandler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:     tunnel,
		Type:       l.option.Type,
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
	handler := &vpnForwardHandler{
		ListenerHandler: &sing_tun.ListenerHandler{
			ListenerHandler: baseHandler,
			Inet4Address:    inet4Address,
			Inet6Address:    inet6Address,
			SourceAdditions: func(source netip.Addr) []A.Addition {
				if l.option.SourceUser == nil {
					return nil
				}
				name := l.option.SourceUser(source)
				if name == "" {
					return nil
				}
				return []A.Addition{A.WithInUser(name)}
			},
		},
		sourceUser:            l.option.SourceUser,
		localAddresses:        make(map[netip.Addr]netip.Addr, len(l.option.LocalPrefixes)),
		dynamicLocalAddresses: l.option.LocalAddresses,
	}
	for _, prefix := range l.option.LocalPrefixes {
		address := prefix.Addr().Unmap()
		if address.Is4() {
			handler.localAddresses[address] = netip.MustParseAddr("127.0.0.1")
		} else {
			handler.localAddresses[address] = netip.MustParseAddr("::1")
		}
	}
	return l.adapter.StartVPNInbound(handler, sing.ICMPTimeout)
}

func (l *VPN) Close() error {
	return l.adapter.Close()
}

type vpnForwardHandler struct {
	*sing_tun.ListenerHandler
	sourceUser            func(netip.Addr) string
	localAddresses        map[netip.Addr]netip.Addr
	dynamicLocalAddresses func() []netip.Addr
}

func localVPNDestination(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.MustParseAddr("127.0.0.1")
	}
	return netip.MustParseAddr("::1")
}

func (h *vpnForwardHandler) directDestination(destination netip.Addr) (netip.Addr, bool) {
	destination = destination.Unmap()
	if directDestination, exists := h.localAddresses[destination]; exists {
		return directDestination, true
	}
	if h.dynamicLocalAddresses != nil {
		for _, address := range h.dynamicLocalAddresses() {
			address = address.Unmap()
			if address.IsValid() && address == destination {
				return localVPNDestination(address), true
			}
		}
	}
	return netip.Addr{}, false
}

func (h *vpnForwardHandler) withMetadata(ctx context.Context, source, destination netip.Addr) context.Context {
	additions := make([]A.Addition, 0, 2)
	if source.IsValid() && h.sourceUser != nil {
		if name := h.sourceUser(source.Unmap()); name != "" {
			additions = append(additions, A.WithInUser(name))
		}
	}
	if destination.IsValid() {
		if directDestination, exists := h.directDestination(destination); exists {
			additions = append(additions, A.WithDirectDstIP(directDestination))
		}
	}
	if len(additions) == 0 {
		return ctx
	}
	return sing.WithAdditions(ctx, additions...)
}

func (h *vpnForwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	return h.ListenerHandler.NewConnection(h.withMetadata(ctx, metadata.Source.Addr, metadata.Destination.Addr), conn, metadata)
}

func (h *vpnForwardHandler) NewPacket(ctx context.Context, key netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
	h.ListenerHandler.NewPacket(h.withMetadata(ctx, metadata.Source.Addr, metadata.Destination.Addr), key, packet, metadata, init)
}

func (h *vpnForwardHandler) NewICMPConnection(ctx context.Context, source, destination netip.Addr, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	return h.PrepareConnection(
		N.NetworkICMP,
		M.SocksaddrFrom(source, 0),
		M.SocksaddrFrom(destination, 0),
		writer,
		timeout,
	)
}

var (
	_ C.InboundListener       = (*VPN)(nil)
	_ C.VPNForwardHandler     = (*vpnForwardHandler)(nil)
	_ C.VPNICMPForwardHandler = (*vpnForwardHandler)(nil)
)
