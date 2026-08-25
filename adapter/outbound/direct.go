package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type Direct struct {
	*Base
	loopBack *loopback.Detector
}

type DirectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	address := metadata.RemoteAddress()
	if metadata.DirectDstIP.IsValid() {
		address = net.JoinHostPort(metadata.DirectDstIP.String(), strconv.FormatUint(uint64(metadata.DstPort), 10))
	}
	c, err := dialer.DialContext(ctx, "tcp", address, opts...)
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewConn(NewConn(c, d)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	remoteAddress := metadata.AddrPort()
	if metadata.DirectDstIP.IsValid() {
		remoteAddress = netip.AddrPortFrom(metadata.DirectDstIP.Unmap(), metadata.DstPort)
	}
	pc, err := dialer.NewDialer(d.DialOptions()...).ListenPacket(ctx, "udp", "", remoteAddress)
	if err != nil {
		return nil, err
	}
	if metadata.DirectDstIP.IsValid() {
		pc = &directMappedPacketConn{
			PacketConn: pc,
			originalIP: metadata.DstIP.Unmap(),
			directIP:   metadata.DirectDstIP.Unmap(),
		}
	}
	return d.loopBack.NewPacketConn(NewPacketConn(pc, d)), nil
}

func (d *Direct) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.DirectDstIP.IsValid() {
		return nil
	}
	if (!metadata.Resolved() || resolver.DirectHostResolver != resolver.DefaultResolver) && metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, d.prefer, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type directMappedPacketConn struct {
	net.PacketConn
	originalIP netip.Addr
	directIP   netip.Addr
}

func (c *directMappedPacketConn) WriteTo(packet []byte, destination net.Addr) (int, error) {
	return c.PacketConn.WriteTo(packet, replaceDirectPacketAddress(destination, c.originalIP, c.directIP))
}

func (c *directMappedPacketConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	n, source, err := c.PacketConn.ReadFrom(packet)
	if err == nil {
		source = replaceDirectPacketAddress(source, c.directIP, c.originalIP)
	}
	return n, source, err
}

func replaceDirectPacketAddress(address net.Addr, from, to netip.Addr) net.Addr {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress == nil {
		return address
	}
	addrPort := udpAddress.AddrPort()
	if addrPort.Addr().Unmap() != from {
		return address
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(to, addrPort.Port()))
}

func (d *Direct) IsL3Protocol(metadata *C.Metadata) bool {
	return true // tell DNSDialer don't send domain to DialContext, avoid lookback to DefaultResolver
}

func NewDirectWithOption(option DirectOption) *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Direct,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewDirect() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "DIRECT",
			Type:   C.Direct,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "COMPATIBLE",
			Type:   C.Compatible,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}
