package proxydialer

import (
	"context"
	"net"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type SingDialer interface {
	N.Dialer
	ListenPacketAddress(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}

type singDialer struct {
	cDialer C.Dialer
}

var _ N.Dialer = (*singDialer)(nil)

func (d singDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.cDialer.DialContext(ctx, network, destination.String())
}

func (d singDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.cDialer.ListenPacket(ctx, "udp", "", destination.AddrPort())
}

func (d singDialer) ListenPacketAddress(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	network := "udp6"
	if destination.IsIPv4() {
		network = "udp4"
	}
	return d.cDialer.ListenPacket(ctx, network, destination.String(), destination.AddrPort())
}

func NewSingDialer(cDialer C.Dialer) SingDialer {
	return singDialer{cDialer: cDialer}
}
