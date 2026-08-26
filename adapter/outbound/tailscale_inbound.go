//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/tailscale/client/tailscale/apitype"
	"github.com/metacubex/tailscale/tsnet"
	"github.com/metacubex/tailscale/types/nettype"
)

const (
	tailscaleUDPIdleTimeout    = 2 * time.Minute
	tailscaleDNSUDPIdleTimeout = 30 * time.Second
)

func (t *Tailscale) VPNInboundOption() C.VPNInboundOption {
	return C.VPNInboundOption{
		Name:           t.Name(),
		Type:           C.TAILSCALE,
		ListenAddress:  netip.AddrPortFrom(netip.IPv4Unspecified(), 0),
		LocalAddresses: t.tailscaleAddresses,
		SourceUser:     t.peerName,
	}
}

func (t *Tailscale) tailscaleAddresses() []netip.Addr {
	if !t.serverStarted.Load() {
		return nil
	}
	v4, v6 := t.server.TailscaleIPs()
	addresses := make([]netip.Addr, 0, 2)
	if v4.IsValid() {
		addresses = append(addresses, v4)
	}
	if v6.IsValid() {
		addresses = append(addresses, v6)
	}
	return addresses
}

func (t *Tailscale) VPNInbound() C.VPNInbound {
	if !t.option.Inbound {
		return nil
	}
	return t
}

func (t *Tailscale) StartVPNInbound(handler C.VPNForwardHandler, _ time.Duration) error {
	if !t.option.Inbound {
		return C.ErrNotSupport
	}
	if handler == nil {
		return errors.New("Tailscale inbound handler is nil")
	}

	t.vpnInboundMutex.Lock()
	if t.unregisterVPNTCP == nil {
		t.unregisterVPNTCP = t.server.RegisterFallbackTCPHandler(t.newFallbackTCPHandler(handler))
		t.unregisterVPNUDP = t.server.RegisterFallbackUDPHandler(t.newFallbackUDPHandler(handler))
	}
	t.vpnInboundMutex.Unlock()

	if err := t.start(); err != nil {
		t.stopVPNInbound()
		return err
	}
	return nil
}

func (t *Tailscale) stopVPNInbound() {
	t.vpnInboundMutex.Lock()
	unregisterTCP := t.unregisterVPNTCP
	unregisterUDP := t.unregisterVPNUDP
	t.unregisterVPNTCP = nil
	t.unregisterVPNUDP = nil
	t.vpnInboundMutex.Unlock()
	if unregisterTCP != nil {
		unregisterTCP()
	}
	if unregisterUDP != nil {
		unregisterUDP()
	}
}

func tailscaleWhoIsName(whoIs *apitype.WhoIsResponse) string {
	if whoIs == nil {
		return ""
	}
	if whoIs.Node != nil && whoIs.Node.ComputedName != "" {
		return whoIs.Node.ComputedName
	}
	if whoIs.UserProfile != nil {
		return whoIs.UserProfile.LoginName
	}
	return ""
}

func (t *Tailscale) peerName(address netip.Addr) string {
	name, loaded := t.peerNames.Load(address.Unmap())
	if !loaded {
		return ""
	}
	return name.(string)
}

func (t *Tailscale) cachePeerName(ctx context.Context, address netip.Addr) {
	address = address.Unmap()
	if _, loaded := t.peerNames.Load(address); loaded || t.server == nil {
		return
	}
	lc, err := t.server.LocalClient()
	if err != nil {
		return
	}
	lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	whoIs, err := lc.WhoIs(lookupCtx, address.String())
	if err != nil {
		return
	}
	t.peerNames.Store(address, tailscaleWhoIsName(whoIs))
}

func tailscaleInboundMetadata(source, destination netip.AddrPort) M.Metadata {
	return M.Metadata{
		Source:      M.SocksaddrFromNetIP(source),
		Destination: M.SocksaddrFromNetIP(destination),
	}
}

func (t *Tailscale) newFallbackTCPHandler(handler C.VPNForwardHandler) tsnet.FallbackTCPHandler {
	return func(source, destination netip.AddrPort) (func(net.Conn), bool) {
		metadata := tailscaleInboundMetadata(source, destination)
		return func(connection net.Conn) {
			t.cachePeerName(t.ctx, source.Addr())
			if err := handler.NewConnection(t.ctx, connection, metadata); err != nil {
				_ = connection.Close()
			}
		}, true
	}
}

func (t *Tailscale) newFallbackUDPHandler(handler C.VPNForwardHandler) tsnet.FallbackUDPHandler {
	return func(source, destination netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		metadata := tailscaleInboundMetadata(source, destination)
		key := t.nextUDPFlowKey()
		idleTimeout := tailscaleUDPIdleTimeout
		if destination.Port() == 53 {
			idleTimeout = tailscaleDNSUDPIdleTimeout
		}
		return func(connection nettype.ConnPacketConn) {
			t.cachePeerName(t.ctx, source.Addr())
			forwardTailscaleUDP(t.ctx, handler, connection, key, metadata, idleTimeout)
		}, true
	}
}

func (t *Tailscale) nextUDPFlowKey() netip.AddrPort {
	var address [16]byte
	binary.BigEndian.PutUint64(address[8:], t.vpnUDPFlowID.Add(1))
	return netip.AddrPortFrom(netip.AddrFrom16(address), 0)
}

func forwardTailscaleUDP(ctx context.Context, handler C.VPNForwardHandler, connection nettype.ConnPacketConn, key netip.AddrPort, metadata M.Metadata, idleTimeout time.Duration) {
	defer connection.Close()
	idleTimer := time.AfterFunc(idleTimeout, func() { _ = connection.Close() })
	defer idleTimer.Stop()
	payload := make([]byte, 65535)
	writer := &tailscaleUDPBackWriter{
		connection: connection,
		extend:     func() { idleTimer.Reset(idleTimeout) },
	}
	for {
		n, err := connection.Read(payload)
		if err != nil {
			return
		}
		idleTimer.Reset(idleTimeout)
		handler.NewPacket(
			ctx,
			key,
			buf.As(payload[:n]).ToOwned(),
			metadata,
			func(N.PacketConn) N.PacketWriter { return writer },
		)
	}
}

type tailscaleUDPBackWriter struct {
	connection net.Conn
	extend     func()
}

func (w *tailscaleUDPBackWriter) WritePacket(packet *buf.Buffer, _ M.Socksaddr) error {
	defer packet.Release()
	n, err := w.connection.Write(packet.Bytes())
	if err == nil && n != packet.Len() {
		return io.ErrShortWrite
	}
	if err == nil && w.extend != nil {
		w.extend()
	}
	return err
}

func (t *Tailscale) VPNInboundAddress() net.Addr {
	if !t.serverStarted.Load() {
		return nil
	}
	v4, v6 := t.server.TailscaleIPs()
	if v4.IsValid() {
		return &net.IPAddr{IP: v4.AsSlice()}
	}
	if v6.IsValid() {
		return &net.IPAddr{IP: v6.AsSlice()}
	}
	return nil
}

var (
	_ C.VPNInboundProvider = (*Tailscale)(nil)
	_ C.VPNInbound         = (*Tailscale)(nil)
)
