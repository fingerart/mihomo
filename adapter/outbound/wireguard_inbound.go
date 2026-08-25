package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	C "github.com/metacubex/mihomo/constant"

	wireguard "github.com/metacubex/sing-wireguard"
)

type WireGuardInboundOption struct {
	Name          string
	ListenAddress netip.AddrPort
	LocalPrefixes []netip.Prefix
	PeerName      func(netip.Addr) string
}

func (w *WireGuard) peerName(address netip.Addr) string {
	address = address.Unmap()
	for _, peerPrefix := range w.peerPrefixes {
		if peerPrefix.prefix.Contains(address) {
			return peerPrefix.name
		}
	}
	return ""
}

func (w *WireGuard) InboundOption() (WireGuardInboundOption, bool) {
	if !w.option.Inbound {
		return WireGuardInboundOption{}, false
	}
	listenAddress := w.listenAddress
	if !listenAddress.IsValid() {
		listenAddress = netip.IPv4Unspecified()
	}
	return WireGuardInboundOption{
		Name:          w.Name(),
		ListenAddress: netip.AddrPortFrom(listenAddress, uint16(w.option.ListenPort)),
		LocalPrefixes: append([]netip.Prefix(nil), w.localPrefixes...),
		PeerName:      w.peerName,
	}, true
}

func (w *WireGuard) WireGuardInbound() *WireGuard {
	if _, enabled := w.InboundOption(); !enabled {
		return nil
	}
	return w
}

func (w *WireGuard) RegisterInbound(handler wireguard.ForwardHandler, icmpTimeout time.Duration) error {
	if !w.option.Inbound {
		return C.ErrNotSupport
	}
	w.forwardMutex.Lock()
	defer w.forwardMutex.Unlock()
	if !w.forwardReady {
		if err := w.tunDevice.RegisterInboundForward(handler, icmpTimeout); err != nil {
			return err
		}
		w.forwardReady = true
	}
	return w.init(context.Background())
}

func (w *WireGuard) InboundAddress() net.Addr {
	return w.bindDialer.LocalAddr()
}
