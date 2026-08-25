package outbound

import (
	"context"
	"net"
	"net/netip"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func (w *WireGuard) peerName(address netip.Addr) string {
	address = address.Unmap()
	for _, peerPrefix := range w.peerPrefixes {
		if peerPrefix.prefix.Contains(address) {
			return peerPrefix.name
		}
	}
	return ""
}

func (w *WireGuard) VPNInboundOption() C.VPNInboundOption {
	listenAddress := w.listenAddress
	if !listenAddress.IsValid() {
		listenAddress = netip.IPv4Unspecified()
	}
	return C.VPNInboundOption{
		Name:          w.Name(),
		Type:          C.WIREGUARD,
		ListenAddress: netip.AddrPortFrom(listenAddress, uint16(w.option.ListenPort)),
		LocalPrefixes: append([]netip.Prefix(nil), w.localPrefixes...),
		SourceUser:    w.peerName,
	}
}

func (w *WireGuard) VPNInbound() C.VPNInbound {
	if !w.option.Inbound {
		return nil
	}
	return w
}

func (w *WireGuard) StartVPNInbound(handler C.VPNForwardHandler, icmpTimeout time.Duration) error {
	if !w.option.Inbound {
		return C.ErrNotSupport
	}
	w.forwardMutex.Lock()
	defer w.forwardMutex.Unlock()
	if !w.forwardReady {
		if err := w.tunDevice.RegisterVPNForward(handler, icmpTimeout); err != nil {
			return err
		}
		w.forwardReady = true
	}
	return w.init(context.Background())
}

func (w *WireGuard) VPNInboundAddress() net.Addr {
	return w.bindDialer.LocalAddr()
}

var (
	_ C.VPNInboundProvider = (*WireGuard)(nil)
	_ C.VPNInbound         = (*WireGuard)(nil)
)
