package inbound

import (
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

type wireGuardInboundProvider interface {
	WireGuardInbound() *outbound.WireGuard
}

func NewProxyInboundListener(adapter C.ProxyAdapter) (C.InboundListener, bool, error) {
	switch provider := adapter.(type) {
	case wireGuardInboundProvider:
		wireGuard := provider.WireGuardInbound()
		if wireGuard == nil {
			return nil, false, nil
		}
		listener, err := NewWireGuard(wireGuard)
		return listener, true, err
	default:
		return nil, false, nil
	}
}
