package inbound

import C "github.com/metacubex/mihomo/constant"

func NewProxyInboundListener(adapter C.ProxyAdapter) (C.InboundListener, bool, error) {
	provider, ok := adapter.(C.VPNInboundProvider)
	if !ok {
		return nil, false, nil
	}
	vpn := provider.VPNInbound()
	if vpn == nil {
		return nil, false, nil
	}
	listener, err := NewVPN(vpn)
	return listener, true, err
}
