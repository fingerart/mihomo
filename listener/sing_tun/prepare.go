package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		if h.DisableICMPForwarding || h.skipPingForwardingByAddr(destination.Addr) { // skip if ICMP handling is disabled or other condition
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
		}
		metadata := &C.Metadata{NetWork: C.ICMP, Type: h.Type}
		inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(source), inbound.WithDstAddr(destination))
		inbound.ApplyAdditions(metadata, h.Additions...)
		if h.SourceAdditions != nil && source.Addr.IsValid() {
			inbound.ApplyAdditions(metadata, h.SourceAdditions(source.Addr.Unmap())...)
		}
		ctx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return h.prepareICMPConnection(ctx, metadata, routeContext, timeout)
	}
	return nil, nil
}

func (h *ListenerHandler) prepareICMPConnection(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (tun.DirectRouteDestination, error) {
	proxyDialer, proxy, rule, err := h.resolveICMPDialer(metadata)
	if err != nil {
		if errors.Is(err, tun.ErrReset) || errors.Is(err, tun.ErrDrop) {
			return nil, err
		}
		log.Warnln("[ICMP] failed to resolve route for %s --> %s: %v", metadata.SourceDetail(), metadata.RemoteAddress(), err)
		return nil, tun.ErrDrop
	}

	if proxyDialer != nil {
		connection, dialErr := proxyDialer.DialICMP(ctx, metadata, writer, timeout)
		if dialErr == nil {
			logICMPRoute(metadata, proxy, rule)
			return connection, nil
		}
		if !errors.Is(dialErr, C.ErrNotSupport) {
			log.Warnln("[ICMP] failed to connect %s via %s: %v", metadata.RemoteAddress(), proxy.Name(), dialErr)
			return nil, tun.ErrDrop
		}
	}

	directDialer := h.directICMPDialer
	if directDialer == nil {
		directDialer = directICMPDialer{}
	}
	connection, err := directDialer.DialICMP(ctx, metadata, writer, timeout)
	if err != nil {
		log.Warnln("[ICMP] failed to connect directly to %s: %v", metadata.RemoteAddress(), err)
		return nil, tun.ErrDrop
	}
	log.Infoln("[ICMP] %s --> %s using DIRECT", metadata.SourceDetail(), metadata.RemoteAddress())
	return connection, nil
}

func (h *ListenerHandler) resolveICMPDialer(metadata *C.Metadata) (C.ICMPDialer, C.Proxy, C.Rule, error) {
	metadataResolver, ok := h.Tunnel.(C.MetadataResolver)
	if !ok {
		return nil, nil, nil, nil
	}
	proxy, rule, err := metadataResolver.ResolveMetadata(metadata)
	if err != nil {
		return nil, nil, rule, err
	}
	for proxy != nil {
		switch proxy.Type() {
		case C.Reject:
			return nil, proxy, rule, tun.ErrReset
		case C.RejectDrop:
			return nil, proxy, rule, tun.ErrDrop
		}
		if icmpDialer, ok := proxy.Adapter().(C.ICMPDialer); ok {
			return icmpDialer, proxy, rule, nil
		}
		proxy = proxy.Unwrap(metadata, true)
	}
	return nil, nil, rule, nil
}

func logICMPRoute(metadata *C.Metadata, proxy C.Proxy, rule C.Rule) {
	if rule == nil {
		log.Infoln("[ICMP] %s --> %s using %s", metadata.SourceDetail(), metadata.RemoteAddress(), proxy.Name())
		return
	}
	log.Infoln("[ICMP] %s --> %s match %s(%s) using %s", metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), rule.Payload(), proxy.Name())
}

type directICMPDialer struct{}

func (directICMPDialer) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	connection, err := ping.ConnectDestination(ctx, log.SingLogger, dialer.ICMPControl(metadata.DstIP), metadata.DstIP, writer, timeout)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (h *ListenerHandler) skipPingForwardingByAddr(addr netip.Addr) bool {
	for _, prefix := range h.Inet4Address { // skip in interface ipv4 range
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address { // skip in interface ipv6 range
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) { // skip in fakeIp pool
		return true
	}
	return false
}
