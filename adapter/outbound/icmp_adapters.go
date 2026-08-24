package outbound

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing-tun/ping"
)

func dialStackICMP(ctx context.Context, stack ipStack, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	return newICMPStackConnection(ctx, stack, metadata, writer, timeout)
}

func (d *Direct) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	return ping.ConnectDestination(ctx, log.SingLogger, dialer.ICMPControl(metadata.DstIP, d.DialOptions()...), metadata.DstIP, writer, timeout)
}

func (w *WireGuard) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	if err := w.init(ctx); err != nil {
		return nil, err
	}
	return dialStackICMP(ctx, w.tunDevice, metadata, writer, timeout)
}

func (o *OpenVPN) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	stack, _, err := o.run(ctx)
	if err != nil {
		return nil, err
	}
	return dialStackICMP(ctx, stack, metadata, writer, timeout)
}

func (w *Masque) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	if w.l4Client != nil {
		return nil, C.ErrNotSupport
	}
	if err := w.run(ctx); err != nil {
		return nil, err
	}
	return dialStackICMP(ctx, w.tunDevice, metadata, writer, timeout)
}

var (
	_ C.ICMPDialer = (*Direct)(nil)
	_ C.ICMPDialer = (*WireGuard)(nil)
	_ C.ICMPDialer = (*OpenVPN)(nil)
	_ C.ICMPDialer = (*Masque)(nil)
)
