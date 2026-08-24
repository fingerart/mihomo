//go:build !no_zerotier

package outbound

import (
	"context"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func (z *ZeroTier) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	if err := z.ensureStarted(ctx); err != nil {
		return nil, err
	}
	_, stack, err := z.networkStackFor(metadata.DstIP)
	if err != nil {
		return nil, err
	}
	return dialStackICMP(ctx, stack, metadata, writer, timeout)
}

var _ C.ICMPDialer = (*ZeroTier)(nil)
