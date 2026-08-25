package outbound

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/proxydialer"

	M "github.com/metacubex/sing/common/metadata"
)

// wireGuardBindDialer keeps listener policy in mihomo while ClientBind remains
// the unmodified sing-wireguard implementation.
type wireGuardBindDialer struct {
	proxydialer.SingDialer
	listenAddress netip.AddrPort
	resultAccess  sync.Mutex
	resultReady   chan struct{}
	resultVersion uint64
	localAddress  net.Addr
	openErr       error
	closed        bool
}

func newWireGuardBindDialer(dialer proxydialer.SingDialer, listenAddress netip.AddrPort) *wireGuardBindDialer {
	return &wireGuardBindDialer{
		SingDialer:    dialer,
		listenAddress: listenAddress,
		resultReady:   make(chan struct{}),
	}
}

func (d *wireGuardBindDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	var (
		packetConn net.PacketConn
		err        error
	)
	if d.listenAddress.Addr().IsValid() {
		packetConn, err = d.SingDialer.ListenPacketAddress(ctx, M.SocksaddrFrom(d.listenAddress.Addr(), d.listenAddress.Port()))
	} else {
		packetConn, err = d.SingDialer.ListenPacket(ctx, destination)
	}
	d.resultAccess.Lock()
	if d.closed {
		d.resultAccess.Unlock()
		if packetConn != nil {
			_ = packetConn.Close()
		}
		return nil, net.ErrClosed
	}
	if packetConn == nil {
		d.localAddress = nil
	} else {
		d.localAddress = packetConn.LocalAddr()
	}
	d.openErr = err
	d.resultVersion++
	close(d.resultReady)
	d.resultReady = make(chan struct{})
	d.resultAccess.Unlock()
	return packetConn, err
}

func (d *wireGuardBindDialer) WaitOpen(ctx context.Context) error {
	d.resultAccess.Lock()
	if d.closed {
		d.resultAccess.Unlock()
		return net.ErrClosed
	}
	if d.localAddress != nil {
		d.resultAccess.Unlock()
		return nil
	}
	version := d.resultVersion
	ready := d.resultReady
	d.resultAccess.Unlock()
	for {
		select {
		case <-ready:
			d.resultAccess.Lock()
			if d.closed {
				d.resultAccess.Unlock()
				return net.ErrClosed
			}
			if d.localAddress != nil {
				d.resultAccess.Unlock()
				return nil
			}
			if d.resultVersion > version {
				err := d.openErr
				d.resultAccess.Unlock()
				return err
			}
			ready = d.resultReady
			d.resultAccess.Unlock()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (d *wireGuardBindDialer) Close() {
	d.resultAccess.Lock()
	defer d.resultAccess.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	d.localAddress = nil
	d.openErr = net.ErrClosed
	d.resultVersion++
	close(d.resultReady)
}

func (d *wireGuardBindDialer) LocalAddr() net.Addr {
	d.resultAccess.Lock()
	defer d.resultAccess.Unlock()
	return d.localAddress
}
