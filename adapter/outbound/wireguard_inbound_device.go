package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/mipstack"
	tun "github.com/metacubex/sing-tun"
	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/cache"
)

type wireguardInboundDevice struct {
	wireguardDevice
	forwardAccess     sync.Mutex
	forwardRegistered bool
	closed            bool
	icmpForwarder     atomic.Pointer[wireGuardICMPForwarder]
	closeOnce         sync.Once
	closeErr          error
}

func (d *wireguardInboundDevice) RegisterVPNForward(handler C.VPNForwardHandler, timeout time.Duration) error {
	if handler == nil {
		return syscall.EINVAL
	}
	d.forwardAccess.Lock()
	defer d.forwardAccess.Unlock()
	if d.closed {
		return net.ErrClosed
	}
	if d.forwardRegistered {
		return syscall.EADDRINUSE
	}
	forwarder, ok := d.wireguardDevice.(wireguard.RegisterForward)
	if !ok {
		return C.ErrNotSupport
	}

	var icmpForwarder *wireGuardICMPForwarder
	if icmpHandler, supportsICMP := handler.(C.VPNICMPForwardHandler); supportsICMP {
		var err error
		icmpForwarder, err = newWireGuardICMPForwarder(d.wireguardDevice, icmpHandler, timeout)
		if err != nil {
			return err
		}
	}
	if err := forwarder.RegisterForward(wireguard.ForwardOptions{
		Handler: handler,
	}); err != nil {
		if icmpForwarder != nil {
			icmpForwarder.Close()
		}
		return err
	}
	d.icmpForwarder.Store(icmpForwarder)
	d.forwardRegistered = true
	return nil
}

func (d *wireguardInboundDevice) Write(buffers [][]byte, offset int) (int, error) {
	forwarder := d.icmpForwarder.Load()
	if forwarder == nil {
		return d.wireguardDevice.Write(buffers, offset)
	}

	forwarded := 0
	var remaining [][]byte
	for index, packet := range buffers {
		if offset >= 0 && offset <= len(packet) && forwarder.ForwardPacket(packet[offset:]) {
			if remaining == nil {
				remaining = make([][]byte, 0, len(buffers)-1)
				remaining = append(remaining, buffers[:index]...)
			}
			forwarded++
		} else if remaining != nil {
			remaining = append(remaining, packet)
		}
	}
	if forwarded == 0 {
		return d.wireguardDevice.Write(buffers, offset)
	}
	if len(remaining) == 0 {
		return forwarded, nil
	}
	written, err := d.wireguardDevice.Write(remaining, offset)
	return forwarded + written, err
}

func (d *wireguardInboundDevice) Close() error {
	d.closeOnce.Do(func() {
		d.forwardAccess.Lock()
		d.closed = true
		forwarder := d.icmpForwarder.Swap(nil)
		d.forwardAccess.Unlock()
		if forwarder != nil {
			forwarder.Close()
		}
		d.closeErr = d.wireguardDevice.Close()
	})
	return d.closeErr
}

type wireGuardICMPForwarder struct {
	ctx         context.Context
	cancel      context.CancelFunc
	handler     C.VPNICMPForwardHandler
	timeout     time.Duration
	local       map[netip.Addr]struct{}
	inet4       net.PacketConn
	inet6       net.PacketConn
	connections *cache.LruCache[tun.DirectRouteSession, C.ICMPConnection]
	fragments   *cache.LruCache[wireGuardICMPFragmentKey, *wireGuardICMPFragmentState]
	gate        wireGuardICMPForwardGate
}

func newWireGuardICMPForwarder(stack ipStack, handler C.VPNICMPForwardHandler, timeout time.Duration) (*wireGuardICMPForwarder, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	forwarder := &wireGuardICMPForwarder{
		ctx:     ctx,
		cancel:  cancel,
		handler: handler,
		timeout: timeout,
		local:   make(map[netip.Addr]struct{}),
	}
	var has4, has6 bool
	for _, address := range stack.LocalAddresses() {
		address = address.Unmap()
		forwarder.local[address] = struct{}{}
		has4 = has4 || address.Is4()
		has6 = has6 || address.Is6()
	}
	var err error
	if has4 {
		forwarder.inet4, err = stack.ListenIP(ctx, "ip4:icmp", netip.Addr{})
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if has6 {
		forwarder.inet6, err = stack.ListenIP(ctx, "ip6:ipv6-icmp", netip.Addr{})
		if err != nil {
			if forwarder.inet4 != nil {
				_ = forwarder.inet4.Close()
			}
			cancel()
			return nil, err
		}
	}
	if forwarder.inet4 == nil && forwarder.inet6 == nil {
		cancel()
		return nil, C.ErrNotSupport
	}
	age := int64(timeout.Seconds())
	if age < 1 {
		age = 1
	}
	forwarder.connections = cache.New(
		cache.WithSize[tun.DirectRouteSession, C.ICMPConnection](1024),
		cache.WithHealthCheck[tun.DirectRouteSession, C.ICMPConnection](func(_ tun.DirectRouteSession, connection C.ICMPConnection) bool {
			return connection != nil && !connection.IsClosed()
		}),
		cache.WithEvict[tun.DirectRouteSession, C.ICMPConnection](func(_ tun.DirectRouteSession, connection C.ICMPConnection) {
			if connection != nil {
				_ = connection.Close()
			}
		}),
		cache.WithUpdateAgeOnGet[tun.DirectRouteSession, C.ICMPConnection](),
		cache.WithAge[tun.DirectRouteSession, C.ICMPConnection](age),
	)
	forwarder.fragments = cache.New(
		cache.WithSize[wireGuardICMPFragmentKey, *wireGuardICMPFragmentState](1024),
		cache.WithEvict[wireGuardICMPFragmentKey, *wireGuardICMPFragmentState](func(_ wireGuardICMPFragmentKey, state *wireGuardICMPFragmentState) {
			state.access.Lock()
			state.reassembly.Reset()
			state.access.Unlock()
		}),
		cache.WithUpdateAgeOnGet[wireGuardICMPFragmentKey, *wireGuardICMPFragmentState](),
		cache.WithAge[wireGuardICMPFragmentKey, *wireGuardICMPFragmentState](age),
	)
	if forwarder.inet4 != nil {
		go forwarder.drain(forwarder.inet4)
	}
	if forwarder.inet6 != nil {
		go forwarder.drain(forwarder.inet6)
	}
	return forwarder, nil
}

func (f *wireGuardICMPForwarder) ForwardPacket(packet []byte) bool {
	if !wireGuardPotentialICMP(packet) {
		return false
	}
	ipPacket, err := mipstack.ParseIPPacket(packet)
	if err != nil {
		return false
	}
	if _, local := f.local[ipPacket.Destination.Unmap()]; local {
		return false
	}
	message, err := ipPacket.ICMPMessage()
	entered := false
	if err != nil {
		fragment, fragmented := ipPacket.Fragment()
		if !fragmented || (fragment.Protocol != mipstack.ProtocolICMPv4 && fragment.Protocol != mipstack.ProtocolICMPv6) {
			return false
		}
		if !f.gate.enter() {
			return true
		}
		entered = true
		var complete bool
		ipPacket, packet, complete = f.reassemble(ipPacket, fragment)
		if !complete {
			f.gate.leave()
			return true
		}
		message, err = ipPacket.ICMPMessage()
		if err != nil {
			f.gate.leave()
			return true
		}
	}
	if !message.IsEchoRequest() {
		if entered {
			f.gate.leave()
			return true
		}
		return false
	}
	if !entered && !f.gate.enter() {
		return true
	}

	session := tun.DirectRouteSession{Source: message.Source, Destination: message.Destination}
	var createErr error
	connection, _, ok := f.connections.LoadOrStoreEx(session, func() (C.ICMPConnection, bool) {
		var connection C.ICMPConnection
		connection, createErr = f.handler.NewICMPConnection(
			f.ctx,
			message.Source,
			message.Destination,
			&wireGuardICMPPacketWriter{forwarder: f, destination: message.Source},
			f.timeout,
		)
		return connection, createErr == nil && connection != nil
	})
	f.gate.leave()
	if !ok {
		if errors.Is(createErr, tun.ErrReset) {
			if err = f.reject(ipPacket, packet); err != nil {
				log.Warnln("[WG] failed to reject ICMP packet: %v", err)
			}
		} else if createErr != nil && !errors.Is(createErr, tun.ErrDrop) {
			log.Warnln("[WG] failed to route ICMP packet: %v", createErr)
		}
		return true
	}
	if err = connection.WritePacket(buf.As(packet).ToOwned()); err != nil {
		log.Warnln("[WG] failed to forward ICMP packet: %v", err)
	}
	return true
}

func wireGuardPotentialICMP(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	switch packet[0] >> 4 {
	case 4:
		return len(packet) > 9 && packet[9] == mipstack.ProtocolICMPv4
	case 6:
		if len(packet) <= 6 {
			return false
		}
		switch packet[6] {
		case mipstack.ProtocolICMPv6,
			mipstack.IPv6ExtensionHeaderHopByHop,
			mipstack.IPv6ExtensionHeaderRouting,
			mipstack.IPv6ExtensionHeaderFragment,
			mipstack.IPv6ExtensionHeaderAuthentication,
			mipstack.IPv6ExtensionHeaderDestination,
			mipstack.IPv6ExtensionHeaderMobility:
			return true
		}
	}
	return false
}

func (f *wireGuardICMPForwarder) reject(request mipstack.IPPacket, original []byte) error {
	maximumQuote := 548
	messageType := uint8(mipstack.ICMPv4TypeDestinationUnreachable)
	messageCode := uint8(mipstack.ICMPv4DestinationUnreachableCodeHost)
	protocol := mipstack.ProtocolICMPv4
	if request.Source.Is6() {
		maximumQuote = 1232
		messageType = mipstack.ICMPv6TypeDestinationUnreachable
		messageCode = mipstack.ICMPv6DestinationUnreachableCodeAddress
		protocol = mipstack.ProtocolICMPv6
	}
	if len(original) > maximumQuote {
		original = original[:maximumQuote]
	}
	body := make([]byte, 4+len(original))
	copy(body[4:], original)
	message := mipstack.ICMPMessage{
		Source:      request.Destination,
		Destination: request.Source,
		Type:        messageType,
		Code:        messageCode,
		Body:        body,
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		return err
	}
	packet, err := (mipstack.IPPacket{
		Source:      request.Destination,
		Destination: request.Source,
		Protocol:    protocol,
		HopLimit:    64,
		Payload:     payload,
	}).MarshalBinary()
	if err != nil {
		return err
	}
	return f.writePacket(packet, request.Source)
}

func (f *wireGuardICMPForwarder) reassemble(fragmentPacket mipstack.IPPacket, fragment mipstack.IPPacketFragmentView) (mipstack.IPPacket, []byte, bool) {
	key := wireGuardICMPFragmentKey{
		source:         fragmentPacket.Source,
		destination:    fragmentPacket.Destination,
		identification: fragment.Identification,
		ipv6:           fragmentPacket.Source.Is6(),
	}
	if !key.ipv6 {
		key.protocol = fragment.Protocol
	}
	state, _ := f.fragments.LoadOrStore(key, func() *wireGuardICMPFragmentState {
		return new(wireGuardICMPFragmentState)
	})
	state.access.Lock()
	packet, complete, err := state.reassembly.Add(fragmentPacket)
	state.access.Unlock()
	if err != nil || complete {
		f.fragments.Delete(key)
	}
	if err != nil || !complete {
		return mipstack.IPPacket{}, nil, false
	}
	wirePacket, err := packet.MarshalBinary()
	if err != nil {
		return mipstack.IPPacket{}, nil, false
	}
	return packet, wirePacket, true
}

func (f *wireGuardICMPForwarder) writePacket(packet []byte, destination netip.Addr) error {
	packetConn := f.inet6
	if destination.Is4() {
		packetConn = f.inet4
	}
	if packetConn == nil {
		return syscall.EAFNOSUPPORT
	}
	written, err := packetConn.WriteTo(packet, &net.IPAddr{IP: net.IP(destination.AsSlice())})
	if err == nil && written != len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func (f *wireGuardICMPForwarder) drain(packetConn net.PacketConn) {
	packet := make([]byte, maxIPPacketSize)
	for {
		if _, _, err := packetConn.ReadFrom(packet); err != nil {
			return
		}
	}
}

func (f *wireGuardICMPForwarder) Close() {
	f.gate.close(func() {
		f.cancel()
		f.fragments.Clear()
		f.connections.Clear()
		if f.inet4 != nil {
			_ = f.inet4.Close()
		}
		if f.inet6 != nil {
			_ = f.inet6.Close()
		}
	})
}

type wireGuardICMPPacketWriter struct {
	forwarder   *wireGuardICMPForwarder
	destination netip.Addr
}

type wireGuardICMPFragmentKey struct {
	source         netip.Addr
	destination    netip.Addr
	identification uint32
	protocol       int
	ipv6           bool
}

type wireGuardICMPFragmentState struct {
	access     sync.Mutex
	reassembly mipstack.IPPacketReassembly
}

func (w *wireGuardICMPPacketWriter) WritePacket(packet []byte) error {
	return w.forwarder.writePacket(packet, w.destination)
}

type wireGuardICMPForwardGate struct {
	access sync.RWMutex
	closed bool
}

func (g *wireGuardICMPForwardGate) enter() bool {
	g.access.RLock()
	if g.closed {
		g.access.RUnlock()
		return false
	}
	return true
}

func (g *wireGuardICMPForwardGate) leave() {
	g.access.RUnlock()
}

func (g *wireGuardICMPForwardGate) close(cleanup func()) {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return
	}
	g.closed = true
	cleanup()
}

var (
	_ wireguardDevice = (*wireguardInboundDevice)(nil)
	_ C.ICMPWriter    = (*wireGuardICMPPacketWriter)(nil)
)
