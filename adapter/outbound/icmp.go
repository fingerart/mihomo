package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	"github.com/metacubex/sing/common/buf"
)

const (
	defaultICMPPacketSize = 2048
	maxIPPacketSize       = 65535
)

type icmpStackConnection struct {
	ctx        context.Context
	conn       net.Conn
	rewriter   *ping.SourceRewriter
	session    tun.DirectRouteSession
	timeout    time.Duration
	packetSize int
	closeOnce  sync.Once
	closed     atomic.Bool
}

func newICMPStackConnection(ctx context.Context, stack ipStack, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	var inet4Address, inet6Address netip.Addr
	for _, address := range stack.LocalAddresses() {
		address = address.Unmap()
		if address.Is4() && !inet4Address.IsValid() {
			inet4Address = address
		} else if address.Is6() && !inet6Address.IsValid() {
			inet6Address = address
		}
	}

	destination := metadata.DstIP.Unmap()
	var network string
	var bindAddress netip.Addr
	if destination.Is4() {
		network = "ip4:icmp"
		bindAddress = inet4Address
	} else if destination.Is6() {
		network = "ip6:ipv6-icmp"
		bindAddress = inet6Address
	} else {
		return nil, fmt.Errorf("invalid ICMP destination: %s", metadata.DstIP)
	}
	if !bindAddress.IsValid() {
		return nil, fmt.Errorf("missing local address for ICMP destination %s", destination)
	}

	conn, err := stack.DialIP(ctx, network, bindAddress, destination)
	if err != nil {
		return nil, err
	}
	session := tun.DirectRouteSession{
		Source:      metadata.SrcIP.Unmap(),
		Destination: destination,
	}
	rewriter := ping.NewSourceRewriter(ctx, log.SingLogger, inet4Address, inet6Address)
	rewriter.CreateSession(session, writer)
	packetSize := defaultICMPPacketSize
	if mtu, mtuErr := stack.MTU(); mtuErr == nil && mtu > packetSize {
		packetSize = mtu
		if packetSize > maxIPPacketSize {
			packetSize = maxIPPacketSize
		}
	}
	connection := &icmpStackConnection{
		ctx:        ctx,
		conn:       conn,
		rewriter:   rewriter,
		session:    session,
		timeout:    timeout,
		packetSize: packetSize,
	}
	go connection.loopRead()
	return connection, nil
}

func (c *icmpStackConnection) loopRead() {
	defer c.Close()
	for {
		packet := make([]byte, c.packetSize)
		if c.timeout > 0 {
			if err := c.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil && !c.closed.Load() {
				log.Warnln("[ICMP] failed to set read deadline: %v", err)
			}
		}
		n, err := c.conn.Read(packet)
		if err != nil {
			if !c.closed.Load() {
				log.Warnln("[ICMP] failed to receive reply: %v", err)
			}
			return
		}
		if _, err = c.rewriter.WriteBack(packet[:n]); err != nil {
			log.Warnln("[ICMP] failed to write reply: %v", err)
		}
	}
}

func (c *icmpStackConnection) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	data := packet.Bytes()
	c.rewriter.RewritePacket(data)
	n, err := c.conn.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func (c *icmpStackConnection) Close() (err error) {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.rewriter.DeleteSession(c.session)
		err = c.conn.Close()
	})
	return
}

func (c *icmpStackConnection) IsClosed() bool {
	return c.closed.Load()
}

var _ C.ICMPConnection = (*icmpStackConnection)(nil)
