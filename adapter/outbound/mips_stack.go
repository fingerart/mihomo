package outbound

import (
	"context"
	"io"
	"sync"
	"syscall"

	"github.com/metacubex/mipstack"
	wireguard "github.com/metacubex/sing-wireguard"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type mipsStack struct {
	*mipstack.Stack
	forwardMutex  sync.Mutex
	forwardCancel context.CancelFunc
}

func (s *mipsStack) RegisterForward(options wireguard.ForwardOptions) error {
	if options.Handler == nil {
		return syscall.EINVAL
	}
	s.forwardMutex.Lock()
	defer s.forwardMutex.Unlock()
	if s.forwardCancel != nil {
		return syscall.EADDRINUSE
	}

	ctx, cancel := context.WithCancel(context.Background())
	tcpForwarder, err := mipstack.NewTCPForwarder(s.Stack, mipstack.TCPForwarderOptions{MaxInFlight: 1024}, func(request *mipstack.TCPForwarderRequest) {
		forwardMIPSTCP(ctx, options.Handler, request)
	})
	if err != nil {
		cancel()
		return err
	}
	_, err = mipstack.NewUDPForwarder(s.Stack, mipstack.UDPForwarderOptions{}, func(request *mipstack.UDPForwarderRequest) {
		forwardMIPSUDP(ctx, options.Handler, request)
	})
	if err != nil {
		_ = tcpForwarder.Close()
		cancel()
		return err
	}
	s.forwardCancel = cancel
	return nil
}

func (s *mipsStack) Close() error {
	s.forwardMutex.Lock()
	cancel := s.forwardCancel
	s.forwardCancel = nil
	s.forwardMutex.Unlock()
	if cancel != nil {
		cancel()
	}
	return s.Stack.Close()
}

func forwardMIPSTCP(ctx context.Context, handler wireguard.ForwardHandler, request *mipstack.TCPForwarderRequest) {
	flow := request.Flow()
	connection, err := request.Accept(ctx)
	if err != nil {
		return
	}
	metadata := mipsForwardMetadata(flow)
	if err = handler.NewConnection(ctx, connection, metadata); err != nil {
		_ = connection.Close()
	}
}

func forwardMIPSUDP(ctx context.Context, handler wireguard.ForwardHandler, request *mipstack.UDPForwarderRequest) {
	flow := request.Flow()
	payload := append([]byte(nil), request.Payload()...)
	responder, err := request.DetachForReplies()
	if err != nil {
		return
	}
	handler.NewPacket(
		ctx,
		flow.Source,
		buf.As(payload).ToOwned(),
		mipsForwardMetadata(flow),
		func(N.PacketConn) N.PacketWriter { return &mipsUDPBackWriter{responder: responder} },
	)
}

type mipsUDPBackWriter struct {
	responder *mipstack.UDPForwarderResponder
}

func (w *mipsUDPBackWriter) WritePacket(packet *buf.Buffer, destination M.Socksaddr) error {
	defer packet.Release()
	if !destination.IsIP() {
		return syscall.EINVAL
	}
	n, err := w.responder.ReplyFrom(packet.Bytes(), destination.AddrPort())
	if err == nil && n != packet.Len() {
		return io.ErrShortWrite
	}
	return err
}

func mipsForwardMetadata(flow mipstack.ForwarderFlow) M.Metadata {
	return M.Metadata{
		Source:      M.SocksaddrFrom(flow.Source.Addr(), flow.Source.Port()),
		Destination: M.SocksaddrFrom(flow.Destination.Addr(), flow.Destination.Port()),
	}
}

var _ ipStack = (*mipsStack)(nil)
var _ wireguard.RegisterForward = (*mipsStack)(nil)
