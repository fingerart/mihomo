package sing_tun

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type testMetadataResolver struct {
	C.Tunnel
	proxy    C.Proxy
	err      error
	metadata *C.Metadata
}

func (r *testMetadataResolver) ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	r.metadata = metadata
	return r.proxy, nil, r.err
}

type testICMPDialer struct {
	*outbound.Base
	connection C.ICMPConnection
	err        error
	calls      int
	metadata   *C.Metadata
	writer     C.ICMPWriter
}

func newTestICMPDialer(name string, adapterType C.AdapterType, connection C.ICMPConnection, err error) *testICMPDialer {
	return &testICMPDialer{
		Base:       outbound.NewBase(outbound.BaseOption{Name: name, Type: adapterType}),
		connection: connection,
		err:        err,
	}
}

func (d *testICMPDialer) DialICMP(_ context.Context, metadata *C.Metadata, writer C.ICMPWriter, _ time.Duration) (C.ICMPConnection, error) {
	d.calls++
	d.metadata = metadata
	d.writer = writer
	return d.connection, d.err
}

type testProxyGroup struct {
	*outbound.Base
	selected C.Proxy
}

type deadlineICMPDialer struct {
	*testICMPDialer
	sawDeadline bool
}

func (d *deadlineICMPDialer) DialICMP(ctx context.Context, metadata *C.Metadata, writer C.ICMPWriter, timeout time.Duration) (C.ICMPConnection, error) {
	_, d.sawDeadline = ctx.Deadline()
	if !d.sawDeadline {
		return nil, errors.New("missing dial deadline")
	}
	return d.testICMPDialer.DialICMP(ctx, metadata, writer, timeout)
}

func (g *testProxyGroup) Unwrap(_ *C.Metadata, _ bool) C.Proxy {
	return g.selected
}

type testICMPConnection struct {
	closed bool
}

func (*testICMPConnection) WritePacket(*buf.Buffer) error { return nil }

func (c *testICMPConnection) Close() error {
	c.closed = true
	return nil
}

func (c *testICMPConnection) IsClosed() bool { return c.closed }

type testICMPWriter struct{}

func (testICMPWriter) WritePacket([]byte) error { return nil }

func newPrepareTestHandler(t *testing.T, tunnel C.Tunnel, direct C.ICMPDialer) *ListenerHandler {
	t.Helper()
	listenerHandler, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TUN,
		Additions: []inbound.Addition{inbound.WithInName("test-tun")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &ListenerHandler{
		ListenerHandler:  listenerHandler,
		directICMPDialer: direct,
	}
}

func TestPrepareConnectionRoutesICMPThroughSelectedProxy(t *testing.T) {
	connection := &testICMPConnection{}
	selected := newTestICMPDialer("selected", C.WireGuard, connection, nil)
	selectedProxy := A.NewProxy(selected)
	group := A.NewProxy(&testProxyGroup{
		Base:     outbound.NewBase(outbound.BaseOption{Name: "group", Type: C.Selector}),
		selected: selectedProxy,
	})
	resolver := &testMetadataResolver{proxy: group}
	direct := newTestICMPDialer("direct", C.Direct, &testICMPConnection{}, nil)
	handler := newPrepareTestHandler(t, resolver, direct)
	handler.SourceAdditions = func(source netip.Addr) []inbound.Addition {
		if source == netip.MustParseAddr("10.0.0.2") {
			return []inbound.Addition{inbound.WithInUser("phone")}
		}
		return nil
	}
	writer := testICMPWriter{}

	destination, err := handler.PrepareConnection(
		N.NetworkICMP,
		M.SocksaddrFrom(netip.MustParseAddr("10.0.0.2"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 0),
		writer,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if destination != connection {
		t.Fatal("ICMP connection did not use the selected proxy")
	}
	if selected.calls != 1 || direct.calls != 0 {
		t.Fatalf("selected calls = %d, direct calls = %d", selected.calls, direct.calls)
	}
	if resolver.metadata == nil || resolver.metadata.NetWork != C.ICMP || resolver.metadata.Type != C.TUN {
		t.Fatalf("unexpected resolved metadata: %+v", resolver.metadata)
	}
	if resolver.metadata.SrcIP != netip.MustParseAddr("10.0.0.2") || resolver.metadata.DstIP != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("unexpected ICMP endpoints: %s --> %s", resolver.metadata.SrcIP, resolver.metadata.DstIP)
	}
	if resolver.metadata.InName != "test-tun" {
		t.Fatalf("inbound additions were not applied: %+v", resolver.metadata)
	}
	if resolver.metadata.InUser != "phone" {
		t.Fatalf("source additions were not applied: %+v", resolver.metadata)
	}
	if selected.writer != writer {
		t.Fatal("selected proxy did not receive the TUN reply writer")
	}
}

func TestPrepareConnectionFallsBackToDirectOnlyWhenUnsupported(t *testing.T) {
	operationalErr := errors.New("dial failed")
	tests := []struct {
		name       string
		proxy      C.Proxy
		wantErr    error
		wantDirect bool
	}{
		{
			name: "missing capability",
			proxy: A.NewProxy(outbound.NewBase(outbound.BaseOption{
				Name: "unsupported", Type: C.Socks5,
			})),
			wantDirect: true,
		},
		{
			name:       "explicitly unsupported mode",
			proxy:      A.NewProxy(newTestICMPDialer("unsupported-mode", C.Masque, nil, C.ErrNotSupport)),
			wantDirect: true,
		},
		{
			name:    "operational failure",
			proxy:   A.NewProxy(newTestICMPDialer("failed", C.WireGuard, nil, operationalErr)),
			wantErr: tun.ErrDrop,
		},
		{
			name:    "reject",
			proxy:   A.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "reject", Type: C.Reject})),
			wantErr: tun.ErrReset,
		},
		{
			name:    "reject drop",
			proxy:   A.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "reject-drop", Type: C.RejectDrop})),
			wantErr: tun.ErrDrop,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directConnection := &testICMPConnection{}
			direct := newTestICMPDialer("direct", C.Direct, directConnection, nil)
			resolver := &testMetadataResolver{proxy: test.proxy}
			handler := newPrepareTestHandler(t, resolver, direct)

			destination, err := handler.PrepareConnection(
				N.NetworkICMP,
				M.SocksaddrFrom(netip.MustParseAddr("10.0.0.2"), 0),
				M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 0),
				testICMPWriter{},
				time.Second,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantDirect {
				if destination != directConnection || direct.calls != 1 {
					t.Fatalf("DIRECT fallback destination = %v, calls = %d", destination, direct.calls)
				}
			} else if destination != nil || direct.calls != 0 {
				t.Fatalf("unexpected DIRECT fallback destination = %v, calls = %d", destination, direct.calls)
			}
		})
	}
}

func TestPrepareConnectionBoundsICMPDialWithSessionTimeout(t *testing.T) {
	connection := &testICMPConnection{}
	dialer := &deadlineICMPDialer{testICMPDialer: newTestICMPDialer("selected", C.WireGuard, connection, nil)}
	resolver := &testMetadataResolver{proxy: A.NewProxy(dialer)}
	direct := newTestICMPDialer("direct", C.Direct, &testICMPConnection{}, nil)
	handler := newPrepareTestHandler(t, resolver, direct)

	destination, err := handler.PrepareConnection(
		N.NetworkICMP,
		M.SocksaddrFrom(netip.MustParseAddr("10.0.0.2"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 0),
		testICMPWriter{},
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if destination != connection || !dialer.sawDeadline {
		t.Fatal("selected ICMP dial did not use the session timeout")
	}
}
