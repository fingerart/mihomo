package outbound

import (
	"context"
	"net/netip"
	"testing"
)

func TestMIPSStackSupportsIPDialing(t *testing.T) {
	stack, err := newIPStack(IPStackOption{Mode: ipStackMips}, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.2/32"),
	}, 1408, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}

	conn, err := stack.DialIP(context.Background(), "ip4:icmp", netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	listener, err := stack.ListenTCP(context.Background(), "tcp4", netip.MustParseAddrPort("10.0.0.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
