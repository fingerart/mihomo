package inbound

import (
	"net/netip"
	"testing"
)

func TestVPNForwardHandlerUsesDynamicLocalAddresses(t *testing.T) {
	localAddress := netip.MustParseAddr("100.64.0.2")
	handler := &vpnForwardHandler{
		localAddresses:        make(map[netip.Addr]netip.Addr),
		dynamicLocalAddresses: func() []netip.Addr { return []netip.Addr{localAddress} },
	}

	directDestination, exists := handler.directDestination(localAddress)
	if !exists || directDestination != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("unexpected direct destination: %s, %v", directDestination, exists)
	}
	if _, exists = handler.directDestination(netip.MustParseAddr("100.64.0.3")); exists {
		t.Fatal("unassigned address was treated as local")
	}
}
