package tunnel

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type mappedHostEnhancer struct {
	address netip.Addr
	host    string
}

func (*mappedHostEnhancer) FakeIPEnabled() bool               { return false }
func (*mappedHostEnhancer) MappingEnabled() bool              { return true }
func (*mappedHostEnhancer) IsFakeIP(netip.Addr) bool          { return false }
func (*mappedHostEnhancer) IsFakeBroadcastIP(netip.Addr) bool { return false }
func (*mappedHostEnhancer) IsExistFakeIP(netip.Addr) bool     { return false }
func (*mappedHostEnhancer) FlushFakeIP() error                { return nil }
func (*mappedHostEnhancer) InsertHostByIP(netip.Addr, string) {}
func (*mappedHostEnhancer) StoreFakePoolState()               {}
func (e *mappedHostEnhancer) FindHostByIP(address netip.Addr) (string, bool) {
	return e.host, address == e.address
}

func TestResolveMetadataPreHandlesMappedDestination(t *testing.T) {
	address := netip.MustParseAddr("1.1.1.1")
	originalHostMapper := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = &mappedHostEnhancer{address: address, host: "example.com"}
	t.Cleanup(func() { resolver.DefaultHostMapper = originalHostMapper })

	metadata := &C.Metadata{NetWork: C.ICMP, Type: C.TUN, DstIP: address}
	if _, _, err := Tunnel.ResolveMetadata(metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Host != "example.com" || metadata.DNSMode != C.DNSMapping {
		t.Fatalf("mapped metadata was not pre-handled: %+v", metadata)
	}
}
