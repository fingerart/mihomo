package constant

import (
	"context"
	"time"

	"github.com/metacubex/sing/common/buf"
)

// ICMPWriter writes a complete IP packet back to an inbound packet source.
type ICMPWriter interface {
	WritePacket(packet []byte) error
}

// ICMPConnection is a routed ICMP session using complete IP packets.
type ICMPConnection interface {
	WritePacket(packet *buf.Buffer) error
	Close() error
	IsClosed() bool
}

// ICMPDialer is an optional outbound capability for routed ICMP sessions.
type ICMPDialer interface {
	DialICMP(ctx context.Context, metadata *Metadata, writer ICMPWriter, timeout time.Duration) (ICMPConnection, error)
}

// MetadataResolver is an optional tunnel capability used by packet-only
// inbound protocols that still need normal rule resolution.
type MetadataResolver interface {
	ResolveMetadata(metadata *Metadata) (Proxy, Rule, error)
}
