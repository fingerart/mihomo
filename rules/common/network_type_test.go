package common

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestNetworkTypeMatchesICMP(t *testing.T) {
	rule, err := NewNetworkType("icmp", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}

	matched, adapter := rule.Match(&C.Metadata{NetWork: C.ICMP}, C.RuleMatchHelper{})
	if !matched {
		t.Fatal("expected ICMP metadata to match")
	}
	if adapter != "DIRECT" {
		t.Fatalf("unexpected adapter: %s", adapter)
	}
	if payload := rule.Payload(); payload != "icmp" {
		t.Fatalf("unexpected payload: %s", payload)
	}
}
