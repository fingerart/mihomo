//go:build with_gvisor

package config

import (
	"encoding/base64"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LI "github.com/metacubex/mihomo/listener/inbound"
)

func configTestWireGuardKey(seed byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func configTestWireGuardProxy() map[string]any {
	return map[string]any{
		"name":        "wg-node",
		"type":        "wireguard",
		"inbound":     true,
		"listen":      "127.0.0.1",
		"listen-port": 51820,
		"ip":          "10.0.0.1/24",
		"private-key": configTestWireGuardKey(1),
		"udp":         true,
		"ip-stack":    map[string]any{"mode": "gvisor"},
		"peers": []any{map[string]any{
			"name":        "phone",
			"public-key":  configTestWireGuardKey(33),
			"allowed-ips": []any{"10.0.0.2/32"},
		}},
	}
}

func TestAppendProxyInboundListenersIncludesProxyInbound(t *testing.T) {
	rawConfig := &RawConfig{Proxy: []map[string]any{configTestWireGuardProxy()}}
	proxies, _, err := parseProxies(rawConfig)
	if err != nil {
		t.Fatal(err)
	}
	listeners, err := parseListeners(rawConfig)
	if err != nil {
		t.Fatal(err)
	}
	if listeners["wg-node"] != nil {
		t.Fatal("parseListeners parsed a proxy-derived inbound")
	}
	if err = appendProxyInboundListeners(listeners, proxies); err != nil {
		t.Fatal(err)
	}
	listener := listeners["wg-node"]
	if listener == nil {
		t.Fatal("proxy-derived inbound is missing from listeners")
	}
	if _, ok := listener.(*LI.WireGuard); !ok {
		t.Fatalf("unexpected listener type: %T", listener)
	}
}

func TestAppendProxyInboundListenersRejectsDuplicateListenerName(t *testing.T) {
	rawConfig := &RawConfig{Proxy: []map[string]any{configTestWireGuardProxy()}}
	proxies, _, err := parseProxies(rawConfig)
	if err != nil {
		t.Fatal(err)
	}
	listeners := map[string]C.InboundListener{"wg-node": nil}
	if err = appendProxyInboundListeners(listeners, proxies); err == nil {
		t.Fatal("duplicate proxy-derived listener name was accepted")
	}
}
