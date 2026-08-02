package wgconfig

import (
	"testing"

	"wireguard-panel/internal/model"
)

func TestRuntimeChangeClassification(t *testing.T) {
	port := uint16(51820)
	mtu := 1420
	base := model.Interface{
		PrivateKey: testPrivateKey(t),
		Address:    []string{"10.0.0.1/24"},
		ListenPort: &port,
		MTU:        &mtu,
		Peers: []model.Peer{{
			Name:       "peer",
			PrivateKey: "export-only",
			PublicKey:  testPublicKey(t),
			AllowedIPs: []string{"10.0.0.2/32"},
		}},
	}

	metadata := base
	metadata.ClientEndpoint = "vpn.example.com:51820"
	metadata.ClientAllowedIPs = []string{"10.0.0.0/8"}
	metadata.Peers = append([]model.Peer(nil), base.Peers...)
	metadata.Peers[0].Name = "renamed"
	metadata.Peers[0].PrivateKey = "changed-export-key"
	if got := classifyRuntimeChange(base, metadata); got != runtimeUnchanged {
		t.Fatalf("metadata change classified as %v", got)
	}

	hot := base
	nextPort := uint16(51821)
	hot.ListenPort = &nextPort
	if got := classifyRuntimeChange(base, hot); got != runtimeHotUpdate {
		t.Fatalf("ListenPort change classified as %v", got)
	}

	automaticPort := base
	automaticPort.ListenPort = nil
	if got := classifyRuntimeChange(base, automaticPort); got != runtimeHotUpdate {
		t.Fatalf("automatic ListenPort change classified as %v", got)
	}
	if got := classifyRuntimeChange(automaticPort, base); got != runtimeHotUpdate {
		t.Fatalf("explicit ListenPort change classified as %v", got)
	}

	address := base
	address.Address = []string{"10.0.0.3/24"}
	if got := classifyRuntimeChange(base, address); got != runtimeHotUpdate {
		t.Fatalf("Address change classified as %v", got)
	}

	fixedMTU := base
	fixedMTU.MTU = nil
	if got := classifyRuntimeChange(fixedMTU, base); got != runtimeHotUpdate {
		t.Fatalf("explicit MTU change classified as %v", got)
	}

	dns := base
	dns.DNS = []string{"1.1.1.1"}
	if got := classifyRuntimeChange(base, dns); got != runtimeRestartRequired {
		t.Fatalf("DNS change classified as %v", got)
	}

	wgQuickDirective := base
	wgQuickDirective.UnmanagedInterfaceLines = []string{"PostUp = nft add rule ..."}
	if got := classifyRuntimeChange(base, wgQuickDirective); got != runtimeRestartRequired {
		t.Fatalf("wg-quick directive change classified as %v", got)
	}

	autoMTU := base
	autoMTU.MTU = nil
	if got := classifyRuntimeChange(base, autoMTU); got != runtimeRestartRequired {
		t.Fatalf("automatic MTU change classified as %v", got)
	}

	defaultRoute := base
	defaultRoute.Peers = append([]model.Peer(nil), base.Peers...)
	defaultRoute.Peers[0].AllowedIPs = []string{"0.0.0.0/0"}
	if got := classifyRuntimeChange(base, defaultRoute); got != runtimeRestartRequired {
		t.Fatalf("default route change classified as %v", got)
	}
}
