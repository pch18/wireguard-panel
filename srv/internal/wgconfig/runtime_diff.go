package wgconfig

import (
	"net/netip"
	"reflect"
	"sort"

	"wireguard-panel/internal/model"
)

type runtimeChangeKind uint8

const (
	runtimeUnchanged runtimeChangeKind = iota
	runtimeHotUpdate
	runtimeRestartRequired
)

func cloneInterface(config model.Interface) model.Interface {
	cloned := config
	cloned.Address = cloneStrings(config.Address)
	cloned.DNS = cloneStrings(config.DNS)
	cloned.ClientAllowedIPs = cloneStrings(config.ClientAllowedIPs)
	cloned.ValidationErrors = cloneStrings(config.ValidationErrors)
	cloned.UnmanagedInterfaceLines = cloneStrings(config.UnmanagedInterfaceLines)
	cloned.Peers = make([]model.Peer, len(config.Peers))
	for index, peer := range config.Peers {
		cloned.Peers[index] = peer
		cloned.Peers[index].AllowedIPs = cloneStrings(peer.AllowedIPs)
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append(make([]string, 0, len(values)), values...)
}

func classifyRuntimeChange(before model.Interface, after model.Interface) runtimeChangeKind {
	if runtimeConfigurationEqual(before, after) {
		return runtimeUnchanged
	}
	if !reflect.DeepEqual(before.DNS, after.DNS) ||
		!reflect.DeepEqual(before.UnmanagedInterfaceLines, after.UnmanagedInterfaceLines) ||
		!mtuCanBeUpdatedWithoutRestart(before.MTU, after.MTU) ||
		defaultRouteSetChanged(before, after) {
		return runtimeRestartRequired
	}
	return runtimeHotUpdate
}

func runtimeConfigurationEqual(left model.Interface, right model.Interface) bool {
	return left.PrivateKey == right.PrivateKey &&
		reflect.DeepEqual(left.Address, right.Address) &&
		equalUint16(left.ListenPort, right.ListenPort) &&
		reflect.DeepEqual(left.DNS, right.DNS) &&
		equalInt(left.MTU, right.MTU) &&
		reflect.DeepEqual(left.UnmanagedInterfaceLines, right.UnmanagedInterfaceLines) &&
		reflect.DeepEqual(runtimePeers(left.Peers), runtimePeers(right.Peers))
}

func wireGuardDeviceChanged(left model.Interface, right model.Interface) bool {
	return left.PrivateKey != right.PrivateKey ||
		!equalUint16(left.ListenPort, right.ListenPort) ||
		!reflect.DeepEqual(runtimePeers(left.Peers), runtimePeers(right.Peers))
}

func runtimePeers(peers []model.Peer) []model.PeerInput {
	result := make([]model.PeerInput, 0, len(peers))
	for _, peer := range peers {
		result = append(result, model.PeerInput{
			PublicKey:           peer.PublicKey,
			PresharedKey:        peer.PresharedKey,
			AllowedIPs:          peer.AllowedIPs,
			Endpoint:            peer.Endpoint,
			PersistentKeepalive: peer.PersistentKeepalive,
		})
	}
	return result
}

func mtuCanBeUpdatedWithoutRestart(before *int, after *int) bool {
	if equalInt(before, after) {
		return true
	}
	// A concrete target can always be applied with `ip link set mtu`.
	// Returning to wg-quick's automatic MTU calculation requires rebuilding
	// the Interface because there is no stored concrete value to restore.
	return after != nil
}

func defaultRouteSetChanged(before model.Interface, after model.Interface) bool {
	beforeRoutes := peerRouteSet(before)
	afterRoutes := peerRouteSet(after)
	for _, route := range []string{"0.0.0.0/0", "::/0"} {
		if beforeRoutes[route] != afterRoutes[route] {
			return true
		}
	}
	return false
}

func peerRouteSet(config model.Interface) map[string]bool {
	routes := make(map[string]bool)
	for _, peer := range config.Peers {
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			routes[prefix.Masked().String()] = true
		}
	}
	return routes
}

func sortedSetDifference(left map[string]bool, right map[string]bool) []string {
	values := make([]string, 0)
	for value := range left {
		if !right[value] {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func equalUint16(left *uint16, right *uint16) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}

func equalInt(left *int, right *int) bool {
	return left == nil && right == nil ||
		left != nil && right != nil && *left == *right
}
