package wgconfig

import (
	"fmt"
	"net/netip"
	"sort"

	"wireguard-panel/internal/model"
)

type ipNetworkState struct {
	prefix             netip.Prefix
	interfaceAddresses []string
	allocated          map[netip.Addr]bool
}

func validateIPAssignments(config model.Interface) error {
	return validateIPAssignmentsWithoutRouteRange(config)
}

func validateIPAssignmentsForRead(config model.Interface) error {
	return validateIPAssignmentsWithoutRouteRange(config)
}

func validateIPAssignmentsWithoutRouteRange(config model.Interface) error {
	interfaceAddresses := make(map[netip.Addr]string)
	for _, value := range config.Address {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		address := prefix.Addr().Unmap()
		if previous, exists := interfaceAddresses[address]; exists {
			return fmt.Errorf(
				"%w: Interface Address %s 与 %s 使用了同一个 IP",
				ErrConflict,
				previous,
				value,
			)
		}
		interfaceAddresses[address] = value
	}
	assigned := make(map[string]string)
	for _, peer := range config.Peers {
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			prefix = normalizedPrefix(prefix)
			for address, interfaceValue := range interfaceAddresses {
				if isHostPrefix(prefix) && prefix.Addr().Unmap() == address {
					return fmt.Errorf(
						"%w: Peer %q 的 AllowedIPs %s 与 Interface Address %s 重复",
						ErrConflict,
						peer.Name,
						value,
						interfaceValue,
					)
				}
			}
			key := prefix.String()
			if previousPeer, exists := assigned[key]; exists {
				if previousPeer == peer.PublicKey {
					return fmt.Errorf(
						"%w: Peer %q 的 AllowedIPs %s 重复",
						ErrConflict,
						peer.Name,
						value,
					)
				}
				return fmt.Errorf(
					"%w: Peer %q 的 AllowedIPs %s 与另一个 Peer 重复",
					ErrConflict,
					peer.Name,
					value,
				)
			}
			assigned[key] = peer.PublicKey
		}
	}
	return nil
}

func BuildIPPlan(config model.Interface) model.IPPlan {
	peerAllowedNetworks := normalizedPrefixes(config.ClientAllowedIPs)
	states := make(map[string]*ipNetworkState)
	order := make([]string, 0)
	for _, value := range config.Address {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		network := normalizedPrefix(prefix)
		key := network.String()
		state, exists := states[key]
		if !exists {
			state = &ipNetworkState{
				prefix:    network,
				allocated: make(map[netip.Addr]bool),
			}
			states[key] = state
			order = append(order, key)
		}
		address := prefix.Addr().Unmap()
		state.interfaceAddresses = append(state.interfaceAddresses, value)
		state.allocated[address] = true
	}

	for _, peer := range config.Peers {
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !isHostPrefix(prefix) {
				continue
			}
			addAddressToNetworks(prefix.Addr().Unmap(), states)
		}
	}

	plan := model.IPPlan{
		Revision:          config.Revision,
		Networks:          make([]model.IPNetworkPlan, 0, len(states)),
		AllowedRanges:     make([]string, 0, len(peerAllowedNetworks)),
		ReservedAddresses: make([]string, 0, len(config.Address)),
		Assignments:       make([]model.IPAssignment, 0),
		Conflicts:         make([]model.IPConflict, 0),
	}
	for _, network := range peerAllowedNetworks {
		plan.AllowedRanges = append(plan.AllowedRanges, network.String())
	}
	for _, value := range config.Address {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		address := prefix.Addr().Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		plan.ReservedAddresses = append(
			plan.ReservedAddresses,
			netip.PrefixFrom(address, bits).String(),
		)
	}
	for _, peer := range config.Peers {
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			plan.Assignments = append(plan.Assignments, model.IPAssignment{
				AllowedIP:     normalizedPrefix(prefix).String(),
				PeerPublicKey: peer.PublicKey,
				PeerName:      peer.Name,
			})
		}
	}
	for _, key := range order {
		state := states[key]
		allocated := make([]string, 0, len(state.allocated))
		for address := range state.allocated {
			allocated = append(allocated, address.String())
		}
		sort.Strings(allocated)
		suggested := firstAvailableAddress(state.prefix, state.allocated)
		item := model.IPNetworkPlan{
			Network:              state.prefix.String(),
			InterfaceAddresses:   state.interfaceAddresses,
			AllocatedAddresses:   allocated,
			AvailableForPlanning: suggested.IsValid(),
		}
		if suggested.IsValid() {
			item.SuggestedAddress = netip.PrefixFrom(
				suggested,
				state.prefix.Bits(),
			).String()
			hostBits := 128
			if suggested.Is4() {
				hostBits = 32
			}
			item.SuggestedAllowedIP = netip.PrefixFrom(
				suggested,
				hostBits,
			).String()
		}
		plan.Networks = append(plan.Networks, item)
	}
	return plan
}

func normalizedPrefix(prefix netip.Prefix) netip.Prefix {
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if address.Is4() && bits > 32 {
		bits -= 96
	}
	return netip.PrefixFrom(address, bits).Masked()
}

func normalizedPrefixes(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		prefix = normalizedPrefix(prefix)
		key := prefix.String()
		if !seen[key] {
			seen[key] = true
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func addAddressToNetworks(
	address netip.Addr,
	states map[string]*ipNetworkState,
) {
	address = address.Unmap()
	for _, state := range states {
		if state.prefix.Contains(address) {
			state.allocated[address] = true
		}
	}
}

func firstAvailableAddress(
	network netip.Prefix,
	allocated map[netip.Addr]bool,
) netip.Addr {
	candidate := network.Addr().Next()
	for attempts := 0; candidate.IsValid() && network.Contains(candidate); attempts++ {
		if attempts > 65536 {
			return netip.Addr{}
		}
		if !allocated[candidate] && !isReservedBroadcast(network, candidate) {
			return candidate
		}
		candidate = candidate.Next()
	}
	return netip.Addr{}
}

func isReservedBroadcast(network netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || network.Bits() >= 31 {
		return false
	}
	next := address.Next()
	return !next.IsValid() || !network.Contains(next)
}

func isHostPrefix(prefix netip.Prefix) bool {
	if prefix.Addr().Is4() {
		return prefix.Bits() == 32
	}
	return prefix.Bits() == 128
}
