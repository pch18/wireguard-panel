package wgconfig

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	"wireguard-panel/internal/model"
)

var peerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type assignedPrefix struct {
	prefix netip.Prefix
	peerID string
}

type ipNetworkState struct {
	prefix             netip.Prefix
	interfaceAddresses []string
	allocated          map[netip.Addr]bool
}

func validPeerID(id string) bool {
	return peerIDPattern.MatchString(id)
}

func validateIPAssignments(config model.Interface) error {
	interfaceNetworks := make([]netip.Prefix, 0, len(config.Address))
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
		interfaceNetworks = append(interfaceNetworks, normalizedPrefix(prefix))
	}

	clientAddresses := make(map[netip.Addr]string)
	allowed := make([]assignedPrefix, 0)
	for _, peer := range config.Peers {
		for _, value := range peer.ClientAddress {
			prefix, _ := netip.ParsePrefix(value)
			address := prefix.Addr().Unmap()
			if interfaceValue, exists := interfaceAddresses[address]; exists {
				return fmt.Errorf(
					"%w: Peer %q 的 ClientAddress %s 与 Interface Address %s 冲突",
					ErrConflict,
					peer.Name,
					value,
					interfaceValue,
				)
			}
			if previousPeer, exists := clientAddresses[address]; exists {
				return fmt.Errorf(
					"%w: Peer %q 与 Peer %q 使用了同一个 ClientAddress %s",
					ErrConflict,
					peer.Name,
					previousPeer,
					address,
				)
			}
			if len(interfaceNetworks) > 0 &&
				!addressInNetworks(address, interfaceNetworks) {
				return fmt.Errorf(
					"%w: Peer %q 的 ClientAddress %s 不属于任何 Interface Address 子网",
					ErrConflict,
					peer.Name,
					value,
				)
			}
			clientAddresses[address] = peer.Name
		}

		for _, value := range peer.AllowedIPs {
			prefix, _ := netip.ParsePrefix(value)
			prefix = normalizedPrefix(prefix)
			for _, previous := range allowed {
				if previous.peerID != peer.ID && prefix.Overlaps(previous.prefix) {
					return fmt.Errorf(
						"%w: Peer %q 的 AllowedIPs %s 与另一个 Peer 的 %s 重叠",
						ErrConflict,
						peer.Name,
						value,
						previous.prefix,
					)
				}
			}
			allowed = append(allowed, assignedPrefix{prefix: prefix, peerID: peer.ID})
		}
	}
	return nil
}

func BuildIPPlan(config model.Interface) model.IPPlan {
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
		for _, value := range peer.ClientAddress {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				continue
			}
			addAddressToNetworks(prefix.Addr().Unmap(), states)
		}
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !isHostPrefix(prefix) {
				continue
			}
			addAddressToNetworks(prefix.Addr().Unmap(), states)
		}
	}

	plan := model.IPPlan{
		Networks:  make([]model.IPNetworkPlan, 0, len(states)),
		Conflicts: make([]model.IPConflict, 0),
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

func addressInNetworks(address netip.Addr, networks []netip.Prefix) bool {
	address = address.Unmap()
	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
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
