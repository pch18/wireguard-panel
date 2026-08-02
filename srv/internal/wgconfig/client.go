package wgconfig

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"wireguard-panel/internal/model"
)

var unsafeFilenameCharacters = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (store *Store) ClientConfig(
	interfaceID string,
	publicKey string,
) (string, []byte, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	config, err := store.readLocked(interfaceID)
	if err != nil {
		return "", nil, err
	}
	index := peerIndexByPublicKey(config.Peers, publicKey)
	if index < 0 {
		return "", nil, ErrPeerNotFound
	}
	filename, data, err := buildClientConfig(config, config.Peers[index])
	return filename, data, err
}

func (store *Store) ClientConfigSettled(
	interfaceID string,
	publicKey string,
) (string, []byte, error) {
	unlock := store.lockInterfaceOperations(interfaceID)
	defer unlock()
	return store.ClientConfig(interfaceID, publicKey)
}

func buildClientConfig(
	config model.Interface,
	peer model.Peer,
) (string, []byte, error) {
	address := ""
	if len(peer.AllowedIPs) > 0 {
		address = firstAddressInPrefix(peer.AllowedIPs[0])
	}
	serverPublicKey := ""
	if config.PrivateKey != "" {
		serverPublicKey, _ = PublicKeyFromPrivate(config.PrivateKey)
	}
	var output strings.Builder
	output.WriteString("[Interface]\n")
	writeRequiredClientField(&output, "PrivateKey", peer.PrivateKey)
	writeField(&output, "Address", address)
	if config.MTU != nil {
		writeField(&output, "MTU", strconv.Itoa(*config.MTU))
	}
	output.WriteString("\n[Peer]\n")
	writeRequiredClientField(&output, "PublicKey", serverPublicKey)
	writeField(&output, "PresharedKey", peer.PresharedKey)
	writeField(
		&output,
		"AllowedIPs",
		strings.Join(config.ClientAllowedIPs, ", "),
	)
	writeField(&output, "Endpoint", config.ClientEndpoint)
	writeField(&output, "PersistentKeepalive", "25")

	name := unsafeFilenameCharacters.ReplaceAllString(peer.Name, "-")
	name = strings.Trim(name, "-._")
	if name == "" {
		pathKey, _ := EncodePeerPublicKeyPath(peer.PublicKey)
		name = "peer-" + pathKey[:12]
	}
	return fmt.Sprintf("%s-%s.conf", strings.TrimSuffix(config.Filename, ".conf"), name),
		[]byte(output.String()),
		nil
}

func firstAddressInPrefix(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return value
	}
	prefix = normalizedPrefix(prefix)
	if isHostPrefix(prefix) {
		return prefix.String()
	}
	address := prefix.Addr().Next()
	if !address.IsValid() || !prefix.Contains(address) {
		return prefix.String()
	}
	return netip.PrefixFrom(address, prefix.Bits()).String()
}

func writeRequiredClientField(output *strings.Builder, key string, value string) {
	fmt.Fprintf(output, "%s =", key)
	if value != "" {
		fmt.Fprintf(output, " %s", value)
	}
	output.WriteString("\n")
}
