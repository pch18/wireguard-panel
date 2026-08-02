package wgconfig

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"wireguard-panel/internal/model"
)

func Parse(id string, filename string, data []byte) (model.Interface, error) {
	config := model.Interface{
		ID:               id,
		Filename:         filename,
		Revision:         revisionFor(data),
		Address:          make([]string, 0),
		DNS:              make([]string, 0),
		ClientAllowedIPs: make([]string, 0),
		Peers:            make([]model.Peer, 0),
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	section := ""
	interfaceSeen := false
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		sourceLine := scanner.Text()
		rawLine := strings.TrimSpace(sourceLine)
		if lineNumber == 1 {
			rawLine = strings.TrimPrefix(rawLine, "\uFEFF")
			sourceLine = strings.TrimPrefix(sourceLine, "\uFEFF")
		}
		if rawLine == "" {
			continue
		}
		if strings.HasPrefix(rawLine, "#") {
			if err := parseMetadataComment(
				&config,
				section,
				strings.TrimSpace(strings.TrimPrefix(rawLine, "#")),
			); err != nil {
				appendConfigProblem(&config, lineNumber, err.Error())
			}
			continue
		}
		if commentAt := strings.Index(rawLine, "#"); commentAt >= 0 {
			rawLine = strings.TrimSpace(rawLine[:commentAt])
			if rawLine == "" {
				continue
			}
		}
		if strings.HasPrefix(rawLine, "[") {
			switch {
			case strings.EqualFold(rawLine, "[Interface]"):
				if interfaceSeen {
					appendConfigProblem(&config, lineNumber, "只能有一个 [Interface]")
				}
				interfaceSeen = true
				section = "interface"
			case strings.EqualFold(rawLine, "[Peer]"):
				if !interfaceSeen {
					appendConfigProblem(
						&config,
						lineNumber,
						"[Peer] 不能出现在 [Interface] 之前",
					)
				}
				section = "peer"
				config.Peers = append(config.Peers, model.Peer{
					AllowedIPs: make([]string, 0),
				})
			default:
				appendConfigProblem(&config, lineNumber, fmt.Sprintf("未知配置段 %s", rawLine))
				section = "unknown"
			}
			continue
		}

		key, value, found := strings.Cut(rawLine, "=")
		if !found || section == "" {
			appendConfigProblem(&config, lineNumber, "配置项格式无效")
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "interface":
			if isUnmanagedInterfaceField(key) {
				config.UnmanagedInterfaceLines = append(
					config.UnmanagedInterfaceLines,
					sourceLine,
				)
			} else {
				err = parseInterfaceField(&config, key, value)
			}
		case "peer":
			err = parsePeerField(&config.Peers[len(config.Peers)-1], key, value)
		default:
			err = fmt.Errorf("字段 %s 位于未知配置段中", key)
		}
		if err != nil {
			appendConfigProblem(&config, lineNumber, err.Error())
		}
	}
	if err := scanner.Err(); err != nil {
		return model.Interface{}, fmt.Errorf("%w: read configuration: %v", ErrInvalidFile, err)
	}
	if !interfaceSeen {
		return model.Interface{}, fmt.Errorf("%w: missing [Interface]", ErrInvalidFile)
	}
	for index := range config.Peers {
		if strings.TrimSpace(config.Peers[index].Name) == "" {
			config.Peers[index].Name = fmt.Sprintf("Peer %d", index+1)
		}
	}
	config.ValidationErrors = append(
		config.ValidationErrors,
		ConfigurationValidationErrors(config)...,
	)
	return config, nil
}

func Serialize(config model.Interface) ([]byte, error) {
	normalized, err := NormalizeInterface(interfaceInput(config))
	if err != nil {
		return nil, err
	}
	applyInterfaceInput(&config, normalized)
	for index := range config.Peers {
		rawPeer := config.Peers[index]
		peerInput, err := NormalizePeer(peerInput(rawPeer))
		if err != nil {
			return nil, fmt.Errorf("Peer %d: %w", index+1, err)
		}
		config.Peers[index] = peerFromInput(peerInput)
	}
	if err := validateRuntimePeerSet(config); err != nil {
		return nil, err
	}

	var output strings.Builder
	writeComment(&output, "ClientEndpoint", config.ClientEndpoint)
	writeCommentList(&output, "ClientAllowedIPs", config.ClientAllowedIPs)
	if output.Len() > 0 {
		output.WriteString("\n")
	}
	output.WriteString("[Interface]\n")
	writeField(&output, "PrivateKey", config.PrivateKey)
	writeList(&output, "Address", config.Address)
	if config.ListenPort != nil {
		writeField(&output, "ListenPort", strconv.FormatUint(uint64(*config.ListenPort), 10))
	}
	writeList(&output, "DNS", config.DNS)
	if config.MTU != nil {
		writeField(&output, "MTU", strconv.Itoa(*config.MTU))
	}
	for _, line := range config.UnmanagedInterfaceLines {
		output.WriteString(line)
		output.WriteString("\n")
	}

	for _, peer := range config.Peers {
		output.WriteString("\n")
		writePeerSection(&output, peer)
	}
	return []byte(output.String()), nil
}

// ParsePeer parses exactly one native [Peer] section. Panel metadata comments
// may appear immediately before or inside the section. The returned model is
// normalized in the same way as a Peer read from a complete Interface file.
func ParsePeer(data []byte) (model.Peer, error) {
	peer := model.Peer{AllowedIPs: make([]string, 0)}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	peerSeen := false
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		rawLine := strings.TrimSpace(scanner.Text())
		if lineNumber == 1 {
			rawLine = strings.TrimPrefix(rawLine, "\uFEFF")
		}
		if rawLine == "" {
			continue
		}
		if strings.HasPrefix(rawLine, "#") {
			if err := parsePeerMetadataComment(
				&peer,
				strings.TrimSpace(strings.TrimPrefix(rawLine, "#")),
			); err != nil {
				return model.Peer{}, parseError(lineNumber, "%v", err)
			}
			continue
		}
		if commentAt := strings.Index(rawLine, "#"); commentAt >= 0 {
			rawLine = strings.TrimSpace(rawLine[:commentAt])
			if rawLine == "" {
				continue
			}
		}
		if strings.HasPrefix(rawLine, "[") {
			if !strings.EqualFold(rawLine, "[Peer]") {
				return model.Peer{}, parseError(
					lineNumber,
					"单个 Peer 配置只能包含 [Peer] 段",
				)
			}
			if peerSeen {
				return model.Peer{}, parseError(lineNumber, "只能有一个 [Peer]")
			}
			peerSeen = true
			continue
		}

		key, value, found := strings.Cut(rawLine, "=")
		if !found || !peerSeen {
			return model.Peer{}, parseError(lineNumber, "配置项格式无效")
		}
		if err := parsePeerField(
			&peer,
			strings.TrimSpace(key),
			strings.TrimSpace(value),
		); err != nil {
			return model.Peer{}, parseError(lineNumber, "%v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return model.Peer{}, fmt.Errorf("%w: read Peer configuration: %v", ErrInvalidFile, err)
	}
	if !peerSeen {
		return model.Peer{}, fmt.Errorf("%w: missing [Peer]", ErrInvalidFile)
	}
	if peer.Name == "" {
		peer.Name = "Imported Peer"
	}
	normalized, err := NormalizePeer(peerInput(peer))
	if err != nil {
		return model.Peer{}, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	return peerFromInput(normalized), nil
}

// SerializePeer returns a canonical, self-contained [Peer] section suitable
// for previewing and importing into another Interface.
func SerializePeer(peer model.Peer) ([]byte, error) {
	normalized, err := NormalizePeer(peerInput(peer))
	if err != nil {
		return nil, err
	}
	peer = peerFromInput(normalized)
	var output strings.Builder
	writePeerSection(&output, peer)
	return []byte(output.String()), nil
}

func parseMetadataComment(
	config *model.Interface,
	section string,
	comment string,
) error {
	key, value, found := strings.Cut(comment, "=")
	if !found {
		return nil
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if section == "peer" && len(config.Peers) > 0 {
		return parsePeerMetadataComment(
			&config.Peers[len(config.Peers)-1],
			comment,
		)
	}
	switch {
	case strings.EqualFold(key, "ClientEndpoint"):
		config.ClientEndpoint = value
	case strings.EqualFold(key, "ClientAllowedIPs"):
		config.ClientAllowedIPs = append(config.ClientAllowedIPs, splitList(value)...)
	}
	return nil
}

func parsePeerMetadataComment(peer *model.Peer, comment string) error {
	key, value, found := strings.Cut(comment, "=")
	if !found {
		return nil
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	switch {
	case strings.EqualFold(key, "ID"):
		// Older panel versions stored a custom Peer ID. It is deliberately
		// ignored and will disappear the next time the config is serialized.
	case strings.EqualFold(key, "Name"):
		peer.Name = value
	case strings.EqualFold(key, "PrivateKey"):
		peer.PrivateKey = value
	}
	return nil
}

func parseInterfaceField(config *model.Interface, key string, value string) error {
	switch {
	case strings.EqualFold(key, "PrivateKey"):
		config.PrivateKey = value
	case strings.EqualFold(key, "Address"):
		config.Address = append(config.Address, splitList(value)...)
	case strings.EqualFold(key, "ListenPort"):
		port, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("ListenPort: %w", err)
		}
		config.ListenPort = &port
	case strings.EqualFold(key, "DNS"):
		config.DNS = append(config.DNS, splitList(value)...)
	case strings.EqualFold(key, "MTU"):
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("MTU 必须是整数")
		}
		config.MTU = &mtu
	default:
		return fmt.Errorf("[Interface] 中存在未知字段 %s", key)
	}
	return nil
}

func isUnmanagedInterfaceField(key string) bool {
	return strings.EqualFold(key, "FwMark") ||
		strings.EqualFold(key, "Table") ||
		strings.EqualFold(key, "PreUp") ||
		strings.EqualFold(key, "PostUp") ||
		strings.EqualFold(key, "PreDown") ||
		strings.EqualFold(key, "PostDown") ||
		strings.EqualFold(key, "SaveConfig")
}

func parsePeerField(peer *model.Peer, key string, value string) error {
	switch {
	case strings.EqualFold(key, "PublicKey"):
		peer.PublicKey = value
	case strings.EqualFold(key, "PresharedKey"):
		peer.PresharedKey = value
	case strings.EqualFold(key, "AllowedIPs"):
		peer.AllowedIPs = append(peer.AllowedIPs, splitList(value)...)
	case strings.EqualFold(key, "Endpoint"):
		peer.Endpoint = value
	case strings.EqualFold(key, "PersistentKeepalive"):
		if strings.EqualFold(value, "off") {
			value = "0"
		}
		keepalive, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("PersistentKeepalive: %w", err)
		}
		peer.PersistentKeepalive = &keepalive
	default:
		return fmt.Errorf("[Peer] 中存在未知字段 %s", key)
	}
	return nil
}

func parseUint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("必须是 0 到 65535 之间的整数")
	}
	return uint16(parsed), nil
}

func parseError(line int, format string, values ...any) error {
	return fmt.Errorf(
		"%w: line %d: %s",
		ErrInvalidFile,
		line,
		fmt.Sprintf(format, values...),
	)
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func appendConfigProblem(config *model.Interface, line int, message string) {
	config.ValidationErrors = append(
		config.ValidationErrors,
		fmt.Sprintf("第 %d 行：%s", line, message),
	)
}

func writeField(output *strings.Builder, key string, value string) {
	if value != "" {
		fmt.Fprintf(output, "%s = %s\n", key, value)
	}
}

func writeList(output *strings.Builder, key string, values []string) {
	if len(values) > 0 {
		writeField(output, key, strings.Join(values, ", "))
	}
}

func writeComment(output *strings.Builder, key string, value string) {
	if value != "" {
		fmt.Fprintf(output, "# %s = %s\n", key, value)
	}
}

func writeCommentList(output *strings.Builder, key string, values []string) {
	if len(values) > 0 {
		writeComment(output, key, strings.Join(values, ", "))
	}
}

func writePeerSection(output *strings.Builder, peer model.Peer) {
	output.WriteString("[Peer]\n")
	writeComment(output, "Name", peer.Name)
	writeComment(output, "PrivateKey", peer.PrivateKey)
	writeField(output, "PublicKey", peer.PublicKey)
	writeField(output, "PresharedKey", peer.PresharedKey)
	writeList(output, "AllowedIPs", peer.AllowedIPs)
	writeField(output, "Endpoint", peer.Endpoint)
	if peer.PersistentKeepalive != nil {
		writeField(
			output,
			"PersistentKeepalive",
			strconv.FormatUint(uint64(*peer.PersistentKeepalive), 10),
		)
	}
}

func interfaceInput(config model.Interface) model.InterfaceInput {
	return model.InterfaceInput{
		PrivateKey:       config.PrivateKey,
		Address:          config.Address,
		ListenPort:       config.ListenPort,
		DNS:              config.DNS,
		MTU:              config.MTU,
		ClientEndpoint:   config.ClientEndpoint,
		ClientAllowedIPs: config.ClientAllowedIPs,
	}
}

func applyInterfaceInput(config *model.Interface, input model.InterfaceInput) {
	config.PrivateKey = input.PrivateKey
	config.Address = input.Address
	config.ListenPort = input.ListenPort
	config.DNS = input.DNS
	config.MTU = input.MTU
	config.ClientEndpoint = input.ClientEndpoint
	config.ClientAllowedIPs = input.ClientAllowedIPs
}

func peerInput(peer model.Peer) model.PeerInput {
	return model.PeerInput{
		Name:                peer.Name,
		PrivateKey:          peer.PrivateKey,
		PublicKey:           peer.PublicKey,
		PresharedKey:        peer.PresharedKey,
		AllowedIPs:          peer.AllowedIPs,
		Endpoint:            peer.Endpoint,
		PersistentKeepalive: peer.PersistentKeepalive,
	}
}

func peerFromInput(input model.PeerInput) model.Peer {
	return model.Peer{
		Name:                input.Name,
		PrivateKey:          input.PrivateKey,
		PublicKey:           input.PublicKey,
		PresharedKey:        input.PresharedKey,
		AllowedIPs:          input.AllowedIPs,
		Endpoint:            input.Endpoint,
		PersistentKeepalive: input.PersistentKeepalive,
	}
}

func validatePeerSet(config model.Interface) error {
	if err := validatePeerPublicKeys(config); err != nil {
		return err
	}
	return validateIPAssignments(config)
}

// validateRuntimePeerSet contains only constraints that affect the native
// WireGuard configuration. ClientAllowedIPs containment is deliberately
// excluded because it is panel metadata, not a wg/wg-quick requirement.
func validateRuntimePeerSet(config model.Interface) error {
	if err := validatePeerPublicKeys(config); err != nil {
		return err
	}
	return validateIPAssignmentsForRead(config)
}

func validatePeerPublicKeys(config model.Interface) error {
	publicKeys := make(map[string]bool)
	for _, peer := range config.Peers {
		if publicKeys[peer.PublicKey] {
			return fmt.Errorf("%w: Peer PublicKey 不能重复", ErrConflict)
		}
		publicKeys[peer.PublicKey] = true
	}
	return nil
}

func revisionFor(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
