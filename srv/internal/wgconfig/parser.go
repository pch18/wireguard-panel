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

func Parse(id int, filename string, data []byte) (model.Interface, error) {
	config := model.Interface{
		ID:               id,
		Filename:         filename,
		Revision:         revisionFor(data),
		Address:          make([]string, 0),
		DNS:              make([]string, 0),
		ClientDNS:        make([]string, 0),
		ClientAllowedIPs: make([]string, 0),
		PreUp:            make([]string, 0),
		PostUp:           make([]string, 0),
		PreDown:          make([]string, 0),
		PostDown:         make([]string, 0),
		Peers:            make([]model.Peer, 0),
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	section := ""
	interfaceSeen := false
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		rawLine := strings.TrimSpace(scanner.Text())
		if rawLine == "" {
			continue
		}
		if strings.HasPrefix(rawLine, "#") {
			if err := parseMetadataComment(
				&config,
				section,
				strings.TrimSpace(strings.TrimPrefix(rawLine, "#")),
			); err != nil {
				return model.Interface{}, parseError(lineNumber, "%v", err)
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
					return model.Interface{}, parseError(lineNumber, "只能有一个 [Interface]")
				}
				interfaceSeen = true
				section = "interface"
			case strings.EqualFold(rawLine, "[Peer]"):
				if !interfaceSeen {
					return model.Interface{}, parseError(
						lineNumber,
						"[Peer] 不能出现在 [Interface] 之前",
					)
				}
				section = "peer"
				config.Peers = append(config.Peers, model.Peer{
					AllowedIPs:    make([]string, 0),
					ClientAddress: make([]string, 0),
				})
			default:
				return model.Interface{}, parseError(lineNumber, "未知配置段 %s", rawLine)
			}
			continue
		}

		key, value, found := strings.Cut(rawLine, "=")
		if !found || section == "" {
			return model.Interface{}, parseError(lineNumber, "配置项格式无效")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		var err error
		switch section {
		case "interface":
			err = parseInterfaceField(&config, key, value)
		case "peer":
			err = parsePeerField(&config.Peers[len(config.Peers)-1], key, value)
		}
		if err != nil {
			return model.Interface{}, parseError(lineNumber, "%v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return model.Interface{}, fmt.Errorf("%w: read configuration: %v", ErrInvalidFile, err)
	}
	if !interfaceSeen {
		return model.Interface{}, fmt.Errorf("%w: missing [Interface]", ErrInvalidFile)
	}
	if config.Name == "" {
		config.Name = strings.TrimSuffix(filename, ".conf")
	}

	normalized, err := NormalizeInterface(interfaceInput(config))
	if err != nil {
		return model.Interface{}, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	applyInterfaceInput(&config, normalized)
	for index := range config.Peers {
		rawPeer := config.Peers[index]
		if rawPeer.Name == "" {
			rawPeer.Name = fmt.Sprintf("Peer %d", index+1)
		}
		peerInput, err := NormalizePeer(peerInput(rawPeer))
		if err != nil {
			return model.Interface{}, fmt.Errorf(
				"%w: Peer %d: %v",
				ErrInvalidFile,
				index+1,
				err,
			)
		}
		if rawPeer.ID == "" {
			rawPeer.ID = LegacyPeerID(peerInput.PublicKey)
		}
		if !validPeerID(rawPeer.ID) {
			return model.Interface{}, fmt.Errorf(
				"%w: Peer %d ID 格式无效",
				ErrInvalidFile,
				index+1,
			)
		}
		config.Peers[index] = peerFromInput(
			peerInput,
			rawPeer.ID,
			rawPeer.SystemGenerated,
		)
	}
	if err := validatePeerSet(config); err != nil {
		return model.Interface{}, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
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
		if rawPeer.ID == "" {
			rawPeer.ID = LegacyPeerID(peerInput.PublicKey)
		}
		if !validPeerID(rawPeer.ID) {
			return nil, invalid("Peer %d ID 格式无效", index+1)
		}
		config.Peers[index] = peerFromInput(
			peerInput,
			rawPeer.ID,
			rawPeer.SystemGenerated,
		)
	}
	if err := validatePeerSet(config); err != nil {
		return nil, err
	}

	var output strings.Builder
	writeComment(&output, "Name", config.Name)
	writeComment(&output, "ClientEndpoint", config.ClientEndpoint)
	writeCommentList(&output, "ClientDNS", config.ClientDNS)
	writeCommentList(&output, "ClientAllowedIPs", config.ClientAllowedIPs)
	if config.ClientPersistentKeepalive != nil {
		writeComment(
			&output,
			"ClientPersistentKeepalive",
			strconv.FormatUint(uint64(*config.ClientPersistentKeepalive), 10),
		)
	}
	output.WriteString("[Interface]\n")
	writeField(&output, "PrivateKey", config.PrivateKey)
	writeList(&output, "Address", config.Address)
	if config.ListenPort != nil {
		writeField(&output, "ListenPort", strconv.FormatUint(uint64(*config.ListenPort), 10))
	}
	writeField(&output, "FwMark", config.FwMark)
	writeList(&output, "DNS", config.DNS)
	if config.MTU != nil {
		writeField(&output, "MTU", strconv.Itoa(*config.MTU))
	}
	writeField(&output, "Table", config.Table)
	writeCommands(&output, "PreUp", config.PreUp)
	writeCommands(&output, "PostUp", config.PostUp)
	writeCommands(&output, "PreDown", config.PreDown)
	writeCommands(&output, "PostDown", config.PostDown)
	if config.SaveConfig {
		writeField(&output, "SaveConfig", "true")
	}

	for _, peer := range config.Peers {
		output.WriteString("\n[Peer]\n")
		writeComment(&output, "ID", peer.ID)
		writeComment(&output, "Name", peer.Name)
		writeComment(&output, "PrivateKey", peer.PrivateKey)
		if peer.SystemGenerated {
			writeComment(&output, "SystemGenerated", "true")
		}
		writeCommentList(&output, "ClientAddress", peer.ClientAddress)
		if peer.ClientPersistentKeepalive != nil {
			writeComment(
				&output,
				"ClientPersistentKeepalive",
				strconv.FormatUint(uint64(*peer.ClientPersistentKeepalive), 10),
			)
		}
		writeField(&output, "PublicKey", peer.PublicKey)
		writeField(&output, "PresharedKey", peer.PresharedKey)
		writeList(&output, "AllowedIPs", peer.AllowedIPs)
		writeField(&output, "Endpoint", peer.Endpoint)
		if peer.PersistentKeepalive != nil {
			writeField(
				&output,
				"PersistentKeepalive",
				strconv.FormatUint(uint64(*peer.PersistentKeepalive), 10),
			)
		}
	}
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
		peer := &config.Peers[len(config.Peers)-1]
		switch {
		case strings.EqualFold(key, "ID"):
			peer.ID = value
		case strings.EqualFold(key, "Name"):
			peer.Name = value
		case strings.EqualFold(key, "PrivateKey"):
			peer.PrivateKey = value
		case strings.EqualFold(key, "SystemGenerated"):
			switch {
			case strings.EqualFold(value, "true"):
				peer.SystemGenerated = true
			case strings.EqualFold(value, "false"):
				peer.SystemGenerated = false
			default:
				return fmt.Errorf("SystemGenerated 必须是 true 或 false")
			}
		case strings.EqualFold(key, "ClientAddress"):
			peer.ClientAddress = append(peer.ClientAddress, splitList(value)...)
		case strings.EqualFold(key, "ClientPersistentKeepalive"):
			keepalive, err := parseUint16(value)
			if err != nil {
				return fmt.Errorf("ClientPersistentKeepalive: %w", err)
			}
			peer.ClientPersistentKeepalive = &keepalive
		}
		return nil
	}
	switch {
	case strings.EqualFold(key, "Name"):
		config.Name = value
	case strings.EqualFold(key, "ClientEndpoint"):
		config.ClientEndpoint = value
	case strings.EqualFold(key, "ClientDNS"):
		config.ClientDNS = append(config.ClientDNS, splitList(value)...)
	case strings.EqualFold(key, "ClientAllowedIPs"):
		config.ClientAllowedIPs = append(config.ClientAllowedIPs, splitList(value)...)
	case strings.EqualFold(key, "ClientPersistentKeepalive"):
		keepalive, err := parseUint16(value)
		if err != nil {
			return fmt.Errorf("ClientPersistentKeepalive: %w", err)
		}
		config.ClientPersistentKeepalive = &keepalive
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
	case strings.EqualFold(key, "FwMark"):
		config.FwMark = value
	case strings.EqualFold(key, "DNS"):
		config.DNS = append(config.DNS, splitList(value)...)
	case strings.EqualFold(key, "MTU"):
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("MTU 必须是整数")
		}
		config.MTU = &mtu
	case strings.EqualFold(key, "Table"):
		config.Table = value
	case strings.EqualFold(key, "PreUp"):
		config.PreUp = append(config.PreUp, value)
	case strings.EqualFold(key, "PostUp"):
		config.PostUp = append(config.PostUp, value)
	case strings.EqualFold(key, "PreDown"):
		config.PreDown = append(config.PreDown, value)
	case strings.EqualFold(key, "PostDown"):
		config.PostDown = append(config.PostDown, value)
	case strings.EqualFold(key, "SaveConfig"):
		if strings.EqualFold(value, "true") {
			config.SaveConfig = true
		} else if strings.EqualFold(value, "false") {
			config.SaveConfig = false
		} else {
			return fmt.Errorf("SaveConfig 必须是 true 或 false")
		}
	default:
		return fmt.Errorf("[Interface] 中存在未知字段 %s", key)
	}
	return nil
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
	return strings.Split(value, ",")
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

func writeCommands(output *strings.Builder, key string, values []string) {
	for _, value := range values {
		writeField(output, key, value)
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

func interfaceInput(config model.Interface) model.InterfaceInput {
	return model.InterfaceInput{
		Name:                      config.Name,
		PrivateKey:                config.PrivateKey,
		Address:                   config.Address,
		ListenPort:                config.ListenPort,
		FwMark:                    config.FwMark,
		DNS:                       config.DNS,
		MTU:                       config.MTU,
		Table:                     config.Table,
		PreUp:                     config.PreUp,
		PostUp:                    config.PostUp,
		PreDown:                   config.PreDown,
		PostDown:                  config.PostDown,
		SaveConfig:                config.SaveConfig,
		ClientEndpoint:            config.ClientEndpoint,
		ClientDNS:                 config.ClientDNS,
		ClientAllowedIPs:          config.ClientAllowedIPs,
		ClientPersistentKeepalive: config.ClientPersistentKeepalive,
	}
}

func applyInterfaceInput(config *model.Interface, input model.InterfaceInput) {
	config.Name = input.Name
	config.PrivateKey = input.PrivateKey
	config.Address = input.Address
	config.ListenPort = input.ListenPort
	config.FwMark = input.FwMark
	config.DNS = input.DNS
	config.MTU = input.MTU
	config.Table = input.Table
	config.PreUp = input.PreUp
	config.PostUp = input.PostUp
	config.PreDown = input.PreDown
	config.PostDown = input.PostDown
	config.SaveConfig = input.SaveConfig
	config.ClientEndpoint = input.ClientEndpoint
	config.ClientDNS = input.ClientDNS
	config.ClientAllowedIPs = input.ClientAllowedIPs
	config.ClientPersistentKeepalive = input.ClientPersistentKeepalive
}

func peerInput(peer model.Peer) model.PeerInput {
	return model.PeerInput{
		Name:                      peer.Name,
		PrivateKey:                peer.PrivateKey,
		PublicKey:                 peer.PublicKey,
		PresharedKey:              peer.PresharedKey,
		AllowedIPs:                peer.AllowedIPs,
		Endpoint:                  peer.Endpoint,
		PersistentKeepalive:       peer.PersistentKeepalive,
		ClientAddress:             peer.ClientAddress,
		ClientPersistentKeepalive: peer.ClientPersistentKeepalive,
	}
}

func peerFromInput(
	input model.PeerInput,
	id string,
	systemGenerated bool,
) model.Peer {
	return model.Peer{
		ID:                        id,
		Name:                      input.Name,
		PrivateKey:                input.PrivateKey,
		PublicKey:                 input.PublicKey,
		PresharedKey:              input.PresharedKey,
		AllowedIPs:                input.AllowedIPs,
		Endpoint:                  input.Endpoint,
		PersistentKeepalive:       input.PersistentKeepalive,
		ClientAddress:             input.ClientAddress,
		ClientPersistentKeepalive: input.ClientPersistentKeepalive,
		SystemGenerated:           systemGenerated,
	}
}

func validatePeerSet(config model.Interface) error {
	ids := make(map[string]bool)
	publicKeys := make(map[string]bool)
	for _, peer := range config.Peers {
		if ids[peer.ID] {
			return fmt.Errorf("%w: Peer ID 不能重复", ErrConflict)
		}
		if publicKeys[peer.PublicKey] {
			return fmt.Errorf("%w: Peer PublicKey 不能重复", ErrConflict)
		}
		ids[peer.ID] = true
		publicKeys[peer.PublicKey] = true
	}
	return validateIPAssignments(config)
}

func revisionFor(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
