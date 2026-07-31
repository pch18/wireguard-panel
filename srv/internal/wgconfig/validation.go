package wgconfig

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"wireguard-panel/internal/model"
)

var routingTableName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

var (
	ErrNotFound            = errors.New("WireGuard Interface 不存在")
	ErrPeerNotFound        = errors.New("WireGuard Peer 不存在")
	ErrConflict            = errors.New("WireGuard 配置冲突")
	ErrRevisionConflict    = errors.New("WireGuard 配置版本冲突")
	ErrRevisionRequired    = errors.New("WireGuard 配置版本不能为空")
	ErrClientConfigMissing = errors.New("客户端配置缺少必要字段")
	ErrInvalidInput        = errors.New("WireGuard 配置无效")
	ErrInvalidFile         = errors.New("WireGuard 配置文件无法解析")
)

func NormalizeInterface(input model.InterfaceInput) (model.InterfaceInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	input.FwMark = strings.TrimSpace(input.FwMark)
	input.Table = strings.TrimSpace(input.Table)
	input.ClientEndpoint = strings.TrimSpace(input.ClientEndpoint)
	input.Address = normalizedList(input.Address)
	input.DNS = normalizedList(input.DNS)
	input.ClientDNS = normalizedList(input.ClientDNS)
	input.ClientAllowedIPs = normalizedList(input.ClientAllowedIPs)
	input.PreUp = normalizedCommands(input.PreUp)
	input.PostUp = normalizedCommands(input.PostUp)
	input.PreDown = normalizedCommands(input.PreDown)
	input.PostDown = normalizedCommands(input.PostDown)

	if err := validateDisplayName("名称", input.Name, true); err != nil {
		return model.InterfaceInput{}, err
	}
	if err := validateKey("PrivateKey", input.PrivateKey, true); err != nil {
		return model.InterfaceInput{}, err
	}
	for _, address := range input.Address {
		if _, err := netip.ParsePrefix(address); err != nil {
			if _, addressErr := netip.ParseAddr(address); addressErr != nil {
				return model.InterfaceInput{}, invalid(
					"Address %q 不是有效的 IP 或 CIDR",
					address,
				)
			}
		}
	}
	for _, dns := range input.DNS {
		if err := validateDNSValue("DNS", dns); err != nil {
			return model.InterfaceInput{}, err
		}
	}
	for _, dns := range input.ClientDNS {
		if err := validateDNSValue("ClientDNS", dns); err != nil {
			return model.InterfaceInput{}, err
		}
	}
	for _, allowedIP := range input.ClientAllowedIPs {
		if _, err := netip.ParsePrefix(allowedIP); err != nil {
			return model.InterfaceInput{}, invalid(
				"ClientAllowedIPs %q 不是有效的 CIDR",
				allowedIP,
			)
		}
	}
	if input.ClientEndpoint != "" {
		if err := validateEndpoint("ClientEndpoint", input.ClientEndpoint); err != nil {
			return model.InterfaceInput{}, err
		}
	}
	if input.MTU != nil && (*input.MTU <= 0 || *input.MTU > 65535) {
		return model.InterfaceInput{}, invalid("MTU 必须在 1 到 65535 之间")
	}
	if input.FwMark != "" && !strings.EqualFold(input.FwMark, "off") {
		value := input.FwMark
		base := 10
		if strings.HasPrefix(strings.ToLower(value), "0x") {
			value = value[2:]
			base = 16
		}
		if value == "" {
			return model.InterfaceInput{}, invalid("FwMark 格式无效")
		}
		if _, err := strconv.ParseUint(value, base, 32); err != nil {
			return model.InterfaceInput{}, invalid(
				"FwMark 必须是 32 位十进制、十六进制或 off",
			)
		}
	}
	if input.Table != "" && !routingTableName.MatchString(input.Table) {
		return model.InterfaceInput{}, invalid(
			"Table 必须是路由表 ID、名称、auto 或 off",
		)
	}
	return input, nil
}

func NormalizePeer(input model.PeerInput) (model.PeerInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	input.PresharedKey = strings.TrimSpace(input.PresharedKey)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.AllowedIPs = normalizedList(input.AllowedIPs)
	input.ClientAddress = normalizedList(input.ClientAddress)

	if err := validateDisplayName("Peer 名称", input.Name, false); err != nil {
		return model.PeerInput{}, err
	}
	if err := validateKey("PublicKey", input.PublicKey, true); err != nil {
		return model.PeerInput{}, err
	}
	if err := validateKey("PrivateKey", input.PrivateKey, false); err != nil {
		return model.PeerInput{}, err
	}
	if input.PrivateKey != "" {
		derived, err := PublicKeyFromPrivate(input.PrivateKey)
		if err != nil {
			return model.PeerInput{}, err
		}
		if derived != input.PublicKey {
			return model.PeerInput{}, invalid(
				"PrivateKey 与 PublicKey 不是同一个 WireGuard 密钥对",
			)
		}
	}
	if err := validateKey("PresharedKey", input.PresharedKey, false); err != nil {
		return model.PeerInput{}, err
	}
	for _, allowedIP := range input.AllowedIPs {
		if _, err := netip.ParsePrefix(allowedIP); err != nil {
			return model.PeerInput{}, invalid(
				"AllowedIPs %q 不是有效的 CIDR",
				allowedIP,
			)
		}
	}
	for _, address := range input.ClientAddress {
		if _, err := netip.ParsePrefix(address); err != nil {
			return model.PeerInput{}, invalid(
				"ClientAddress %q 必须是带掩码的 IP 地址",
				address,
			)
		}
	}
	if input.Endpoint != "" {
		if err := validateEndpoint("Endpoint", input.Endpoint); err != nil {
			return model.PeerInput{}, err
		}
	}
	input.GenerateKeyPair = false
	input.GeneratePresharedKey = false
	return input, nil
}

func LegacyPeerID(publicKey string) string {
	hash := sha256.Sum256([]byte(strings.TrimSpace(publicKey)))
	return "legacy-" + hex.EncodeToString(hash[:16])
}

// PeerID is retained for callers that need the deterministic ID assigned to a
// legacy [Peer] section which does not yet contain "# ID = ...".
func PeerID(publicKey string) string {
	return LegacyPeerID(publicKey)
}

func validateKey(field string, value string, required bool) error {
	if value == "" {
		if required {
			return invalid("%s 不能为空", field)
		}
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return invalid("%s 必须是 WireGuard 使用的 32 字节 Base64 密钥", field)
	}
	return nil
}

func normalizedList(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" || seen[part] {
				continue
			}
			seen[part] = true
			normalized = append(normalized, part)
		}
	}
	return normalized
}

func normalizedCommands(commands []string) []string {
	normalized := make([]string, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command != "" {
			normalized = append(normalized, command)
		}
	}
	return normalized
}

func validateDisplayName(field string, value string, required bool) error {
	if value == "" {
		if required {
			return invalid("%s 不能为空", field)
		}
		return nil
	}
	if strings.ContainsAny(value, "\r\n") || utf8.RuneCountInString(value) > 128 {
		return invalid("%s 不能换行且不能超过 128 个字符", field)
	}
	return nil
}

func validateDNSValue(field string, value string) error {
	if strings.ContainsAny(value, " \t\r\n,") {
		return invalid("%s %q 格式无效", field, value)
	}
	return nil
}

func validateEndpoint(field string, value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return invalid("%s 必须使用 host:port 或 [IPv6]:port 格式", field)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return invalid("%s 端口必须在 1 到 65535 之间", field)
	}
	return nil
}

func invalid(format string, values ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, values...))
}
