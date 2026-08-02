package wgconfig

import (
	"encoding/base64"
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

var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

var (
	ErrNotFound            = errors.New("WireGuard Interface 不存在")
	ErrPeerNotFound        = errors.New("WireGuard Peer 不存在")
	ErrConflict            = errors.New("WireGuard 配置冲突")
	ErrRevisionConflict    = errors.New("WireGuard 配置版本冲突")
	ErrRevisionRequired    = errors.New("WireGuard 配置版本不能为空")
	ErrClientConfigMissing = errors.New("客户端配置缺少必要字段")
	ErrInvalidInput        = errors.New("WireGuard 配置无效")
	ErrInvalidFile         = errors.New("WireGuard 配置文件无法解析")
	ErrRestartRequired     = errors.New("WireGuard Interface 需要重启")
	ErrTunnelOperation     = errors.New("WireGuard 隧道操作失败")
)

func NormalizeInterface(input model.InterfaceInput) (model.InterfaceInput, error) {
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	input.ClientEndpoint = strings.TrimSpace(input.ClientEndpoint)
	input.Address = normalizedList(input.Address)
	input.DNS = normalizedList(input.DNS)
	input.ClientAllowedIPs = normalizedList(input.ClientAllowedIPs)

	if err := validateKey("PrivateKey", input.PrivateKey, true); err != nil {
		return model.InterfaceInput{}, err
	}
	for _, address := range input.Address {
		if _, err := netip.ParsePrefix(address); err != nil {
			return model.InterfaceInput{}, invalid(
				"Address %q 不是有效的 CIDR",
				address,
			)
		}
	}
	for _, dns := range input.DNS {
		if err := validateDNSValue("DNS", dns); err != nil {
			return model.InterfaceInput{}, err
		}
	}
	if input.ClientEndpoint != "" {
		if err := validateEndpoint("ClientEndpoint", input.ClientEndpoint); err != nil {
			return model.InterfaceInput{}, err
		}
	}
	for _, allowedIP := range input.ClientAllowedIPs {
		if _, err := netip.ParsePrefix(allowedIP); err != nil {
			return model.InterfaceInput{}, invalid(
				"路由范围约束 %q 不是有效的 CIDR",
				allowedIP,
			)
		}
	}
	if input.MTU != nil && (*input.MTU <= 0 || *input.MTU > 65535) {
		return model.InterfaceInput{}, invalid("MTU 必须在 1 到 65535 之间")
	}
	return input, nil
}

func ValidateInterfaceName(value string) error {
	if !interfaceNamePattern.MatchString(value) {
		return invalid("Interface 名称必须是 1 到 15 位英文字母、数字、减号或下划线")
	}
	return nil
}

func NormalizePeer(input model.PeerInput) (model.PeerInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.PrivateKey = strings.TrimSpace(input.PrivateKey)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	input.PresharedKey = strings.TrimSpace(input.PresharedKey)
	input.Endpoint = strings.TrimSpace(input.Endpoint)
	input.AllowedIPs = normalizedList(input.AllowedIPs)

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
	if input.Endpoint != "" {
		if err := validateEndpoint("Endpoint", input.Endpoint); err != nil {
			return model.PeerInput{}, err
		}
	}
	return input, nil
}

// ConfigurationValidationErrors reports semantic problems without preventing
// an existing native file from being opened and repaired in the panel.
func ConfigurationValidationErrors(config model.Interface) []string {
	problems := make([]string, 0)
	seen := make(map[string]bool)
	appendProblem := func(message string) {
		if message == "" || seen[message] {
			return
		}
		seen[message] = true
		problems = append(problems, message)
	}
	if _, err := NormalizeInterface(interfaceInput(config)); err != nil {
		appendProblem(err.Error())
	}
	for index, peer := range config.Peers {
		if _, err := NormalizePeer(peerInput(peer)); err != nil {
			appendProblem(fmt.Sprintf("Peer %d（%s）：%v", index+1, peer.Name, err))
		}
	}
	if err := validateRuntimePeerSet(config); err != nil {
		appendProblem(err.Error())
	}
	return problems
}

func blockingConfigurationValidationErrors(config model.Interface) []string {
	return append([]string(nil), config.ValidationErrors...)
}

func validateKey(field string, value string, required bool) error {
	if value == "" {
		if required {
			return invalid("%s 不能为空", field)
		}
		return nil
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return invalid("%s 必须是 WireGuard 使用的 32 字节 Base64 密钥", field)
	}
	return nil
}

// EncodePeerPublicKeyPath converts a standard WireGuard PublicKey into one
// canonical, URL-safe path segment. Padding is omitted so '/', '+' and '=' can
// never affect route matching.
func EncodePeerPublicKeyPath(publicKey string) (string, error) {
	publicKey = strings.TrimSpace(publicKey)
	if err := validateKey("PublicKey", publicKey, true); err != nil {
		return "", err
	}
	decoded, _ := base64.StdEncoding.Strict().DecodeString(publicKey)
	return base64.RawURLEncoding.EncodeToString(decoded), nil
}

// DecodePeerPublicKeyPath accepts only the canonical path representation and
// restores the standard padded Base64 value stored in WireGuard configs.
func DecodePeerPublicKeyPath(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", invalid("Peer PublicKey 路径无效")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", invalid("Peer PublicKey 路径无效")
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
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
