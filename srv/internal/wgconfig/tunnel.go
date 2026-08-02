package wgconfig

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"wireguard-panel/internal/model"
)

const defaultTunnelCommandTimeout = 20 * time.Second

// TunnelController applies a native wg-quick configuration and verifies that
// the kernel WireGuard configuration is the configuration produced from that
// file. Names are validated before they reach this interface.
type TunnelController interface {
	IsRunning(context.Context, string) (bool, error)
	Down(context.Context, string) error
	Up(context.Context, string) error
	Verify(context.Context, string) error
}

// IncrementalTunnelController updates a running Interface without taking it
// down. The Store calls it only for changes that can be safely reconciled with
// wg and ip commands; file-only metadata never reaches this interface.
type IncrementalTunnelController interface {
	ApplyIncremental(
		context.Context,
		string,
		model.Interface,
		model.Interface,
	) error
}

// PreflightTunnelController validates the complete wg-quick file without
// changing runtime state. RestartApplied uses it before stopping a live tunnel.
type PreflightTunnelController interface {
	ValidateConfiguration(context.Context, string, []byte) error
}

// FileOnlyTunnelController is an explicit development controller that keeps
// native configuration files editable without invoking wg or wg-quick. It
// always reports Interfaces as stopped and refuses attempts to start one.
type FileOnlyTunnelController struct{}

func (FileOnlyTunnelController) IsRunning(context.Context, string) (bool, error) {
	return false, nil
}

func (FileOnlyTunnelController) Down(context.Context, string) error {
	return nil
}

func (FileOnlyTunnelController) Up(context.Context, string) error {
	return fileOnlyStartError()
}

func (FileOnlyTunnelController) Verify(context.Context, string) error {
	return fileOnlyStartError()
}

func (FileOnlyTunnelController) fileOnly() {}

type fileOnlyController interface {
	fileOnly()
}

func isFileOnlyController(controller TunnelController) bool {
	_, ok := controller.(fileOnlyController)
	return ok
}

// RuntimeControllable reports whether mutations can be applied to a real
// WireGuard interface. HTTP status responses expose this distinction so the UI
// never describes file-only development mode as a running system tunnel.
func RuntimeControllable(controller TunnelController) bool {
	return controller != nil && !isFileOnlyController(controller)
}

func fileOnlyStartError() error {
	return fmt.Errorf(
		"%w: file-only 模式只保存配置文件，不能启动真实 WireGuard 隧道",
		ErrTunnelOperation,
	)
}

type ExecTunnelController struct {
	WGBinary        string
	WGQuickBinary   string
	IPBinary        string
	ConfigDirectory string
	Timeout         time.Duration
}

func (controller ExecTunnelController) ValidateEnvironment() error {
	for _, binary := range []string{
		controller.wgBinary(),
		controller.wgQuickBinary(),
		controller.ipBinary(),
	} {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Errorf("required WireGuard command %q is unavailable: %w", binary, err)
		}
	}
	if controller.ConfigDirectory != "" && !filepath.IsAbs(controller.ConfigDirectory) {
		return fmt.Errorf("WireGuard configuration directory must be absolute")
	}
	return nil
}

func (controller ExecTunnelController) ValidateConfiguration(
	ctx context.Context,
	name string,
	data []byte,
) error {
	temporaryDirectory, err := os.MkdirTemp("", ".wireguard-panel-preflight-*")
	if err != nil {
		return fmt.Errorf("%w: 无法创建配置预检目录: %v", ErrInvalidInput, err)
	}
	defer os.RemoveAll(temporaryDirectory)
	if err := os.Chmod(temporaryDirectory, 0o700); err != nil {
		return fmt.Errorf("%w: 无法保护配置预检目录: %v", ErrInvalidInput, err)
	}
	temporaryConfig := filepath.Join(temporaryDirectory, filenameForID(name))
	if err := os.WriteFile(temporaryConfig, data, 0o600); err != nil {
		return fmt.Errorf("%w: 无法写入待预检配置: %v", ErrInvalidInput, err)
	}
	if _, err := controller.run(
		ctx, controller.wgQuickBinary(), "strip", temporaryConfig,
	); err != nil {
		return fmt.Errorf(
			"%w: 配置预检失败，Interface 保持当前运行状态: %v",
			ErrInvalidInput,
			err,
		)
	}
	return nil
}

func (controller ExecTunnelController) ApplyIncremental(
	ctx context.Context,
	name string,
	before model.Interface,
	after model.Interface,
) error {
	for _, address := range stringSetDifference(after.Address, before.Address) {
		if err := controller.replaceAddress(ctx, name, address); err != nil {
			return err
		}
	}
	if wireGuardDeviceChanged(before, after) {
		if err := controller.syncWireGuard(ctx, name); err != nil {
			return err
		}
		for _, publicKey := range keepalivesToDisable(before, after) {
			if _, err := controller.run(
				ctx,
				controller.wgBinary(),
				"set", name, "peer", publicKey, "persistent-keepalive", "0",
			); err != nil {
				return fmt.Errorf(
					"%w: 清除 %s Peer PersistentKeepalive 失败: %v",
					ErrTunnelOperation,
					name,
					err,
				)
			}
		}
	}
	beforeRoutes := peerRouteSet(before)
	afterRoutes := peerRouteSet(after)
	for _, route := range sortedSetDifference(afterRoutes, beforeRoutes) {
		if err := controller.addRoute(ctx, name, route); err != nil {
			return err
		}
	}
	for _, route := range sortedSetDifference(beforeRoutes, afterRoutes) {
		if err := controller.deleteRoute(ctx, name, route); err != nil {
			return err
		}
	}
	for _, address := range stringSetDifference(before.Address, after.Address) {
		if err := controller.deleteAddress(ctx, name, address); err != nil {
			return err
		}
	}
	// Apply MTU last. A concrete MTU update has no following failure point, so
	// an earlier address/route failure can still be rolled back completely.
	if !equalInt(before.MTU, after.MTU) && after.MTU != nil {
		if _, err := controller.run(
			ctx,
			controller.ipBinary(),
			"link", "set", "mtu", fmt.Sprint(*after.MTU), "dev", name,
		); err != nil {
			return fmt.Errorf("%w: 更新 %s MTU 失败: %v", ErrTunnelOperation, name, err)
		}
	}
	return nil
}

func (controller ExecTunnelController) IsRunning(
	ctx context.Context,
	name string,
) (bool, error) {
	output, err := controller.run(ctx, controller.wgBinary(), "show", "interfaces")
	if err != nil {
		return false, fmt.Errorf("%w: 无法确认 Interface 是否正在运行: %v", ErrTunnelOperation, err)
	}
	for _, active := range strings.Fields(string(output)) {
		if active == name {
			return true, nil
		}
	}
	return false, nil
}

func (controller ExecTunnelController) Down(ctx context.Context, name string) error {
	if _, err := controller.run(
		ctx, controller.wgQuickBinary(), "down", controller.configTarget(name),
	); err != nil {
		return fmt.Errorf("%w: 停止隧道 %s 失败: %v", ErrTunnelOperation, name, err)
	}
	return nil
}

func (controller ExecTunnelController) Up(ctx context.Context, name string) error {
	if _, err := controller.run(
		ctx, controller.wgQuickBinary(), "up", controller.configTarget(name),
	); err != nil {
		return fmt.Errorf("%w: 启动隧道 %s 失败: %v", ErrTunnelOperation, name, err)
	}
	return nil
}

func (controller ExecTunnelController) Verify(ctx context.Context, name string) error {
	desired, err := controller.run(
		ctx, controller.wgQuickBinary(), "strip", controller.configTarget(name),
	)
	if err != nil {
		return fmt.Errorf("%w: 无法生成 %s 的待应用配置: %v", ErrTunnelOperation, name, err)
	}
	actual, err := controller.run(ctx, controller.wgBinary(), "showconf", name)
	if err != nil {
		return fmt.Errorf("%w: 无法读取 %s 的实际运行配置: %v", ErrTunnelOperation, name, err)
	}
	match, err := runtimeConfigMatches(desired, actual)
	if err != nil {
		return fmt.Errorf("%w: 校验 %s 的实际运行配置失败: %v", ErrTunnelOperation, name, err)
	}
	if !match {
		return fmt.Errorf(
			"%w: %s.conf 与实际运行中的 WireGuard 配置不一致",
			ErrTunnelOperation,
			name,
		)
	}
	return nil
}

func (controller ExecTunnelController) syncWireGuard(
	ctx context.Context,
	name string,
) error {
	desired, err := controller.run(
		ctx, controller.wgQuickBinary(), "strip", controller.configTarget(name),
	)
	if err != nil {
		return fmt.Errorf(
			"%w: 无法生成 %s 的增量 WireGuard 配置: %v",
			ErrTunnelOperation,
			name,
			err,
		)
	}
	temporary, err := os.CreateTemp("", ".wg-panel-sync-*.conf")
	if err != nil {
		return fmt.Errorf("%w: 创建增量配置失败: %v", ErrTunnelOperation, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("%w: 保护增量配置失败: %v", ErrTunnelOperation, err)
	}
	if _, err := temporary.Write(desired); err != nil {
		temporary.Close()
		return fmt.Errorf("%w: 写入增量配置失败: %v", ErrTunnelOperation, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: 关闭增量配置失败: %v", ErrTunnelOperation, err)
	}
	if _, err := controller.run(
		ctx,
		controller.wgBinary(),
		"syncconf",
		name,
		temporaryPath,
	); err != nil {
		return fmt.Errorf("%w: 热更新 %s 失败: %v", ErrTunnelOperation, name, err)
	}
	return nil
}

func (controller ExecTunnelController) replaceAddress(
	ctx context.Context,
	name string,
	address string,
) error {
	if _, err := controller.run(
		ctx,
		controller.ipBinary(),
		ipFamilyFlag(address), "address", "add", address, "dev", name,
	); err != nil {
		return fmt.Errorf("%w: 添加地址 %s 失败: %v", ErrTunnelOperation, address, err)
	}
	return nil
}

func (controller ExecTunnelController) deleteAddress(
	ctx context.Context,
	name string,
	address string,
) error {
	if _, err := controller.run(
		ctx,
		controller.ipBinary(),
		ipFamilyFlag(address), "address", "del", address, "dev", name,
	); err != nil && !isMissingIPObject(err) {
		return fmt.Errorf("%w: 删除地址 %s 失败: %v", ErrTunnelOperation, address, err)
	}
	return nil
}

func (controller ExecTunnelController) addRoute(
	ctx context.Context,
	name string,
	route string,
) error {
	existing, err := controller.run(
		ctx,
		controller.ipBinary(),
		ipFamilyFlag(route), "route", "show", "dev", name, "match", route,
	)
	if err != nil {
		return fmt.Errorf("%w: 检查路由 %s 失败: %v", ErrTunnelOperation, route, err)
	}
	if strings.TrimSpace(string(existing)) != "" {
		return nil
	}
	if _, err := controller.run(
		ctx,
		controller.ipBinary(),
		ipFamilyFlag(route), "route", "add", route, "dev", name,
	); err != nil {
		return fmt.Errorf("%w: 更新路由 %s 失败: %v", ErrTunnelOperation, route, err)
	}
	return nil
}

func (controller ExecTunnelController) deleteRoute(
	ctx context.Context,
	name string,
	route string,
) error {
	if _, err := controller.run(
		ctx,
		controller.ipBinary(),
		ipFamilyFlag(route), "route", "del", route, "dev", name,
	); err != nil && !isMissingIPObject(err) {
		return fmt.Errorf("%w: 删除路由 %s 失败: %v", ErrTunnelOperation, route, err)
	}
	return nil
}

func ipFamilyFlag(value string) string {
	address := strings.SplitN(value, "/", 2)[0]
	if strings.Contains(address, ":") {
		return "-6"
	}
	return "-4"
}

func isMissingIPObject(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "cannot assign requested address") ||
		strings.Contains(message, "no such process") ||
		strings.Contains(message, "not found")
}

func stringSetDifference(left []string, right []string) []string {
	rightSet := make(map[string]bool, len(right))
	for _, value := range right {
		rightSet[value] = true
	}
	values := make([]string, 0)
	for _, value := range left {
		if !rightSet[value] {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}

func keepalivesToDisable(before model.Interface, after model.Interface) []string {
	afterByPublicKey := make(map[string]model.Peer, len(after.Peers))
	for _, peer := range after.Peers {
		afterByPublicKey[peer.PublicKey] = peer
	}
	publicKeys := make([]string, 0)
	for _, peer := range before.Peers {
		if peer.PersistentKeepalive == nil || *peer.PersistentKeepalive == 0 {
			continue
		}
		next, ok := afterByPublicKey[peer.PublicKey]
		if !ok {
			continue
		}
		if next.PersistentKeepalive == nil || *next.PersistentKeepalive == 0 {
			publicKeys = append(publicKeys, peer.PublicKey)
		}
	}
	sort.Strings(publicKeys)
	return publicKeys
}

type runtimeWireGuardConfig struct {
	interfaceFields map[string]string
	peers           map[string]map[string]string
}

func runtimeConfigMatches(desiredData []byte, actualData []byte) (bool, error) {
	desired, err := parseRuntimeWireGuardConfig(desiredData)
	if err != nil {
		return false, fmt.Errorf("parse desired configuration: %w", err)
	}
	actual, err := parseRuntimeWireGuardConfig(actualData)
	if err != nil {
		return false, fmt.Errorf("parse running configuration: %w", err)
	}
	if !runtimeFieldsMatch(desired.interfaceFields, actual.interfaceFields, true) {
		return false, nil
	}
	if len(desired.peers) != len(actual.peers) {
		return false, nil
	}
	for publicKey, desiredPeer := range desired.peers {
		actualPeer, ok := actual.peers[publicKey]
		if !ok || !runtimeFieldsMatch(desiredPeer, actualPeer, false) {
			return false, nil
		}
	}
	return true, nil
}

func parseRuntimeWireGuardConfig(data []byte) (runtimeWireGuardConfig, error) {
	config := runtimeWireGuardConfig{
		interfaceFields: make(map[string]string),
		peers:           make(map[string]map[string]string),
	}
	section := ""
	sawInterface := false
	var peer map[string]string
	finishPeer := func() error {
		if peer == nil {
			return nil
		}
		publicKey := peer["publickey"]
		if publicKey == "" {
			return fmt.Errorf("Peer is missing PublicKey")
		}
		if _, exists := config.peers[publicKey]; exists {
			return fmt.Errorf("duplicate Peer PublicKey")
		}
		config.peers[publicKey] = peer
		peer = nil
		return nil
	}

	for lineNumber, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if err := finishPeer(); err != nil {
				return runtimeWireGuardConfig{}, err
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				if sawInterface {
					return runtimeWireGuardConfig{}, fmt.Errorf("duplicate Interface section")
				}
				sawInterface = true
			case "peer":
				peer = make(map[string]string)
			default:
				return runtimeWireGuardConfig{}, fmt.Errorf(
					"line %d has unsupported section %q",
					lineNumber+1,
					section,
				)
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || section == "" {
			return runtimeWireGuardConfig{}, fmt.Errorf("line %d is invalid", lineNumber+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		target := config.interfaceFields
		if section == "peer" {
			target = peer
		}
		if _, exists := target[key]; exists {
			return runtimeWireGuardConfig{}, fmt.Errorf("line %d duplicates %s", lineNumber+1, key)
		}
		target[key] = value
	}
	if err := finishPeer(); err != nil {
		return runtimeWireGuardConfig{}, err
	}
	if !sawInterface {
		return runtimeWireGuardConfig{}, fmt.Errorf("Interface section is missing")
	}
	return config, nil
}

func runtimeFieldsMatch(
	desired map[string]string,
	actual map[string]string,
	isInterface bool,
) bool {
	for key, desiredValue := range desired {
		// Endpoint is live roaming state, not a stable configuration value.
		// WireGuard updates it after authenticated packets, and showconf reports
		// that learned address even when the source file omits Endpoint.
		if !isInterface && key == "endpoint" {
			continue
		}
		actualValue, ok := actual[key]
		if isInterface && (key == "listenport" || key == "fwmark") && desiredValue == "0" {
			continue
		}
		if !ok || !runtimeValueMatches(key, desiredValue, actualValue) {
			return false
		}
	}
	for key := range actual {
		if !isInterface && key == "endpoint" {
			continue
		}
		if _, ok := desired[key]; ok {
			continue
		}
		// wg-quick assigns these values dynamically when they are omitted from
		// the file. They do not represent a configuration mismatch.
		if isInterface && (key == "listenport" || key == "fwmark") {
			continue
		}
		return false
	}
	return true
}

func runtimeValueMatches(key string, desired string, actual string) bool {
	switch key {
	case "allowedips":
		return canonicalPrefixes(desired) == canonicalPrefixes(actual)
	default:
		return desired == actual
	}
}

func canonicalPrefixes(value string) string {
	parts := strings.Split(value, ",")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			trimmed = prefix.Masked().String()
		}
		normalized = append(normalized, trimmed)
	}
	sort.Strings(normalized)
	return strings.Join(normalized, ",")
}

func (controller ExecTunnelController) run(
	ctx context.Context,
	binary string,
	arguments ...string,
) ([]byte, error) {
	timeout := controller.Timeout
	if timeout <= 0 {
		timeout = defaultTunnelCommandTimeout
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := exec.CommandContext(commandContext, binary, arguments...).CombinedOutput()
	if err == nil {
		return output, nil
	}
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("命令执行超时")
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return nil, err
	}
	if len(detail) > 500 {
		detail = detail[:500] + "…"
	}
	return nil, fmt.Errorf("%v: %s", err, detail)
}

func (controller ExecTunnelController) wgBinary() string {
	if controller.WGBinary != "" {
		return controller.WGBinary
	}
	return "wg"
}

func (controller ExecTunnelController) wgQuickBinary() string {
	if controller.WGQuickBinary != "" {
		return controller.WGQuickBinary
	}
	return "wg-quick"
}

func (controller ExecTunnelController) ipBinary() string {
	if controller.IPBinary != "" {
		return controller.IPBinary
	}
	return "ip"
}

func (controller ExecTunnelController) configTarget(name string) string {
	if controller.ConfigDirectory == "" {
		return name
	}
	return filepath.Join(controller.ConfigDirectory, filenameForID(name))
}
