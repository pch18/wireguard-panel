package wgconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"wireguard-panel/internal/model"
)

const rollbackTimeout = 2 * time.Minute

// Applied methods serialize file and runtime operations per Interface. The
// configuration file is the only durable source of truth owned by the panel:
// metadata changes only rewrite it, safe live changes use the incremental
// controller, and rebuild-required changes execute a confirmed stop/write/up
// transaction. No second "applied configuration" snapshot is maintained.

func (store *Store) CreateApplied(
	ctx context.Context,
	id string,
	input model.InterfaceInput,
	tunnels TunnelController,
) (model.Interface, error) {
	if err := ValidateInterfaceName(id); err != nil {
		return model.Interface{}, err
	}
	input, err := NormalizeInterface(input)
	if err != nil {
		return model.Interface{}, err
	}
	store.namespaceMu.Lock()
	defer store.namespaceMu.Unlock()
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	exists, err := store.configExists(id)
	if err != nil {
		return model.Interface{}, fmt.Errorf("inspect WireGuard configuration: %w", err)
	}
	if exists {
		return model.Interface{}, fmt.Errorf("%w: Interface 名称 %q 已存在", ErrConflict, id)
	}
	config := model.Interface{ID: id, Filename: filenameForID(id), Peers: make([]model.Peer, 0)}
	applyInterfaceInput(&config, input)
	data, err := Serialize(config)
	if err != nil {
		return model.Interface{}, err
	}
	return store.createAppliedLocked(ctx, id, data, tunnels)
}

func (store *Store) ImportApplied(
	ctx context.Context,
	data []byte,
	tunnels TunnelController,
) (model.Interface, error) {
	store.namespaceMu.Lock()
	defer store.namespaceMu.Unlock()
	ids, err := store.occupiedInterfaceIDs()
	if err != nil {
		return model.Interface{}, err
	}
	used := make(map[string]bool, len(ids))
	for _, id := range ids {
		used[id] = true
	}
	nextID := ""
	for index := 0; ; index++ {
		candidate := fmt.Sprintf("wg%d", index)
		if !used[candidate] {
			nextID = candidate
			break
		}
	}
	unlock := store.lockInterfaceOperations(nextID)
	defer unlock()
	parsed, err := Parse(nextID, filenameForID(nextID), data)
	if err != nil {
		return model.Interface{}, err
	}
	if blocking := blockingConfigurationValidationErrors(parsed); len(blocking) > 0 {
		return model.Interface{}, fmt.Errorf(
			"%w: 导入的 Interface 必须先修正：%s",
			ErrInvalidFile,
			strings.Join(blocking, "；"),
		)
	}
	return store.createAppliedLocked(ctx, nextID, data, tunnels)
}

func (store *Store) createAppliedLocked(
	ctx context.Context,
	id string,
	data []byte,
	tunnels TunnelController,
) (model.Interface, error) {
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	running, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if running {
		return model.Interface{}, fmt.Errorf(
			"%w: 运行中已存在同名 Interface %q",
			ErrConflict,
			id,
		)
	}
	if !isFileOnlyController(tunnels) {
		if err := preflightConfiguration(ctx, id, data, tunnels); err != nil {
			return model.Interface{}, err
		}
	}
	if err := store.writeRaw(id, data); err != nil {
		return model.Interface{}, err
	}
	if isFileOnlyController(tunnels) {
		return store.Get(id)
	}
	if err := startAndVerify(ctx, id, tunnels); err != nil {
		rollbackErr := store.rollbackCreatedLocked(id, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	return store.Get(id)
}

func (store *Store) UpdateApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	input model.InterfaceInput,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	input, err := NormalizeInterface(input)
	if err != nil {
		return model.Interface{}, err
	}
	return store.mutateApplied(ctx, id, expectedRevision, tunnels, restartConfirmed, func(config *model.Interface) error {
		applyInterfaceInput(config, input)
		return nil
	})
}

func (store *Store) ImportOverApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	data []byte,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	parsed, err := Parse(id, filenameForID(id), data)
	if err != nil {
		return model.Interface{}, err
	}
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	existing, err := store.Get(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(existing, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	wasRunning, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	changeKind := classifyRuntimeChange(existing, parsed)
	if changeKind == runtimeUnchanged || !wasRunning || isFileOnlyController(tunnels) {
		if err := store.writeRaw(id, data); err != nil {
			return model.Interface{}, err
		}
		return store.Get(id)
	}
	if blocking := blockingConfigurationValidationErrors(parsed); len(blocking) > 0 {
		return model.Interface{}, fmt.Errorf(
			"%w: 应用到运行中的 Interface 前请先修正配置：%s",
			ErrInvalidFile,
			strings.Join(blocking, "；"),
		)
	}
	originalData, err := store.RawConfig(id)
	if err != nil {
		return model.Interface{}, fmt.Errorf("read WireGuard configuration for replacement: %w", err)
	}
	if changeKind == runtimeHotUpdate {
		if incremental, ok := tunnels.(IncrementalTunnelController); ok {
			if err := store.writeRaw(id, data); err != nil {
				return model.Interface{}, err
			}
			if err := incremental.ApplyIncremental(ctx, id, existing, parsed); err != nil {
				rollbackErr := store.rollbackIncrementalMutationLocked(
					id, originalData, parsed, existing, incremental, tunnels,
				)
				return model.Interface{}, appliedOperationError(err, rollbackErr)
			}
			if err := tunnels.Verify(ctx, id); err != nil {
				rollbackErr := store.rollbackIncrementalMutationLocked(
					id, originalData, parsed, existing, incremental, tunnels,
				)
				return model.Interface{}, appliedOperationError(err, rollbackErr)
			}
			return store.Get(id)
		}
	}
	if !restartConfirmed {
		return model.Interface{}, restartRequired()
	}
	if err := preflightConfiguration(ctx, id, data, tunnels); err != nil {
		return model.Interface{}, err
	}
	return store.restartWithNewConfigurationLocked(ctx, id, originalData, data, tunnels)
}

func (store *Store) StartApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	tunnels TunnelController,
) (model.Interface, error) {
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	if isFileOnlyController(tunnels) {
		return model.Interface{}, fileOnlyStartError()
	}
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	config, data, err := store.validatedConfiguration(id, expectedRevision, "启动")
	if err != nil {
		return model.Interface{}, err
	}
	running, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if running {
		if err := tunnels.Verify(ctx, id); err != nil {
			return model.Interface{}, err
		}
		return config, nil
	}
	if err := preflightConfiguration(ctx, id, data, tunnels); err != nil {
		return model.Interface{}, err
	}
	if err := startAndVerify(ctx, id, tunnels); err != nil {
		rollbackErr := stopForRollback(context.Background(), id, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	return store.Get(id)
}

func (store *Store) StopApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	tunnels TunnelController,
) (model.Interface, error) {
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	config, err := store.Get(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	running, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if !running {
		return config, nil
	}
	if err := tunnels.Down(ctx, id); err != nil {
		rollbackErr := store.restoreCurrentConfigurationRuntime(id, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	if err := verifyStopped(ctx, id, tunnels); err != nil {
		rollbackErr := store.restoreCurrentConfigurationRuntime(id, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	return store.Get(id)
}

func (store *Store) RestartApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	tunnels TunnelController,
) (model.Interface, error) {
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	if isFileOnlyController(tunnels) {
		return model.Interface{}, fileOnlyStartError()
	}
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	_, data, err := store.validatedConfiguration(id, expectedRevision, "重启")
	if err != nil {
		return model.Interface{}, err
	}
	if err := preflightConfiguration(ctx, id, data, tunnels); err != nil {
		return model.Interface{}, err
	}
	wasRunning, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if wasRunning {
		if err := tunnels.Down(ctx, id); err != nil {
			rollbackErr := store.restoreCurrentConfigurationRuntime(id, tunnels)
			return model.Interface{}, appliedOperationError(err, rollbackErr)
		}
		if err := verifyStopped(ctx, id, tunnels); err != nil {
			rollbackErr := store.restoreCurrentConfigurationRuntime(id, tunnels)
			return model.Interface{}, appliedOperationError(err, rollbackErr)
		}
	}
	if err := startAndVerify(ctx, id, tunnels); err != nil {
		rollbackErr := store.restoreCurrentConfigurationRuntime(id, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	return store.Get(id)
}

func (store *Store) AddPeerApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	input model.PeerInput,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	input, err := preparePeerInput(input)
	if err != nil {
		return model.Interface{}, err
	}
	return store.mutateApplied(ctx, id, expectedRevision, tunnels, restartConfirmed, func(config *model.Interface) error {
		if peerIndexByPublicKey(config.Peers, input.PublicKey) >= 0 {
			return duplicatePeerPublicKey()
		}
		config.Peers = append(config.Peers, peerFromInput(input))
		return validatePeerSet(*config)
	})
}

func (store *Store) ImportPeerApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	data []byte,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	peer, err := ParsePeer(data)
	if err != nil {
		return model.Interface{}, err
	}
	return store.mutateApplied(ctx, id, expectedRevision, tunnels, restartConfirmed, func(config *model.Interface) error {
		if peerIndexByPublicKey(config.Peers, peer.PublicKey) >= 0 {
			return duplicatePeerPublicKey()
		}
		config.Peers = append(config.Peers, peer)
		return validatePeerSet(*config)
	})
}

func (store *Store) UpdatePeerApplied(
	ctx context.Context,
	interfaceID string,
	originalPublicKey string,
	expectedRevision string,
	input model.PeerInput,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	input, err := preparePeerInput(input)
	if err != nil {
		return model.Interface{}, err
	}
	return store.mutateApplied(ctx, interfaceID, expectedRevision, tunnels, restartConfirmed, func(config *model.Interface) error {
		index := peerIndexByPublicKey(config.Peers, originalPublicKey)
		if index < 0 {
			return ErrPeerNotFound
		}
		if duplicateIndex := peerIndexByPublicKey(config.Peers, input.PublicKey); duplicateIndex >= 0 && duplicateIndex != index {
			return duplicatePeerPublicKey()
		}
		config.Peers[index] = peerFromInput(input)
		return validatePeerSet(*config)
	})
}

func (store *Store) DeletePeerApplied(
	ctx context.Context,
	interfaceID string,
	publicKey string,
	expectedRevision string,
	tunnels TunnelController,
	restartConfirmed bool,
) (model.Interface, error) {
	return store.mutateApplied(ctx, interfaceID, expectedRevision, tunnels, restartConfirmed, func(config *model.Interface) error {
		index := peerIndexByPublicKey(config.Peers, publicKey)
		if index < 0 {
			return ErrPeerNotFound
		}
		config.Peers = append(config.Peers[:index], config.Peers[index+1:]...)
		return nil
	})
}

func (store *Store) mutateApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	tunnels TunnelController,
	restartConfirmed bool,
	mutate func(*model.Interface) error,
) (model.Interface, error) {
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	config, err := store.Get(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	originalConfig := cloneInterface(config)
	if err := mutate(&config); err != nil {
		return model.Interface{}, err
	}
	changeKind := classifyRuntimeChange(originalConfig, config)
	if changeKind == runtimeUnchanged {
		if err := store.write(config); err != nil {
			return model.Interface{}, err
		}
		return store.Get(id)
	}
	wasRunning, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if !wasRunning || isFileOnlyController(tunnels) {
		if err := store.write(config); err != nil {
			return model.Interface{}, err
		}
		return store.Get(id)
	}
	if changeKind == runtimeHotUpdate {
		if incremental, ok := tunnels.(IncrementalTunnelController); ok {
			originalData, err := store.RawConfig(id)
			if err != nil {
				return model.Interface{}, fmt.Errorf("read WireGuard configuration for transaction: %w", err)
			}
			if err := store.write(config); err != nil {
				return model.Interface{}, err
			}
			if err := incremental.ApplyIncremental(ctx, id, originalConfig, config); err != nil {
				rollbackErr := store.rollbackIncrementalMutationLocked(id, originalData, config, originalConfig, incremental, tunnels)
				return model.Interface{}, appliedOperationError(err, rollbackErr)
			}
			if err := tunnels.Verify(ctx, id); err != nil {
				rollbackErr := store.rollbackIncrementalMutationLocked(id, originalData, config, originalConfig, incremental, tunnels)
				return model.Interface{}, appliedOperationError(err, rollbackErr)
			}
			return store.Get(id)
		}
	}
	if !restartConfirmed {
		return model.Interface{}, restartRequired()
	}
	newData, err := Serialize(config)
	if err != nil {
		return model.Interface{}, err
	}
	if err := preflightConfiguration(ctx, id, newData, tunnels); err != nil {
		return model.Interface{}, err
	}
	originalData, err := store.RawConfig(id)
	if err != nil {
		return model.Interface{}, fmt.Errorf("read WireGuard configuration for transaction: %w", err)
	}
	return store.restartWithNewConfigurationLocked(ctx, id, originalData, newData, tunnels)
}

func (store *Store) restartWithNewConfigurationLocked(
	ctx context.Context,
	id string,
	originalData []byte,
	newData []byte,
	tunnels TunnelController,
) (model.Interface, error) {
	// The old file intentionally remains untouched until Down returns and the
	// stopped state is verified. wg-quick therefore always tears down using the
	// same file that was present before this save began.
	if err := tunnels.Down(ctx, id); err != nil {
		rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	if err := verifyStopped(ctx, id, tunnels); err != nil {
		rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	if err := store.writeRaw(id, newData); err != nil {
		rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	if err := startAndVerify(ctx, id, tunnels); err != nil {
		rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
		return model.Interface{}, appliedOperationError(err, rollbackErr)
	}
	return store.Get(id)
}

func (store *Store) validatedConfiguration(
	id string,
	expectedRevision string,
	action string,
) (model.Interface, []byte, error) {
	config, err := store.Get(id)
	if err != nil {
		return model.Interface{}, nil, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, nil, err
	}
	if blocking := blockingConfigurationValidationErrors(config); len(blocking) > 0 {
		return model.Interface{}, nil, fmt.Errorf(
			"%w: %s前请先修正配置：%s",
			ErrInvalidInput,
			action,
			strings.Join(blocking, "；"),
		)
	}
	data, err := store.RawConfig(id)
	if err != nil {
		return model.Interface{}, nil, fmt.Errorf("read WireGuard configuration for %s: %w", action, err)
	}
	return config, data, nil
}

func preflightConfiguration(
	ctx context.Context,
	id string,
	data []byte,
	tunnels TunnelController,
) error {
	if preflight, ok := tunnels.(PreflightTunnelController); ok {
		return preflight.ValidateConfiguration(ctx, id, data)
	}
	return nil
}

func restartRequired() error {
	return fmt.Errorf(
		"%w: 此修改需要短暂停止并重新启动 Interface；请确认后重试",
		ErrRestartRequired,
	)
}

func (store *Store) rollbackIncrementalMutationLocked(
	id string,
	originalData []byte,
	current model.Interface,
	original model.Interface,
	incremental IncrementalTunnelController,
	tunnels TunnelController,
) error {
	recoveryContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := store.writeRaw(id, originalData); err != nil {
		return fmt.Errorf("恢复原配置文件失败: %w", err)
	}
	if err := incremental.ApplyIncremental(recoveryContext, id, current, original); err != nil {
		return fmt.Errorf("恢复原运行配置失败: %w", err)
	}
	return tunnels.Verify(recoveryContext, id)
}

func (store *Store) DeleteApplied(
	ctx context.Context,
	id string,
	expectedRevision string,
	tunnels TunnelController,
) error {
	if tunnels == nil {
		return tunnelUnavailable()
	}
	store.namespaceMu.Lock()
	defer store.namespaceMu.Unlock()
	unlock := store.lockInterfaceOperations(id)
	defer unlock()
	config, err := store.Get(id)
	if err != nil {
		return err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return err
	}
	originalData, err := store.RawConfig(id)
	if err != nil {
		return fmt.Errorf("read WireGuard configuration for transaction: %w", err)
	}
	wasRunning, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return err
	}
	if wasRunning {
		if err := tunnels.Down(ctx, id); err != nil {
			rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
			return appliedOperationError(err, rollbackErr)
		}
		if err := verifyStopped(ctx, id, tunnels); err != nil {
			rollbackErr := store.recoverOldConfiguration(id, originalData, tunnels)
			return appliedOperationError(err, rollbackErr)
		}
	}
	if err := store.remove(id); err != nil {
		var rollbackErr error
		if wasRunning {
			rollbackErr = store.recoverOldConfiguration(id, originalData, tunnels)
		} else {
			rollbackErr = store.writeRaw(id, originalData)
		}
		if os.IsNotExist(err) {
			err = ErrNotFound
		} else {
			err = fmt.Errorf("delete WireGuard configuration: %w", err)
		}
		return appliedOperationError(err, rollbackErr)
	}
	return nil
}

func (store *Store) RenameApplied(
	ctx context.Context,
	id string,
	newID string,
	expectedRevision string,
	tunnels TunnelController,
) (model.Interface, error) {
	if err := ValidateInterfaceName(newID); err != nil {
		return model.Interface{}, err
	}
	if id == newID {
		return model.Interface{}, invalid("新的 Interface 名称必须与当前名称不同")
	}
	if tunnels == nil {
		return model.Interface{}, tunnelUnavailable()
	}
	store.namespaceMu.Lock()
	defer store.namespaceMu.Unlock()
	unlock := store.lockInterfaceOperations(id, newID)
	defer unlock()
	config, err := store.Get(id)
	if err != nil {
		return model.Interface{}, err
	}
	if err := checkRevision(config, expectedRevision); err != nil {
		return model.Interface{}, err
	}
	exists, err := store.configExists(newID)
	if err != nil {
		return model.Interface{}, fmt.Errorf("inspect renamed WireGuard configuration: %w", err)
	}
	if exists {
		return model.Interface{}, fmt.Errorf("%w: Interface 名称 %q 已存在", ErrConflict, newID)
	}
	newRunning, err := tunnels.IsRunning(ctx, newID)
	if err != nil {
		return model.Interface{}, err
	}
	if newRunning {
		return model.Interface{}, fmt.Errorf("%w: 运行中已存在同名 Interface %q", ErrConflict, newID)
	}
	wasRunning, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return model.Interface{}, err
	}
	if wasRunning {
		return model.Interface{}, fmt.Errorf(
			"%w: 运行中的 Interface 不能直接重命名；请先停止后再重命名",
			ErrConflict,
		)
	}
	if err := store.rename(id, newID); err != nil {
		return model.Interface{}, fmt.Errorf("rename WireGuard configuration: %w", err)
	}
	return store.Get(newID)
}

func startAndVerify(ctx context.Context, id string, tunnels TunnelController) error {
	if err := tunnels.Up(ctx, id); err != nil {
		return err
	}
	return tunnels.Verify(ctx, id)
}

func verifyStopped(ctx context.Context, id string, tunnels TunnelController) error {
	running, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return err
	}
	if running {
		return fmt.Errorf("%w: %s 仍在运行", ErrTunnelOperation, id)
	}
	return nil
}

func (store *Store) recoverOldConfiguration(
	id string,
	originalData []byte,
	tunnels TunnelController,
) error {
	recoveryContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	// If a failed Up left a partial Interface, the file currently on disk still
	// describes that attempted runtime and is therefore safe for its Down.
	if err := stopForRollback(recoveryContext, id, tunnels); err != nil {
		return fmt.Errorf("停止未完整提交的 Interface 失败: %w", err)
	}
	if err := store.writeRaw(id, originalData); err != nil {
		return fmt.Errorf("恢复原配置文件失败: %w", err)
	}
	if err := startAndVerify(recoveryContext, id, tunnels); err != nil {
		return fmt.Errorf("恢复原运行配置失败: %w", err)
	}
	return nil
}

func (store *Store) restoreCurrentConfigurationRuntime(
	id string,
	tunnels TunnelController,
) error {
	recoveryContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := stopForRollback(recoveryContext, id, tunnels); err != nil {
		return err
	}
	return startAndVerify(recoveryContext, id, tunnels)
}

func (store *Store) rollbackCreatedLocked(id string, tunnels TunnelController) error {
	recoveryContext, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	if err := stopForRollback(recoveryContext, id, tunnels); err != nil {
		return fmt.Errorf("无法确认新隧道已停止，已保留配置文件以便恢复: %w", err)
	}
	if err := store.remove(id); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除新配置文件失败: %w", err)
	}
	return nil
}

// stopForRollback never changes a configuration file until the runtime has
// been proven stopped. This keeps wg-quick teardown paired with the file that
// describes the possibly live Interface.
func stopForRollback(ctx context.Context, id string, tunnels TunnelController) error {
	running, err := tunnels.IsRunning(ctx, id)
	if err != nil {
		return err
	}
	if running {
		if err := tunnels.Down(ctx, id); err != nil {
			return err
		}
	}
	return verifyStopped(ctx, id, tunnels)
}

func appliedOperationError(operationErr error, rollbackErr error) error {
	if rollbackErr == nil {
		return fmt.Errorf("%w: 操作未提交，原配置和运行状态已恢复: %v", ErrTunnelOperation, operationErr)
	}
	return fmt.Errorf(
		"%w: 操作未提交，但自动恢复也未能完整完成: %v；恢复错误: %v",
		ErrTunnelOperation,
		operationErr,
		rollbackErr,
	)
}

func tunnelUnavailable() error {
	return fmt.Errorf("%w: 隧道控制器未启用", ErrTunnelOperation)
}
