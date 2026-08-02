package httpapi

import (
	stdcontext "context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"wireguard-panel/internal/model"
	"wireguard-panel/internal/mtuprobe"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"

	"github.com/gin-gonic/gin"
)

type wireGuardHandler struct {
	configs            *wgconfig.Store
	status             *wgstatus.Collector
	mtuProbe           mtuprobe.Detector
	tunnels            wgconfig.TunnelController
	applicationContext stdcontext.Context
}

func (handler *wireGuardHandler) probeMTU(request *gin.Context) {
	probeContext, cancel := stdcontext.WithTimeout(request.Request.Context(), 8*time.Second)
	defer cancel()
	result, err := handler.mtuProbe.Detect(probeContext)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, stdcontext.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		writeError(request, status, "mtu_probe_failed", err.Error())
		return
	}
	request.JSON(http.StatusOK, result)
}

type configTextInput struct {
	Config string `json:"config"`
}

type interfaceRenameInput struct {
	Name string `json:"name"`
}

func (handler *wireGuardHandler) list(context *gin.Context) {
	configs, occupiedNames, problems, err := handler.configs.InventorySettled()
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{
		"interfaces":    configs,
		"occupiedNames": occupiedNames,
		"problems":      problems,
	})
}

func (handler *wireGuardHandler) get(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	config, err := handler.configs.GetSettled(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) create(context *gin.Context) {
	var input model.InterfaceCreateInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Interface 参数无效")
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.CreateApplied(
		operationContext,
		input.Name,
		input.InterfaceInput,
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusCreated, config)
}

func (handler *wireGuardHandler) importInterface(context *gin.Context) {
	input, ok := bindConfigText(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.ImportApplied(
		operationContext,
		[]byte(input.Config),
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusCreated, config)
}

func (handler *wireGuardHandler) update(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	var input model.InterfaceInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Interface 参数无效")
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.UpdateApplied(
		operationContext,
		id,
		revision,
		input,
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) rename(request *gin.Context) {
	id, ok := interfaceID(request)
	if !ok {
		return
	}
	var input interfaceRenameInput
	if err := request.ShouldBindJSON(&input); err != nil {
		writeError(request, http.StatusBadRequest, "invalid_request", "重命名参数无效")
		return
	}
	revision, ok := expectedRevision(request)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(request, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.RenameApplied(
		operationContext,
		id,
		input.Name,
		revision,
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(request, err)
		return
	}
	writeConfig(request, http.StatusOK, config)
}

func (handler *wireGuardHandler) importOverInterface(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	input, ok := bindConfigText(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.ImportOverApplied(
		operationContext,
		id,
		revision,
		[]byte(input.Config),
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) interfaceConfig(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	data, err := handler.configs.ConfigSettled(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.Data(http.StatusOK, "text/plain; charset=utf-8", data)
}

func (handler *wireGuardHandler) rawInterfaceConfig(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	data, err := handler.configs.RawConfigSettled(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.Data(http.StatusOK, "text/plain; charset=utf-8", data)
}

func (handler *wireGuardHandler) start(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.StartApplied(
		operationContext,
		id,
		revision,
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) stop(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.StopApplied(
		operationContext,
		id,
		revision,
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) restart(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.RestartApplied(
		operationContext,
		id,
		revision,
		handler.tunnels,
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) delete(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	if err := handler.configs.DeleteApplied(
		operationContext,
		id,
		revision,
		handler.tunnels,
	); err != nil {
		handler.writeError(context, err)
		return
	}
	context.Status(http.StatusNoContent)
}

func (handler *wireGuardHandler) createPeer(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	var input model.PeerInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Peer 参数无效")
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.AddPeerApplied(
		operationContext,
		id,
		revision,
		input,
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusCreated, config)
}

func (handler *wireGuardHandler) importPeer(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	input, ok := bindConfigText(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.ImportPeerApplied(
		operationContext,
		id,
		revision,
		[]byte(input.Config),
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusCreated, config)
}

func (handler *wireGuardHandler) peerConfig(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	publicKey, ok := peerPublicKey(context)
	if !ok {
		return
	}
	data, err := handler.configs.PeerConfigSettled(id, publicKey)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.Data(http.StatusOK, "text/plain; charset=utf-8", data)
}

func (handler *wireGuardHandler) updatePeer(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	originalPublicKey, ok := peerPublicKey(context)
	if !ok {
		return
	}
	var input model.PeerInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Peer 参数无效")
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.UpdatePeerApplied(
		operationContext,
		id,
		originalPublicKey,
		revision,
		input,
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) deletePeer(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	publicKey, ok := peerPublicKey(context)
	if !ok {
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	operationContext, cancel := wireGuardMutationContext(context, handler.applicationContext)
	defer cancel()
	config, err := handler.configs.DeletePeerApplied(
		operationContext,
		id,
		publicKey,
		revision,
		handler.tunnels,
		restartConfirmed(context),
	)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) ipPlan(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	plan, err := handler.configs.IPPlanSettled(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.JSON(http.StatusOK, plan)
}

func (handler *wireGuardHandler) runtimeStatus(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	var running bool
	var runtimeStateAvailable bool
	config, err := handler.configs.InspectSettled(
		id,
		func(model.Interface) error {
			if !wgconfig.RuntimeControllable(handler.tunnels) {
				return nil
			}
			var inspectErr error
			running, inspectErr = handler.tunnels.IsRunning(
				context.Request.Context(),
				id,
			)
			runtimeStateAvailable = inspectErr == nil
			return inspectErr
		},
	)
	if err != nil {
		// A status-probe failure should not hide a readable configuration or
		// its cached traffic data. Re-read the settled file and report the
		// running state as unavailable instead.
		config, err = handler.configs.GetSettled(id)
		if err != nil {
			handler.writeError(context, err)
			return
		}
	}
	status := handler.runtimeStatusSnapshot(context.Request.Context(), config)
	if status.RuntimeControllable {
		if !runtimeStateAvailable {
			status.RuntimeStateAvailable = false
			if status.Message == "" {
				status.Message = "运行状态暂时无法确认"
			}
		} else {
			status.Running = running
			status.RuntimeStateAvailable = true
		}
	}
	context.JSON(http.StatusOK, status)
}

func (handler *wireGuardHandler) runtimeStatusSnapshot(
	context stdcontext.Context,
	config model.Interface,
) model.InterfaceRuntimeStatus {
	status := handler.status.InterfaceStatus(context, config)
	status.RuntimeControllable = wgconfig.RuntimeControllable(handler.tunnels)
	status.RuntimeStateAvailable = status.CollectorAvailable
	if !status.RuntimeControllable {
		status.Running = false
		status.RuntimeStateAvailable = false
		status.CollectorAvailable = false
		status.Message = "当前为仅文件模式；后端不会执行 wg 或 wg-quick"
	}
	return status
}

func (handler *wireGuardHandler) runtimeEvents(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	if _, err := handler.configs.GetSettled(id); err != nil {
		handler.writeError(context, err)
		return
	}

	context.Header("Content-Type", "text/event-stream; charset=utf-8")
	context.Header("Cache-Control", "no-cache")
	context.Header("X-Accel-Buffering", "no")
	updates, unsubscribe := handler.status.Subscribe()
	defer unsubscribe()

	lastSentAt := time.Time{}
	send := func(kind string, after time.Time) bool {
		config, err := handler.configs.GetSettled(id)
		if err != nil {
			return false
		}
		status := handler.runtimeStatusSnapshot(context.Request.Context(), config)
		publicKeys := make([]string, 0, len(config.Peers))
		for _, peer := range config.Peers {
			publicKeys = append(publicKeys, peer.PublicKey)
		}
		interfaceTraffic, peerTraffic := handler.status.TrafficHistory(
			status.InterfaceName,
			after,
			publicKeys,
		)
		context.SSEvent("traffic", model.InterfaceTrafficEvent{
			Kind:             kind,
			Status:           status,
			InterfaceTraffic: interfaceTraffic,
			PeerTraffic:      peerTraffic,
		})
		context.Writer.Flush()
		if status.SampledAt != nil && status.SampledAt.After(lastSentAt) {
			lastSentAt = *status.SampledAt
		}
		return true
	}

	if !send("history", time.Time{}) {
		return
	}
	for {
		select {
		case <-context.Request.Context().Done():
			return
		case <-handler.applicationContext.Done():
			return
		case <-updates:
			if !send("update", lastSentAt) {
				return
			}
		}
	}
}

func (handler *wireGuardHandler) clientConfig(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	publicKey, ok := peerPublicKey(context)
	if !ok {
		return
	}
	_, data, err := handler.configs.ClientConfigSettled(id, publicKey)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.Header("Content-Type", "text/plain; charset=utf-8")
	context.Data(http.StatusOK, "text/plain; charset=utf-8", data)
}

func peerPublicKey(context *gin.Context) (string, bool) {
	publicKey, err := wgconfig.DecodePeerPublicKeyPath(context.Param("publicKey"))
	if err != nil {
		writeError(
			context,
			http.StatusBadRequest,
			"invalid_peer_public_key",
			err.Error(),
		)
		return "", false
	}
	return publicKey, true
}

func (handler *wireGuardHandler) writeError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, wgconfig.ErrNotFound):
		writeError(context, http.StatusNotFound, "interface_not_found", err.Error())
	case errors.Is(err, wgconfig.ErrPeerNotFound):
		writeError(context, http.StatusNotFound, "peer_not_found", err.Error())
	case errors.Is(err, wgconfig.ErrConflict):
		writeError(context, http.StatusConflict, "wireguard_conflict", err.Error())
	case errors.Is(err, wgconfig.ErrRevisionConflict):
		writeError(
			context,
			http.StatusPreconditionFailed,
			"stale_revision",
			err.Error(),
		)
	case errors.Is(err, wgconfig.ErrRevisionRequired):
		writeError(
			context,
			http.StatusPreconditionRequired,
			"revision_required",
			err.Error(),
		)
	case errors.Is(err, wgconfig.ErrRestartRequired):
		writeError(
			context,
			http.StatusConflict,
			"restart_required",
			err.Error(),
		)
	case errors.Is(err, wgconfig.ErrClientConfigMissing):
		writeError(
			context,
			http.StatusUnprocessableEntity,
			"client_config_incomplete",
			err.Error(),
		)
	case errors.Is(err, wgconfig.ErrInvalidInput):
		writeError(context, http.StatusBadRequest, "invalid_wireguard_config", err.Error())
	case errors.Is(err, wgconfig.ErrInvalidFile):
		writeError(
			context,
			http.StatusUnprocessableEntity,
			"invalid_wireguard_file",
			err.Error(),
		)
	case errors.Is(err, wgconfig.ErrTunnelOperation):
		writeError(
			context,
			http.StatusInternalServerError,
			"tunnel_operation_failed",
			err.Error(),
		)
	default:
		_ = context.Error(err)
		writeError(
			context,
			http.StatusInternalServerError,
			"wireguard_io_error",
			"WireGuard 配置文件暂时无法访问",
		)
	}
}

func expectedRevision(context *gin.Context) (string, bool) {
	revision := strings.TrimSpace(context.GetHeader("If-Match"))
	revision = strings.TrimPrefix(revision, "W/")
	revision = strings.Trim(revision, `"`)
	if revision == "" {
		writeError(
			context,
			http.StatusPreconditionRequired,
			"revision_required",
			"修改配置时必须携带最新 revision",
		)
		return "", false
	}
	return revision, true
}

func restartConfirmed(context *gin.Context) bool {
	return strings.EqualFold(
		strings.TrimSpace(context.GetHeader("X-WireGuard-Restart-Confirmed")),
		"true",
	)
}

func writeConfig(
	context *gin.Context,
	status int,
	config model.Interface,
) {
	context.Header("ETag", fmt.Sprintf(`"%s"`, config.Revision))
	context.JSON(status, config)
}

func interfaceID(context *gin.Context) (string, bool) {
	id := context.Param("id")
	if err := wgconfig.ValidateInterfaceName(id); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", err.Error())
		return "", false
	}
	return id, true
}

func bindConfigText(context *gin.Context) (configTextInput, bool) {
	var input configTextInput
	if err := context.ShouldBindJSON(&input); err != nil || strings.TrimSpace(input.Config) == "" {
		writeError(context, http.StatusBadRequest, "invalid_request", "配置文本不能为空")
		return configTextInput{}, false
	}
	return input, true
}

func wireGuardMutationContext(
	request *gin.Context,
	applicationContext stdcontext.Context,
) (stdcontext.Context, stdcontext.CancelFunc) {
	operationContext, cancel := stdcontext.WithTimeout(
		stdcontext.WithoutCancel(request.Request.Context()),
		3*time.Minute,
	)
	stopShutdownCancellation := stdcontext.AfterFunc(applicationContext, cancel)
	return operationContext, func() {
		stopShutdownCancellation()
		cancel()
	}
}
