package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wireguard-panel/internal/model"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"

	"github.com/gin-gonic/gin"
)

type wireGuardHandler struct {
	configs *wgconfig.Store
	status  *wgstatus.Collector
}

func (handler *wireGuardHandler) list(context *gin.Context) {
	configs, err := handler.configs.List()
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.JSON(http.StatusOK, gin.H{"interfaces": configs})
}

func (handler *wireGuardHandler) get(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	config, err := handler.configs.Get(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusOK, config)
}

func (handler *wireGuardHandler) create(context *gin.Context) {
	var input model.InterfaceInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Interface 参数无效")
		return
	}
	config, err := handler.configs.Create(input)
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
	config, err := handler.configs.Update(id, revision, input)
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
	if err := handler.configs.Delete(id, revision); err != nil {
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
	config, err := handler.configs.AddPeer(id, revision, input)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	writeConfig(context, http.StatusCreated, config)
}

func (handler *wireGuardHandler) updatePeer(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	peerID := context.Param("peerID")
	var input model.PeerInput
	if err := context.ShouldBindJSON(&input); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "Peer 参数无效")
		return
	}
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	config, err := handler.configs.UpdatePeer(id, peerID, revision, input)
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
	revision, ok := expectedRevision(context)
	if !ok {
		return
	}
	config, err := handler.configs.DeletePeer(
		id,
		context.Param("peerID"),
		revision,
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
	plan, err := handler.configs.IPPlan(id)
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
	config, err := handler.configs.Get(id)
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.JSON(
		http.StatusOK,
		handler.status.InterfaceStatus(config, time.Now().UTC()),
	)
}

func (handler *wireGuardHandler) clientConfig(context *gin.Context) {
	id, ok := interfaceID(context)
	if !ok {
		return
	}
	filename, data, err := handler.configs.ClientConfig(id, context.Param("peerID"))
	if err != nil {
		handler.writeError(context, err)
		return
	}
	context.Header("Content-Type", "text/plain; charset=utf-8")
	context.Header(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(filename, `"`, "")),
	)
	context.Data(http.StatusOK, "text/plain; charset=utf-8", data)
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

func writeConfig(
	context *gin.Context,
	status int,
	config model.Interface,
) {
	context.Header("ETag", fmt.Sprintf(`"%s"`, config.Revision))
	context.JSON(status, config)
}

func interfaceID(context *gin.Context) (int, bool) {
	id, err := strconv.Atoi(context.Param("id"))
	if err != nil || id < 0 {
		writeError(context, http.StatusBadRequest, "invalid_request", "Interface ID 无效")
		return 0, false
	}
	return id, true
}
