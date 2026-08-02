package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"wireguard-panel/internal/model"
	"wireguard-panel/internal/service"

	"github.com/gin-gonic/gin"
)

const (
	sessionCookieName = "app_session"
	sessionMaxAge     = int(service.SessionLifetime / time.Second)
	sessionUserKey    = "session_user"
)

type authHandler struct {
	auth *service.AuthService
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required"`
}

func (handler *authHandler) login(context *gin.Context) {
	var request loginRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "请输入用户名和密码")
		return
	}
	token, user, authenticated, err := handler.auth.Login(
		strings.TrimSpace(request.Username),
		request.Password,
	)
	if err != nil {
		_ = context.Error(err)
		writeError(context, http.StatusInternalServerError, "internal_error", "登录服务暂时不可用")
		return
	}
	if !authenticated {
		writeError(context, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误")
		return
	}
	handler.setSessionCookie(context, token, sessionMaxAge)
	context.JSON(http.StatusOK, gin.H{"authenticated": true, "user": user})
}

func (handler *authHandler) logout(context *gin.Context) {
	if token, err := context.Cookie(sessionCookieName); err == nil {
		handler.auth.Logout(token)
	}
	handler.setSessionCookie(context, "", -1)
	context.Status(http.StatusNoContent)
}

func (handler *authHandler) session(context *gin.Context) {
	token, err := context.Cookie(sessionCookieName)
	if err != nil || !handler.auth.RenewSession(token) {
		handler.writeSessionExpired(context)
		return
	}
	handler.setSessionCookie(context, token, sessionMaxAge)
	user, _ := currentUser(context)
	context.JSON(http.StatusOK, gin.H{"authenticated": true, "user": user})
}

func (handler *authHandler) changePassword(context *gin.Context) {
	var request changePasswordRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		writeError(context, http.StatusBadRequest, "invalid_request", "请输入当前密码和新密码")
		return
	}
	token, err := context.Cookie(sessionCookieName)
	if err != nil {
		handler.writeSessionExpired(context)
		return
	}
	if err := handler.auth.ChangePassword(
		request.CurrentPassword,
		request.NewPassword,
		token,
	); err != nil {
		switch {
		case errors.Is(err, service.ErrCurrentPasswordMismatch):
			writeError(context, http.StatusForbidden, "invalid_current_password", err.Error())
		case errors.Is(err, service.ErrPasswordUnchanged),
			errors.Is(err, service.ErrInvalidNewPassword):
			writeError(context, http.StatusBadRequest, "invalid_new_password", err.Error())
		default:
			_ = context.Error(err)
			writeError(
				context,
				http.StatusInternalServerError,
				"password_update_failed",
				"密码暂时无法保存，请稍后重试",
			)
		}
		return
	}
	context.Status(http.StatusNoContent)
}

func (handler *authHandler) requireSession(context *gin.Context) {
	token, err := context.Cookie(sessionCookieName)
	if err != nil {
		handler.writeSessionExpired(context)
		context.Abort()
		return
	}
	user, valid := handler.auth.Session(token)
	if !valid {
		handler.writeSessionExpired(context)
		context.Abort()
		return
	}
	context.Set(sessionUserKey, user)
	context.Next()
}

func (handler *authHandler) writeSessionExpired(context *gin.Context) {
	writeError(context, http.StatusUnauthorized, "unauthorized", "登录状态已失效")
}

func (handler *authHandler) setSessionCookie(
	context *gin.Context,
	value string,
	maxAge int,
) {
	context.SetSameSite(http.SameSiteLaxMode)
	context.SetCookie(
		sessionCookieName,
		value,
		maxAge,
		"/",
		"",
		false,
		true,
	)
}

func currentUser(context *gin.Context) (model.User, bool) {
	value, found := context.Get(sessionUserKey)
	if !found {
		return model.User{}, false
	}
	user, ok := value.(model.User)
	return user, ok
}

func writeError(context *gin.Context, status int, code string, message string) {
	context.JSON(status, gin.H{
		"error": gin.H{
			"code":    code,
			"message": message,
		},
	})
}
