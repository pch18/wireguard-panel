package httpapi

import (
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

type Dependencies struct {
	Auth     *service.AuthService
	Configs  *wgconfig.Store
	Status   *wgstatus.Collector
	WebFiles fs.FS
}

func NewRouter(deps Dependencies) (*gin.Engine, error) {
	if deps.Auth == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	if deps.Configs == nil {
		return nil, fmt.Errorf("WireGuard configuration store is required")
	}
	if deps.WebFiles == nil {
		return nil, fmt.Errorf("web files are required")
	}
	webRoot, err := fs.Sub(deps.WebFiles, "web")
	if err != nil {
		return nil, fmt.Errorf("open embedded web files: %w", err)
	}

	auth := &authHandler{auth: deps.Auth}
	wireGuard := &wireGuardHandler{configs: deps.Configs, status: deps.Status}
	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}
	router.Use(gin.Logger(), gin.Recovery(), gzip.Gzip(gzip.DefaultCompression))

	router.GET("/api/health", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	api := router.Group("/api/v1")
	api.Use(func(context *gin.Context) {
		context.Header("Cache-Control", "no-store")
		context.Next()
	})
	api.POST("/login", auth.login)
	api.POST("/logout", auth.logout)
	api.GET("/session", auth.requireSession, auth.session)

	authenticated := api.Group("", auth.requireSession)
	authenticated.GET("/interfaces", wireGuard.list)
	authenticated.POST("/interfaces", wireGuard.create)
	authenticated.GET("/interfaces/:id", wireGuard.get)
	authenticated.PUT("/interfaces/:id", wireGuard.update)
	authenticated.DELETE("/interfaces/:id", wireGuard.delete)
	authenticated.GET("/interfaces/:id/ip-plan", wireGuard.ipPlan)
	authenticated.GET("/interfaces/:id/status", wireGuard.runtimeStatus)
	authenticated.POST("/interfaces/:id/peers", wireGuard.createPeer)
	authenticated.PUT("/interfaces/:id/peers/:peerID", wireGuard.updatePeer)
	authenticated.DELETE("/interfaces/:id/peers/:peerID", wireGuard.deletePeer)
	authenticated.GET(
		"/interfaces/:id/peers/:peerID/client-config",
		wireGuard.clientConfig,
	)

	fileServer := http.FileServer(http.FS(webRoot))
	router.NoRoute(func(context *gin.Context) {
		if strings.HasPrefix(context.Request.URL.Path, "/api/") {
			writeError(context, http.StatusNotFound, "not_found", "接口不存在")
			return
		}
		path := strings.TrimPrefix(context.Request.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(webRoot, path); err != nil {
			context.Request.URL.Path = "/"
		}
		fileServer.ServeHTTP(context.Writer, context.Request)
	})
	return router, nil
}
