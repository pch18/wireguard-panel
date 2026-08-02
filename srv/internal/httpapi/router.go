package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"wireguard-panel/internal/mtuprobe"
	"wireguard-panel/internal/service"
	"wireguard-panel/internal/wgconfig"
	"wireguard-panel/internal/wgstatus"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
)

const maxRequestBodyBytes = 2 << 20

type Dependencies struct {
	Auth               *service.AuthService
	Configs            *wgconfig.Store
	Status             *wgstatus.Collector
	MTUProbe           mtuprobe.Detector
	Tunnels            wgconfig.TunnelController
	WebFiles           fs.FS
	ApplicationContext context.Context
}

func NewRouter(deps Dependencies) (*gin.Engine, error) {
	if deps.Auth == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	if deps.Configs == nil {
		return nil, fmt.Errorf("WireGuard configuration store is required")
	}
	if deps.Tunnels == nil {
		return nil, fmt.Errorf("WireGuard tunnel controller is required")
	}
	if deps.WebFiles == nil {
		return nil, fmt.Errorf("web files are required")
	}
	webRoot, err := fs.Sub(deps.WebFiles, "web")
	if err != nil {
		return nil, fmt.Errorf("open embedded web files: %w", err)
	}

	auth := &authHandler{auth: deps.Auth}
	if deps.MTUProbe == nil {
		deps.MTUProbe = mtuprobe.NewDetector()
	}
	wireGuard := &wireGuardHandler{
		configs:            deps.Configs,
		status:             deps.Status,
		mtuProbe:           deps.MTUProbe,
		tunnels:            deps.Tunnels,
		applicationContext: deps.ApplicationContext,
	}
	if wireGuard.applicationContext == nil {
		wireGuard.applicationContext = context.Background()
	}
	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("disable trusted proxies: %w", err)
	}
	router.Use(
		func(context *gin.Context) {
			if context.Request.Body != nil {
				context.Request.Body = http.MaxBytesReader(
					context.Writer,
					context.Request.Body,
					maxRequestBodyBytes,
				)
			}
			context.Next()
		},
		gin.Logger(),
		gin.Recovery(),
		gzip.Gzip(
			gzip.DefaultCompression,
			gzip.WithExcludedPathsRegexs(
				[]string{`^/api/v1/interfaces/[^/]+/events$`},
			),
		),
	)

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
	authenticated.PUT("/account/password", auth.changePassword)
	authenticated.POST("/wireguard/mtu-probe", wireGuard.probeMTU)
	authenticated.GET("/interfaces", wireGuard.list)
	authenticated.POST("/interfaces", wireGuard.create)
	authenticated.POST("/interfaces/import", wireGuard.importInterface)
	authenticated.GET("/interfaces/:id", wireGuard.get)
	authenticated.PUT("/interfaces/:id", wireGuard.update)
	authenticated.POST("/interfaces/:id/rename", wireGuard.rename)
	authenticated.DELETE("/interfaces/:id", wireGuard.delete)
	authenticated.GET("/interfaces/:id/config", wireGuard.interfaceConfig)
	authenticated.GET("/interfaces/:id/raw-config", wireGuard.rawInterfaceConfig)
	authenticated.POST("/interfaces/:id/start", wireGuard.start)
	authenticated.POST("/interfaces/:id/stop", wireGuard.stop)
	authenticated.POST("/interfaces/:id/restart", wireGuard.restart)
	authenticated.PUT("/interfaces/:id/import", wireGuard.importOverInterface)
	authenticated.GET("/interfaces/:id/ip-plan", wireGuard.ipPlan)
	authenticated.GET("/interfaces/:id/status", wireGuard.runtimeStatus)
	authenticated.GET("/interfaces/:id/events", wireGuard.runtimeEvents)
	authenticated.POST("/interfaces/:id/peers", wireGuard.createPeer)
	authenticated.POST("/interfaces/:id/peers/import", wireGuard.importPeer)
	authenticated.PUT("/interfaces/:id/peers/:publicKey", wireGuard.updatePeer)
	authenticated.DELETE("/interfaces/:id/peers/:publicKey", wireGuard.deletePeer)
	authenticated.GET(
		"/interfaces/:id/peers/:publicKey/config",
		wireGuard.peerConfig,
	)
	authenticated.GET(
		"/interfaces/:id/peers/:publicKey/client-config",
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
