package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/api/handlers"
	"github.com/reconmaster/backend/internal/cache"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/middleware"
	"github.com/reconmaster/backend/internal/services"
)

// SetupRouter 设置路由
// mcpHandler 为 MCP HTTP 端点（nil 表示未启用）
func SetupRouter(taskService *services.TaskService, enterpriseService *services.EnterpriseService, mcpHandler http.Handler, monitorRunner handlers.MonitorRunner) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.SecurityHeaders())
	mcpEnabled := mcpHandler != nil
	// Persist request-level diagnostics alongside application errors so failed UI/API
	// calls can be correlated by path, status, latency, and client address.
	router.Use(func(c *gin.Context) {
		started := time.Now()
		c.Next()
		logger.Info("HTTP %s %s status=%d latency=%s client=%s", c.Request.Method, redactedRequestURI(c.Request), c.Writer.Status(), time.Since(started).Round(time.Millisecond), c.ClientIP())
	})
	router.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<20)
		c.Next()
	})

	// Only explicitly configured proxies may supply client IP headers. This keeps
	// login throttling meaningful when the service is exposed directly.
	trustedProxies := []string(nil)
	allowedOrigins := []string(nil)
	if config.GlobalConfig != nil {
		trustedProxies = config.GlobalConfig.Server.TrustedProxies
		allowedOrigins = config.GlobalConfig.Security.AllowedOrigins
	}
	if err := router.SetTrustedProxies(trustedProxies); err != nil {
		panic("invalid trusted proxy configuration: " + err.Error())
	}

	// Same-origin production deployments need no CORS headers. Development or
	// split-origin deployments can opt in to a finite allowlist.
	if len(allowedOrigins) > 0 {
		router.Use(cors.New(cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
			ExposeHeaders:    []string{"Content-Length"},
			AllowCredentials: false,
		}))
	}

	// WebSocket处理器（全局单例）
	wsHandler := handlers.NewWebSocketHandler()

	// 将 WebSocket handler 传递给 taskService
	taskService.SetWebSocketHandler(wsHandler)

	// 健康检查
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "mcp_enabled": mcpEnabled, "task_workers": taskService.WorkerCount()})
	})
	router.GET("/ready", readinessHandler)

	// MCP 端点 — 供 AI 客户端调用（无需 JWT 认证）
	if mcpHandler != nil {
		mcpPath := config.GlobalConfig.MCP.Path
		if mcpPath == "" {
			mcpPath = "/mcp"
		}
		router.Any(mcpPath, gin.WrapH(mcpHandler))
		router.Any(mcpPath+"/*path", gin.WrapH(mcpHandler))
	}

	// 静态文件服务 - 前端页面（公开）
	router.Static("/assets", "./web/dist/assets")
	router.Static("/cursors", "./web/dist/cursors")
	router.StaticFile("/logo.svg", "./web/dist/logo.svg")
	router.StaticFile("/logo-icon.svg", "./web/dist/logo-icon.svg")

	// 截图 — FlexibleAuth（支持 Authorization header 或 ?token= query 参数）
	screenshotsGroup := router.Group("/screenshots")
	screenshotsGroup.Use(middleware.FlexibleAuth())
	screenshotsGroup.Static("", "./data/screenshots")

	// 认证接口（不需要token）
	authHandler := handlers.NewAuthHandler()
	auth := router.Group("/api/v1/auth")
	auth.Use(middleware.RateLimit(middleware.NewRateLimiter(1, 10)))
	{
		auth.POST("/login", authHandler.Login)
		if config.GlobalConfig.Security.AllowRegistration {
			auth.POST("/register", authHandler.Register)
		} else {
			auth.POST("/register", func(c *gin.Context) { c.JSON(http.StatusForbidden, gin.H{"error": "registration is disabled"}) })
		}
	}

	// WebSocket — FlexibleAuth（浏览器 WebSocket 不能设自定义 header）
	wsGroup := router.Group("/api/v1")
	wsGroup.Use(middleware.FlexibleAuth())
	wsGroup.GET("/ws/progress", wsHandler.HandleWebSocket)

	// API v1（需要严格 Authorization header 认证）
	v1 := router.Group("/api/v1")
	v1.Use(middleware.AuthRequired())
	{
		// 任务管理
		taskHandler := handlers.NewTaskHandler(taskService)
		tasks := v1.Group("/tasks")
		{
			tasks.POST("", taskHandler.CreateTask)
			tasks.GET("", taskHandler.ListTasks)
			tasks.GET("/:id", taskHandler.GetTask)
			tasks.GET("/:id/logs", taskHandler.GetTaskLogs)
			tasks.DELETE("/:id", taskHandler.DeleteTask)
			tasks.POST("/:id/start", taskHandler.StartTask) // 手动启动任务
			tasks.POST("/:id/retry", taskHandler.RetryTask)
			tasks.POST("/:id/cancel", taskHandler.CancelTask)
			tasks.GET("/stats", taskHandler.GetTaskStats)
			tasks.POST("/batch/delete", taskHandler.BatchDeleteTasks) //  批量删除
		}

		scanScopeHandler := handlers.NewScanScopeHandler()
		scanScopes := v1.Group("/scan-scopes")
		{
			scanScopes.GET("", scanScopeHandler.List)
			scanScopes.POST("", scanScopeHandler.Create)
			scanScopes.PUT("/:id", scanScopeHandler.Update)
			scanScopes.DELETE("/:id", scanScopeHandler.Delete)
			scanScopes.POST("/:id/set-default", scanScopeHandler.SetDefault)
			scanScopes.POST("/validate", scanScopeHandler.Validate)
		}

		enterpriseHandler := handlers.NewEnterpriseHandler(enterpriseService)
		enterprise := v1.Group("/enterprise")
		{
			enterprise.GET("/providers", enterpriseHandler.Providers)
			enterprise.POST("/queries", enterpriseHandler.CreateQuery)
			enterprise.GET("/queries", enterpriseHandler.ListQueries)
			enterprise.GET("/queries/:id", enterpriseHandler.GetQuery)
			enterprise.DELETE("/queries/:id", enterpriseHandler.DeleteQuery)
			enterprise.GET("/assets", enterpriseHandler.ListAssets)
			enterprise.POST("/sync", enterpriseHandler.SyncAssets)
			enterprise.POST("/scans", enterpriseHandler.LaunchScan)
		}

		// 资产管理
		assetHandler := handlers.NewAssetHandler()
		assetCatalogHandler := handlers.NewAssetCatalogHandler()
		assetLeadHandler := handlers.NewAssetLeadHandler()
		assetProfileHandler := handlers.NewAssetProfileHandler()
		assets := v1.Group("/assets")
		{
			assets.GET("/domains", assetHandler.ListDomains)
			assets.GET("/ips", assetHandler.ListIPs)
			assets.GET("/ports", assetHandler.ListPorts)
			assets.GET("/sites", assetHandler.ListSites)
			assets.GET("/urls", assetHandler.ListURLs)
			assets.GET("/http-transactions", assetHandler.ListHTTPTransactions)
			assets.GET("/http-transactions/:id", assetHandler.GetHTTPTransaction)
			assets.GET("/vulnerabilities", assetHandler.ListVulnerabilities)
			assets.PUT("/vulnerabilities/:id/triage", assetLeadHandler.UpdateFindingTriage)
			assets.GET("/stats", assetHandler.GetAssetStats)
			assets.GET("/inventory", assetCatalogHandler.List)
			assets.GET("/inventory/stats", assetCatalogHandler.Stats)
			assets.GET("/inventory/:id", assetCatalogHandler.Get)
			assets.GET("/leads", assetLeadHandler.List)
			assets.PUT("/leads/triage", assetLeadHandler.UpdateTriage)
			assets.POST("/leads/execute-poc", assetLeadHandler.ExecutePoC)

			// 资产画像
			assets.GET("/profile", assetProfileHandler.GetAssetProfile)
			assets.GET("/relations", assetProfileHandler.GetAssetRelations)
			assets.GET("/graph", assetProfileHandler.GetAssetGraph)
			assets.GET("/c-segment", assetProfileHandler.AnalyzeCSegment)
		}

		// 资产标签
		assetTagHandler := handlers.NewAssetTagHandler()
		tags := v1.Group("/tags")
		{
			tags.GET("", assetTagHandler.ListTags)
			tags.POST("", assetTagHandler.CreateTag)
			tags.PUT("/:id", assetTagHandler.UpdateTag)
			tags.DELETE("/:id", assetTagHandler.DeleteTag)
			tags.GET("/:id/stats", assetTagHandler.GetTagStats)
			tags.POST("/attach", assetTagHandler.AddAssetTags)
			tags.GET("/asset", assetTagHandler.GetAssetTags)
			tags.GET("/search", assetTagHandler.SearchAssetsByTag)
		}

		// 资产分组
		assetGroupHandler := handlers.NewAssetGroupHandler()
		assetGroups := v1.Group("/asset-groups")
		{
			assetGroups.GET("", assetGroupHandler.List)
			assetGroups.POST("", assetGroupHandler.Create)
			assetGroups.PUT("/:id", assetGroupHandler.Update)
			assetGroups.DELETE("/:id", assetGroupHandler.Delete)
			assetGroups.GET("/:id/items", assetGroupHandler.ListMembers)
			assetGroups.POST("/:id/items", assetGroupHandler.AddMembers)
			assetGroups.DELETE("/:id/items/:member_id", assetGroupHandler.DeleteMember)
		}

		// 监控管理
		monitorHandler := handlers.NewMonitorHandler(monitorRunner)
		monitors := v1.Group("/monitors")
		{
			monitors.POST("", monitorHandler.CreateMonitor)
			monitors.GET("", monitorHandler.ListMonitors)
			monitors.GET("/:id", monitorHandler.GetMonitor)
			monitors.PUT("/:id", monitorHandler.UpdateMonitor) // 🆕 更新监控
			monitors.PATCH("/:id/status", monitorHandler.UpdateMonitorStatus)
			monitors.POST("/:id/run", monitorHandler.RunNow)
			monitors.DELETE("/:id", monitorHandler.DeleteMonitor)
			monitors.POST("/batch/delete", monitorHandler.BatchDeleteMonitors) // 🆕 批量删除
			monitors.GET("/:id/results", monitorHandler.ListMonitorResults)
		}

		// 导出管理
		exportHandler := handlers.NewExportHandler()
		exports := v1.Group("/export")
		{
			exports.GET("/task/:id", exportHandler.ExportTask)
			exports.GET("/download", exportHandler.DownloadExport)
		}

		// 用户管理
		users := v1.Group("/users")
		{
			users.GET("/me", authHandler.GetCurrentUser)
			users.PUT("/me", authHandler.UpdateProfile)
			users.PUT("/me/password", authHandler.UpdatePassword)
			users.POST("/logout", authHandler.Logout)

			// 管理员接口
			admin := users.Group("")
			admin.Use(middleware.AdminRequired())
			{
				admin.GET("", authHandler.ListUsers)
				admin.PATCH("/:id/status", authHandler.UpdateUserStatus)
			}
		}

		// 系统设置（管理员权限）
		settingHandler := handlers.NewSettingHandler()
		settings := v1.Group("/settings")
		settings.Use(middleware.AdminRequired())
		{
			settings.GET("", settingHandler.GetSettings)
			settings.POST("/validate/:provider", settingHandler.ValidateProvider)
			settings.POST("/test-notification/:channel", settingHandler.TestNotification)
			settings.GET("/:key", settingHandler.GetSetting)
			settings.POST("", settingHandler.UpdateSetting)
			settings.POST("/batch", settingHandler.BatchUpdateSettings)
			settings.DELETE("/:key", settingHandler.DeleteSetting)
		}

		// 字典管理
		dictionaries := v1.Group("/dictionaries")
		{
			// 所有用户都可以查看字典列表
			dictionaries.GET("", settingHandler.ListDictionaries)

			// 以下操作需要管理员权限
			admin := dictionaries.Group("")
			admin.Use(middleware.AdminRequired())
			{
				admin.POST("/upload", settingHandler.UploadDictionary)
				admin.DELETE("/:id", settingHandler.DeleteDictionary)
				admin.POST("/:id/default", settingHandler.SetDefaultDictionary)
			}
		}

		// 指纹管理
		fingerprintHandler := handlers.NewFingerprintHandler()
		fingerprints := v1.Group("/fingerprints")
		{
			// 特定路径的路由要放在前面
			fingerprints.GET("/categories", fingerprintHandler.GetCategories)
			fingerprints.POST("/batch", fingerprintHandler.BatchCreateFingerprints)
			fingerprints.POST("/import", fingerprintHandler.ImportFingerprints) // 导入接口

			// 通用路由放在后面
			fingerprints.GET("", fingerprintHandler.ListFingerprints)
			fingerprints.POST("", fingerprintHandler.CreateFingerprint)
			fingerprints.GET("/:id", fingerprintHandler.GetFingerprint)
			fingerprints.PUT("/:id", fingerprintHandler.UpdateFingerprint)
			fingerprints.DELETE("/:id", fingerprintHandler.DeleteFingerprint)
		}

		proxyHandler := handlers.NewProxyHandler()
		proxies := v1.Group("/proxies")
		{
			proxies.GET("", proxyHandler.List)
			proxies.POST("", proxyHandler.Create)
			proxies.POST("/batch", proxyHandler.BatchCreate)
			proxies.POST("/batch/delete", proxyHandler.BatchDelete)
			proxies.POST("/batch/test", proxyHandler.BatchTest)
			proxies.POST("/test-all", proxyHandler.TestAll)
			proxies.PUT("/:id", proxyHandler.Update)
			proxies.DELETE("/:id", proxyHandler.Delete)
			proxies.POST("/:id/test", proxyHandler.Test)
		}

		// PoC管理
		pocHandler := handlers.NewPoCHandler()
		pocs := v1.Group("/pocs")
		{
			// 特定路径的路由要放在前面
			pocs.POST("/import/zip", pocHandler.ImportPoCsFromZip) // zip批量导入接口
			pocs.POST("/import", pocHandler.BatchImportPoCs)       // yaml批量导入接口

			// 通用路由放在后面
			pocs.GET("", pocHandler.ListPoCs)
			pocs.GET("/:id", pocHandler.GetPoC)
			pocs.POST("", pocHandler.CreatePoC)
			pocs.PUT("/:id", pocHandler.UpdatePoC)
			pocs.DELETE("/:id", pocHandler.DeletePoC)
			pocs.POST("/:id/toggle", pocHandler.TogglePoCStatus)
			pocs.POST("/:id/execute", pocHandler.ExecutePoC)
			pocs.POST("/batch", pocHandler.BatchImportPoCs)
			pocs.GET("/categories", pocHandler.GetPoCCategories)
			pocs.GET("/stats", pocHandler.GetPoCStats)
		}

		// GitHub监控
		githubHandler := handlers.NewGitHubMonitorHandler()
		github := v1.Group("/github-monitors")
		{
			github.GET("", githubHandler.ListGitHubMonitors)
			github.GET("/:id", githubHandler.GetGitHubMonitor)
			github.POST("", githubHandler.CreateGitHubMonitor)
			github.PUT("/:id", githubHandler.UpdateGitHubMonitor)
			github.DELETE("/:id", githubHandler.DeleteGitHubMonitor)
			github.POST("/:id/toggle", githubHandler.ToggleGitHubMonitorStatus)
			github.POST("/:id/run", githubHandler.RunGitHubMonitor)
			github.GET("/:id/results", githubHandler.ListGitHubMonitorResults)
			github.POST("/results/:result_id/read", githubHandler.MarkResultAsRead)
			github.GET("/stats", githubHandler.GetGitHubMonitorStats)
		}

		// 计划任务
		scheduledTaskHandler := handlers.NewScheduledTaskHandler(taskService)
		scheduledTasks := v1.Group("/scheduled-tasks")
		{
			scheduledTasks.GET("", scheduledTaskHandler.ListScheduledTasks)
			scheduledTasks.GET("/:id", scheduledTaskHandler.GetScheduledTask)
			scheduledTasks.POST("", scheduledTaskHandler.CreateScheduledTask)
			scheduledTasks.PUT("/:id", scheduledTaskHandler.UpdateScheduledTask)
			scheduledTasks.DELETE("/:id", scheduledTaskHandler.DeleteScheduledTask)
			scheduledTasks.POST("/:id/toggle", scheduledTaskHandler.ToggleScheduledTaskStatus)
			scheduledTasks.POST("/:id/run", scheduledTaskHandler.RunScheduledTaskNow)
			scheduledTasks.GET("/:id/logs", scheduledTaskHandler.GetScheduledTaskLogs)
			scheduledTasks.GET("/stats", scheduledTaskHandler.GetScheduledTaskStats)
			scheduledTasks.POST("/batch/delete", scheduledTaskHandler.BatchDeleteScheduledTasks)
			scheduledTasks.POST("/batch/toggle", scheduledTaskHandler.BatchToggleScheduledTasks)
		}

		// 策略配置
		policyHandler := handlers.NewPolicyHandler()
		policies := v1.Group("/policies")
		{
			policies.GET("", policyHandler.ListPolicies)
			policies.GET("/:id", policyHandler.GetPolicy)
			policies.POST("", policyHandler.CreatePolicy)
			policies.PUT("/:id", policyHandler.UpdatePolicy)
			policies.DELETE("/:id", policyHandler.DeletePolicy)
			policies.POST("/:id/set-default", policyHandler.SetDefaultPolicy)
			policies.GET("/default", policyHandler.GetDefaultPolicy)
			policies.POST("/batch/delete", policyHandler.BatchDelete)
			policies.GET("/stats", policyHandler.GetStats)
		}

		// 敏感信息规则
		sensitiveRuleHandler := handlers.NewSensitiveRuleHandler()
		sensitiveRules := v1.Group("/sensitive-rules")
		{
			// 规则管理
			sensitiveRules.GET("", sensitiveRuleHandler.ListSensitiveRules)
			sensitiveRules.GET("/:id", sensitiveRuleHandler.GetSensitiveRule)
			sensitiveRules.POST("", sensitiveRuleHandler.CreateSensitiveRule)
			sensitiveRules.PUT("/:id", sensitiveRuleHandler.UpdateSensitiveRule)
			sensitiveRules.DELETE("/:id", sensitiveRuleHandler.DeleteSensitiveRule)
			sensitiveRules.POST("/:id/toggle", sensitiveRuleHandler.ToggleSensitiveRule)
			sensitiveRules.POST("/batch/delete", sensitiveRuleHandler.BatchDeleteSensitiveRules)
			sensitiveRules.POST("/batch/toggle", sensitiveRuleHandler.BatchToggleSensitiveRules)
			sensitiveRules.GET("/stats", sensitiveRuleHandler.GetSensitiveRuleStats)

			// 匹配记录
			sensitiveRules.GET("/matches", sensitiveRuleHandler.ListSensitiveMatches)
		}
	}

	// 前端路由 - 所有非API请求都返回index.html（支持前端路由）
	router.NoRoute(func(c *gin.Context) {
		mcpPath := config.GlobalConfig.MCP.Path
		if mcpPath == "" {
			mcpPath = "/mcp"
		}
		if isPathOrSubpath(c.Request.URL.Path, "/api") || isPathOrSubpath(c.Request.URL.Path, mcpPath) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.File("./web/dist/index.html")
	})

	return router
}

func readinessHandler(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	dependencies := gin.H{"database": "ok", "redis": "ok"}
	ready := true
	if database.DB == nil {
		dependencies["database"] = "unavailable"
		ready = false
	} else if sqlDB, err := database.DB.DB(); err != nil || sqlDB.PingContext(ctx) != nil {
		dependencies["database"] = "unavailable"
		ready = false
	}
	if cache.Client == nil || cache.Client.Ping(ctx).Err() != nil {
		dependencies["redis"] = "unavailable"
		ready = false
	}
	if !ready {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "dependencies": dependencies})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ready", "dependencies": dependencies})
}

func redactedRequestURI(request *http.Request) string {
	if request == nil || request.URL == nil {
		return ""
	}
	uri := *request.URL
	query := uri.Query()
	for key := range query {
		switch strings.ToLower(key) {
		case "token", "access_token", "api_key", "apikey", "authorization":
			query.Set(key, "[REDACTED]")
		}
	}
	uri.RawQuery = query.Encode()
	return uri.RequestURI()
}

func isPathOrSubpath(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/")
}
