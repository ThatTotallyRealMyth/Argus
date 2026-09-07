package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/api"
	"github.com/reconmaster/backend/internal/auth"
	"github.com/reconmaster/backend/internal/cache"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/mcpserver"
	"github.com/reconmaster/backend/internal/proxypool"
	"github.com/reconmaster/backend/internal/scheduler"
	"github.com/reconmaster/backend/internal/services"
)

func main() {
	// 加载全局配置
	if err := config.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 验证必要配置项
	if missing := config.GlobalConfig.IsMissingRequiredConfig(); len(missing) > 0 {
		log.Fatalf("Missing required config: %v", missing)
	}
	gin.SetMode(config.GlobalConfig.Server.Mode)

	// 初始化日志系统
	if err := logger.InitLogger(config.GlobalConfig.Logging.File, config.GlobalConfig.Logging.Level); err != nil {
		log.Printf("Warning: Failed to initialize logger: %v (using default log)", err)
	}

	// 初始化JWT配置（密钥不存在会直接panic）
	auth.Init()

	// 初始化数据库
	dbConfig := database.Config{
		Host:         config.GlobalConfig.Database.Host,
		Port:         config.GlobalConfig.Database.Port,
		User:         config.GlobalConfig.Database.User,
		Password:     config.GlobalConfig.Database.Password,
		DBName:       config.GlobalConfig.Database.DBName,
		SSLMode:      config.GlobalConfig.Database.SSLMode,
		MaxIdleConns: config.GlobalConfig.Database.MaxIdleConns,
		MaxOpenConns: config.GlobalConfig.Database.MaxOpenConns,
	}

	if err := database.Initialize(dbConfig); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()
	stopProxyChecker := proxypool.StartAutoChecker()
	defer stopProxyChecker()

	// 初始化字典数据
	if err := database.InitDictionaries(); err != nil {
		log.Printf("Warning: Failed to initialize dictionaries: %v", err)
	}

	// 自动加载默认指纹库（首次启动时）
	fingerprintLoader := services.NewFingerprintLoader()
	if err := fingerprintLoader.LoadDefaultFingerprints(); err != nil {
		log.Printf("Warning: Failed to load default fingerprints: %v", err)
	}

	log.Println("Using smart PoC detection based on fingerprints")

	// 初始化Redis
	redisConfig := cache.Config{
		Host:     config.GlobalConfig.Redis.Host,
		Port:     config.GlobalConfig.Redis.Port,
		Password: config.GlobalConfig.Redis.Password,
		DB:       config.GlobalConfig.Redis.DB,
	}

	if err := cache.Initialize(redisConfig); err != nil {
		log.Fatalf("Failed to initialize redis: %v", err)
	}
	defer cache.Close()

	// 创建任务服务
	taskService := services.NewTaskService()
	defer taskService.Close()
	enterpriseService := services.NewEnterpriseService(taskService)
	defer enterpriseService.Close()
	monitorScheduler := scheduler.NewScheduler(taskService)
	monitorScheduler.Start()
	defer monitorScheduler.Stop()
	go func() {
		if err := services.NewAssetCatalogService().BackfillLegacyAssets(context.Background()); err != nil {
			log.Printf("Warning: Failed to backfill asset catalog: %v", err)
		}
	}()

	// MCP 服务（默认启用，可通过 config.yaml 中 mcp.enabled 关闭）
	var mcpHandler http.Handler
	if config.GlobalConfig.MCP.Enabled {
		apiKey := config.GlobalConfig.MCP.APIKey
		if len(apiKey) < 32 {
			log.Printf("MCP endpoint disabled: MCP_API_KEY must contain at least 32 characters")
		} else {
			mcpHandler = mcpserver.NewHandler(&mcpserver.Deps{TaskService: taskService, EnterpriseService: enterpriseService, MonitorRunner: monitorScheduler, ScheduledTasks: services.NewScheduledTaskService(taskService)}, apiKey)
			log.Printf("MCP endpoint enabled: %s (API key auth required)", config.GlobalConfig.MCP.Path)
		}
	}

	// 设置路由
	router := api.SetupRouter(taskService, enterpriseService, mcpHandler, monitorScheduler)

	// 启动服务器
	host := config.GlobalConfig.Server.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := config.GlobalConfig.Server.Port
	if port == "" {
		port = "8080"
	}
	address := net.JoinHostPort(host, port)
	httpServer := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: time.Duration(config.GlobalConfig.Server.ReadHeaderTimeout) * time.Second,
		ReadTimeout:       time.Duration(config.GlobalConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(config.GlobalConfig.Server.WriteTimeout) * time.Second,
		IdleTimeout:       time.Duration(config.GlobalConfig.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Starting Eclipse Recon server on %s (%s)...", address, config.GlobalConfig.Server.Environment)
		serverErrors <- httpServer.ListenAndServe()
	}()

	stopContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
		return
	case <-stopContext.Done():
		log.Printf("Shutdown signal received")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Duration(config.GlobalConfig.Server.ShutdownTimeout)*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		log.Printf("Graceful HTTP shutdown failed: %v", err)
		_ = httpServer.Close()
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("HTTP server stopped with error: %v", err)
	}
}
