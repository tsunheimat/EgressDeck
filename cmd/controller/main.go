package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func main() {
	logger := log.New(os.Stdout, "controller ", log.LstdFlags|log.LUTC)
	addr := env("LISTEN_ADDR", ":"+env("PORT", "8080"))
	httpConfig, err := loadHTTPConfig()
	if err != nil {
		logger.Fatalf("configure HTTP server: %v", err)
	}
	encryptionKey, err := secrets.ParseKey(os.Getenv("APP_ENCRYPTION_KEY"))
	if err != nil {
		logger.Fatal("APP_ENCRYPTION_KEY must be a base64-encoded 32-byte encryption key")
	}
	vault, err := secrets.New(env("APP_ENCRYPTION_KEY_ID", "primary"), encryptionKey)
	clear(encryptionKey)
	if err != nil {
		logger.Fatalf("configure application encryption: %v", err)
	}
	storagePath := env("STORAGE_PATH", "/var/lib/homelab-proxy-controller/store.json")
	storageDSN := strings.TrimSpace(os.Getenv("STORAGE_DSN"))
	if storageDSN == "" {
		// DATABASE_URL is retained as a deployment-friendly alias. STORAGE_DSN
		// is preferred because it describes the controller's storage boundary.
		storageDSN = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	storageDriver := env("STORAGE_DRIVER", env("POSTGRES_DRIVER", "pgx"))
	storeCtx, cancelStore := context.WithTimeout(context.Background(), 10*time.Second)
	controllerStore, closeStore, err := store.OpenConfiguredStore(storeCtx, storagePath, storageDriver, storageDSN)
	cancelStore()
	if err != nil {
		logger.Fatalf("open controller store: %v", err)
	}
	defer func() {
		if err := closeStore(); err != nil {
			logger.Printf("close controller store: %v", err)
		}
	}()
	server := api.NewServer(controllerStore, logger)
	operationJournal, err := deployment.OpenEncryptedFileJournal(env("OPERATION_JOURNAL_PATH", filepath.Join(filepath.Dir(storagePath), "operations.json")), vault)
	if err != nil {
		logger.Fatalf("open operation journal: %v", err)
	}
	server.Services.Journal = operationJournal
	server.Services.Runner = deployment.NewRunner(operationJournal)
	server.Services.Providers, err = newProviderRegistry(os.Getenv("PROVIDER_FETCH_CONFIG_FILE"))
	if err != nil {
		logger.Fatalf("configure provider fetching: %v", err)
	}
	server.Services.ProviderStageEnabled = true
	firewallCleanup, err := configureOPNsense(context.Background(), server, os.Getenv("OPNSENSE_CONFIG_FILE"))
	if err != nil {
		logger.Fatalf("configure OPNsense adapter: %v", err)
	}
	defer firewallCleanup()
	gatewayCleanup, err := configureGateways(context.Background(), server, os.Getenv("CONTROLLER_GATEWAYS_FILE"))
	if err != nil {
		logger.Fatalf("configure gateway adapters: %v", err)
	}
	defer gatewayCleanup()
	documents, ok := controllerStore.(store.DocumentStore)
	if !ok {
		logger.Fatal("controller store does not support durable service state")
	}
	loadCtx, cancelLoad := context.WithTimeout(context.Background(), 10*time.Second)
	err = server.Services.Load(loadCtx, documents, vault)
	cancelLoad()
	if err != nil {
		logger.Fatalf("load controller service state: %v", err)
	}
	server.Services.Providers.SetMetadataImpactEvaluator(server.Services.Outbounds.ProviderMetadataImpact)
	if err := server.StartProviderScheduler(context.Background()); err != nil {
		logger.Fatalf("configure provider scheduler: %v", err)
	}
	defer server.StopProviderScheduler()
	stopReconciliation, err := startOperationReconciliation(context.Background(), server, logger, reconciliationOptions{Interval: 30 * time.Second, Timeout: 10 * time.Second})
	if err != nil {
		logger.Fatalf("configure operation reconciliation: %v", err)
	}
	defer stopReconciliation()
	configureTelemetry(server)
	handler, err := newControllerHTTP(context.Background(), server.Handler(), httpConfig)
	if err != nil {
		logger.Fatalf("configure HTTP server: %v", err)
	}
	httpServer := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Printf("listening on %s auth_mode=%s static_dir=%s", addr, httpConfig.AuthMode, httpConfig.StaticDir)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
