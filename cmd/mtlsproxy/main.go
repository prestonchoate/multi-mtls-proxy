package main

import (
	"log"

	"github.com/prestonchoate/mtlsProxy/internal/admin"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"github.com/prestonchoate/mtlsProxy/internal/proxy"
)

func main() {
	// Initialize configuration
	cfg := config.GetConfig()

	// Create necessary directories
	config.CreateDirectories(cfg)

	// Initialize certificate authority
	certAuth := ca.New()
	if err := certAuth.Initialize(cfg); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Check and create proxy certificates if needed
	if err := certAuth.CheckProxyCert(cfg); err != nil {
		log.Fatalf("Failed to check/create proxy certificates: %v", err)
	}

	// Check and create admin signing cert/key if needed
	if err := certAuth.CheckAdminSigningCert(cfg); err != nil {
		log.Fatalf("Failed to check/create admin signing cert: %v", err)
	}

	// Load app configs
	appConfigs, err := config.LoadAppConfigs(cfg)
	if err != nil {
		log.Printf("Failed to load app configs: %v", err)
		appConfigs = make(models.AppConfigs)
		config.SaveAppConfigs(cfg, appConfigs) // Create initial empty config
	}

	// Initialize admin server
	adminServer := admin.New(cfg, appConfigs, certAuth)

	// Initialize proxy server
	proxyServer := proxy.New(cfg, appConfigs)

	// Start admin API server in a goroutine
	go adminServer.Start()

	// Start proxy server (blocking call)
	proxyServer.Start()
}
