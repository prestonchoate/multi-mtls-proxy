package main

import (
	"github.com/prestonchoate/mtlsProxy/internal/admin"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"log"
)

// main is the entry point for the application, initializing configuration, certificate authority, and the admin API server. It ensures required directories and certificates exist, loads application configurations, and starts the admin server. The program terminates on critical initialization failures.
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

	// Start admin API server
	adminServer.Start()
}
