package main

import (
	"log"

	"github.com/prestonchoate/mtlsProxy/internal/admin"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/db"
)

// main is the entry point for the application, initializing configuration, certificate authority, and the admin API server. It ensures required directories and certificates exist, loads application configurations, and starts the admin server. The program terminates on critical initialization failures.
func main() {
	// Initialize configuration
	cfg := config.GetConfig()

	client, err := db.NewMongoClient(cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.Fatalf("Failed to connect to db: %v", err)
	}

	// Initialize certificate authority
	certAuth := ca.New()
	if err := certAuth.Initialize(cfg, client); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Check and create admin signing cert/key if needed
	if err := certAuth.CheckAdminSigningCert(cfg); err != nil {
		log.Fatalf("Failed to check/create admin signing cert: %v", err)
	}

	// Initialize admin server
	adminServer, err := admin.New(cfg, certAuth)
	if err != nil {
		log.Fatalf("Failed to create admin server: %v\n", err)
	}

	// Start admin API server
	adminServer.Start()
}
