package main

import (
	"log"

	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/proxy"
	"github.com/prestonchoate/mtlsProxy/internal/repository"
)

// main is the entry point for the mTLS proxy application, handling configuration, certificate authority initialization, proxy certificate management, application configuration loading, and starting the proxy server.
func main() {
	// Initialize configuration
	cfg := config.GetConfig()
	mongoClient, err := db.NewMongoClient(cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.Fatalf("Failed to initialize db connection: %v", err)
	}

	defer func() {
		if err := mongoClient.Close(); err != nil {
			log.Printf("Error disconnecting from DB: %v", err)
		}
	}()

	appRepo := repository.NewMongoAppRepository(mongoClient, cfg.MongoAppsColl)

	// Initialize certificate authority
	certAuth := ca.New()
	if err := certAuth.Initialize(cfg, mongoClient); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Check and create proxy certificates if needed
	if err := certAuth.CheckProxyCert(cfg); err != nil {
		log.Fatalf("Failed to check/create proxy certificates: %v", err)
	}

	// Initialize proxy server
	proxyServer := proxy.New(cfg, appRepo, certAuth)

	if proxyServer == nil {
		log.Fatalf("Failed to start proxy server")
	}

	// Start proxy server
	proxyServer.Start()
}
