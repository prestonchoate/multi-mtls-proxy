package main

import (
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/proxy"
	"log"
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

	// Load app configs
	appConfigs, err := config.LoadAppConfigs(cfg)
	if err != nil {
		log.Fatalf("Failed to load app configs: %v", err)
	}

	// Initialize proxy server
	proxyServer := proxy.New(cfg, appConfigs)

	// Start proxy server
	proxyServer.Start()
}
