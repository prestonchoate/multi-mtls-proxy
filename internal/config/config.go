package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/prestonchoate/mtlsProxy/internal/models"
	"maps"
)

var (
	// ConfigMutex synchronizes access to the configuration
	ConfigMutex sync.RWMutex

	// IOMutex synchronizes file operations
	IOMutex sync.Mutex
)

// GetDefaultConfig returns a default configuration
func GetDefaultConfig() models.Config {
	return models.Config{
		AdminAPIPort:        8080,
		ProxyPort:           8443,
		CertDir:             "./certs",
		CAKeyFile:           "./ca/ca.key",
		CACertFile:          "./ca/ca.crt",
		ProxyServerCertFile: "./certs/server.crt",
		ProxyServerKeyFile:  "./certs/server.key",
		ConfigFile:          "./config/apps.json",
		CertValidityDays:    365,
	}
}

// CreateDirectories creates necessary directories
func CreateDirectories(config *models.Config) {
	IOMutex.Lock()
	defer IOMutex.Unlock()

	os.MkdirAll(config.CertDir, 0755)
	os.MkdirAll(filepath.Dir(config.CAKeyFile), 0755)
	os.MkdirAll(filepath.Dir(config.ConfigFile), 0755)
}

// LoadAppConfigs loads app configuration from disk
func LoadAppConfigs(config *models.Config) (models.AppConfigs, error) {
	ConfigMutex.Lock()
	defer ConfigMutex.Unlock()

	IOMutex.Lock()
	file, err := os.ReadFile(config.ConfigFile)
	IOMutex.Unlock()

	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configs models.AppConfigs
	if err := json.Unmarshal(file, &configs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal app configs: %w", err)
	}

	return configs, nil
}

// SaveAppConfigs saves app configuration to disk
func SaveAppConfigs(config *models.Config, appConfigs models.AppConfigs) error {
	ConfigMutex.Lock()
	configCopy := make(models.AppConfigs)
	maps.Copy(configCopy, appConfigs)
	ConfigMutex.Unlock()

	data, err := json.MarshalIndent(configCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal app configs: %w", err)
	}

	IOMutex.Lock()
	defer IOMutex.Unlock()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(config.ConfigFile), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write to a temporary file first for atomic update
	tempFile := config.ConfigFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp config file: %w", err)
	}

	// Rename for atomic replacement
	if err := os.Rename(tempFile, config.ConfigFile); err != nil {
		return fmt.Errorf("failed to rename temp config file: %w", err)
	}

	return nil
}
