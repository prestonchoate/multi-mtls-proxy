package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"

	"maps"

	"github.com/joho/godotenv"
	"github.com/prestonchoate/mtlsProxy/internal/models"
)

var (
	// ConfigMutex synchronizes access to the configuration
	ConfigMutex sync.RWMutex

	// IOMutex synchronizes file operations
	IOMutex sync.Mutex

	configInstance *models.Config
)

// loadEnv will attempt to load ".env" file
func loadEnv() {
	_, err := os.Stat(".env")
	if err == nil {
		err = godotenv.Load()
		if err != nil {
			log.Println("Error loading .env file")
			return
		}
	}
}

func checkEnvVar[T any](varName string, defaults models.Config) T {
	val, exists := os.LookupEnv(varName)
	var zero T

	if exists {
		switch any(zero).(type) {
		case string:
			return any(val).(T)
		case int:
			if i, err := strconv.Atoi(val); err == nil {
				return any(i).(T)
			}
		case int64:
			if i, err := strconv.ParseInt(val, 10, 64); err == nil {
				return any(i).(T)
			}
		case float64:
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				return any(f).(T)
			}
		case bool:
			if b, err := strconv.ParseBool(val); err == nil {
				return any(b).(T)
			}
		}
	}

	// Fallback: get default from struct field
	fieldName := defaults.EnvVarToFieldName(varName)
	valRef := reflect.ValueOf(defaults)
	field := valRef.FieldByName(fieldName)
	if field.IsValid() && field.CanInterface() {
		if def, ok := field.Interface().(T); ok {
			return def
		}
	}

	return zero
}

func GetConfig() *models.Config {
	if configInstance != nil {
		return configInstance
	}

	loadEnv()
	defaults := getDefaultConfig()

	configInstance = &models.Config{
		AdminAPIPort:         checkEnvVar[int]("ADMIN_API_PORT", defaults),
		ProxyPort:            checkEnvVar[int]("PROXY_PORT", defaults),
		CertDir:              checkEnvVar[string]("CERT_DIR", defaults),
		CAKeyFile:            checkEnvVar[string]("CA_KEY_FILE", defaults),
		CACertFile:           checkEnvVar[string]("CA_CERT_FILE", defaults),
		ProxyServerCertFile:  checkEnvVar[string]("PROXY_SERVER_CERT_FILE", defaults),
		ProxyServerKeyFile:   checkEnvVar[string]("PROXY_SERVER_KEY_FILE", defaults),
		ConfigFile:           checkEnvVar[string]("CONFIG_FILE", defaults),
		CertValidityDays:     checkEnvVar[int]("CERT_VALIDITY_DAYS", defaults),
		HostName:             checkEnvVar[string]("HOSTNAME", defaults),
		DefaultAdminUser:     checkEnvVar[string]("DEFAULT_ADMIN_USER", defaults),
		DefaultAdminPassword: checkEnvVar[string]("DEFAULT_ADMIN_PASSWORD", defaults),
		JWTSigningKeyFile:    checkEnvVar[string]("JWT_SIGNING_KEY_FILE", defaults),
		JWTSigningCertFile:   checkEnvVar[string]("JWT_SIGNING_CERT_FILE", defaults),
		MongoURI:             checkEnvVar[string]("MONGO_URI", defaults),
		MongoDB:              checkEnvVar[string]("MONGO_DB", defaults),
		MongoAppsColl:        checkEnvVar[string]("MONGO_APPS_COLL", defaults),
		MongoUsersColl:       checkEnvVar[string]("MONGO_USERS_COLL", defaults),
	}

	return configInstance
}

// getDefaultConfig returns a default configuration
func getDefaultConfig() models.Config {
	return models.Config{
		AdminAPIPort:         8080,
		ProxyPort:            8443,
		CertDir:              "./certs",
		CAKeyFile:            "./ca/ca.key",
		CACertFile:           "./ca/ca.crt",
		ProxyServerCertFile:  "./certs/server.crt",
		ProxyServerKeyFile:   "./certs/server.key",
		ConfigFile:           "./config/apps.json",
		CertValidityDays:     365,
		HostName:             "localhost",
		DefaultAdminUser:     "admin",
		DefaultAdminPassword: "password",
		JWTSigningKeyFile:    "./certs/admin.key",
		JWTSigningCertFile:   "./certs/admin.crt",
		MongoURI:             "mongodb://localhost:27017",
		MongoDB:              "mtlsProxy",
		MongoAppsColl:        "apps",
		MongoUsersColl:       "users",
		Mapping: map[string]string{
			"ADMIN_API_PORT":         "AdminAPIPort",
			"PROXY_PORT":             "ProxyPort",
			"CERT_DIR":               "CertDir",
			"CA_KEY_FILE":            "CAKeyFile",
			"CA_CERT_FILE":           "CACertFile",
			"PROXY_SERVER_CERT_FILE": "ProxyServerCertFile",
			"PROXY_SERVER_KEY_FILE":  "ProxyServerKeyFile",
			"CONFIG_FILE":            "ConfigFile",
			"CERT_VALIDITY_DAYS":     "CertValidityDays",
			"HOSTNAME":               "HostName",
			"DEFAULT_ADMIN_USER":     "DefaultAdminUser",
			"DEFAULT_ADMIN_PASSWORD": "DefaultAdminPassword",
			"JWT_SIGNING_KEY_FILE":   "JWTSigningKeyFile",
			"JWT_SIGNING_CERT_FILE":  "JWTSigningCertFile",
		},
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
