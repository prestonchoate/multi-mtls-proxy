package config

import (
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"

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
		EncryptionKey:        checkEnvVar[string]("ENCRYPTION_KEY", defaults),
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
		EncryptionKey:        "ybVYwwik+g8LWj2v8NH4auxxc8j5XFy8Gl8RXZe/HUCUPfwR2sP/eV/ouKIeZPsv",
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
