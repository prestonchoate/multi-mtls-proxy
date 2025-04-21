package config

import (
	"log"
	"os"
	"reflect"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/prestonchoate/mtlsProxy/internal/models"
)

var (
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
		CAKeyName:            checkEnvVar[string]("CA_KEY_NAME", defaults),
		CACertName:           checkEnvVar[string]("CA_CERT_NAME", defaults),
		ProxyServerCertName:  checkEnvVar[string]("PROXY_SERVER_CERT_NAME", defaults),
		ProxyServerKeyName:   checkEnvVar[string]("PROXY_SERVER_KEY_NAME", defaults),
		CertValidityDays:     checkEnvVar[int]("CERT_VALIDITY_DAYS", defaults),
		HostName:             checkEnvVar[string]("HOSTNAME", defaults),
		DefaultAdminUser:     checkEnvVar[string]("DEFAULT_ADMIN_USER", defaults),
		DefaultAdminPassword: checkEnvVar[string]("DEFAULT_ADMIN_PASSWORD", defaults),
		JWTSigningKeyName:    checkEnvVar[string]("JWT_SIGNING_KEY_NAME", defaults),
		JWTSigningCertName:   checkEnvVar[string]("JWT_SIGNING_CERT_NAME", defaults),
		MongoURI:             checkEnvVar[string]("MONGO_URI", defaults),
		MongoDB:              checkEnvVar[string]("MONGO_DB", defaults),
		MongoAppsColl:        checkEnvVar[string]("MONGO_APPS_COLL", defaults),
		MongoUsersColl:       checkEnvVar[string]("MONGO_USERS_COLL", defaults),
		EncryptionKey:        checkEnvVar[string]("ENCRYPTION_KEY", defaults),
		MongoCertColl:        checkEnvVar[string]("MONGO_CERT_COLL", defaults),
	}

	return configInstance
}

// getDefaultConfig returns a default configuration
func getDefaultConfig() models.Config {
	return models.Config{
		AdminAPIPort:         8080,
		ProxyPort:            8443,
		CAKeyName:            "ca/ca.key",
		CACertName:           "ca/ca.crt",
		ProxyServerCertName:  "proxy/server.crt",
		ProxyServerKeyName:   "proxy/server.key",
		CertValidityDays:     365,
		HostName:             "localhost",
		DefaultAdminUser:     "admin",
		DefaultAdminPassword: "password",
		JWTSigningKeyName:    "admin/signing.key",
		JWTSigningCertName:   "admin/signing.crt",
		MongoURI:             "mongodb://localhost:27017",
		MongoDB:              "mtlsProxy",
		MongoAppsColl:        "apps",
		MongoUsersColl:       "users",
		MongoCertColl:        "certs",
		EncryptionKey:        "rTdRG79RqfXnHVIrPui3d4qW7qaF/uVQj5VnkWb96KQ=",
		Mapping: map[string]string{
			"ADMIN_API_PORT":         "AdminAPIPort",
			"PROXY_PORT":             "ProxyPort",
			"CA_KEY_NAME":            "CAKeyName",
			"CA_CERT_NAME":           "CACertName",
			"PROXY_SERVER_CERT_NAME": "ProxyServerCertName",
			"PROXY_SERVER_KEY_NAME":  "ProxyServerKeyName",
			"CERT_VALIDITY_DAYS":     "CertValidityDays",
			"HOSTNAME":               "HostName",
			"DEFAULT_ADMIN_USER":     "DefaultAdminUser",
			"DEFAULT_ADMIN_PASSWORD": "DefaultAdminPassword",
			"JWT_SIGNING_KEY_NAME":   "JWTSigningKeyName",
			"JWT_SIGNING_CERT_NAME":  "JWTSigningCertName",
			"MONGO_URI":              "MongoURI",
			"MONGO_DB":               "MongoDB",
			"MONGO_APPS_COLL":        "MongoAppsColl",
			"MONGO_USERS_COLL":       "MongoUsersColl",
			"MONGO_CERT_COLL":        "MongoCertColl",
			"ENCRYPTION_KEY":         "EncryptionKey",
		},
	}
}
