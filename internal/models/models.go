package models

import (
	"time"

	"github.com/google/uuid"
)

// Config represents the application configuration
type Config struct {
	AdminAPIPort         int               `json:"adminApiPort"`
	ProxyPort            int               `json:"proxyPort"`
	CertDir              string            `json:"certDir"`
	CAKeyFile            string            `json:"caKeyFile"`
	CACertFile           string            `json:"caCertFile"`
	ProxyServerCertFile  string            `json:"proxyServerCertFile"`
	ProxyServerKeyFile   string            `json:"proxyServerKeyFile"`
	ConfigFile           string            `json:"configFile"`
	CertValidityDays     int               `json:"certValidityDays"`
	HostName             string            `json:"hostname"`
	DefaultAdminUser     string            `json:"defaultAdminUser"`
	DefaultAdminPassword string            `json:"-"`
	JWTSigningCertFile   string            `json:"jwtSigningCertFile"`
	JWTSigningKeyFile    string            `json:"jwtSigningKeyFile"`
	Mapping              map[string]string `json:"-"`
}

// envVarToFieldName converts ENV_VAR_NAME to StructFieldName (e.g., ADMIN_API_PORT → AdminAPIPort)
func (c *Config) EnvVarToFieldName(envVar string) string {
	fieldName, exists := c.Mapping[envVar]
	if !exists {
		return ""
	}
	return fieldName
}

// AppConfig represents an application configuration for proxying
type AppConfig struct {
	AppID       string            `json:"appId"`
	TargetURLs  map[string]string `json:"targetUrls"` // path prefix -> target URL
	ClientCerts ClientCertInfo    `json:"clientCerts"`
	Owner       uuid.UUID         `json:"owner"`
	Created     time.Time         `json:"created"`
	Updated     time.Time         `json:"updated"`
}

// ClientCertInfo holds information about the client certificate
type ClientCertInfo struct {
	CertFile    string    `json:"certFile"`
	KeyFile     string    `json:"keyFile"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

type AdminUser struct {
	ID           uuid.UUID `json:"id"`
	UserName     string    `json:"userName"`
	PasswordHash string    `json:"-"`
}

// AppConfigs is a map of appID to AppConfig TODO: Convert this to persistent storage instead of file based
type AppConfigs map[string]AppConfig

// AdminUsers is a map of AdminUser.ID to *AdminUser TODO: Convert this to persistent storage
type AdminUsers map[uuid.UUID]*AdminUser
