package models

import (
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
	MongoURI             string            `json:"mongoURI"`
	MongoDB              string            `json:"mongoDB"`
	MongoAppsColl        string            `json:"mongoAppsColl"`
	MongoUsersColl       string            `json:"mongoUsersColl"`
	EncryptionKey        string            `json:"encryptionKey"`
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
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	AppID       string             `json:"appId" bson:"appId"`
	TargetURLs  map[string]string  `json:"targetUrls" json:"targetUrls"` // path prefix -> target URL
	ClientCerts ClientCertInfo     `json:"clientCerts" json:"clientCerts"`
	Owner       uuid.UUID          `json:"owner" json:"owner"`
	CreatedAt   time.Time          `json:"createdAt" json:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt" json:"updatedAt"`
}

// ClientCertInfo holds information about the client certificate
type ClientCertInfo struct {
	CertFile        string    `json:"certFile"`
	KeyFile         string    `json:"keyFile"`
	CertPEM         string    `json:"certPEM,omitempty"`
	EncryptedKeyPEM string    `json:"encryptedKeyPEM,omitempty"`
	Fingerprint     string    `json:"fingerprint"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

type AdminUser struct {
	ID           uuid.UUID `json:"id" bson:"id"`
	UserName     string    `json:"userName" bson:"userName"`
	PasswordHash string    `json:"-" bson:"passwordHash"`
	CreatedAt    time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt" bson:"updatedAt"`
	LastLogin    time.Time `json:"lastLogin" bson:"lastLogin"`
}

// AppConfigs is a map of appID to AppConfig TODO: Convert this to persistent storage instead of file based
type AppConfigs map[string]AppConfig
