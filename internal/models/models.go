package models

import (
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Config represents the application configuration
type Config struct {
	AdminAPIPort         int               `json:"adminApiPort"`
	ProxyPort            int               `json:"proxyPort"`
	CAKeyName            string            `json:"caKeyFile"`
	CACertName           string            `json:"caCertFile"`
	ProxyServerCertName  string            `json:"proxyServerCertFile"`
	ProxyServerKeyName   string            `json:"proxyServerKeyFile"`
	CertValidityDays     int               `json:"certValidityDays"`
	HostName             string            `json:"hostname"`
	DefaultAdminUser     string            `json:"defaultAdminUser"`
	DefaultAdminPassword string            `json:"-"`
	JWTSigningCertName   string            `json:"jwtSigningCertFile"`
	JWTSigningKeyName    string            `json:"jwtSigningKeyFile"`
	MongoURI             string            `json:"mongoURI"`
	MongoDB              string            `json:"mongoDB"`
	MongoAppsColl        string            `json:"mongoAppsColl"`
	MongoUsersColl       string            `json:"mongoUsersColl"`
	MongoCertColl        string            `json:"mongoCertColl"`
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

// GetEncryptionKey decodes base64 encoded key and returns it as an array of bytes
func (c *Config) GetEncryptionKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(c.EncryptionKey)
}

// AppConfig represents an application configuration for proxying
type AppConfig struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	AppID       string             `json:"appId" bson:"appId"`
	TargetURLs  map[string]string  `json:"targetUrls" bson:"targetUrls"` // path prefix -> target URL
	ClientCerts ClientCertInfo     `json:"clientCerts" bson:"clientCerts"`
	Owner       uuid.UUID          `json:"owner" bson:"owner"`
	CreatedAt   time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt" bson:"updatedAt"`
}

// ClientCertInfo holds information about the client certificate
type ClientCertInfo struct {
	CertFile    string    `json:"certFile" bson:"certFile"`
	KeyFile     string    `json:"keyFile" bson:"keyFile"`
	Fingerprint string    `json:"fingerprint" bson:"fingerprint"`
	ExpiresAt   time.Time `json:"expiresAt" bson:"expiresAt"`
}

type AdminUser struct {
	ID           uuid.UUID `json:"id" bson:"id"`
	UserName     string    `json:"userName" bson:"userName"`
	PasswordHash string    `json:"-" bson:"passwordHash"`
	CreatedAt    time.Time `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt" bson:"updatedAt"`
	LastLogin    time.Time `json:"lastLogin" bson:"lastLogin"`
}

// AppConfigs is a map of appID to AppConfig
type AppConfigs map[string]AppConfig

type CertDataType string

const (
	Cert CertDataType = "cert"
	Key  CertDataType = "key"
)

type CertData struct {
	ID        primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Type      CertDataType       `json:"type" bson:"type"`
	Data      string             `json:"data" bson:"data"`
	CreatedAt time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt time.Time          `json:"updatedAt" bson:"updatedAt"`
}
