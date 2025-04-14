package models

import (
	"time"
)

// Config represents the application configuration
type Config struct {
	AdminAPIPort        int    `json:"adminApiPort"`
	ProxyPort           int    `json:"proxyPort"`
	CertDir             string `json:"certDir"`
	CAKeyFile           string `json:"caKeyFile"`
	CACertFile          string `json:"caCertFile"`
	ProxyServerCertFile string `json:"proxyServerCertFile"`
	ProxyServerKeyFile  string `json:"proxyServerKeyFile"`
	ConfigFile          string `json:"configFile"`
	CertValidityDays    int    `json:"certValidityDays"`
	HostName            string `json:"hostname"`
}

// AppConfig represents an application configuration for proxying
type AppConfig struct {
	AppID       string            `json:"appId"`
	TargetURLs  map[string]string `json:"targetUrls"` // path prefix -> target URL
	ClientCerts ClientCertInfo    `json:"clientCerts"`
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

// AppConfigs is a map of appID to AppConfig
type AppConfigs map[string]AppConfig
