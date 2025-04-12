package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"maps"

	"github.com/gin-gonic/gin"
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

// CA certificate authority for signing client certificates
type CA struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

var (
	config     Config
	appConfigs AppConfigs
	ca         CA

	// Mutexes for thread safety
	configMutex sync.RWMutex
	caMutex     sync.Mutex
	certMutex   sync.Mutex
	ioMutex     sync.Mutex
)

func main() {
	// Initialize configuration
	config = Config{
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

	// Create necessary directories
	createDirectories()

	// Initialize or load CA
	if err := initializeCA(); err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	// Load app configs
	if err := loadAppConfigs(); err != nil {
		log.Printf("Failed to load app configs: %v", err)
		appConfigs = make(AppConfigs)
		saveAppConfigs() // Create initial empty config
	}

	// Start admin API server in a goroutine
	go startAdminAPI()

	// Start proxy server
	startProxyServer()
}

// Create necessary directories with thread safety
func createDirectories() {
	ioMutex.Lock()
	defer ioMutex.Unlock()

	os.MkdirAll(config.CertDir, 0755)
	os.MkdirAll(filepath.Dir(config.CAKeyFile), 0755)
	os.MkdirAll(filepath.Dir(config.ConfigFile), 0755)
}

// Initialize or load the Certificate Authority with thread safety
func initializeCA() error {
	caMutex.Lock()
	defer caMutex.Unlock()

	// Check if CA files exist
	_, keyErr := os.Stat(config.CAKeyFile)
	_, certErr := os.Stat(config.CACertFile)

	if os.IsNotExist(keyErr) || os.IsNotExist(certErr) {
		log.Println("CA files not found, creating new CA")
		return createCA()
	}

	// Load existing CA
	keyBytes, err := os.ReadFile(config.CAKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	certBytes, err := os.ReadFile(config.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert file: %w", err)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	ca.PrivateKey = privateKey
	ca.Certificate = cert
	log.Println("CA loaded successfully")
	return nil
}

// Create a new Certificate Authority
func createCA() error {
	// caMutex is already locked by the caller (initializeCA)

	// Create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy CA"},
			CommonName:   "mTLS Proxy Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Save private key to file
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	ioMutex.Lock()
	if err := os.MkdirAll(filepath.Dir(config.CAKeyFile), 0755); err != nil {
		ioMutex.Unlock()
		return fmt.Errorf("failed to create CA key directory: %w", err)
	}
	if err := os.WriteFile(config.CAKeyFile, keyPEM, 0600); err != nil {
		ioMutex.Unlock()
		return fmt.Errorf("failed to write CA key file: %w", err)
	}
	ioMutex.Unlock()

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	ioMutex.Lock()
	if err := os.WriteFile(config.CACertFile, certPEM, 0644); err != nil {
		ioMutex.Unlock()
		return fmt.Errorf("failed to write CA cert file: %w", err)
	}
	ioMutex.Unlock()

	// Parse the created certificate for internal use
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	ca.PrivateKey = privateKey
	ca.Certificate = cert
	log.Println("CA created successfully")
	return nil
}

// Load app configurations from file with thread safety
func loadAppConfigs() error {
	configMutex.Lock()
	defer configMutex.Unlock()

	ioMutex.Lock()
	file, err := os.ReadFile(config.ConfigFile)
	ioMutex.Unlock()

	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var configs AppConfigs
	if err := json.Unmarshal(file, &configs); err != nil {
		return fmt.Errorf("failed to unmarshal app configs: %w", err)
	}

	appConfigs = configs
	return nil
}

// Save app configurations to file with thread safety and atomic writes
func saveAppConfigs() error {
	configMutex.Lock()
	configCopy := make(AppConfigs)
	maps.Copy(configCopy, appConfigs)
	configMutex.Unlock()

	data, err := json.MarshalIndent(configCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal app configs: %w", err)
	}

	ioMutex.Lock()
	defer ioMutex.Unlock()

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

// Generate client certificate for an app with thread safety
func generateClientCertificate(appID string) (ClientCertInfo, error) {
	// Lock for certificate generation
	certMutex.Lock()
	defer certMutex.Unlock()

	// Use CA to sign
	caMutex.Lock()
	caCert := ca.Certificate
	caKey := ca.PrivateKey
	caMutex.Unlock()

	// Create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ClientCertInfo{}, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return ClientCertInfo{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	expiresAt := time.Now().AddDate(0, 0, config.CertValidityDays)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy Clients"},
			CommonName:   appID,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // Allow for clock skew
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate with our CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return ClientCertInfo{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Compute certificate fingerprint
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return ClientCertInfo{}, fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	fingerprint := fmt.Sprintf("%x", parsedCert.SerialNumber)

	// Save private key to file
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	keyFile := filepath.Join(config.CertDir, fmt.Sprintf("%s.key", appID))

	ioMutex.Lock()
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		ioMutex.Unlock()
		return ClientCertInfo{}, fmt.Errorf("failed to write client key file: %w", err)
	}
	ioMutex.Unlock()

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certFile := filepath.Join(config.CertDir, fmt.Sprintf("%s.crt", appID))

	ioMutex.Lock()
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		ioMutex.Unlock()
		return ClientCertInfo{}, fmt.Errorf("failed to write client cert file: %w", err)
	}
	ioMutex.Unlock()

	return ClientCertInfo{
		CertFile:    certFile,
		KeyFile:     keyFile,
		Fingerprint: fingerprint,
		ExpiresAt:   expiresAt,
	}, nil
}

// Start the admin API server
func startAdminAPI() {
	router := gin.Default()

	// API endpoints
	admin := router.Group("/admin")
	{
		// Create a new app
		admin.POST("/apps", func(c *gin.Context) {
			var appRequest struct {
				AppID      string            `json:"appId"`
				TargetURLs map[string]string `json:"targetUrls"`
			}

			if err := c.BindJSON(&appRequest); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}

			if appRequest.AppID == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "AppID is required"})
				return
			}

			if len(appRequest.TargetURLs) == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "At least one target URL is required"})
				return
			}

			// Validate target URLs
			for path, target := range appRequest.TargetURLs {
				if _, err := url.Parse(target); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid target URL for path %s: %s", path, target)})
					return
				}
			}

			// Check if app already exists
			configMutex.RLock()
			_, exists := appConfigs[appRequest.AppID]
			configMutex.RUnlock()

			if exists {
				c.JSON(http.StatusConflict, gin.H{"error": "App ID already exists"})
				return
			}

			// Generate client certificates
			clientCertInfo, err := generateClientCertificate(appRequest.AppID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate client certificate: %v", err)})
				return
			}

			// Create new app config
			now := time.Now()
			newApp := AppConfig{
				AppID:       appRequest.AppID,
				TargetURLs:  appRequest.TargetURLs,
				ClientCerts: clientCertInfo,
				Created:     now,
				Updated:     now,
			}

			// Update the appConfigs map
			configMutex.Lock()
			appConfigs[appRequest.AppID] = newApp
			configMutex.Unlock()

			// Save updated configs
			if err := saveAppConfigs(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
				return
			}

			// Return client certificate information
			c.JSON(http.StatusCreated, gin.H{
				"appId": appRequest.AppID,
				"certs": gin.H{
					"certFile":    clientCertInfo.CertFile,
					"keyFile":     clientCertInfo.KeyFile,
					"fingerprint": clientCertInfo.Fingerprint,
					"expiresAt":   clientCertInfo.ExpiresAt,
				},
				"targetUrls": appRequest.TargetURLs,
			})
		})

		// Get all apps
		admin.GET("/apps", func(c *gin.Context) {
			configMutex.RLock()
			configCopy := make(AppConfigs)
			maps.Copy(configCopy, appConfigs)
			configMutex.RUnlock()

			c.JSON(http.StatusOK, configCopy)
		})

		// Get a specific app
		admin.GET("/apps/:appId", func(c *gin.Context) {
			appID := c.Param("appId")

			configMutex.RLock()
			app, exists := appConfigs[appID]
			configMutex.RUnlock()

			if !exists {
				c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
				return
			}
			c.JSON(http.StatusOK, app)
		})

		// Update app target URLs
		admin.PUT("/apps/:appId/targets", func(c *gin.Context) {
			appID := c.Param("appId")

			var targetRequest struct {
				TargetURLs map[string]string `json:"targetUrls"`
			}

			if err := c.BindJSON(&targetRequest); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}

			if len(targetRequest.TargetURLs) == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "At least one target URL is required"})
				return
			}

			// Validate target URLs
			for path, target := range targetRequest.TargetURLs {
				if _, err := url.Parse(target); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid target URL for path %s: %s", path, target)})
					return
				}
			}

			// Update app config
			configMutex.Lock()
			app, exists := appConfigs[appID]
			if !exists {
				configMutex.Unlock()
				c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
				return
			}

			app.TargetURLs = targetRequest.TargetURLs
			app.Updated = time.Now()
			appConfigs[appID] = app
			configMutex.Unlock()

			// Save updated configs
			if err := saveAppConfigs(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
				return
			}

			c.JSON(http.StatusOK, app)
		})

		// Rotate client certificate
		admin.POST("/apps/:appId/rotate-cert", func(c *gin.Context) {
			appID := c.Param("appId")

			configMutex.RLock()
			_, exists := appConfigs[appID]
			configMutex.RUnlock()

			if !exists {
				c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
				return
			}

			// Generate new client certificates
			clientCertInfo, err := generateClientCertificate(appID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate client certificate: %v", err)})
				return
			}

			// Update app config
			configMutex.Lock()
			app := appConfigs[appID]
			app.ClientCerts = clientCertInfo
			app.Updated = time.Now()
			appConfigs[appID] = app
			configMutex.Unlock()

			// Save updated configs
			if err := saveAppConfigs(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"appId": appID,
				"certs": gin.H{
					"certFile":    clientCertInfo.CertFile,
					"keyFile":     clientCertInfo.KeyFile,
					"fingerprint": clientCertInfo.Fingerprint,
					"expiresAt":   clientCertInfo.ExpiresAt,
				},
			})
		})

		// Delete an app
		admin.DELETE("/apps/:appId", func(c *gin.Context) {
			appID := c.Param("appId")

			configMutex.Lock()
			app, exists := appConfigs[appID]
			if !exists {
				configMutex.Unlock()
				c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
				return
			}

			// Remove from configs
			delete(appConfigs, appID)
			configMutex.Unlock()

			// Save updated configs before deleting files
			if err := saveAppConfigs(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
				return
			}

			// Delete cert files
			ioMutex.Lock()
			os.Remove(app.ClientCerts.CertFile)
			os.Remove(app.ClientCerts.KeyFile)
			ioMutex.Unlock()

			c.JSON(http.StatusOK, gin.H{"message": "App deleted successfully"})
		})

		// Get CA certificate
		admin.GET("/ca-cert", func(c *gin.Context) {
			ioMutex.Lock()
			certBytes, err := os.ReadFile(config.CACertFile)
			ioMutex.Unlock()

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read CA certificate"})
				return
			}
			c.Data(http.StatusOK, "application/x-pem-file", certBytes)
		})
	}

	// Start the admin API server
	log.Printf("Starting admin API server on port %d", config.AdminAPIPort)
	if err := router.Run(fmt.Sprintf(":%d", config.AdminAPIPort)); err != nil {
		log.Fatalf("Failed to start admin API server: %v", err)
	}
}

func checkProxyCert() {
	_, err := os.Stat(config.ProxyServerCertFile)
	if err != nil {
		createProxyCert()
		return
	}

	_, err = os.Stat(config.ProxyServerKeyFile)
	if err != nil {
		createProxyCert()
		return
	}
}

func createProxyCert() {
	// Generate server private key
	serverKey, _ := rsa.GenerateKey(rand.Reader, 4096)

	// Create server certificate template
	serverCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Load CA cert and key
	caCertPEM, _ := os.ReadFile(config.CACertFile)
	caKeyPEM, _ := os.ReadFile(config.CAKeyFile)

	// Parse CA certificate
	block, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	// Parse CA private key
	block, _ = pem.Decode(caKeyPEM)
	caKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// Self-signed cert using CA
	serverCertDER, _ := x509.CreateCertificate(rand.Reader, serverCertTemplate, caCert, &serverKey.PublicKey, caKey)

	// Save server cert
	serverCertFile, _ := os.Create(config.ProxyServerCertFile)
	pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverCertFile.Close()

	// Save server key
	serverKeyFile, _ := os.Create(config.ProxyServerKeyFile)
	pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	serverKeyFile.Close()
}

// Start the proxy server
func startProxyServer() {
	// Create a CA cert pool for client authentication
	caCertPool := x509.NewCertPool()

	ioMutex.Lock()
	caCert, err := os.ReadFile(config.CACertFile)
	ioMutex.Unlock()

	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Check if proxy server cert and key exist
	checkProxyCert()

	// Create TLS config
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	// Create server
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.ProxyPort),
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(proxyHandler),
	}

	// Start the server
	log.Printf("Starting proxy server on port %d", config.ProxyPort)
	if err := server.ListenAndServeTLS(config.ProxyServerCertFile, config.ProxyServerKeyFile); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}

// Handler for proxy requests
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Get client certificate
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}
	clientCert := r.TLS.PeerCertificates[0]
	clientAppID := clientCert.Subject.CommonName

	// Find app config
	configMutex.RLock()
	app, exists := appConfigs[clientAppID]
	configMutex.RUnlock()

	if !exists {
		http.Error(w, "Unknown client", http.StatusUnauthorized)
		return
	}

	// Find matching target URL for the request path
	var targetURL string
	var matchedPathPrefix string

	for pathPrefix, target := range app.TargetURLs {
		fmt.Printf("checking path: %v - %v\tagainst %v\n", pathPrefix, target, r.URL.Path)
		// Find the longest matching path prefix
		if r.URL.Path == pathPrefix || (len(r.URL.Path) > len(pathPrefix) &&
			r.URL.Path[:len(pathPrefix)] == pathPrefix &&
			(len(matchedPathPrefix) == 0 || len(pathPrefix) > len(matchedPathPrefix))) {
			targetURL = target
			matchedPathPrefix = pathPrefix
		}
	}

	if targetURL == "" {
		http.Error(w, "No matching target found for path", http.StatusNotFound)
		return
	}

	// Parse the target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Create a reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Update the request host and scheme
	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.Host = target.Host

	// If the original request path has a prefix, remove it
	if matchedPathPrefix != "/" {
		r.URL.Path = r.URL.Path[len(matchedPathPrefix):]
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	// Add X-Forwarded headers
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
	r.Header.Set("X-Client-Cert-CN", clientAppID)
	r.Header.Set("X-Client-Cert-Fingerprint", app.ClientCerts.Fingerprint)

	// Log the request
	log.Printf("Proxying request from %s to %s%s", clientAppID, targetURL, r.URL.Path)

	// Forward the request
	proxy.ServeHTTP(w, r)
}
