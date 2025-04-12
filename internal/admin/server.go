package admin

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
)

// Server represents the admin API server
type Server struct {
	config     *models.Config
	appConfigs models.AppConfigs
	ca         *ca.CertificateAuthority
}

// New creates a new admin server
func New(cfg *models.Config, appCfgs models.AppConfigs, certAuth *ca.CertificateAuthority) *Server {
	return &Server{
		config:     cfg,
		appConfigs: appCfgs,
		ca:         certAuth,
	}
}

// Start starts the admin API server
func (s *Server) Start() {
	router := gin.Default()

	// API endpoints
	admin := router.Group("/admin")
	{
		// Create a new app
		admin.POST("/apps", s.createApp)

		// Get all apps
		admin.GET("/apps", s.getAllApps)

		// Get a specific app
		admin.GET("/apps/:appId", s.getApp)

		// Update app target URLs
		admin.PUT("/apps/:appId/targets", s.updateAppTargets)

		// Rotate client certificate
		admin.POST("/apps/:appId/rotate-cert", s.rotateAppCert)

		// Delete an app
		admin.DELETE("/apps/:appId", s.deleteApp)

		// Get CA certificate
		admin.GET("/ca-cert", s.getCACert)
	}

	// Start the admin API server
	log.Printf("Starting admin API server on port %d", s.config.AdminAPIPort)
	if err := router.Run(fmt.Sprintf(":%d", s.config.AdminAPIPort)); err != nil {
		log.Fatalf("Failed to start admin API server: %v", err)
	}
}

// Create a new app
func (s *Server) createApp(c *gin.Context) {
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
	config.ConfigMutex.RLock()
	_, exists := s.appConfigs[appRequest.AppID]
	config.ConfigMutex.RUnlock()

	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "App ID already exists"})
		return
	}

	// Generate client certificates
	clientCertInfo, err := s.ca.GenerateClientCertificate(appRequest.AppID, s.config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate client certificate: %v", err)})
		return
	}

	// Create new app config
	now := time.Now()
	newApp := models.AppConfig{
		AppID:       appRequest.AppID,
		TargetURLs:  appRequest.TargetURLs,
		ClientCerts: clientCertInfo,
		Created:     now,
		Updated:     now,
	}

	// Update the appConfigs map
	config.ConfigMutex.Lock()
	s.appConfigs[appRequest.AppID] = newApp
	config.ConfigMutex.Unlock()

	// Save updated configs
	if err := config.SaveAppConfigs(s.config, s.appConfigs); err != nil {
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
}

// Get all apps
func (s *Server) getAllApps(c *gin.Context) {
	config.ConfigMutex.RLock()
	configCopy := make(models.AppConfigs)
	for k, v := range s.appConfigs {
		configCopy[k] = v
	}
	config.ConfigMutex.RUnlock()

	c.JSON(http.StatusOK, configCopy)
}

// Get a specific app
func (s *Server) getApp(c *gin.Context) {
	appID := c.Param("appId")

	config.ConfigMutex.RLock()
	app, exists := s.appConfigs[appID]
	config.ConfigMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}
	c.JSON(http.StatusOK, app)
}

// Update app target URLs
func (s *Server) updateAppTargets(c *gin.Context) {
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
	config.ConfigMutex.Lock()
	app, exists := s.appConfigs[appID]
	if !exists {
		config.ConfigMutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	app.TargetURLs = targetRequest.TargetURLs
	app.Updated = time.Now()
	s.appConfigs[appID] = app
	config.ConfigMutex.Unlock()

	// Save updated configs
	if err := config.SaveAppConfigs(s.config, s.appConfigs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
		return
	}

	c.JSON(http.StatusOK, app)
}

// Rotate client certificate
func (s *Server) rotateAppCert(c *gin.Context) {
	appID := c.Param("appId")

	config.ConfigMutex.RLock()
	_, exists := s.appConfigs[appID]
	config.ConfigMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	// Generate new client certificates
	clientCertInfo, err := s.ca.GenerateClientCertificate(appID, s.config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to generate client certificate: %v", err)})
		return
	}

	// Update app config
	config.ConfigMutex.Lock()
	app := s.appConfigs[appID]
	app.ClientCerts = clientCertInfo
	app.Updated = time.Now()
	s.appConfigs[appID] = app
	config.ConfigMutex.Unlock()

	// Save updated configs
	if err := config.SaveAppConfigs(s.config, s.appConfigs); err != nil {
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
}

// Delete an app
func (s *Server) deleteApp(c *gin.Context) {
	appID := c.Param("appId")

	config.ConfigMutex.Lock()
	app, exists := s.appConfigs[appID]
	if !exists {
		config.ConfigMutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	// Remove from configs
	delete(s.appConfigs, appID)
	config.ConfigMutex.Unlock()

	// Save updated configs before deleting files
	if err := config.SaveAppConfigs(s.config, s.appConfigs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
		return
	}

	// Delete cert files
	config.IOMutex.Lock()
	os.Remove(app.ClientCerts.CertFile)
	os.Remove(app.ClientCerts.KeyFile)
	config.IOMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{"message": "App deleted successfully"})
}

// Get CA certificate
func (s *Server) getCACert(c *gin.Context) {
	config.IOMutex.Lock()
	certBytes, err := os.ReadFile(s.config.CACertFile)
	config.IOMutex.Unlock()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read CA certificate"})
		return
	}
	c.Data(http.StatusOK, "application/x-pem-file", certBytes)
}
