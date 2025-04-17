package admin

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"golang.org/x/crypto/bcrypt"
)

var (
	adminUsersMutex sync.RWMutex
)

// Server represents the admin API server
type Server struct {
	config     *models.Config
	appConfigs models.AppConfigs
	ca         *ca.CertificateAuthority
	adminUsers models.AdminUsers
}

// New creates a new admin server
func New(cfg *models.Config, appCfgs models.AppConfigs, certAuth *ca.CertificateAuthority) *Server {
	return &Server{
		config:     cfg,
		appConfigs: appCfgs,
		ca:         certAuth,
		adminUsers: make(models.AdminUsers, 0),
	}
}

// Start starts the admin API server
func (s *Server) Start() {
	if len(s.adminUsers) == 0 && s.config.DefaultAdminUser != "" && s.config.DefaultAdminPassword != "" {
		log.Println("Creating default admin user")
		admin := s.createAdmin(s.config.DefaultAdminUser, s.config.DefaultAdminPassword)
		if admin != nil {
			adminUsersMutex.Lock()
			s.adminUsers[admin.ID] = admin
			adminUsersMutex.Unlock()
		}
	}
	router := gin.Default()
	router.Use(s.CORSMiddleware())
	// Public Admin API endpoints
	public := router.Group("/admin")
	{
		// Handle Admin Login
		public.POST("/login", s.adminLogin)

		// Get CA certificate
		public.GET("/ca-cert", s.getCACert)
	}

	// Restricted Admin API endpoints
	admin := router.Group("/admin")
	admin.Use(s.validateAdminAuth())

	{
		// Create new admin user
		admin.POST("/create", s.createAdminUser)

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

	}

	// Start the admin API server
	log.Printf("Starting admin API server on port %d", s.config.AdminAPIPort)
	if err := router.Run(fmt.Sprintf(":%d", s.config.AdminAPIPort)); err != nil {
		log.Fatalf("Failed to start admin API server: %v", err)
	}
}

// Create a new app
func (s *Server) createApp(c *gin.Context) {
	adminUser := s.extractAdminFromContext(c)

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
		Owner:       adminUser.ID,
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

// Get all apps filtered by logged in user ID
func (s *Server) getAllApps(c *gin.Context) {
	adminUser := s.extractAdminFromContext(c)

	config.ConfigMutex.RLock()
	configCopy := make(models.AppConfigs)
	for k, v := range s.appConfigs {
		if v.Owner == adminUser.ID {
			configCopy[k] = v
		}
	}
	config.ConfigMutex.RUnlock()

	c.JSON(http.StatusOK, configCopy)
}

// Get a specific app
func (s *Server) getApp(c *gin.Context) {
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	config.ConfigMutex.RLock()
	app, exists := s.appConfigs[appID]
	config.ConfigMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.JSON(http.StatusOK, app)
}

// Update app target URLs
func (s *Server) updateAppTargets(c *gin.Context) {
	adminUser := s.extractAdminFromContext(c)
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

	if app.Owner != adminUser.ID {
		config.ConfigMutex.Unlock()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
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
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	config.ConfigMutex.RLock()
	app, exists := s.appConfigs[appID]
	config.ConfigMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
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
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	config.ConfigMutex.Lock()
	app, exists := s.appConfigs[appID]
	if !exists {
		config.ConfigMutex.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
		return
	}

	if app.Owner != adminUser.ID {
		config.ConfigMutex.Unlock()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
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

// Handle Admin Creation request
func (s *Server) createAdminUser(c *gin.Context) {
	var adminCreateRequest struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BindJSON(&adminCreateRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	if adminCreateRequest.UserName == "" || adminCreateRequest.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	existingAdmin := s.getAdminByUsername(adminCreateRequest.UserName)
	if existingAdmin != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	user := s.createAdmin(adminCreateRequest.UserName, adminCreateRequest.Password)
	if user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	adminUsersMutex.Lock()
	s.adminUsers[user.ID] = user
	adminUsersMutex.Unlock()

	c.JSONP(http.StatusCreated, user)
}

// Handle admin login request
func (s *Server) adminLogin(c *gin.Context) {
	var adminLoginRequest struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&adminLoginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	if adminLoginRequest.UserName == "" || adminLoginRequest.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	existingAdmin := s.getAdminByUsername(adminLoginRequest.UserName)
	if existingAdmin == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(existingAdmin.PasswordHash), []byte(adminLoginRequest.Password))
	if passErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	token, err := s.generateAdminJwt(existingAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})

}

// Generate a signed Admin JWT for user
func (s *Server) generateAdminJwt(user *models.AdminUser) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": user.ID,
		"iss": "mtls-proxy-admin",
		"aud": "admin",
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	signingKey, err := s.getSigningKey()
	if err != nil {
		log.Printf("error retrieving signing key: %v\n", err)
		return "", err
	}

	signedStr, err := token.SignedString(signingKey)
	if err != nil {
		log.Printf("error signing token: %v\n", err)
		return "", err
	}

	return signedStr, nil
}

// Retrieve Signing Cert as RSA PublicKey
func (s *Server) getSigningCert() (*rsa.PublicKey, error) {
	val, err := os.ReadFile(s.config.JWTSigningCertFile)
	if err != nil {
		log.Println("failed to load signing cert from disk: ", err)
		return nil, err
	}

	block, _ := pem.Decode(val)
	if block == nil {
		log.Println("failed to parse PEM block for signing cert")
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("failed to parse x509 cert: %w", err)
		return nil, err
	}

	pubkey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type")
	}

	return pubkey, nil
}

// Retrieve Signing Key as RSA PrivateKey
func (s *Server) getSigningKey() (*rsa.PrivateKey, error) {
	val, err := os.ReadFile(s.config.JWTSigningKeyFile)
	if err != nil {
		log.Println("failed to load signing key from disk: ", err)
		return nil, err
	}

	block, _ := pem.Decode(val)
	if block == nil {
		log.Println("failed to parse PEM block")
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Create new admin user with specified username and password
func (s *Server) createAdmin(username string, password string) *models.AdminUser {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Failed to create admin user: ", err.Error())
		return nil
	}
	return &models.AdminUser{
		ID:           uuid.New(),
		UserName:     username,
		PasswordHash: string(passHash),
	}
}

// Look up admin by username
func (s *Server) getAdminByUsername(username string) *models.AdminUser {
	adminUsersMutex.RLock()
	for _, admin := range s.adminUsers {
		if admin.UserName == username {
			adminUsersMutex.RUnlock()
			return admin
		}
	}
	adminUsersMutex.RUnlock()
	return nil
}

// Look up admin by ID
func (s *Server) getAdminById(adminId uuid.UUID) *models.AdminUser {
	adminUsersMutex.RLock()
	admin, exists := s.adminUsers[adminId]
	if !exists {
		return nil
	}
	adminUsersMutex.RUnlock()
	return admin
}

// Helper function to get admin from context or respond with 401 error
func (s *Server) extractAdminFromContext(c *gin.Context) *models.AdminUser {
	a, exists := c.Get("admin")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user"})
		return nil
	}

	adminUser, ok := a.(*models.AdminUser)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user"})
		return nil
	}

	return adminUser
}
