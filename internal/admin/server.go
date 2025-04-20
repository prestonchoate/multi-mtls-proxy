package admin

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"github.com/prestonchoate/mtlsProxy/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// Server represents the admin API server
type Server struct {
	config         *models.Config
	appRepository  repository.AppRepository
	userRepository repository.UserRepository
	mongoClient    *db.MongoClient
	ca             *ca.CertificateAuthority
}

// New creates a new admin server
func New(cfg *models.Config, certAuth *ca.CertificateAuthority) (*Server, error) {
	mongoClient, err := db.NewMongoClient(cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	appRepo := repository.NewMongoAppRepository(mongoClient, cfg.MongoAppsColl)
	userRepo := repository.NewMongoUserRepository(mongoClient, cfg.MongoUsersColl)

	db.EnsureIndexes(mongoClient, cfg)

	return &Server{
		config:         cfg,
		ca:             certAuth,
		appRepository:  appRepo,
		userRepository: userRepo,
	}, nil
}

// Start starts the admin API server
func (s *Server) Start() {
	existingAdmin, _ := s.userRepository.GetByUsername(context.Background(), s.config.DefaultAdminUser)
	if existingAdmin == nil {
		log.Println("Creating default admin user")
		admin := s.createAdmin(s.config.DefaultAdminUser, s.config.DefaultAdminPassword)
		if admin != nil {
			err := s.userRepository.Create(context.Background(), *admin)
			if err != nil {
				log.Printf("Failed to create default admin: %v\n", err)
			}
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

		// Download cert bundle for app
		admin.GET("/apps/:appId/download-cert", s.downloadAppCertBundle)

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
	ctx := c.Request.Context()
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
	existingApp, err := s.appRepository.GetByID(ctx, appRequest.AppID)
	if err == nil && existingApp != nil {
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
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.appRepository.Create(ctx, newApp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save app config: %v", err)})
		return
	}

	// Return client certificate information
	c.JSON(http.StatusCreated, gin.H{
		"appId": newApp.AppID,
		"certs": gin.H{
			"certFile":    clientCertInfo.CertFile,
			"keyFile":     clientCertInfo.KeyFile,
			"fingerprint": clientCertInfo.Fingerprint,
			"expiresAt":   clientCertInfo.ExpiresAt,
		},
		"targetUrls": newApp.TargetURLs,
	})
}

// Get all apps filtered by logged in user ID
func (s *Server) getAllApps(c *gin.Context) {
	ctx := c.Request.Context()
	adminUser := s.extractAdminFromContext(c)

	apps, err := s.appRepository.GetAll(ctx, adminUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve app configs: %v", err))
		return
	}

	c.JSON(http.StatusOK, apps)
}

// Get a specific app
func (s *Server) getApp(c *gin.Context) {
	ctx := c.Request.Context()
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	app, err := s.appRepository.GetByID(ctx, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve app config: %v", err))
		return
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(http.StatusOK, app)
}

// Update app target URLs
func (s *Server) updateAppTargets(c *gin.Context) {
	ctx := c.Request.Context()
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

	app, err := s.appRepository.GetByID(ctx, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, fmt.Sprintf("Failed to retrieve app config: %v", err))
		return
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	app.TargetURLs = targetRequest.TargetURLs
	app.UpdatedAt = time.Now()

	err = s.appRepository.Update(ctx, *app)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to save updated app config: %v", err)})
		return
	}

	c.JSON(http.StatusOK, app)
}

// Rotate client certificate
func (s *Server) rotateAppCert(c *gin.Context) {
	ctx := c.Request.Context()
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	app, err := s.appRepository.GetByID(ctx, appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Failed to retrieve app config: %v", err)})
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
	app.ClientCerts = clientCertInfo
	app.UpdatedAt = time.Now()

	err = s.appRepository.Update(ctx, *app)
	if err != nil {
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
	ctx := c.Request.Context()
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	app, err := s.appRepository.GetByID(ctx, appID)
	if err != nil {
		c.JSON(http.StatusNotFound, "App not found")
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Remove from configs
	err = s.appRepository.Delete(ctx, appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete app config: %v", err)})
		return
	}

	// Delete cert files
	err1 := s.ca.RemoveCert(app.ClientCerts.CertFile)
	err2 := s.ca.RemoveKey(app.ClientCerts.KeyFile)

	if err1 != nil || err2 != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "App deleted successfully"})
}

// Get CA certificate
func (s *Server) getCACert(c *gin.Context) {
	certBytes, err := s.ca.GetCert(s.config.CACertFile)

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

	ctx := c.Request.Context()

	if err := c.BindJSON(&adminCreateRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	if adminCreateRequest.UserName == "" || adminCreateRequest.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	existingAdmin, _ := s.userRepository.GetByUsername(ctx, adminCreateRequest.UserName)

	if existingAdmin != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	user := s.createAdmin(adminCreateRequest.UserName, adminCreateRequest.Password)
	if user == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	err := s.userRepository.Create(ctx, *user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
		return
	}

	c.JSONP(http.StatusCreated, user)
}

// Handle admin login request
func (s *Server) adminLogin(c *gin.Context) {
	var adminLoginRequest struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}

	ctx := c.Request.Context()

	if err := c.BindJSON(&adminLoginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Request"})
		return
	}

	if adminLoginRequest.UserName == "" || adminLoginRequest.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and Password are required"})
		return
	}

	existingAdmin, err := s.userRepository.GetByUsername(ctx, adminLoginRequest.UserName)
	if err != nil || existingAdmin == nil {
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

	existingAdmin.LastLogin = time.Now()
	err = s.userRepository.Update(ctx, *existingAdmin)
	if err != nil {
		log.Println("Failed to update last login time for admin: ", existingAdmin.ID, " Error was: ", err)
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
	val, err := s.ca.GetCert(s.config.JWTSigningCertFile)
	if err != nil {
		log.Println("failed to retrieve signing cert: ", err)
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
	val, err := s.ca.GetKey(s.config.JWTSigningKeyFile)
	if err != nil {
		log.Println("failed to retrieve signing key: ", err)
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

// handle serving cert/key bundle as zip
func (s *Server) downloadAppCertBundle(c *gin.Context) {
	ctx := c.Request.Context()
	adminUser := s.extractAdminFromContext(c)
	appID := c.Param("appId")

	app, err := s.appRepository.GetByID(ctx, appID)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "App not found"})
	}

	if app.Owner != adminUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	files := map[models.CertDataType]string{
		models.Cert: app.ClientCerts.CertFile,
		models.Key:  app.ClientCerts.KeyFile,
	}

	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for fileType, file := range files {
		err := s.addFileToZip(zipWriter, file, fileType)
		if err != nil {
			zipWriter.Close()
			log.Printf("something went wrong adding file to zip: %s\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
			return
		}
	}
	if err := zipWriter.Close(); err != nil {
		log.Printf("error closing zip writer: %s\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to finalize zip archive"})
		return
	}

	c.Header("Content-Type", "application/zip")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s_cert_bundle.zip"`, appID))
	c.Data(http.StatusOK, "application/zip", buf.Bytes())
}

// Helper function to add files to zip
func (s *Server) addFileToZip(zipWriter *zip.Writer, filePath string, fileType models.CertDataType) error {
	var file []byte
	var err error
	if fileType == models.Cert {
		file, err = s.ca.GetCert(filePath)
	} else {
		file, err = s.ca.GetKey(filePath)
	}

	if err != nil {
		return err
	}

	name := path.Base(filePath)
	header := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = writer.Write(file)
	return err
}
