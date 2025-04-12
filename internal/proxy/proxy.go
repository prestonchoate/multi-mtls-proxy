package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
)

// Server represents the proxy server
type Server struct {
	config     *models.Config
	appConfigs models.AppConfigs
}

// New creates a new proxy server
func New(cfg *models.Config, appCfgs models.AppConfigs) *Server {
	return &Server{
		config:     cfg,
		appConfigs: appCfgs,
	}
}

// Start starts the proxy server
func (s *Server) Start() {
	// Create a CA cert pool for client authentication
	caCertPool := x509.NewCertPool()

	config.IOMutex.Lock()
	caCert, err := os.ReadFile(s.config.CACertFile)
	config.IOMutex.Unlock()

	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	// Create server
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.config.ProxyPort),
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(s.proxyHandler),
	}

	// Start the server
	log.Printf("Starting proxy server on port %d", s.config.ProxyPort)
	if err := server.ListenAndServeTLS(s.config.ProxyServerCertFile, s.config.ProxyServerKeyFile); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}

// Handler for proxy requests
func (s *Server) proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Get client certificate
	if len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "Client certificate required", http.StatusUnauthorized)
		return
	}
	clientCert := r.TLS.PeerCertificates[0]
	clientAppID := clientCert.Subject.CommonName

	// Find app config
	config.ConfigMutex.RLock()
	app, exists := s.appConfigs[clientAppID]
	config.ConfigMutex.RUnlock()

	if !exists {
		http.Error(w, "Unknown client", http.StatusUnauthorized)
		return
	}

	// Find matching target URL for the request path
	var targetURL string
	var matchedPathPrefix string

	for pathPrefix, target := range app.TargetURLs {
		log.Printf("checking path: %v - %v\tagainst %v\n", pathPrefix, target, r.URL.Path)
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
