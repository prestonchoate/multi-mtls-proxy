package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prestonchoate/mtlsProxy/internal/ca"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"github.com/prestonchoate/mtlsProxy/internal/repository"
)

// Server represents the proxy server
type Server struct {
	config         *models.Config
	appConfigs     models.AppConfigs
	appRepo        repository.AppRepository
	certAuthority  *ca.CertificateAuthority
	natsClient     *nats.Conn
	appConfigMutex sync.RWMutex
}

// New creates a new proxy server
func New(cfg *models.Config, appRepo repository.AppRepository, certAuthority *ca.CertificateAuthority) *Server {
	if certAuthority == nil {
		log.Fatalf("Nil CA pointer in initialization of Proxy server")
	}

	nc, ncErr := nats.Connect(cfg.NatsURL)
	if ncErr != nil {
		log.Printf("Failed to connect to NATS at %s: %v\n", cfg.NatsURL, ncErr)
		return nil
	}
	log.Println("Connected to NATS at ", cfg.NatsURL)

	s := &Server{
		config:         cfg,
		certAuthority:  certAuthority,
		appRepo:        appRepo,
		natsClient:     nc,
		appConfigMutex: sync.RWMutex{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	s.appConfigs, err = s.appRepo.GetFullCollection(ctx)
	if err != nil {
		log.Fatalf("Failed to retrieve app config: %v", err)
	}

	return s
}

// Start starts the proxy server
func (s *Server) Start() {
	// Create a CA cert pool for client authentication
	caCertPool := x509.NewCertPool()

	caCert, err := s.certAuthority.GetCert(s.config.CACertName)

	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{},
	}

	// Create server
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", s.config.ProxyPort),
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(s.proxyHandler),
	}

	// Listen for NATS messages
	defer s.natsClient.Close()
	go s.subscribeToConfigChanges()

	// Start the server
	log.Printf("Starting proxy server on port %d", s.config.ProxyPort)
	cert, certErr := s.certAuthority.GetCert(s.config.ProxyServerCertName)
	key, keyErr := s.certAuthority.GetKey(s.config.ProxyServerKeyName)
	if keyErr != nil || certErr != nil {
		log.Fatalf("Problem getting cert or key for proxy server. Cert err: %v\tKey Err: %v", certErr, keyErr)
	}

	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		log.Fatalf("failed to load key pair: %v", err)
	}

	server.TLSConfig.Certificates = append(server.TLSConfig.Certificates, tlsCert)

	if err := server.ListenAndServeTLS("", ""); err != nil {
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

	s.appConfigMutex.RLock()
	// Find app config
	app, exists := s.appConfigs[clientAppID]
	s.appConfigMutex.RUnlock()

	if !exists {
		http.Error(w, "Unknown client", http.StatusUnauthorized)
		return
	}

	// Find matching target URL for the request path
	var targetURL string
	var matchedPathPrefix string

	for pathPrefix, target := range app.TargetURLs {
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

func (s *Server) subscribeToConfigChanges() {
	topic := s.config.NatsAppConfigTopic

	_, err := s.natsClient.Subscribe(topic, func(msg *nats.Msg) {
		log.Printf("Received NATS message: %s\n", string(msg.Data))

		var payload models.AppConfigEventData

		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Printf("Failed to unmarshal NATS message: %v\n", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		s.appConfigMutex.Lock()
		defer s.appConfigMutex.Unlock()

		switch payload.Operation {
		case "created", "updated", "rotated":
			newConfigs, err := s.appRepo.GetFullCollection(ctx)
			if err != nil {
				log.Printf("Failed to retrieve app configs: %v", err)
				return
			}
			s.appConfigs = newConfigs
			log.Println("Updated app configs")
			break

		case "deleted":
			delete(s.appConfigs, payload.AppId)
			log.Printf("Deleted app config for %s\n", payload.AppId)
			break

		default:
			log.Printf("Unknown operation '%s' for app %s\n", payload.Operation, payload.AppId)
		}
	})

	if err != nil {
		log.Fatalf("Failed to subscribe to topic %s: %v\n", topic, err)
	}

	log.Printf("Subscribed to NATS topic: %s\n", topic)
}
