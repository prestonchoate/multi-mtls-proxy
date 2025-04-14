package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prestonchoate/mtlsProxy/internal/config"
	"github.com/prestonchoate/mtlsProxy/internal/models"
)

// CertificateAuthority represents a CA for certificate operations
type CertificateAuthority struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
	mutex       sync.Mutex
}

// New creates a new certificate authority
func New() *CertificateAuthority {
	return &CertificateAuthority{
		mutex: sync.Mutex{},
	}
}

// Initialize initializes or loads the Certificate Authority
func (ca *CertificateAuthority) Initialize(cfg *models.Config) error {
	ca.mutex.Lock()
	defer ca.mutex.Unlock()

	// Check if CA files exist
	_, keyErr := os.Stat(cfg.CAKeyFile)
	_, certErr := os.Stat(cfg.CACertFile)

	if os.IsNotExist(keyErr) || os.IsNotExist(certErr) {
		log.Println("CA files not found, creating new CA")
		return ca.create(cfg)
	}

	// Load existing CA
	keyBytes, err := os.ReadFile(cfg.CAKeyFile)
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

	certBytes, err := os.ReadFile(cfg.CACertFile)
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
func (ca *CertificateAuthority) create(cfg *models.Config) error {
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

	config.IOMutex.Lock()
	if err := os.MkdirAll(filepath.Dir(cfg.CAKeyFile), 0755); err != nil {
		config.IOMutex.Unlock()
		return fmt.Errorf("failed to create CA key directory: %w", err)
	}
	if err := os.WriteFile(cfg.CAKeyFile, keyPEM, 0600); err != nil {
		config.IOMutex.Unlock()
		return fmt.Errorf("failed to write CA key file: %w", err)
	}
	config.IOMutex.Unlock()

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	config.IOMutex.Lock()
	if err := os.WriteFile(cfg.CACertFile, certPEM, 0644); err != nil {
		config.IOMutex.Unlock()
		return fmt.Errorf("failed to write CA cert file: %w", err)
	}
	config.IOMutex.Unlock()

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

// GenerateClientCertificate generates a client certificate for an app
func (ca *CertificateAuthority) GenerateClientCertificate(appID string, cfg *models.Config) (models.ClientCertInfo, error) {
	// Lock for certificate generation
	certMutex := sync.Mutex{}
	certMutex.Lock()
	defer certMutex.Unlock()

	// Use CA to sign
	ca.mutex.Lock()
	caCert := ca.Certificate
	caKey := ca.PrivateKey
	ca.mutex.Unlock()

	// Create private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	expiresAt := time.Now().AddDate(0, 0, cfg.CertValidityDays)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy Clients"},
			CommonName:   appID,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute), // Allow for clock skew
		NotAfter:              expiresAt,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate with our CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Compute certificate fingerprint
	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to parse generated certificate: %w", err)
	}
	fingerprint := fmt.Sprintf("%x", parsedCert.SerialNumber)

	// Save private key to file
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	keyFile := filepath.Join(cfg.CertDir, fmt.Sprintf("%s.key", appID))

	config.IOMutex.Lock()
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		config.IOMutex.Unlock()
		return models.ClientCertInfo{}, fmt.Errorf("failed to write client key file: %w", err)
	}
	config.IOMutex.Unlock()

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certFile := filepath.Join(cfg.CertDir, fmt.Sprintf("%s.crt", appID))

	config.IOMutex.Lock()
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		config.IOMutex.Unlock()
		return models.ClientCertInfo{}, fmt.Errorf("failed to write client cert file: %w", err)
	}
	config.IOMutex.Unlock()

	return models.ClientCertInfo{
		CertFile:    certFile,
		KeyFile:     keyFile,
		Fingerprint: fingerprint,
		ExpiresAt:   expiresAt,
	}, nil
}

// CreateProxyCert creates the proxy server certificate
func (ca *CertificateAuthority) CreateProxyCert(cfg *models.Config) error {
	ca.mutex.Lock()
	defer ca.mutex.Unlock()

	// Generate server private key
	serverKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Create server certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy"},
			CommonName:   cfg.HostName,
		},
		DNSNames:              []string{cfg.HostName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-sign the certificate with our CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverCertTemplate, ca.Certificate, &serverKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Save the server certificate to file
	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	config.IOMutex.Lock()
	defer config.IOMutex.Unlock()

	if err := os.WriteFile(cfg.ProxyServerCertFile, serverCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write server certificate file: %w", err)
	}

	// Save the server key to file
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	if err := os.WriteFile(cfg.ProxyServerKeyFile, serverKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write server key file: %w", err)
	}

	return nil
}

// CheckProxyCert checks if the proxy certificate exists, and creates it if it doesn't
func (ca *CertificateAuthority) CheckProxyCert(cfg *models.Config) error {
	_, err1 := os.Stat(cfg.ProxyServerCertFile)
	_, err2 := os.Stat(cfg.ProxyServerKeyFile)

	if os.IsNotExist(err1) || os.IsNotExist(err2) {
		return ca.CreateProxyCert(cfg)
	}

	return nil
}
