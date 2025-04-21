package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"github.com/prestonchoate/mtlsProxy/internal/repository"
)

// CertificateAuthority represents a CA for certificate operations
type CertificateAuthority struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
	certRepo    repository.CertificateRepository
}

// New creates a new certificate authority
func New() *CertificateAuthority {
	return &CertificateAuthority{}
}

// Initialize initializes or loads the Certificate Authority
func (ca *CertificateAuthority) Initialize(cfg *models.Config, client *db.MongoClient) error {
	if client == nil {
		return fmt.Errorf("bad db client")
	}

	encKey, err := cfg.GetEncryptionKey()
	if err != nil {
		return err
	}

	ca.certRepo = repository.NewMongoCertificateRepository(client, cfg.MongoCertColl, string(encKey))

	// Check if CA files exist
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	certData, certErr := ca.certRepo.GetCert(ctx, cfg.CACertName)
	key, keyErr := ca.certRepo.GetKey(ctx, cfg.CAKeyName)

	if certErr != nil || keyErr != nil {
		log.Println("CA files not found, creating new CA")
		return ca.create(cfg)
	}

	// Load existing CA
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	certBlock, _ := pem.Decode(certData)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveKey(ctx, cfg.CAKeyName, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to save CA Key: %w", err)
	}

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveCert(ctx, cfg.CACertName, certPEM)
	if err != nil {
		return fmt.Errorf("failed to save CA Key: %w", err)
	}

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
	// Verify appID doesn't contain path separators or other bad things that could cause path traversal shenanigans
	if strings.Contains(appID, "/") || strings.Contains(appID, "\\") || strings.Contains(appID, "..") {
		return models.ClientCertInfo{}, fmt.Errorf("bad app ID. cannot generate cert")
	}

	// Use CA to sign
	caCert := ca.Certificate
	caKey := ca.PrivateKey

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
	keyName := fmt.Sprintf("%s.key", appID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveKey(ctx, keyName, keyPEM)
	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to write client key: %w", err)
	}

	// Save certificate to file
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certName := fmt.Sprintf("%s.crt", appID)

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveCert(ctx, certName, certPEM)

	if err != nil {
		return models.ClientCertInfo{}, fmt.Errorf("failed to write client cert: %w", err)
	}

	return models.ClientCertInfo{
		CertFile:    certName,
		KeyFile:     keyName,
		Fingerprint: fingerprint,
		ExpiresAt:   expiresAt,
	}, nil
}

// CreateProxyCert creates the proxy server certificate
func (ca *CertificateAuthority) CreateProxyCert(cfg *models.Config) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveCert(ctx, cfg.ProxyServerCertName, serverCertPEM)

	if err != nil {
		return fmt.Errorf("failed to write server certificate file: %w", err)
	}

	// Save the server key to file
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverKey),
	})

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveKey(ctx, cfg.ProxyServerKeyName, serverKeyPEM)

	if err != nil {
		return fmt.Errorf("failed to write server key file: %w", err)
	}

	return nil
}

// CheckProxyCert checks if the proxy certificate exists, and creates it if it doesn't
func (ca *CertificateAuthority) CheckProxyCert(cfg *models.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	_, err1 := ca.certRepo.GetCert(ctx, cfg.ProxyServerCertName)
	_, err2 := ca.certRepo.GetKey(ctx, cfg.ProxyServerKeyName)

	if err1 != nil || err2 != nil {
		return ca.CreateProxyCert(cfg)
	}

	return nil
}

func (ca *CertificateAuthority) CreateAdminSigningCert(cfg *models.Config) error {
	// Generate signing private key
	signingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	// Create signing certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	signingCertTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mTLS Proxy"},
			CommonName:   cfg.HostName,
		},
		DNSNames:              []string{cfg.HostName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(cfg.CertValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign certificate with CA
	signingCertDER, err := x509.CreateCertificate(rand.Reader, signingCertTemplate, ca.Certificate, &signingKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create signing certificate: %w", err)
	}

	// Save the signing certificate to file
	signingCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signingCertDER,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveCert(ctx, cfg.JWTSigningCertName, signingCertPEM)

	if err != nil {
		return fmt.Errorf("failed to write signing certificate: %w", err)
	}

	// Save the signing key to file
	signingKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(signingKey),
	})

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = ca.certRepo.SaveKey(ctx, cfg.JWTSigningKeyName, signingKeyPEM)

	if err != nil {
		return fmt.Errorf("failed to write signing key: %w", err)
	}

	return nil
}

func (ca *CertificateAuthority) CheckAdminSigningCert(cfg *models.Config) error {
	log.Println("Checking admin signing cert/key bundle")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err1 := ca.certRepo.GetCert(ctx, cfg.JWTSigningCertName)
	_, err2 := ca.certRepo.GetKey(ctx, cfg.JWTSigningKeyName)

	if err1 != nil || err2 != nil {
		return ca.CreateAdminSigningCert(cfg)
	}
	return nil
}

func (ca *CertificateAuthority) GetKey(name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return ca.certRepo.GetKey(ctx, name)
}

func (ca *CertificateAuthority) GetCert(name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return ca.certRepo.GetCert(ctx, name)
}

func (ca *CertificateAuthority) RemoveCert(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return ca.certRepo.DeleteCert(ctx, name)
}

func (ca *CertificateAuthority) RemoveKey(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return ca.certRepo.DeleteKey(ctx, name)
}
