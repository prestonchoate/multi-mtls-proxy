package genenv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func GenerateSelfSignedCerts(base string) error {
	certs := []string{"mtls.localhost", "admin.localhost"}
	certDir := filepath.Join(base, "certs")
	os.MkdirAll(certDir, 0755)

	for _, cn := range certs {
		certPath := filepath.Join(certDir, cn+".crt")
		keyPath := filepath.Join(certDir, cn+".key")

		priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		notBefore := time.Now()
		notAfter := notBefore.Add(365 * 24 * time.Hour)

		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

		template := x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{cn},
		}

		derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		certOut, _ := os.Create(certPath)
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()

		keyOut, _ := os.Create(keyPath)
		b, _ := x509.MarshalECPrivateKey(priv)
		pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		keyOut.Close()
	}

	return nil
}
