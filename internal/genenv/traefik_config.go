package genenv

import (
	"fmt"
	"os"
	"path/filepath"
)

func WriteTraefikConfig(base string) error {
	outPath := filepath.Join(base, "traefik.yml")
	if _, err := os.Stat(outPath); err == nil {
		fmt.Printf("⏭️  Skipping existing file: %s\n", outPath)
		return nil
	}

	content := `entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false

log:
  level: DEBUG

# Add TLS Config
tls:
 certificates:
    - certFile: "/certs/mtls.localhost.crt"
      keyFile: "/certs/mtls.localhost.key"
`

	return os.WriteFile(outPath, []byte(content), 0644)
}
