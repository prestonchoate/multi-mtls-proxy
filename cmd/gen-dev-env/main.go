package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/prestonchoate/mtlsProxy/internal/genenv"
)

func main() {
	baseDir := filepath.Join(".", "dev-env")

	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		log.Fatalf("failed to create base directory: %v", err)
	}

	if err := genenv.WriteDockerCompose(baseDir); err != nil {
		log.Fatal(err)
	}

	if err := genenv.WriteTraefikConfig(baseDir); err != nil {
		log.Fatal(err)
	}

	if err := genenv.GenerateSelfSignedCerts(baseDir); err != nil {
		log.Fatal(err)
	}

	fmt.Println("✅ Local dev environment generated in ./dev-env")
}
