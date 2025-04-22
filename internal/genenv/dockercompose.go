package genenv

import (
	"fmt"
	"os"
	"path/filepath"
)

func WriteDockerCompose(base string) error {
	outPath := filepath.Join(base, "docker-compose.yml")
	if _, err := os.Stat(outPath); err == nil {
		fmt.Printf("⏭️  Skipping existing file: %s\n", outPath)
		return nil
	}

	content := `
services:
  traefik:
    image: traefik:v2.11
    command:
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--log.level=DEBUG"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik.yml:/etc/traefik/traefik.yml:ro"
      - "./certs:/certs:ro"
    restart: unless-stopped

  mtls-proxy:
    build:
      context: ..
      dockerfile: ./proxy.Dockerfile
    labels:
      - "traefik.enable=true"
      - "traefik.tcp.routers.mtlsproxy.rule=HostSNI(` + "`mtls.localhost`" + `)"
      - "traefik.tcp.routers.mtlsproxy.entrypoints=websecure"
      - "traefik.tcp.routers.mtlsproxy.service=mtlsproxy-svc"
      - "traefik.tcp.routers.mtlsproxy.tls.passthrough=true"
      - "traefik.tcp.services.mtlsproxy-svc.loadbalancer.server.port=8443"
    environment:
      - MONGO_URI=mongodb://mongo:27017
      - MONGO_DB=mtlsAdmin
      - HOSTNAME=mtls.localhost
    restart: unless-stopped

  admin-api:
    build:
      context: ..
      dockerfile: ./admin.Dockerfile
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.adminapi.rule=Host(` + "`admin.localhost`" + `)"
      - "traefik.http.routers.adminapi.entrypoints=websecure"
      - "traefik.http.routers.adminapi.tls=true"
    environment:
      - MONGO_URI=mongodb://mongo:27017
      - MONGO_DB=mtlsAdmin
      - HOSTNAME=admin.localhost
    restart: unless-stopped

  mongo:
    image: mongo:latest
    container_name: mongo
    volumes:
      - mongo-data:/data/db
    restart: unless-stopped

volumes:
  mongo-data:
`

	return os.WriteFile(outPath, []byte(content), 0644)
}
