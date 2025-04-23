# Multi-Tenant mTLS Proxy

## :memo: Overview
A scalable, secure multi-tenant mTLS proxy written in Go that manages mutual TLS authentication for multiple backend services.

## :sparkles: Features
- Mutual TLS (mTLS) authentication between clients and proxy
- Multi-tenancy support with tenant isolation
- Dynamic certificate management and rotation
- High performance with minimal overhead
- Detailed access logging and metrics

## :bookmark_tabs: Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Performance](#performance)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## :clipboard: Prerequisites
- Go 1.24 or higher

## :hammer_and_wrench: Installation

### From Source

#### Admin Binary

```bash
git clone https://github.com/prestonchoate/multi-mtls-proxy.git
cd multi-mtls-proxy
go build -o mtls-admin ./cmd/admin/
```

#### Proxy Binary

```bash
git clone https://github.com/prestonchoate/multi-mtls-proxy.git
cd multi-mtls-proxy
go build -o mtls-proxy ./cmd/proxy/
```

### Using Docker
No official Docker image yet

## :computer: Development Environment
A generator is included to help you quickly set up a local development environment with all required services and self-signed certificates.

#### Generate the Environment
```bash
go run ./cmd/dev-env-generator
```
This will create a dev-env/ directory containing:

- `docker-compose.yml` — Compose file for Traefik, mTLS proxy, admin API, and MongoDB
- `traefik.yml` — Traefik configuration referencing generated certs
- `certs/mtls.localhost.crt` and `.key` — Self-signed cert for mTLS proxy
- `certs/admin.localhost.crt` and `.key` — Self-signed cert for admin API
> Note: Existing files are not overwritten.

#### Start the Stack
```bash
cd dev-env
docker compose up --build
```

#### Accessing Services
- mTLS Proxy:
  - Host: https://mtls.localhost (mTLS required)
- Admin API:
  - Host: https://admin.localhost

Add these to your /etc/hosts if needed:

```text
127.0.0.1 mtls.localhost admin.localhost
```
#### Stopping
```bash
docker compose down
```

## :gear: Configuration

### Environment Variables
Both the admin API and proxy can be configured using environment variables:

- `ADMIN_API_PORT`: Admin Server Port (default: `8080`)
- `PROXY_PORT`: Server port (default: `8443`)
- `CA_KEY_NAME`: Path to Root CA key file (default: `ca/ca.key`)
- `CA_CERT_NAME`: Path to Root CA Cert file (default: `ca/ca.crt`)
- `PROXY_SERVER_CERT_NAME`: Path to server certificate (default: `proxy/server.crt`)
- `PROXY_SERVER_KEY_NAME`: Path to server private key (default: `proxy/server.key`)
- `CERT_VALIDITY_DAYS`: Number of days to issue client certificates for (default: `365`)
- `HOSTNAME`: Hostname for the server (default: `localhost`)
- `DEFAULT_ADMIN_USER`: Default admin username (default: `admin`)
- `DEFAULT_ADMIN_PASSWORD`: Default admin password (default: `password`)
- `JWT_SIGNING_KEY_NAME`: Path to admin JWT signing key (default: `admin/signing.key`)
- `JWT_SIGNING_CERT_NAME`: Path to admin JWT signing cert (default: `admin/signing.crt`)
- `MONGO_URI`: MongoDB connection string (default: `mongodb://localhost:27017`)
- `MONGO_DB`: MongoDB database name (default: `mtlsAdmin`)
- `MONGO_APPS_COLL`: MongoDB collection for apps (default: `apps`)
- `MONGO_USERS_COLL`: MongoDB collection for users (default: `users`)
- `MONGO_CERT_COLL`: MongoDB collection for certificates (default: `certs`)
- `ENCRYPTION_KEY`: 32-byte Base64 encoded encryption key for sensitive data (default: `rTdRG79RqfXnHVIrPui3d4qW7qaF/uVQj5VnkWb96KQ=`)

The repository provides a `.env.dist` with these default values. It is not required to copy this into a `.env` file, but if you choose to change any configs you may do so with that method. 

**WARNING**: The default credentials are not secure. Always change `DEFAULT_ADMIN_USER` and `DEFAULT_ADMIN_PASSWORD` in production deployments!
**WARNING**: The default encryption key is not secure. Always change `ENCRYPTION_KEY` in production deployments to prevent unauthorized access to sensitive data!


## :wrench: Usage

### Starting the Proxy

#### Admin Server

```bash
./mtls-admin
```

#### Proxy Server

```bash
./mtls-proxy
```

**WARNING**: The proxy server will not hot reload app configs if they change from the admin while both binaries are running. This is due to the app config living in a file on the local filesystem. Simply restart the proxy server binary to pick up the latest changes. This will change in a future release

### Client Connection Example
```bash
curl --cert client.crt --key client.key --cacert ca.crt https://proxy.example.com:8443/api/endpoint
```

### Tenant Management

#### Create new client app
  1. Send POST request to `/admin/apps` with the following payload structure
  ```json
{
  "appId": "test-app",
  "targetUrls": {
    "/get": "https://postman-echo.com/get",
    "/post": "https://postman-echo.com/post"
   }
}
  ```

  2. Distribute client cert and key to end user. This will live in the `CERT_DIR` directory and be named the client `appId` (`test-app.crt` and `test-app.key` for this example)

#### Rotate Client Cert/Key Pair
  - Send a `POST` request to `/admin/apps/:appId/rotate-cert` and re-distribute the new cert/key pair

#### Update Client Target URLs
  - Send a `PUT` request to `/admin/apps/:appId/targets` with the following payload structure
  ```json
  {
    "targetUrls": {
      "/newProxyUrl": "https://exmple.com/newProxyUrl"
    }
  }
  ```


## :classical_building: Architecture
![mTLS system architecture diagram](./docs/mTLS%20Proxy%20System%20Diagram.png)

See [Roadmap](./docs/roadmap.md) for future considerations

The multi-tenant mTLS proxy consists of the following components:

1. **TLS Termination Layer**: Handles incoming mTLS connections and certificate validation
2. **Tenant Router**: Routes requests to the appropriate backend based on tenant configuration
3. **Certificate Manager**: Handles certificate storage, retrieval, and rotation
4. **Backend Connector**: Establishes secure connections to backend services
5. **Metrics and Monitoring**: Collects and exposes operational metrics

## :book: API Reference
See [API Reference Guide](./docs/mtls-proxy-api-reference.md) or the [OpenAPI spec](./docs/openapi.yaml)


## :chart_with_upwards_trend: Performance
[TODO: Include performance metrics, benchmarks, or considerations]

## :shield: Security Considerations
- Certificate rotation practices
- Tenant isolation mechanisms
- Authentication and authorization

## :handshake: Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Submit a pull request

## :page_facing_up: License
See [LICENSE](./LICENSE)
