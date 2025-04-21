# Multi-Tenant mTLS Proxy

## Overview
A scalable, secure multi-tenant mTLS proxy written in Go that manages mutual TLS authentication for multiple backend services.

## Features
- Mutual TLS (mTLS) authentication between clients and proxy
- Multi-tenancy support with tenant isolation
- Dynamic certificate management and rotation
- High performance with minimal overhead
- Detailed access logging and metrics

## Table of Contents
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

## Prerequisites
- Go 1.20 or higher

## Installation

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

## Configuration

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


## Usage

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


## Architecture
![mTLS system architecture diagram](./docs/mTLS%20Proxy%20System%20Diagram.png)

See [Roadmap](./docs/roadmap.md) for future considerations

The multi-tenant mTLS proxy consists of the following components:

1. **TLS Termination Layer**: Handles incoming mTLS connections and certificate validation
2. **Tenant Router**: Routes requests to the appropriate backend based on tenant configuration
3. **Certificate Manager**: Handles certificate storage, retrieval, and rotation
4. **Backend Connector**: Establishes secure connections to backend services
5. **Metrics and Monitoring**: Collects and exposes operational metrics

## API Reference
See [API Reference Guide](./docs/mtls-proxy-api-reference.md) or the [OpenAPI spec](./docs/openapi.yaml)


## Performance
[TODO: Include performance metrics, benchmarks, or considerations]

## Security Considerations
- Certificate rotation practices
- Tenant isolation mechanisms
- Authentication and authorization

## Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Submit a pull request

## License
See [LICENSE](./LICENSE)
