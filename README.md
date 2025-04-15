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
```bash
git clone https://github.com/prestonchoate/multi-mtls-proxy.git
cd multi-mtls-proxy
go build -o mtls-proxy ./cmd/mtlsproxy/
```

### Using Docker
No official Docker image yet

## Configuration

### Basic Configuration File
Upon startup the server will check for the existence of the following directories

- `./ca/`
- `./certs/`
- `./config/`

If they do not exist they will be created. Required CA cert and key will be created as well as the server's TLS Cert and Key. The Root CA will exist in the `./ca/` directory. The server's TLS cert and key will be at `./certs/server.crt` and `./certs/server.key` respectively.


### Environment Variables
The proxy can also be configured using environment variables:

- `ADMIN_API_PORT`: Admin Server Port (default: `8080`)
- `PROXY_PORT`: Server port (default: `8443`)
- `CERT_DIR`: Directory to store certificate files and keys (default: `./certs/`)
- `CA_KEY_FILE`: Path to Root CA key file (default: `./ca/ca.key`)
- `CA_CERT_FILE`: Path to Root CA Cert file (default: `./ca/ca.crt`)
- `PROXY_SERVER_CERT_FILE`: Path to server certificate (default: `./certs/server.crt`)
- `PROXY_SERVER_KEY_FILE`: Path to server private key (default: `./certs/server.key`)
- `CONFIG_FILE`: Path to app conifg file (default: `./config/apps.json`)
- `CERT_VALIDITY_DAYS`: Number to days to issue client certificates for (default: `365`)
- `HOSTNAME`: Hostname for the server (default: `localhost`)

The repository provides a `.env.dist` with these default values. It is not required to copy this into a `.env` file, but if you choose to change any configs you may do so with that method. 

## Usage

### Starting the Proxy
```bash
./mtls-proxy
```

### Client Connection Example
```bash
curl --cert client.crt --key client.key --cacert ca.crt https://proxy.example.com:8443/api/endpoint
```

### Tenant Management
<div class="alert">
  <strong>WARNING!:</strong> NO ADMIN AUTHENTICATION CURRENTLY IMPLEMENTED
</div>

### Create new client app
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

### Rotate Client Cert/Key Pair
  - Send a `POST` request to `/admin/apps/:appId/rotate-cert` and re-distribute the new cert/key pair

### Update Client Target URLs
  - Send a `PUT` request to `/admin/apps/:appId/targets` with the following payload structure
  ```json
  {
    "targetUrls": {
      "/newProxyUrl": "https://exmple.com/newProxyUrl"
    }
  }
  ```


## Architecture
[TODO: Diagram or description of the architecture]

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
