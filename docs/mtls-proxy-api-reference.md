# mTLS Proxy API Reference

## Overview

The mTLS Proxy is a service that provides mutual TLS authentication for applications. It acts as a reverse proxy, authenticating clients using client certificates and forwarding requests to configured target URLs. This document describes the administrative API endpoints that can be used to manage applications and certificates.

## Base URL

All API endpoints are relative to the base URL:

```
https://localhost:{AdminAPIPort}/admin
```

Where `AdminAPIPort` is configured in the application settings (default: 8080).

## Authentication

The admin API does not require authentication in the current implementation.

## Endpoints

### Create a New App

Creates a new application configuration with client certificates.

**Endpoint:** `POST /admin/apps`

**Request Body:**

```json
{
  "appId": "string",
  "targetUrls": {
    "path_prefix1": "target_url1",
    "path_prefix2": "target_url2"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| appId | string | Unique identifier for the application |
| targetUrls | object | Map of path prefixes to target URLs |

**Response:** `201 Created`

```json
{
  "appId": "string",
  "certs": {
    "certFile": "string",
    "keyFile": "string",
    "fingerprint": "string",
    "expiresAt": "string"
  },
  "targetUrls": {
    "path_prefix1": "target_url1",
    "path_prefix2": "target_url2"
  }
}
```

**Error Responses:**

- `400 Bad Request`: Invalid request body or missing required fields
- `409 Conflict`: App ID already exists
- `500 Internal Server Error`: Failed to generate client certificate or save configuration

### Get All Apps

Retrieves all configured applications.

**Endpoint:** `GET /admin/apps`

**Response:** `200 OK`

```json
{
  "app1": {
    "appId": "app1",
    "targetUrls": {
      "path_prefix1": "target_url1"
    },
    "clientCerts": {
      "certFile": "string",
      "keyFile": "string",
      "fingerprint": "string",
      "expiresAt": "string"
    },
    "created": "string",
    "updated": "string"
  },
  "app2": {
    "appId": "app2",
    "targetUrls": {
      "path_prefix1": "target_url1"
    },
    "clientCerts": {
      "certFile": "string",
      "keyFile": "string",
      "fingerprint": "string",
      "expiresAt": "string"
    },
    "created": "string",
    "updated": "string"
  }
}
```

### Get an App

Retrieves a specific application configuration.

**Endpoint:** `GET /admin/apps/:appId`

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| appId | path | ID of the application to retrieve |

**Response:** `200 OK`

```json
{
  "appId": "string",
  "targetUrls": {
    "path_prefix1": "target_url1",
    "path_prefix2": "target_url2"
  },
  "clientCerts": {
    "certFile": "string",
    "keyFile": "string",
    "fingerprint": "string",
    "expiresAt": "string"
  },
  "created": "string",
  "updated": "string"
}
```

**Error Responses:**

- `404 Not Found`: App not found

### Update App Targets

Updates the target URLs for an application.

**Endpoint:** `PUT /admin/apps/:appId/targets`

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| appId | path | ID of the application to update |

**Request Body:**

```json
{
  "targetUrls": {
    "path_prefix1": "new_target_url1",
    "path_prefix2": "new_target_url2"
  }
}
```

**Response:** `200 OK`

```json
{
  "appId": "string",
  "targetUrls": {
    "path_prefix1": "new_target_url1",
    "path_prefix2": "new_target_url2"
  },
  "clientCerts": {
    "certFile": "string",
    "keyFile": "string",
    "fingerprint": "string",
    "expiresAt": "string"
  },
  "created": "string",
  "updated": "string"
}
```

**Error Responses:**

- `400 Bad Request`: Invalid request body or missing required fields
- `404 Not Found`: App not found
- `500 Internal Server Error`: Failed to save configuration

### Rotate Client Certificate

Generates a new client certificate for an application.

**Endpoint:** `POST /admin/apps/:appId/rotate-cert`

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| appId | path | ID of the application to rotate certificate for |

**Response:** `200 OK`

```json
{
  "appId": "string",
  "certs": {
    "certFile": "string",
    "keyFile": "string",
    "fingerprint": "string",
    "expiresAt": "string"
  }
}
```

**Error Responses:**

- `404 Not Found`: App not found
- `500 Internal Server Error`: Failed to generate client certificate or save configuration

### Delete an App

Deletes an application configuration and its associated certificates.

**Endpoint:** `DELETE /admin/apps/:appId`

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| appId | path | ID of the application to delete |

**Response:** `200 OK`

```json
{
  "message": "App deleted successfully"
}
```

**Error Responses:**

- `404 Not Found`: App not found
- `500 Internal Server Error`: Failed to save configuration

### Get CA Certificate

Downloads the Certificate Authority certificate. This certificate should be trusted by clients connecting to the proxy.

**Endpoint:** `GET /admin/ca-cert`

**Response:** `200 OK`

The response body contains the CA certificate in PEM format with content type `application/x-pem-file`.

**Error Responses:**

- `500 Internal Server Error`: Failed to read CA certificate

## Proxy Server

The proxy server listens on the configured proxy port (default: 8443) and requires client authentication using certificates issued by the admin API. Requests are forwarded to the appropriate target URL based on the request path and the app configuration.

### Request Headers

The proxy adds the following headers to the forwarded request:

- `X-Forwarded-For`: The client's IP address
- `X-Forwarded-Host`: The original host header
- `X-Forwarded-Proto`: The original protocol (scheme)
- `X-Client-Cert-CN`: The client certificate's Common Name (same as appId)
- `X-Client-Cert-Fingerprint`: The client certificate's fingerprint

## Configuration

The default configuration:

```json
{
  "adminApiPort": 8080,
  "proxyPort": 8443,
  "certDir": "./certs",
  "caKeyFile": "./ca/ca.key",
  "caCertFile": "./ca/ca.crt",
  "proxyServerCertFile": "./certs/server.crt",
  "proxyServerKeyFile": "./certs/server.key",
  "configFile": "./config/apps.json",
  "certValidityDays": 365
}
```

## Data Models

### Application Configuration

```json
{
  "appId": "string",
  "targetUrls": {
    "path_prefix1": "target_url1",
    "path_prefix2": "target_url2"
  },
  "clientCerts": {
    "certFile": "string",
    "keyFile": "string",
    "fingerprint": "string",
    "expiresAt": "string"
  },
  "created": "string",
  "updated": "string"
}
```

### Client Certificate Information

```json
{
  "certFile": "string",
  "keyFile": "string",
  "fingerprint": "string",
  "expiresAt": "string"
}
```
