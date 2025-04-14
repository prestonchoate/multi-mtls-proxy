# Roadmap

## Security Hardening

1. TLS Configuration Improvements
    - TLS configuration needs more security parameters like cipher suite restrictions
    - Consider implementing OCSP stapling for certificate revocation checks
    - Add stricter SSL/TLS settings (HSTS headers, secure cookies)<br><br>

2. Certificate Management
    - Implement certificate rotation and renewal processes
    - Add certificate expiration monitoring and alerting
    - Consider using a proper secrets management solution instead of file-based storage<br><br>

3. API Security
    - Implement Admin API authentication mechanism
    - Implement rate limiting to prevent abuse
    - Add input validation on all API endpoints
 

## Architecture for Scalability

1. Statelessness Issues
    - Your current design uses local file storage for configurations and certificates
    - For K8s/load balancing: Move to a shared storage or database system for configuration
    - Consider using a secrets management service like HashiCorp Vault or cloud-native solutions<br><br>

2. High Availability Design
    - Implement proper liveness and readiness probes for Kubernetes
    - Separate the admin API and proxy components into distinct services
    - Add health check endpoints for both components<br><br>

3. Load Balancing Considerations
    - TLS termination would need special handling with client certificate validation
    - Ensure session affinity isn't required (or implement if needed)
    - Configure appropriate ingress settings for client certificate passthrough

## Operational Improvements

1. Observability
    - Add structured logging (currently using basic log package)
    - Implement metrics collection (Prometheus endpoints)
    - Add distributed tracing for request tracking
    - Setup proper monitoring for certificate expiration<br><br>

2. Configuration Management
    - Implement proper configuration validation
    - Consider using a more robust configuration system (e.g., Viper)
    - Make environment variable handling more consistent<br><br>

3. Resource Management
    - Add resource limits and requests for containers
    - Implement graceful shutdown handling
    - Add circuit breakers for backend services
