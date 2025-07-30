# Keycloak Authentication Testing Suite

A comprehensive Docker-based Keycloak test environment for validating enterprise authentication methods before production deployment. This project provides automated testing for OIDC, SAML, Local Users, and OAuth2 Client Credentials authentication flows.

## 🎯 Purpose

This test suite is designed for enterprise system architects who need to validate authentication methods in shadow deployments before migrating users and clients to a new Identity Provider. All four major authentication patterns are supported:

- **OIDC (OpenID Connect)** - Modern web application authentication
- **SAML** - Enterprise SSO integration  
- **Local Users** - Direct username/password authentication
- **OAuth2 Client Credentials** - API service-to-service authentication

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Make (optional, for convenience commands)
- curl (for health checks)

### Start Services

```bash
# Using Make (recommended)
make start

# Or using Docker Compose directly
docker-compose up -d
```

Services will be available at:
- **Keycloak Admin Console**: http://localhost:8080/admin (admin/admin)
- **OIDC Test App**: http://localhost:8082  
- **SAML Test App**: http://localhost:8081

### Run Tests

```bash
# Run all tests
make test

# Run specific authentication method tests
make test-oidc    # OIDC tests only
make test-saml    # SAML tests only  
make test-oauth2  # OAuth2 Client Credentials tests
make test-local   # Local user authentication tests
```

## 🏗️ Architecture

### Services

- **Keycloak** (port 8080) - Identity Provider with pre-configured test realm
- **PostgreSQL** - Keycloak database backend
- **OIDC Test Client** (port 8082) - Mock web application for OIDC testing
- **SAML Service Provider** (port 8081) - Mock application for SAML testing
- **Test Runner** - Python-based automated test suite

### Test Realm Configuration

The `test-realm` is automatically imported with:

- **OIDC Client**: `oidc-test-client` 
- **SAML Service Provider**: `saml-test-sp`
- **OAuth2 API Client**: `oauth2-api-client`
- **Test Users**: `testuser`, `samluser`
- **Roles**: `api-user`

## 🧪 Testing Framework

### Test Structure

```
tests/
├── conftest.py                    # Shared test configuration
├── test_oidc_auth.py             # OIDC authentication tests
├── test_saml_auth.py             # SAML authentication tests  
├── test_local_auth.py            # Local user tests
├── test_oauth2_client_credentials.py # OAuth2 API tests
└── requirements.txt              # Python dependencies
```

### Test Coverage

#### OIDC Tests
- Well-known configuration endpoint
- Authorization Code Flow
- Client Credentials Flow  
- Token introspection
- UserInfo endpoint
- Logout functionality
- JWKS endpoint validation

#### SAML Tests
- Identity Provider metadata
- SSO with HTTP-Redirect binding
- SSO with HTTP-POST binding
- Complete login flow simulation
- Single Logout (SLO)
- Signature validation

#### Local User Tests
- User existence validation
- Direct grant authentication
- Invalid credential handling
- Disabled user behavior
- Password reset functionality
- Session management
- Custom attributes
- Role assignment

#### OAuth2 Client Credentials Tests
- Client configuration validation
- Token grant flow
- Invalid credentials handling
- Token validation and introspection
- Scope handling
- Token lifetime verification
- Service account validation
- API resource access
- Token revocation
- Concurrent request handling

## 🔄 CI/CD Integration

### GitHub Actions

The project includes a comprehensive GitHub Actions workflow (`.github/workflows/keycloak-auth-tests.yml`) that:

- Starts Keycloak test environment
- Runs all authentication tests
- Performs security analysis with Trivy
- Generates test reports
- Provides security recommendations

### Generic CI Script

For other CI/CD systems, use the included script:

```bash
# Full test suite
./ci-test-script.sh

# Test-only (assumes services running)
./ci-test-script.sh --test-only

# Cleanup only
./ci-test-script.sh --cleanup-only

# Verbose output
./ci-test-script.sh --verbose
```

## 🛠️ Development

### Available Commands

```bash
make help         # Show all available commands
make start        # Start services
make stop         # Stop services  
make clean        # Stop and remove volumes
make logs         # Show service logs
make status       # Check service health
make dev          # Start development environment
```

### Configuration Files

- `docker-compose.yml` - Main service orchestration
- `docker-compose.test.yml` - Test runner configuration  
- `keycloak/import/test-realm.json` - Realm configuration
- `ci-test-script.sh` - Standalone CI script
- `Makefile` - Development convenience commands

### Test Apps

Interactive test applications are available for manual testing:

- **OIDC Client** (http://localhost:8082) - Test OIDC flows interactively
- **SAML SP** (http://localhost:8081) - Test SAML authentication flows

## 🔒 Security

### Development Environment

This setup uses default credentials and configurations suitable for testing:

- Admin credentials: `admin/admin`
- Test user passwords: `testpass123`, `samlpass123`
- Client secrets: `oidc-test-secret`, `oauth2-api-secret`

### Production Recommendations

For production deployments:

1. **Enable HTTPS** with valid certificates
2. **Use strong passwords** for admin accounts
3. **Rotate client secrets** regularly
4. **Implement rate limiting** on authentication endpoints
5. **Monitor authentication failures** and audit logs
6. **Use dedicated service accounts** for API access
7. **Enable proper logging** and SIEM integration

## 📊 Test Results

Test results are generated in multiple formats:

- **JUnit XML** - For CI/CD integration
- **HTML Report** - Human-readable test results
- **Docker Logs** - Service debugging information
- **Summary Report** - Markdown summary with recommendations

## 🤝 Contributing

This project follows enterprise security best practices. When contributing:

1. All tests must validate authentication security
2. No hardcoded secrets in production configurations
3. Document any new authentication flows
4. Include security recommendations for production use

## 📋 Troubleshooting

### Common Issues

**Services won't start:**
```bash
make clean  # Remove volumes and networks
make start  # Restart services
```

**Tests failing:**
```bash
make logs   # Check service logs
make status # Verify service health
```

**Port conflicts:**
```bash
# Edit docker-compose.yml to change ports
# Default ports: 8080 (Keycloak), 8081 (SAML), 8082 (OIDC)
```

### Logs and Debugging

```bash
# View all service logs
make logs

# View specific service logs  
docker-compose logs keycloak
docker-compose logs postgres

# Check service health
curl http://localhost:8080/health/ready
```

## 📚 References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OIDC Specification](https://openid.net/connect/)
- [SAML 2.0 Specification](https://docs.oasis-open.org/security/saml/v2.0/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)
