# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a Keycloak test instance setup for mocking authentication methods in enterprise environments. The project supports shadow deployment testing for:

- OIDC (OpenID Connect)
- SAML authentication
- Local user authentication
- OAuth2 client credentials (API access)

## Architecture

The project uses Docker Compose to orchestrate:

- Keycloak server instance
- PostgreSQL database for Keycloak data persistence
- Test automation containers for CI/CD integration

## Development Commands

```bash
# Start Keycloak test environment
docker compose up -d

# Run all authentication tests
docker compose -f docker-compose.test.yml up --abort-on-container-exit

# Tear down environment (for CI/CD)
docker compose down -v

# View Keycloak logs
docker compose logs keycloak

# Access Keycloak admin console
# http://localhost:8080/admin/ (admin/admin)
```

## Testing Strategy

Tests are designed to validate each authentication method before production migrations:

- Unit tests for each auth flow
- Integration tests with mock applications
- Performance baseline tests
- Security validation tests

The test suite runs in isolated containers and cleans up automatically for CI/CD pipeline integration.
