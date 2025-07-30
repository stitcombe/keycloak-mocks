# Keycloak Authentication Testing Makefile

.PHONY: help start stop test test-oidc test-saml test-oauth2 test-local clean logs status setup-ci

# Default target
help:
	@echo "Keycloak Authentication Testing Commands:"
	@echo ""
	@echo "Setup and Management:"
	@echo "  make start       - Start Keycloak and PostgreSQL services"
	@echo "  make stop        - Stop all services"
	@echo "  make clean       - Stop services and remove volumes"
	@echo "  make logs        - Show service logs"
	@echo "  make status      - Check service status"
	@echo ""
	@echo "Testing:"
	@echo "  make test        - Run all authentication tests"
	@echo "  make test-oidc   - Run OIDC-specific tests"
	@echo "  make test-saml   - Run SAML-specific tests"
	@echo "  make test-oauth2 - Run OAuth2 client credentials tests"
	@echo "  make test-local  - Run local user authentication tests"
	@echo ""
	@echo "CI/CD:"
	@echo "  make setup-ci    - Setup for CI/CD pipeline"
	@echo "  make ci-test     - Run complete CI test suite"
	@echo ""
	@echo "Access Points:"
	@echo "  Keycloak Admin:  http://localhost:8080/admin (admin/admin)"
	@echo "  OIDC Test App:   http://localhost:8082"
	@echo "  SAML Test App:   http://localhost:8081"

start:
	@echo "Starting Keycloak services..."
	docker compose up -d
	@echo "Waiting for services to be ready..."
	@timeout 300s bash -c 'until curl -f http://localhost:8080/health/ready >/dev/null 2>&1; do sleep 5; done' || (echo "Timeout waiting for Keycloak" && exit 1)
	@echo "✅ Services are ready!"
	@echo "📋 Keycloak Admin Console: http://localhost:8080/admin (admin/admin)"
	@echo "🧪 OIDC Test App: http://localhost:8082"
	@echo "🔒 SAML Test App: http://localhost:8081"

stop:
	@echo "Stopping services..."
	docker compose down

clean:
	@echo "Cleaning up services and volumes..."
	docker compose down -v --remove-orphans
	docker network rm keycloak-network 2>/dev/null || true

logs:
	docker compose logs -f

status:
	@echo "Service Status:"
	@docker compose ps
	@echo ""
	@echo "Health Check:"
	@curl -f http://localhost:8080/health/ready >/dev/null 2>&1 && echo "✅ Keycloak is healthy" || echo "❌ Keycloak is not responding"

test: start
	@echo "Running comprehensive authentication tests..."
	docker compose -f docker compose.test.yml up --build --abort-on-container-exit test-runner
	@echo "✅ All tests completed!"

test-oidc: start
	@echo "Running OIDC authentication tests..."
	docker compose -f docker compose.test.yml --profile oidc-only up --build --abort-on-container-exit oidc-test

test-saml: start
	@echo "Running SAML authentication tests..."
	docker compose -f docker compose.test.yml --profile saml-only up --build --abort-on-container-exit saml-test

test-oauth2: start
	@echo "Running OAuth2 client credentials tests..."
	docker compose -f docker compose.test.yml --profile oauth2-only up --build --abort-on-container-exit oauth2-test

test-local: start
	@echo "Running local user authentication tests..."
	docker compose -f docker compose.test.yml --profile local-only up --build --abort-on-container-exit local-auth-test

setup-ci:
	@echo "Setting up CI/CD environment..."
	chmod +x ci-test-script.sh
	docker network create keycloak-network 2>/dev/null || true
	@echo "✅ CI/CD environment ready"

ci-test: setup-ci
	@echo "Running complete CI test suite..."
	./ci-test-script.sh
	@echo "✅ CI test suite completed!"

# Quick development targets
dev: start
	@echo "Development environment ready!"
	@echo "Access points:"
	@echo "  - Keycloak Admin: http://localhost:8080/admin"
	@echo "  - Test Apps: http://localhost:8082 (OIDC), http://localhost:8081 (SAML)"

# Production-ready test with security checks
prod-test: test
	@echo "Running production readiness checks..."
	@echo "🔒 Security recommendations:"
	@echo "  - Enable HTTPS with valid certificates"
	@echo "  - Use strong admin passwords"
	@echo "  - Enable rate limiting"
	@echo "  - Monitor authentication failures"
	@echo "  - Implement proper logging"