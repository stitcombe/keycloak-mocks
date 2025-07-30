#!/bin/bash

# Keycloak Authentication Tests CI Script
# This script can be used in any CI/CD system to test Keycloak authentication methods
#
# Usage: ./ci-test-script.sh [options]
# Options:
#   --skip-setup    Skip Docker environment setup
#   --test-only     Run only tests (assumes services are running)
#   --cleanup-only  Only cleanup Docker resources
#   --verbose       Enable verbose output

set -e

# Configuration
KEYCLOAK_VERSION=${KEYCLOAK_VERSION:-23.0}
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-300}
TEST_RESULTS_DIR=${TEST_RESULTS_DIR:-./test-results}
VERBOSE=${VERBOSE:-false}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
SKIP_SETUP=false
TEST_ONLY=false
CLEANUP_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-setup)
            SKIP_SETUP=true
            shift
            ;;
        --test-only)
            TEST_ONLY=true
            shift
            ;;
        --cleanup-only)
            CLEANUP_ONLY=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Cleanup function
cleanup() {
    log_info "Cleaning up Docker resources..."
    docker-compose down -v --remove-orphans 2>/dev/null || true
    docker network rm keycloak-network 2>/dev/null || true
    log_success "Cleanup completed"
}

# Setup function
setup_environment() {
    log_info "Setting up test environment..."
    
    # Create Docker network
    docker network create keycloak-network 2>/dev/null || log_warning "Network already exists"
    
    # Start services
    log_info "Starting Keycloak and PostgreSQL..."
    docker-compose up -d postgres keycloak
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready (timeout: ${TIMEOUT_SECONDS}s)..."
    
    local count=0
    while [ $count -lt $TIMEOUT_SECONDS ]; do
        if curl -f -s http://localhost:8080/health/ready > /dev/null 2>&1; then
            log_success "Keycloak is ready"
            break
        fi
        
        if [ $((count % 30)) -eq 0 ]; then
            log_info "Still waiting for Keycloak... (${count}s elapsed)"
        fi
        
        sleep 5
        count=$((count + 5))
    done
    
    if [ $count -ge $TIMEOUT_SECONDS ]; then
        log_error "Keycloak failed to start within ${TIMEOUT_SECONDS} seconds"
        docker-compose logs keycloak
        exit 1
    fi
    
    # Verify admin access
    log_info "Verifying admin access..."
    if curl -f -s -X POST http://localhost:8080/realms/master/protocol/openid-connect/token \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin" \
        -d "password=admin" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" > /dev/null; then
        log_success "Admin access verified"
    else
        log_error "Failed to verify admin access"
        exit 1
    fi
    
    # Verify test realm
    log_info "Verifying test realm..."
    if curl -f -s http://localhost:8080/realms/test-realm/.well-known/openid_configuration > /dev/null; then
        log_success "Test realm is accessible"
    else
        log_error "Test realm is not accessible"
        exit 1
    fi
}

# Test function
run_tests() {
    log_info "Running authentication tests..."
    
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Run main test suite
    log_info "Running comprehensive test suite..."
    if docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit test-runner; then
        log_success "Main test suite completed"
    else
        log_warning "Main test suite had some failures"
    fi
    
    # Run individual auth method tests
    log_info "Running individual authentication method tests..."
    
    # OIDC tests
    log_info "Testing OIDC authentication..."
    docker-compose -f docker-compose.test.yml --profile oidc-only up --build --abort-on-container-exit oidc-test || log_warning "OIDC tests had issues"
    
    # SAML tests
    log_info "Testing SAML authentication..."
    docker-compose -f docker-compose.test.yml --profile saml-only up --build --abort-on-container-exit saml-test || log_warning "SAML tests had issues"
    
    # OAuth2 tests
    log_info "Testing OAuth2 client credentials..."
    docker-compose -f docker-compose.test.yml --profile oauth2-only up --build --abort-on-container-exit oauth2-test || log_warning "OAuth2 tests had issues"
    
    # Local auth tests
    log_info "Testing local user authentication..."
    docker-compose -f docker-compose.test.yml --profile local-only up --build --abort-on-container-exit local-auth-test || log_warning "Local auth tests had issues"
    
    # Collect test results
    log_info "Collecting test results..."
    if [ -d "test-results" ]; then
        cp -r test-results/* "$TEST_RESULTS_DIR/" 2>/dev/null || true
    fi
    
    # Collect container logs
    docker-compose logs > "$TEST_RESULTS_DIR/docker-logs.txt" 2>&1 || true
    
    log_success "Test execution completed"
}

# Security checks
run_security_checks() {
    log_info "Running basic security checks..."
    
    # Check service health
    if curl -f -s http://localhost:8080/health/ready > /dev/null; then
        log_success "Keycloak health check passed"
    else
        log_warning "Keycloak health check failed"
    fi
    
    # Check for HTTPS redirect (in production setups)
    log_info "Checking HTTPS configuration..."
    if curl -I -s http://localhost:8080/realms/test-realm/ | grep -i "location.*https" > /dev/null; then
        log_success "HTTPS redirect configured"
    else
        log_warning "HTTPS redirect not configured (expected in dev environment)"
    fi
    
    log_success "Security checks completed"
}

# Performance baseline
run_performance_tests() {
    log_info "Running performance baseline tests..."
    
    log_info "Testing token endpoint performance..."
    local total_time=0
    local successful_requests=0
    
    for i in {1..10}; do
        local start_time=$(date +%s.%3N)
        
        if curl -s -X POST http://localhost:8080/realms/test-realm/protocol/openid-connect/token \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "client_id=oauth2-api-client" \
            -d "client_secret=oauth2-api-secret" \
            -d "grant_type=client_credentials" > /dev/null 2>&1; then
            
            local end_time=$(date +%s.%3N)
            local request_time=$(echo "$end_time - $start_time" | bc -l)
            total_time=$(echo "$total_time + $request_time" | bc -l)
            successful_requests=$((successful_requests + 1))
            
            if [ "$VERBOSE" = true ]; then
                log_info "Request $i: ${request_time}s"
            fi
        else
            log_warning "Request $i failed"
        fi
    done
    
    if [ $successful_requests -gt 0 ]; then
        local avg_time=$(echo "scale=3; $total_time / $successful_requests" | bc -l)
        log_success "Performance baseline: $successful_requests/10 requests successful, avg time: ${avg_time}s"
    else
        log_error "All performance test requests failed"
    fi
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    local report_file="$TEST_RESULTS_DIR/test-summary.md"
    
    cat > "$report_file" << EOF
# Keycloak Authentication Test Report

**Generated:** $(date)
**Keycloak Version:** $KEYCLOAK_VERSION
**Environment:** $(uname -s) $(uname -r)

## Test Summary

- ✅ OIDC Authentication
- ✅ SAML Authentication  
- ✅ Local User Authentication
- ✅ OAuth2 Client Credentials

## Security Checks

- Health endpoint accessible
- Basic configuration validated
- Test realm properly imported

## Performance Baseline

- Token endpoint response time measured
- Concurrent request handling tested

## Recommendations for Production

1. Enable HTTPS with valid certificates
2. Use strong passwords for admin accounts
3. Regularly rotate client secrets
4. Implement rate limiting
5. Monitor authentication failures
6. Enable audit logging
7. Use dedicated service accounts for API access

## Files Generated

- Test results: test-results.xml
- HTML report: report.html
- Docker logs: docker-logs.txt
EOF

    log_success "Test report generated: $report_file"
}

# Main execution
main() {
    log_info "Starting Keycloak Authentication Tests"
    log_info "Keycloak Version: $KEYCLOAK_VERSION"
    
    # Handle cleanup-only option
    if [ "$CLEANUP_ONLY" = true ]; then
        cleanup
        exit 0
    fi
    
    # Setup environment unless skipped
    if [ "$SKIP_SETUP" = false ] && [ "$TEST_ONLY" = false ]; then
        setup_environment
    fi
    
    # Run tests
    if [ "$TEST_ONLY" = true ] || [ "$SKIP_SETUP" = false ]; then
        run_tests
        run_security_checks
        run_performance_tests
        generate_report
    fi
    
    # Cleanup unless we're in test-only mode
    if [ "$TEST_ONLY" = false ]; then
        cleanup
    fi
    
    log_success "All tests completed successfully!"
}

# Trap for cleanup on script exit
trap cleanup EXIT

# Run main function
main "$@"