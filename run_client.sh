#!/bin/bash
# Shell script to set environment variables and run the AgentCore TIP MFA Athena client
# Usage: source run_client.sh  OR  bash run_client.sh
#
# This script:
# 1. Writes a .env file with all configuration for docker-compose
# 2. Exports variables for the local client
# 3. Optionally starts the Docker container with the correct configuration
# 4. Runs the MFA Athena client

# ============================================================================
# TIP Configuration
# ============================================================================

# Token Exchange Application ARN (required by server)
export SSO_CLIENT_ID="${SSO_CLIENT_ID:-}"

# OIDC Role ARN (intermediary role for token exchange)
export OIDC_ROLE_ARN="${OIDC_ROLE_ARN:-}"

# ID Enhanced Role ARN (final role for Lake Formation access)
export TIP_ROLE_ARN="${TIP_ROLE_ARN:-}"

# ============================================================================
# Identity Provider Configuration (Entra ID)
# ============================================================================

# Identity Provider type
export IDP="entra-id"

# Entra ID Tenant ID
export ENTRA_TENANT_ID="${ENTRA_TENANT_ID:-}"

# Entra ID Client ID
export OIDC_CLIENT_ID="${OIDC_CLIENT_ID:-}"

# ============================================================================
# OIDC Settings
# ============================================================================

# OIDC Discovery URL (will be auto-generated from tenant ID if not set)
# Uncomment and modify if you need a custom discovery URL
# export OIDC_DISCOVERY_URL="https://login.microsoftonline.com/<TENANT_ID>/v2.0/.well-known/openid-configuration"

# OIDC Redirect URI (default: http://127.0.0.1:8765/callback)
# Uncomment and modify if you need a custom redirect URI
# export OIDC_REDIRECT_URI="http://127.0.0.1:8765/callback"

# OIDC Scopes (default: openid profile email)
# Uncomment and modify if you need custom scopes
# export OIDC_SCOPES="openid profile email"

# ============================================================================
# AWS Configuration
# ============================================================================

# AWS Region (optional)
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Session Duration in seconds (default: 3600)
# export SESSION_DURATION_SECONDS="3600"

# ============================================================================
# Server Configuration
# ============================================================================

# Athena configuration for the server
export ATHENA_WORKGROUP="${ATHENA_WORKGROUP:-idc-wg}"
export ATHENA_DATABASE="${ATHENA_DATABASE:-lfdb}"

# ============================================================================
# Functions
# ============================================================================

write_env_file() {
    # Write .env file so docker-compose picks up all variables
    cat > .env <<EOF
SSO_CLIENT_ID=${SSO_CLIENT_ID}
OIDC_ROLE_ARN=${OIDC_ROLE_ARN}
TIP_ROLE_ARN=${TIP_ROLE_ARN}
AWS_REGION=${AWS_REGION}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ATHENA_WORKGROUP=${ATHENA_WORKGROUP}
ATHENA_DATABASE=${ATHENA_DATABASE}
EOF
}

start_docker_server() {
    echo "=========================================="
    echo "Starting AgentCoreTIP Server in Docker"
    echo "=========================================="
    echo ""
    
    # Write .env file for docker-compose
    write_env_file
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        echo "ERROR: Docker is not installed or not in PATH"
        return 1
    fi
    
    # Stop any existing container
    echo "Stopping any existing container..."
    docker-compose down 2>/dev/null || true
    echo ""
    
    # Start the container with environment variables
    echo "Starting Docker container with configuration..."
    docker-compose up --build -d
    
    # Wait for server to be ready
    echo ""
    echo "Waiting for server to start..."
    sleep 5
    
    # Check if server is healthy
    if curl -s http://localhost:8080/ping > /dev/null; then
        echo "✓ Server is running and healthy!"
    else
        echo "⚠ Warning: Server may not be ready yet"
        echo "  Check logs with: docker-compose logs -f"
    fi
    echo ""
}

run_client() {
    echo "=========================================="
    echo "Starting MFA Athena Client"
    echo "=========================================="
    echo ""
    echo "Configuration Summary:"
    echo "  IDP: $IDP"
    echo "  Identity provider configuration: ${ENTRA_TENANT_ID:+configured}"
    echo "  AWS role configuration: $([ -n "$OIDC_ROLE_ARN" ] && [ -n "$TIP_ROLE_ARN" ] && echo configured || echo incomplete)"
    echo "  AWS Region: $AWS_REGION"
    echo "  Athena Workgroup: $ATHENA_WORKGROUP"
    echo ""
    echo "Opening browser for MFA authentication..."
    echo ""
    
    # Run the MFA Athena client
    python examples/mfa_athena_client.py "$@"
}

stop_server() {
    echo "Stopping Docker server..."
    docker-compose down
}

show_help() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start     Start the Docker server"
    echo "  run       Run the MFA Athena client"
    echo "  stop      Stop the Docker server"
    echo "  restart   Restart the Docker server and run client"
    echo "  help      Show this help message"
    echo ""
    echo "If no command is specified, defaults to 'restart'"
    echo ""
    echo "Environment variables are automatically set by this script."
}

# ============================================================================
# Main Execution
# ============================================================================

echo "Environment variables set successfully!"
echo ""

# Parse command line argument
COMMAND="${1:-restart}"

case $COMMAND in
    start)
        start_docker_server
        ;;
    run)
        run_client
        ;;
    stop)
        stop_server
        ;;
    restart)
        start_docker_server
        sleep 2
        run_client
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
