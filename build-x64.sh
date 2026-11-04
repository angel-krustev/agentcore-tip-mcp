#!/bin/bash
# ==============================================================================
# AgentCore-TIP-MCP-Broker - Linux AMD64 Wheel Builder
# ==============================================================================
# Builds a Cython-compiled wheel for Linux x86_64 with IP protection.
# Uses Docker to compile on Linux even when running on Windows/Mac.
#
# Usage:
#   ./build-x64.sh                    # Build Linux AMD64 wheel
#   ./build-x64.sh clean              # Remove build artifacts
#   ./build-x64.sh verify             # Verify wheel IP protection
#   ./build-x64.sh help               # Show this help message
#
# Output:
#   dist/agentcore_tip-<version>-cp311-cp311-linux_x86_64.whl
#
# Prerequisites:
#   - Docker Desktop running
#   - Git Bash or WSL (Windows)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_IMAGE="agentcore_tip-build"
DOCKER_TAG="latest"
OUTPUT_DIR="${SCRIPT_DIR}/dist"
TEMP_CONTAINER="vt-wheel-builder"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Helper Functions ────────────────────────────────────────────────────────

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERR]${NC} $1"
}

show_help() {
    cat << 'EOF'
AgentCore-TIP-MCP-Broker - Linux AMD64 Wheel Builder
===========================================

DESCRIPTION
    Builds a Cython-compiled Linux x86_64 wheel with IP protection.
    Core modules are compiled to .so binaries; source .py files are
    removed from the final wheel to protect proprietary code.

USAGE
    ./build-x64.sh [command]

COMMANDS
    (no args)     Build the Linux AMD64 wheel (default)
    clean         Remove build artifacts (dist/, temp containers)
    verify        Verify IP protection in the built wheel
    help          Show this help message

PREREQUISITES
    - Docker Desktop must be running
    - Git Bash or WSL on Windows

WORKFLOW
    1. Docker builds an image with Cython compilation
    2. Core IP modules are compiled to .so binaries
    3. Post-build cleanup removes .py and .c source files
    4. The protected wheel is copied to dist/

PROTECTED MODULES
    - agentcore_tip.core.context
    - agentcore_tip.core.credentials
    - agentcore_tip.core.hooks
    - agentcore_tip.core.strategies.sso_oidc
    - agentcore_tip.core.strategies.web_identity

OUTPUT
    dist/agentcore_tip-<version>-cp311-cp311-linux_x86_64.whl

EXAMPLES
    # Build the wheel
    ./build-x64.sh

    # Clean previous builds, then build fresh
    ./build-x64.sh clean && ./build-x64.sh

    # Verify IP protection after building
    ./build-x64.sh && ./build-x64.sh verify

ENVIRONMENT VARIABLES
    DOCKER_IMAGE      Docker image name (default: agentcore_tip-build)
    DOCKER_TAG        Docker image tag (default: latest)
    OUTPUT_DIR        Output directory (default: ./dist)
EOF
}

# ─── Prerequisite Checks ────────────────────────────────────────────────────

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Start Docker Desktop and try again."
        exit 1
    fi

    log_success "Docker is available"
}

# ─── Build Functions ────────────────────────────────────────────────────────

build_wheel() {
    log_info "Building Linux AMD64 wheel with Cython compilation..."
    log_info "This may take a few minutes on first run (image build)..."
    echo

    # Step 1: Build Docker image
    log_info "Step 1/4: Building Docker image..."
    cd "$SCRIPT_DIR"
    docker build -f Dockerfile.wheel -t "${DOCKER_IMAGE}:${DOCKER_TAG}" .
    log_success "Docker image built: ${DOCKER_IMAGE}:${DOCKER_TAG}"
    echo

    # Step 2: Run container to extract wheel
    log_info "Step 2/4: Running container to build wheel..."

    # Remove any leftover temp container
    docker rm -f "$TEMP_CONTAINER" &> /dev/null || true

    docker run --name "$TEMP_CONTAINER" "${DOCKER_IMAGE}:${DOCKER_TAG}" > /dev/null 2>&1
    log_success "Container executed successfully"
    echo

    # Step 3: Copy wheel from container
    log_info "Step 3/4: Extracting wheel from container..."

    mkdir -p "$OUTPUT_DIR"
    docker cp "${TEMP_CONTAINER}:/wheel/" "${OUTPUT_DIR}/"
    log_success "Wheel extracted to ${OUTPUT_DIR}/wheel/"
    echo

    # Step 4: Cleanup
    log_info "Step 4/4: Cleaning up..."
    docker rm "$TEMP_CONTAINER" > /dev/null 2>&1
    log_success "Temp container removed"
    echo

    # Find the wheel file
    WHEEL_FILE=$(find "$OUTPUT_DIR/wheel" -name "*.whl" -type f 2>/dev/null | head -1)
    if [[ -z "$WHEEL_FILE" ]]; then
        log_error "No wheel file found in $OUTPUT_DIR/wheel/"
        exit 1
    fi

    log_success "========================================="
    log_success "Build complete!"
    log_success "========================================="
    echo
    log_info "Wheel location: ${WHEEL_FILE}"
    log_info "Wheel size: $(du -h "$WHEEL_FILE" | cut -f1)"
    echo

    # Auto-verify IP protection
    log_info "Verifying IP protection..."
    verify_wheel "$WHEEL_FILE"
}

# ─── Verification Functions ─────────────────────────────────────────────────

verify_wheel() {
    local wheel_file="${1:-}"

    # If no wheel file specified, find the latest one
    if [[ -z "$wheel_file" ]]; then
        wheel_file=$(find "$OUTPUT_DIR/wheel" -name "*.whl" -type f 2>/dev/null | head -1)
        if [[ -z "$wheel_file" ]]; then
            log_error "No wheel file found. Run ./build-x64.sh first."
            exit 1
        fi
    fi

    if [[ ! -f "$wheel_file" ]]; then
        log_error "Wheel file not found: $wheel_file"
        exit 1
    fi

    log_info "Verifying IP protection in: $(basename "$wheel_file")"
    echo

    # Convert Git Bash path to Windows path for Python (cygpath -m)
    local wheel_file_win
    wheel_file_win=$(cygpath -m "$wheel_file")

    # Use Python to inspect wheel contents
    python -c "
import zipfile
import sys

wheel_path = '$wheel_file_win'
core_modules = [
    'context',
    'credentials',
    'hooks',
    'sso_oidc',
    'web_identity',
]

with zipfile.ZipFile(wheel_path) as z:
    all_files = z.namelist()

    # Find core module files
    core_files = [f for f in all_files if any(m in f for m in core_modules)]

    print('Core module files in wheel:')
    for f in sorted(core_files):
        print('  ' + f)
    print()

    # Count by extension
    py_count = len([f for f in all_files if f.endswith('.py')])
    so_count = len([f for f in all_files if f.endswith('.so')])
    c_count = len([f for f in all_files if f.endswith('.c')])
    pyd_count = len([f for f in all_files if f.endswith('.pyd')])

    print('File summary:')
    print('  .py files:  ' + str(py_count))
    print('  .so files:  ' + str(so_count))
    print('  .pyd files: ' + str(pyd_count))
    print('  .c files:   ' + str(c_count))
    print()

    # Check IP protection status
    core_py = [f for f in core_files if f.endswith('.py')]
    core_so = [f for f in core_files if f.endswith('.so') or f.endswith('.pyd')]

    if core_py:
        print('IP PROTECTION: FAILED')
        print('  WARNING: Source .py files found for core modules:')
        for f in core_py:
            print('    - ' + f)
        sys.exit(1)
    elif core_so and len(core_so) == 5:
        print('IP PROTECTION: PASSED')
        print('  All 5 core modules compiled to native extensions')
        print('  No source .py files for protected modules')
    else:
        print('IP PROTECTION: PARTIAL')
        print('  Some core modules may not be compiled')
        sys.exit(1)
"
}

# ─── Clean Function ─────────────────────────────────────────────────────────

clean_build() {
    log_info "Cleaning build artifacts..."

    # Remove temp container if it exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${TEMP_CONTAINER}$"; then
        docker rm -f "$TEMP_CONTAINER" > /dev/null 2>&1
        log_success "Removed temp container"
    fi

    # Remove output directory
    if [[ -d "$OUTPUT_DIR/wheel" ]]; then
        rm -rf "$OUTPUT_DIR/wheel"
        log_success "Removed $OUTPUT_DIR/wheel/"
    fi

    log_success "Clean complete"
}

# ─── Main Entry Point ──────────────────────────────────────────────────────

main() {
    local command="${1:-build}"

    case "$command" in
        build|"")
            check_docker
            build_wheel
            ;;
        clean)
            clean_build
            ;;
        verify)
            verify_wheel
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Run './build-x64.sh help' for usage information."
            exit 1
            ;;
    esac
}

main "$@"
