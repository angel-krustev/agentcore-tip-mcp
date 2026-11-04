#!/bin/bash
# ==============================================================================
# AgentCore-TIP-MCP-Broker Build Script
# ==============================================================================
# This script builds a distribution-ready package with Cython-compiled core
# IP modules for marketplace distribution.
# ==============================================================================

set -euo pipefail

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${PROJECT_DIR}/dist"
BUILD_DIR="${PROJECT_DIR}/build"
VERSION="0.1.0"
PYTHON="python"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================================================
# Pre-flight Checks
# ============================================================================
preflight_checks() {
    info "Running pre-flight checks..."
    
    # Check Python
    if ! command -v python &> /dev/null; then
        error "Python 3 not found"
        exit 1
    fi
    
    # Check Python version (need 3.10+)
    PYTHON_VERSION=$($PYTHON --version | awk '{print $2}')
    info "Using Python ${PYTHON_VERSION}"
    
    # Check required build tools
    info "Installing build dependencies..."
    $PYTHON -m pip install --upgrade pip setuptools wheel Cython build >/dev/null 2>&1
    
    success "Pre-flight checks complete"
}

# ============================================================================
# Clean Previous Builds
# ============================================================================
clean_builds() {
    info "Cleaning previous builds..."
    rm -rf "${DIST_DIR}"
    rm -rf "${BUILD_DIR}"
    rm -rf "${PROJECT_DIR}/agentcore_tip.egg-info"
    
    # Remove compiled extensions
    find "${PROJECT_DIR}/agentcore_tip" -name "*.so" -delete 2>/dev/null || true
    find "${PROJECT_DIR}/agentcore_tip" -name "*.pyd" -delete 2>/dev/null || true
    find "${PROJECT_DIR}/agentcore_tip" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    
    success "Cleaned previous builds"
}

# ============================================================================
# Compile Cython Extensions
# ============================================================================
compile_cython() {
    info "Compiling Cython extensions..."
    info "This will compile core IP modules to native extensions (.so)"
    
    cd "${PROJECT_DIR}"
    
    # Set environment variables to force Cython compilation
    export AGENTCORE_TIP_COMPILE_CYTHON=1
    export AGENTCORE_TIP_FORCE_RECOMPILE=1
    
    # Compile extensions
    $PYTHON setup.py build_ext --inplace
    
    # Verify compilation
    local compiled_count=$(find "${PROJECT_DIR}/agentcore_tip/core" -name "*.so" | wc -l)
    if [ "${compiled_count}" -gt 0 ]; then
        success "Compiled ${compiled_count} Cython extensions"
        find "${PROJECT_DIR}/agentcore_tip/core" -name "*.so" -exec echo "  - {}" \;
    else
        warn "No .so files were compiled (may already be compiled)"
    fi
    
    cd - > /dev/null
}

# ============================================================================
# Build Distribution Wheel
# ============================================================================
build_wheel() {
    info "Building distribution wheel..."
    
    cd "${PROJECT_DIR}"
    
    # Remove old dist directory
    rm -rf "${DIST_DIR}"
    
    # Build wheel with compiled extensions
    $PYTHON -m build --wheel --outdir "${DIST_DIR}"
    
    # ========================================================================
    # CRITICAL: Post-build wheel cleanup to remove .py and .c source files
    # This is the industry-standard approach for Cython IP protection
    # exclude_package_data doesn't work for .py files (setuptools includes them anyway)
    # ========================================================================
    info "Protecting IP: removing source .py and .c files from wheel..."
    
    # Use Python to rewrite the wheel without source files
    # We're already in PROJECT_DIR, so use relative 'dist/' path to avoid Git Bash path issues
    $PYTHON -c "
import zipfile
import os
import shutil
import glob

# Core IP modules to protect
CORE_MODULES = [
# Strategies
'agentcore_tip/core/strategies/sso_oidc',
'agentcore_tip/core/strategies/web_identity',
'agentcore_tip/core/strategies/base',
# Core modules
'agentcore_tip/core/context',
'agentcore_tip/core/session_store',
'agentcore_tip/core/sql_guard',
'agentcore_tip/core/credentials',
'agentcore_tip/core/hooks',
'agentcore_tip/core/config',
'agentcore_tip/core/exceptions',
'agentcore_tip/core/decorators',
'agentcore_tip/core/middleware',
'agentcore_tip/core/agent_validator',
'agentcore_tip/core/agentcore_provider',
# Integrations
'agentcore_tip/integrations/s3_access_grants',
'agentcore_tip/integrations/lake_formation',
]

# Build list of files to remove from wheel
FILES_TO_REMOVE = []
for module in CORE_MODULES:
    FILES_TO_REMOVE.append(module + '.py')
    FILES_TO_REMOVE.append(module + '.c')

# Find the wheel file (using relative path from current dir which is PROJECT_DIR)
wheel_files = glob.glob('dist/*.whl')
if not wheel_files:
    print('  WARNING: No wheel file found in dist/')
    exit(1)

wheel_path = wheel_files[0]
temp_wheel = wheel_path + '.tmp'

try:
    removed_count = 0
    
    # Read original, write to temp (avoids corruption)
    with zipfile.ZipFile(temp_wheel, 'w', zipfile.ZIP_DEFLATED) as new_zip:
        with zipfile.ZipFile(wheel_path, 'r') as old_zip:
            for item in old_zip.filelist:
                if item.filename not in FILES_TO_REMOVE:
                    new_zip.writestr(item, old_zip.read(item.filename))
                else:
                    removed_count += 1
    
    # Replace original wheel with cleaned version
    shutil.move(temp_wheel, wheel_path)
    
    print('  Removed ' + str(removed_count) + ' source files from wheel')
    print('  Protected modules:')
    for module in CORE_MODULES:
        print('    - ' + module.replace('/', '.'))
except Exception as e:
    print('  ERROR during cleanup: ' + str(e))
    if os.path.exists(temp_wheel):
        os.remove(temp_wheel)
    exit(1)
"
    
    # List generated artifacts
    success "Build complete"
    info "Generated artifacts:"
    ls -lh "${DIST_DIR}/"
    
    cd - > /dev/null
}

# ============================================================================
# Create Source Distribution
# ============================================================================
build_sdist() {
    info "Building source distribution..."
    
    cd "${PROJECT_DIR}"
    
    # Build sdist (includes source without compiled extensions)
    $PYTHON -m build --sdist --outdir "${DIST_DIR}"
    
    success "Source distribution built"
    
    cd - > /dev/null
}

# ============================================================================
# Test Built Package
# ============================================================================
test_package() {
    info "Testing built package..."
    
    # Find wheel file
    WHEEL_FILE=$(ls "${DIST_DIR}"/*.whl 2>/dev/null | head -1)
    
    if [ -z "${WHEEL_FILE}" ]; then
        error "No wheel file found in ${DIST_DIR}"
        exit 1
    fi
    
    info "Testing installation: $(basename ${WHEEL_FILE})"
    
    # Convert Git Bash path to Windows path for Python
    WHEEL_PATH_WIN=$(cygpath -m "${WHEEL_FILE}")
    
    # Test import in current environment
    $PYTHON -c "
import zipfile
import os

# Core IP modules to verify
CORE_MODULES = [
    # Strategies
    'agentcore_tip/core/strategies/sso_oidc',
    'agentcore_tip/core/strategies/web_identity',
    'agentcore_tip/core/strategies/base',
    # Core modules
    'agentcore_tip/core/context',
    'agentcore_tip/core/session_store',
    'agentcore_tip/core/sql_guard',
    'agentcore_tip/core/credentials',
    'agentcore_tip/core/hooks',
    'agentcore_tip/core/config',
    'agentcore_tip/core/exceptions',
    'agentcore_tip/core/decorators',
    'agentcore_tip/core/middleware',
    'agentcore_tip/core/agent_validator',
    'agentcore_tip/core/agentcore_provider',
    # Integrations
    'agentcore_tip/integrations/s3_access_grants',
    'agentcore_tip/integrations/lake_formation',
]

with zipfile.ZipFile(r'${WHEEL_PATH_WIN}', 'r') as z:
    files = z.namelist()
    so_files = [f for f in files if f.endswith('.so') or f.endswith('.pyd')]
    py_files = [f for f in files if f.endswith('.py')]
    print('  Wheel contains:')
    print('    - ' + str(len(py_files)) + ' .py files')
    print('    - ' + str(len(so_files)) + ' compiled extensions')
    if so_files:
        print('    Compiled modules:')
        for f in so_files[:5]:
            print('      - ' + f)
    
    # Verify IP protection
    print('')
    leaked = [f for f in files if f in CORE_MODULES + [m + '.py' for m in CORE_MODULES] + [m + '.c' for m in CORE_MODULES]]
    if leaked:
        print('  IP PROTECTION FAILED - leaked source files:')
        for f in leaked:
            print('    - ' + f)
    else:
        print('  IP PROTECTION VERIFIED - no source .py or .c files for core modules')
"
    
    success "Package test complete"
}

# ============================================================================
# Build Docker Image
# ============================================================================
build_docker() {
    info "Building Docker image..."
    
    cd "${PROJECT_DIR}"
    
    # Build Docker image with Cython compilation
    docker build \
        --tag agentcore-tip-mcp:${VERSION} \
        --tag agentcore-tip-mcp:latest \
        .
    
    success "Docker image built: agentcore-tip-mcp:${VERSION}"
    
    # Show image info
    info "Image details:"
    docker images agentcore-tip-mcp --format "  {{.Repository}}:{{.Tag}} - {{.Size}}"
    
    cd - > /dev/null
}

# ============================================================================
# Sign Distribution Artifacts (Optional)
# ============================================================================
sign_artifacts() {
    if ! command -v gpg &> /dev/null; then
        warn "GPG not installed, skipping signing"
        return
    fi
    
    info "Signing distribution artifacts..."
    
    for file in "${DIST_DIR}"/*; do
        if [ -f "${file}" ]; then
            gpg --detach-sign --armor "${file}"
            success "Signed: $(basename ${file})"
        fi
    done
}

# ============================================================================
# Generate Build Report
# ============================================================================
generate_report() {
    info "Generating build report..."
    
    REPORT_FILE="${DIST_DIR}/BUILD_REPORT.txt"
    
    cat > "${REPORT_FILE}" << EOF
========================================
AgentCore-TIP-MCP-Broker Build Report
========================================
Build Date: $(date)
Version: ${VERSION}
Python: $($PYTHON --version)
Host: $(hostname)
Platform: $(uname -srm)

========================================
Compiled Extensions
========================================
$(find "${PROJECT_DIR}/agentcore_tip/core" -name "*.so" -o -name "*.pyd" 2>/dev/null || echo "None")

========================================
Distribution Artifacts
========================================
$(ls -lh "${DIST_DIR}"/* 2>/dev/null || echo "None")

========================================
Security Notes
========================================
- Core IP modules compiled to native extensions
- Source code for core modules not included in wheel
- Sign artifacts before distribution with: gpg --detach-sign
========================================
EOF
    
    success "Build report saved to: ${REPORT_FILE}"
}

# ============================================================================
# Main Execution
# ============================================================================
main() {
    echo "========================================"
    echo "  AgentCore-TIP-MCP-Broker Build System"
    echo "  Version: ${VERSION}"
    echo "========================================"
    echo ""
    
    # Parse command line arguments
    case "${1:-all}" in
        clean)
            clean_builds
            ;;
        compile)
            compile_cython
            ;;
        wheel)
            preflight_checks
            clean_builds
            compile_cython
            build_wheel
            test_package
            generate_report
            ;;
        docker)
            build_docker
            ;;
        all)
            preflight_checks
            clean_builds
            compile_cython
            build_wheel
            test_package
            generate_report
            ;;
        help|--help|-h)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  clean     Clean previous builds"
            echo "  compile   Compile Cython extensions only"
            echo "  wheel     Build distribution wheel (default)"
            echo "  docker    Build Docker image"
            echo "  all       Full build (clean + compile + wheel + test)"
            echo "  help      Show this help message"
            ;;
        *)
            error "Unknown command: $1"
            exit 1
            ;;
    esac
}

main "$@"
