# ==============================================================================
# AgentCore-TIP-MCP-Broker Build Script (Windows PowerShell)
# ==============================================================================
# This script builds a distribution-ready package with Cython-compiled core
# IP modules for marketplace distribution.
# ==============================================================================

param(
    [Parameter(Position=0)]
    [ValidateSet("all", "clean", "compile", "wheel", "docker", "help")]
    [string]$Command = "all"
)

$ErrorActionPreference = "Stop"

# Configuration
$ProjectDir = $PSScriptRoot
$DistDir = Join-Path $ProjectDir "dist"
$Version = "0.1.0"

# ============================================================================
# Helper Functions
# ============================================================================
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# ============================================================================
# Pre-flight Checks
# ============================================================================
function Test-Preflight {
    Write-Info "Running pre-flight checks..."
    
    # Check Python
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error-Custom "Python not found"
        exit 1
    }
    
    # Check Python version
    $PythonVersion = python --version
    Write-Info "Using Python: $PythonVersion"
    
    # Install build dependencies
    Write-Info "Installing build dependencies..."
    python -m pip install --upgrade pip setuptools wheel Cython build > $null 2>&1
    
    Write-Success "Pre-flight checks complete"
}

# ============================================================================
# Clean Previous Builds
# ============================================================================
function Invoke-Clean {
    Write-Info "Cleaning previous builds..."
    
    # Remove dist directory
    if (Test-Path $DistDir) {
        Remove-Item -Recurse -Force $DistDir
    }
    
    # Remove build artifacts
    Remove-Item -Recurse -Force (Join-Path $ProjectDir "build") -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $ProjectDir "agentcore_tip.egg-info") -ErrorAction SilentlyContinue
    
    # Remove compiled extensions
    Get-ChildItem -Path (Join-Path $ProjectDir "agentcore_tip") -Recurse -Filter "*.so" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $ProjectDir "agentcore_tip") -Recurse -Filter "*.pyd" | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path (Join-Path $ProjectDir "agentcore_tip") -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Success "Cleaned previous builds"
}

# ============================================================================
# Compile Cython Extensions
# ============================================================================
function Invoke-Compile {
    Write-Info "Compiling Cython extensions..."
    Write-Info "This will compile core IP modules to native extensions (.pyd)"
    
    Push-Location $ProjectDir
    
    try {
        # Set environment variables
        $env:AGENTCORE_TIP_COMPILE_CYTHON = "1"
        $env:AGENTCORE_TIP_FORCE_RECOMPILE = "1"
        
        # Compile extensions
        python setup.py build_ext --inplace
        
        # Verify compilation
        $CompiledFiles = Get-ChildItem -Path (Join-Path $ProjectDir "agentcore_tip/core") -Recurse -Include "*.so","*.pyd" -File -ErrorAction SilentlyContinue
        if ($CompiledFiles.Count -gt 0) {
            Write-Success "Compiled $($CompiledFiles.Count) Cython extensions"
            foreach ($file in $CompiledFiles) {
                Write-Info "  - $($file.Name)"
            }
        } else {
            Write-Warn "No compiled files found (may already be compiled)"
        }
    } finally {
        Pop-Location
    }
}

# ============================================================================
# Build Distribution Wheel
# ============================================================================
function Invoke-BuildWheel {
    Write-Info "Building distribution wheel..."
    
    Push-Location $ProjectDir
    
    try {
        # Remove old dist directory
        if (Test-Path $DistDir) {
            Remove-Item -Recurse -Force $DistDir
        }
        
        # Build wheel with compiled extensions
        python -m build --wheel --outdir $DistDir
        
        # ========================================================================
        # CRITICAL: Post-build wheel cleanup to remove .py and .c source files
        # This is the industry-standard approach for Cython IP protection
        # exclude_package_data doesn't work for .py files (setuptools includes them anyway)
        # ========================================================================
        Write-Info "Protecting IP: removing source .py and .c files from wheel..."
        
        python -c "
import zipfile
import os
import shutil
import glob

# All compiled modules that must be stripped from the wheel
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

# Find the wheel file
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
        Write-Success "Build complete"
        Write-Info "Generated artifacts:"
        Get-ChildItem $DistDir | Format-Table Name, Length, LastWriteTime -AutoSize
    } finally {
        Pop-Location
    }
}

# ============================================================================
# Test Built Package
# ============================================================================
function Invoke-Test {
    Write-Info "Testing built package..."
    
    $WheelFile = Get-ChildItem $DistDir -Filter "*.whl" -File | Select-Object -First 1
    
    if (-not $WheelFile) {
        Write-Error-Custom "No wheel file found in $DistDir"
        exit 1
    }
    
    Write-Info "Testing installation: $($WheelFile.Name)"
    
    # Test import
    python -c "
import sys
import zipfile
with zipfile.ZipFile('$($WheelFile.FullName)', 'r') as z:
    files = z.namelist()
    so_files = [f for f in files if f.endswith('.so') or f.endswith('.pyd')]
    py_files = [f for f in files if f.endswith('.py')]
    print(f'  Wheel contains:')
    print(f'    - {len(py_files)} .py files')
    print(f'    - {len(so_files)} compiled extensions')
    if so_files:
        print('    Compiled modules:')
        for f in so_files[:5]:
            print(f'      - {f}')
"
    
    Write-Success "Package test complete"
}

# ============================================================================
# Build Docker Image
# ============================================================================
function Invoke-BuildDocker {
    Write-Info "Building Docker image..."
    
    Push-Location $ProjectDir
    
    try {
        # Build Docker image with Cython compilation
        docker build `
            --tag "agentcore-tip-mcp:$Version" `
            --tag "agentcore-tip-mcp:latest" `
            .
        
        Write-Success "Docker image built: agentcore-tip-mcp:$Version"
        
        # Show image info
        Write-Info "Image details:"
        docker images agentcore-tip-mcp --format "  {{.Repository}}:{{.Tag}} - {{.Size}}"
    } finally {
        Pop-Location
    }
}

# ============================================================================
# Generate Build Report
# ============================================================================
function Invoke-GenerateReport {
    Write-Info "Generating build report..."
    
    $ReportFile = Join-Path $DistDir "BUILD_REPORT.txt"
    $BuildDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $PythonVersion = python --version
    $Hostname = $env:COMPUTERNAME
    
    $Report = @"
========================================
AgentCore-TIP-MCP-Broker Build Report
========================================
Build Date: $BuildDate
Version: $Version
Python: $PythonVersion
Host: $Hostname
Platform: $(Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption)

========================================
Compiled Extensions
========================================
$(Get-ChildItem -Path (Join-Path $ProjectDir "agentcore_tip/core") -Recurse -Include "*.so","*.pyd" -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } | Out-String)

========================================
Distribution Artifacts
========================================
$(Get-ChildItem $DistDir -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name) ($($_.Length) bytes)" } | Out-String)

========================================
Security Notes
========================================
- Core IP modules compiled to native extensions
- Source code for core modules not included in wheel
- Sign artifacts before distribution with: gpg --detach-sign
========================================
"@
    
    $Report | Out-File -FilePath $ReportFile -Encoding utf8
    
    Write-Success "Build report saved to: $ReportFile"
}

# ============================================================================
# Main Execution
# ============================================================================
Write-Host "========================================"
Write-Host "  AgentCore-TIP-MCP-Broker Build System"
Write-Host "  Version: $Version"
Write-Host "========================================"
Write-Host ""

switch ($Command) {
    "clean" {
        Invoke-Clean
    }
    "compile" {
        Invoke-Compile
    }
    "wheel" {
        Test-Preflight
        Invoke-Clean
        Invoke-Compile
        Invoke-BuildWheel
        Invoke-Test
        Invoke-GenerateReport
    }
    "docker" {
        Invoke-BuildDocker
    }
    "all" {
        Test-Preflight
        Invoke-Clean
        Invoke-Compile
        Invoke-BuildWheel
        Invoke-Test
        Invoke-GenerateReport
    }
    "help" {
        Write-Host "Usage: .\build.ps1 [command]"
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  clean     Clean previous builds"
        Write-Host "  compile   Compile Cython extensions only"
        Write-Host "  wheel     Build distribution wheel (default)"
        Write-Host "  docker    Build Docker image"
        Write-Host "  all       Full build (clean + compile + wheel + test)"
        Write-Host "  help      Show this help message"
    }
}
