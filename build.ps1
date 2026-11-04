param(
    [Parameter(Position=0)]
    [ValidateSet("all", "clean", "wheel", "help")]
    [string]$Command = "all"
)

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$DistDir = Join-Path $ProjectDir "dist"

function Invoke-Clean {
    foreach ($Path in @($DistDir, (Join-Path $ProjectDir "build"), (Join-Path $ProjectDir "agentcore_tip_mcp.egg-info"))) {
        if (Test-Path $Path) {
            Remove-Item -Recurse -Force $Path
        }
    }
}

function Invoke-Wheel {
    Push-Location $ProjectDir
    try {
        python -m pip install --upgrade build
        if ($LASTEXITCODE -ne 0) { throw "Could not install the Python build frontend." }
        python -m build --wheel --outdir $DistDir
        if ($LASTEXITCODE -ne 0) { throw "Wheel build failed." }
    } finally {
        Pop-Location
    }
}

switch ($Command) {
    "clean" { Invoke-Clean }
    "wheel" { Invoke-Wheel }
    "all" {
        Invoke-Clean
        Invoke-Wheel
    }
    "help" {
        Write-Host "Usage: .\build.ps1 [all|clean|wheel|help]"
        Write-Host "Build a pure-Python wheel into dist/."
    }
}
