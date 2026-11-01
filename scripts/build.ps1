param([switch]$Test)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'build-engine.ps1') -Tests:$Test
Push-Location $project
try {
    & cargo build --release --locked -j 8
    if ($LASTEXITCODE -ne 0) { throw 'Rust GUI build failed' }
    if ($Test) {
        & cargo test --release --locked -j 8
        if ($LASTEXITCODE -ne 0) { throw 'Rust integration tests failed' }
        Push-Location engine
        try { & go test ./...; if ($LASTEXITCODE -ne 0) { throw 'Engine tests failed' } } finally { Pop-Location }
    }
} finally { Pop-Location }
