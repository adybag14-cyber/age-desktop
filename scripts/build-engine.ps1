param([switch]$Tests)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$engineOutput = Join-Path $project 'target\engine'
New-Item -ItemType Directory -Path $engineOutput -Force | Out-Null
Push-Location (Join-Path $project 'engine')
try {
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Go module verification failed' }
    $targets = [ordered]@{
        'age-engine.exe' = '.'
        'age-inspect.exe' = 'filippo.io/age/cmd/age-inspect'
        'age-plugin-pq.exe' = 'filippo.io/age/extra/age-plugin-pq'
        'age-plugin-tag.exe' = 'filippo.io/age/extra/age-plugin-tag'
        'age-plugin-tagpq.exe' = 'filippo.io/age/extra/age-plugin-tagpq'
    }
    foreach ($target in $targets.GetEnumerator()) {
        & go build -mod=readonly -buildvcs=false -trimpath '-ldflags=-s -w -H=windowsgui' -o (Join-Path $engineOutput $target.Key) $target.Value
        if ($LASTEXITCODE -ne 0) { throw "Engine build failed: $($target.Key)" }
    }
    if ($Tests) {
        & go build -mod=readonly -buildvcs=false -trimpath '-ldflags=-s -w -H=windowsgui' -o (Join-Path $project 'target\testplugin\age-plugin-desktoptest.exe') './testplugin'
        if ($LASTEXITCODE -ne 0) { throw 'Test plugin build failed' }
    }
    $release = Join-Path $project 'target\release'
    New-Item -ItemType Directory -Path $release -Force | Out-Null
    foreach ($name in $targets.Keys) { Copy-Item -LiteralPath (Join-Path $engineOutput $name) -Destination $release }
    Write-Output 'Pinned official age 1.3.2 engine, inspector, and compatibility plugins built.'
} finally { Pop-Location }
