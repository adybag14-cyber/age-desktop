param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Push-Location $project
try {
    if (-not $SkipBuild) {
        & cargo build --release --locked
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    }
    $dist = Join-Path $project 'dist'
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $project 'target\release\age-desktop.exe') -Destination $dist
    Copy-Item -LiteralPath (Join-Path $project 'README.md'),(Join-Path $project 'LICENSE') -Destination $dist
    Copy-Item -LiteralPath (Join-Path $project 'docs') -Destination $dist -Recurse -Force
    $licenses = Join-Path $dist 'licenses'
    New-Item -ItemType Directory -Path $licenses -Force | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $project 'licenses') -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $licenses }
    $metadata = & cargo metadata --locked --format-version 1 | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate dependency notices' }
    foreach ($package in $metadata.packages) {
        $source = Split-Path -Parent $package.manifest_path
        $destination = Join-Path $licenses "$($package.name)-$($package.version)"
        $notices = @(Get-ChildItem -LiteralPath $source -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE|UNLICENSE|COPYRIGHT)' })
        if ($notices.Count) {
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
            foreach ($notice in $notices) { Copy-Item -LiteralPath $notice.FullName -Destination $destination }
        }
        if ($package.name -eq 'shadcn_iced_core') {
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
            Get-ChildItem -LiteralPath (Join-Path $source 'assets\fonts') -Filter '*LICENSE*' | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination }
        }
    }
    $metadata.packages | Select-Object name,version,license,repository | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $licenses 'dependency-inventory.json')
    $zip = Join-Path $project 'age-desktop-0.1.0-windows-x64.zip'
    if (Test-Path -LiteralPath $zip) { throw "Package already exists; preserve it or choose a new release version: $zip" }
    Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip
    Get-FileHash -LiteralPath $zip,(Join-Path $dist 'age-desktop.exe') -Algorithm SHA256 | Format-Table -AutoSize
} finally { Pop-Location }
