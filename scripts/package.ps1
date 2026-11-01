param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
Push-Location $project
try {
    if (-not $SkipBuild) {
        & (Join-Path $PSScriptRoot 'build.ps1')
        if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    }
    $manifest = & cargo metadata --locked --format-version 1 --no-deps | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read package metadata' }
    $version = ($manifest.packages | Where-Object name -eq 'age-desktop').version
    $zip = Join-Path $project "age-desktop-$version-windows-x64.zip"
    if (Test-Path -LiteralPath $zip) { throw "Package already exists; preserve this release: $zip" }
    $dist = Join-Path $project "dist\$version"
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $project 'target\release\age-desktop.exe') -Destination $dist
    foreach ($name in @('age-engine.exe','age-inspect.exe','age-plugin-pq.exe','age-plugin-tag.exe','age-plugin-tagpq.exe')) {
        Copy-Item -LiteralPath (Join-Path $project "target\release\$name") -Destination $dist
    }
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
    Push-Location (Join-Path $project 'engine')
    try {
        $goModules = & go list -mod=readonly -m -f '{{.Path}}|{{.Version}}|{{.Dir}}' all
        if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate Go module notices' }
        $goModules | ForEach-Object { $entry=$_ -split '\|',3; "$($entry[0]) $($entry[1])" } | Set-Content -LiteralPath (Join-Path $licenses 'go-module-inventory.txt')
        foreach ($module in $goModules) {
            $parts = $module -split '\|',3
            if ($parts.Count -ne 3 -or -not $parts[2]) { continue }
            $name = ($parts[0] -replace '[/\\:]','_') + '-' + $parts[1]
            $destination = Join-Path $licenses $name
            New-Item -ItemType Directory -Path $destination -Force | Out-Null
            Get-ChildItem -LiteralPath $parts[2] -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE|PATENTS)' } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination }
        }
        $goRoot = (& go env GOROOT).Trim()
        Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') -Destination (Join-Path $licenses 'Go-standard-library-LICENSE')
    } finally { Pop-Location }
    Copy-Item -LiteralPath (Join-Path $project 'engine\AGE-LICENSE.txt') -Destination $licenses
    $checksums = Get-ChildItem -LiteralPath $dist -Filter '*.exe' | ForEach-Object { $digest=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); "$digest  $($_.Name)" }
    $checksums | Set-Content -LiteralPath (Join-Path $dist 'SHA256SUMS.txt')
    # ZIP timestamps cannot represent earlier years. Normalize only staged copies.
    Get-ChildItem -LiteralPath $dist -Recurse -File | Where-Object LastWriteTime -lt ([datetime]'1980-01-01') | ForEach-Object { $_.LastWriteTime=[datetime]'1980-01-01' }
    Compress-Archive -Path (Join-Path $dist '*') -DestinationPath $zip
    Get-FileHash -LiteralPath $zip,(Join-Path $dist 'age-desktop.exe') -Algorithm SHA256 | Format-Table -AutoSize
} finally { Pop-Location }
