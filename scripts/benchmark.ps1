param([int]$Runs = 3, [string]$Executable = '')
$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
if (-not $Executable) { $Executable = Join-Path $project 'target\release\age-desktop.exe' }
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$root = Join-Path $project "evidence\launch-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$measurements = @()
foreach ($renderer in @('cpu', 'gpu', 'auto')) {
    for ($run = 1; $run -le $Runs; $run++) {
        $output = Join-Path $root "$renderer-$run"
        $watch = [Diagnostics.Stopwatch]::StartNew()
        # This is a visible desktop app requested by the user, with an automatic
        # diagnostic exit. No unrelated processes are controlled by this script.
        $process = Start-Process -FilePath $Executable -ArgumentList @('--renderer', $renderer, '--probe', ('"' + $output + '"')) -PassThru
        $frame = Join-Path $output 'first-frame-ms.txt'
        while (-not (Test-Path -LiteralPath $frame) -and -not $process.HasExited -and $watch.Elapsed.TotalSeconds -lt 45) { Start-Sleep -Milliseconds 10; $process.Refresh() }
        $observed = $watch.Elapsed.TotalMilliseconds
        $identity = Get-CimInstance Win32_Process -Filter "ProcessId = $($process.Id)"
        $identity | Select-Object ProcessId,ParentProcessId,ExecutablePath,CreationDate,CommandLine | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root "$renderer-$run-process.json")
        if (-not $process.WaitForExit(15000)) { throw "Probe did not exit: PID $($process.Id). Ownership is recorded; no process was killed." }
        if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $frame)) { throw "Probe failed for $renderer run $run (exit $($process.ExitCode))" }
        $measurement = [pscustomobject]@{
            renderer = $renderer; run = $run
            first_redraw_ms = [double](Get-Content -LiteralPath $frame)
            launch_to_observed_redraw_ms = [math]::Round($observed, 3)
            capture_ms = [double](Get-Content -LiteralPath (Join-Path $output 'capture-ms.txt'))
            renderer_info = (Get-Content -LiteralPath (Join-Path $output 'renderer.txt') -Raw).Trim()
        }
        $measurements += $measurement
        $measurement | Select-Object renderer,run,first_redraw_ms,launch_to_observed_redraw_ms,capture_ms | Format-Table
    }
}
$measurements | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'results.json')
Write-Output "Evidence: $root"
