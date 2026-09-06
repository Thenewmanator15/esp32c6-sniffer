# Measures sustained USB throughput across payload sizes.
#
#   . .\idf-env.ps1
#   .\bench-sweep.ps1
#
# For each payload size this rebuilds the benchmark firmware, flashes it, and
# runs the host-side measurement. Results go to bench-results.json and a
# summary table is printed.
#
# Throughput is expected to rise with payload size as the 10-byte frame header
# amortises. The point of the sweep is to find where that curve flattens, which
# tells us how much of the link the header overhead is costing.

param(
    [string]$Port = "COM3",
    [double]$Seconds = 20.0,
    [int[]]$Payloads = @(64, 128, 256, 512, 1024, 1500)
)

$ErrorActionPreference = 'Stop'

if (-not $env:IDF_PATH) { throw "Run '. .\idf-env.ps1' first." }

# Resolved from this script's own location, so a clone anywhere works.
$hostRoot = Join-Path $PSScriptRoot '..\host'
$hostPy = $null
foreach ($rel in @('.venv\Scripts\python.exe', '.venv/bin/python')) {
    $candidate = Join-Path $hostRoot $rel
    if (Test-Path $candidate) { $hostPy = $candidate; break }
}
if (-not $hostPy) {
    throw "host venv not found under $hostRoot - create it, then 'pip install -e .'"
}

$results = @()

foreach ($n in $Payloads) {
    Write-Host ""
    Write-Host "=== payload $n bytes ===" -ForegroundColor Cyan

    # No 2>&1 here. Both tools write progress to stderr, and merging it into
    # the pipeline turns those lines into terminating errors.
    idf.py -DSN_MODE=1 "-DSN_BENCH_PAYLOAD=$n" build | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "build failed for payload $n" }

    & "$PSScriptRoot\flash.ps1" -Port $Port | Out-Null

    # The benchmark firmware stays quiet for 5 s after boot so esptool can
    # reflash it. Wait past that window before measuring, or the first seconds
    # of the sample would be idle and understate throughput.
    Start-Sleep -Seconds 7

    $raw = & $hostPy -m esp32c6_sniffer.benchmark --port $Port --seconds $Seconds
    $row = @{ payload = $n }
    foreach ($line in $raw) {
        if ($line -match '^\s*(\S+)\s+(\S+)\s*$') { $row[$Matches[1]] = $Matches[2] }
    }
    $results += [pscustomobject]$row
    Write-Host ("  {0} kB/s payload, {1} frames/s, {2} missed" -f `
        $row.payload_kB_per_s, $row.frames_per_s, $row.frames_missed_host_side)
}

$out = Join-Path $PSScriptRoot 'bench-results.json'
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding utf8

Write-Host ""
Write-Host "=== summary ===" -ForegroundColor Green
$results | Format-Table payload, payload_kB_per_s, wire_kB_per_s, frames_per_s,
    frames_missed_host_side, fw_tx_stalls, fw_short_writes -AutoSize
Write-Host "written to $out"
