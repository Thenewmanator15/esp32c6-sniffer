# Flashes the board, bypassing esptool's differential write.
#
#   .\flash.ps1              # defaults to COM3
#   .\flash.ps1 -Port COM7
#
# Why this exists: `idf.py flash` performs a differential write, which READS
# existing flash to compare before writing. On this board that read fails with
# "Packet content transfer stopped". Plain writes are unaffected, and the same
# failure appears with `esptool read-flash` unless --no-stub is used, so the
# fault is in the stub loader's read path over USB-Serial-JTAG rather than in
# ESP-IDF. Writing without the diff is reliable and barely slower here.
#
# Run `idf.py build` first; this only flashes.

param(
    [string]$Port = "COM3",
    [int]$Baud = 460800
)

$ErrorActionPreference = 'Stop'

# The ESP-IDF python, taken from the environment export.ps1 sets up. A
# hardcoded path here tied this script to one machine's disk layout.
$py = $null
if ($env:IDF_PYTHON_ENV_PATH) {
    foreach ($rel in @('Scripts\python.exe', 'bin/python')) {
        $candidate = Join-Path $env:IDF_PYTHON_ENV_PATH $rel
        if (Test-Path $candidate) { $py = $candidate; break }
    }
}
if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source }
if (-not $py) { throw "ESP-IDF python not found. Run '. .\idf-env.ps1' first." }

$build = Join-Path $PSScriptRoot 'build'
foreach ($f in @(
    "$build\bootloader\bootloader.bin",
    "$build\partition_table\partition-table.bin",
    "$build\esp32c6_sniffer.bin")) {
    if (-not (Test-Path $f)) { throw "missing $f - run 'idf.py build' first" }
}

# esptool writes its progress bars to stderr. If a caller merges stderr into
# the pipeline (2>&1) while ErrorActionPreference is 'Stop', PowerShell turns
# those progress lines into terminating errors and the flash appears to fail
# despite succeeding. Relax the preference across the native call only.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

# Retry, because a board already streaming at full rate can drown esptool's
# sync handshake. Each attempt resets the chip first, and the benchmark
# firmware stays quiet for a few seconds after boot to leave room for this.
$code = 1
for ($attempt = 1; $attempt -le 3; $attempt++) {
    if ($attempt -gt 1) {
        Write-Host "  flash attempt $attempt..." -ForegroundColor Yellow
        Start-Sleep -Milliseconds 800
    }
    & $py -m esptool --chip esp32c6 -p $Port -b $Baud `
        --before default-reset --after hard-reset `
        write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m `
        0x0     "$build\bootloader\bootloader.bin" `
        0x8000  "$build\partition_table\partition-table.bin" `
        0x10000 "$build\esp32c6_sniffer.bin"
    $code = $LASTEXITCODE
    if ($code -eq 0) { break }
}

$ErrorActionPreference = $prevEap

if ($code -ne 0) {
    throw "flash failed after 3 attempts (esptool exit $code). Hold BOOT, tap RESET, release BOOT, then retry."
}
Write-Host "Flashed $Port" -ForegroundColor Green
