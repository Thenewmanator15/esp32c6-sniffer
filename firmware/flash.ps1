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

$py = "H:\dev\tools\.espressif\python_env\idf6.1_py3.14_env\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "ESP-IDF python not found at $py" }

$build = Join-Path $PSScriptRoot 'build'
foreach ($f in @(
    "$build\bootloader\bootloader.bin",
    "$build\partition_table\partition-table.bin",
    "$build\esp32c6_sniffer.bin")) {
    if (-not (Test-Path $f)) { throw "missing $f - run 'idf.py build' first" }
}

& $py -m esptool --chip esp32c6 -p $Port -b $Baud `
    --before default-reset --after hard-reset `
    write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m `
    0x0     "$build\bootloader\bootloader.bin" `
    0x8000  "$build\partition_table\partition-table.bin" `
    0x10000 "$build\esp32c6_sniffer.bin"

if ($LASTEXITCODE -ne 0) {
    throw "flash failed. Hold BOOT, tap RESET, release BOOT, then retry."
}
Write-Host "Flashed $Port" -ForegroundColor Green
