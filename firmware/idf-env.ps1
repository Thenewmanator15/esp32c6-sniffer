# Activates ESP-IDF v6.1 for this project.
#
#   . .\idf-env.ps1          then   idf.py build
#
# Dot-source it; running it normally would set the variables in a child scope
# that vanishes on exit.
#
# The toolchain lives on the dev drive per H:\dev\README.md, which designates
# H:\dev\tools for development toolchains. IDF_TOOLS_PATH matches the value
# H:\dev\setup-caches.ps1 sets, so this does not fight that script.

$ErrorActionPreference = 'Stop'

$IdfToolsPath = 'H:\dev\tools\.espressif'
$IdfPath      = 'H:\dev\tools\.espressif\v6.1\esp-idf'

if (-not (Test-Path $IdfPath)) {
    throw "ESP-IDF not found at $IdfPath. Install with: eim install -i v6.1"
}

$env:IDF_TOOLS_PATH = $IdfToolsPath
$env:IDF_PATH       = $IdfPath

& "$IdfPath\export.ps1"

Write-Host ""
Write-Host "ESP-IDF ready." -ForegroundColor Green
Write-Host "  IDF_PATH       $env:IDF_PATH"
Write-Host "  IDF_TOOLS_PATH $env:IDF_TOOLS_PATH"
Write-Host "  target         esp32c6"
Write-Host "  board port     COM3"
