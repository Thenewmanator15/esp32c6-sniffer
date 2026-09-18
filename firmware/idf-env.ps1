# Activates ESP-IDF for this project.
#
#   . .\idf-env.ps1                              # finds a v6.1 install
#   . .\idf-env.ps1 -IdfPath D:\esp\esp-idf      # or say where it is
#
# Dot-source it; running it normally would set the variables in a child scope
# that vanishes on exit.
#
# ESP-IDF v6.1 or later. On v6.0.2 this board's Wi-Fi receiver hears nothing
# even with the RF switch driven correctly -- measured, and written up in
# docs/2026-09-05-wifi-investigation-postmortem.md.

param(
    [string]$IdfPath = $env:IDF_PATH,
    [string]$IdfToolsPath = $env:IDF_TOOLS_PATH
)

$ErrorActionPreference = 'Stop'

# A machine whose toolchain is somewhere unusual says so here rather than in
# this file. Not tracked, so it never becomes somebody else's broken path:
#
#   firmware\idf-env.local.ps1
#   $LocalIdfPath = 'D:\path\to\esp-idf'
#
$local = Join-Path $PSScriptRoot 'idf-env.local.ps1'
if (Test-Path $local) { . $local }

# Where ESP-IDF usually ends up. `eim` and the ESP-IDF Installer use the first
# few; the rest are what a manual clone into the documented location gives.
# An explicit -IdfPath, IDF_PATH, or the local override wins over all of them.
$candidates = @(
    $IdfPath,
    $LocalIdfPath,
    "$env:USERPROFILE\esp\v6.1\esp-idf",
    "$env:USERPROFILE\esp\esp-idf",
    "$env:USERPROFILE\.espressif\v6.1\esp-idf",
    "C:\Espressif\frameworks\esp-idf-v6.1",
    "$HOME/esp/v6.1/esp-idf",
    "$HOME/esp/esp-idf"
) | Where-Object { $_ }

$found = $candidates |
    Where-Object { Test-Path (Join-Path $_ 'export.ps1') } |
    Select-Object -First 1

if (-not $found) {
    $looked = ($candidates | ForEach-Object { "  $_" }) -join [Environment]::NewLine
    throw @"
ESP-IDF not found. Looked in:
$looked

Install it (eim install -i v6.1, or the ESP-IDF Installer), then either set
IDF_PATH or say where it is:  . .\idf-env.ps1 -IdfPath <path to esp-idf>
"@
}

# ESP-IDF's own default when unset, and where its installers put the tools.
if (-not $IdfToolsPath) { $IdfToolsPath = "$env:USERPROFILE\.espressif" }

# Checked here because export.ps1 does not check it in a way anyone can read.
# A tools path that is missing, or present and empty, produces this:
#
#   ERROR: ESP-IDF Python virtual environment
#   "<IDF_TOOLS_PATH>\python_env\idf6.1_py3.13_env\Scripts\python.exe"
#   not found.
#   InvalidOperation: ...\export.ps1:20
#
# which names a path and a PowerShell line number and neither of the two
# things actually wrong: that the drive in that path no longer exists, and
# that IDF_TOOLS_PATH said something else for the user account than it did in
# the shell asking. A process inherits its environment when it starts, so a
# terminal opened before the variable changed carries the old value forever.
#
# Reported rather than corrected. Preferring the user account's value would
# fix the stale shell and break the deliberate one -- a second tools
# directory set for this shell on purpose is a thing people do -- and this
# script has said since it was written that an explicit value wins.
$toolsReady = (Test-Path $IdfToolsPath) -and
              (Test-Path (Join-Path $IdfToolsPath 'python_env'))
if (-not $toolsReady) {
    $why = if (Test-Path $IdfToolsPath) {
        "That directory exists but holds no python_env, so nothing is installed in it."
    } else {
        "That directory does not exist."
    }

    # Only when the path came from the environment. Said about a path given
    # as -IdfToolsPath it would be talking about a shell that had nothing to
    # do with it, which is the kind of confident wrong answer this whole
    # check exists to stop.
    $fromEnvironment = $IdfToolsPath -eq $env:IDF_TOOLS_PATH
    $userValue = [Environment]::GetEnvironmentVariable('IDF_TOOLS_PATH', 'User')
    $stale = ""
    if ($fromEnvironment -and $userValue -and $userValue -ne $IdfToolsPath) {
        $stale = @"


IDF_TOOLS_PATH is '$IdfToolsPath' in this shell and '$userValue' for your
user account. A process keeps the environment it started with, so a terminal
-- or an application -- opened before that variable changed still carries the
old one. Restarting it is the whole fix.
"@
    }

    throw @"
ESP-IDF tools not found at:
  $IdfToolsPath

$why$stale

Install them for this project's target:
  & "$found\install.ps1" esp32c6

Or point somewhere they already are:  . .\idf-env.ps1 -IdfToolsPath <path>
"@
}

$env:IDF_PATH       = $found
$env:IDF_TOOLS_PATH = $IdfToolsPath

& "$found\export.ps1"

Write-Host ""
Write-Host "ESP-IDF ready." -ForegroundColor Green
Write-Host "  IDF_PATH       $env:IDF_PATH"
Write-Host "  IDF_TOOLS_PATH $env:IDF_TOOLS_PATH"
Write-Host "  target         esp32c6"
