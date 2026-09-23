# Installs the extcap plugin into Wireshark's per-user plugin directory.
#
#   .\extcap\install.ps1
#   .\extcap\install.ps1 -Uninstall
#
# Installs to %APPDATA%\Wireshark\extcap rather than the Program Files copy:
# it needs no administrator rights and survives a Wireshark upgrade.
#
# Wireshark executes .bat or .exe from that directory, never .py, so a launcher
# is generated pointing at a Python that has pyserial and this project's
# package. Wireshark's own Python, if any, has neither.
#
# Two layouts run this script and it detects which:
#
#   repository -- host\.venv exists, and the launcher runs the repository's
#                 own plugin script with it. Nothing is copied, so Wireshark
#                 runs what the repository holds, never a snapshot of it.
#   release    -- the script sits in an unpacked release zip beside a wheel.
#                 A virtual environment is created inside the extcap
#                 directory and the wheel installed into it, so the plugin
#                 owns its dependencies and the system Python is untouched.
#
# The release layout has no lib\ directory: the wheel puts the package in the
# environment's site-packages, where a plain import finds it.

param(
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$repo       = Split-Path -Parent $PSScriptRoot
$extcapDir  = Join-Path $env:APPDATA 'Wireshark\extcap'
$pluginName = 'esp32c6-sniffer'
$venvPython = Join-Path $repo 'host\.venv\Scripts\python.exe'
$package    = Join-Path $repo 'host\src\esp32c6_sniffer'

$targetPy   = Join-Path $extcapDir "$pluginName.py"
$targetBat  = Join-Path $extcapDir "$pluginName.bat"
$targetLib  = Join-Path $extcapDir 'lib\esp32c6_sniffer'
$targetVenv = Join-Path $extcapDir "$pluginName-venv"

if ($Uninstall) {
    $profileRoot = Join-Path $env:APPDATA 'Wireshark\profiles'
    $profiles = @('ESP32-C6 802.15.4', 'ESP32-C6 Wi-Fi', 'ESP32-C6 BLE',
                  'ESP32-C6 Sniffer')   # the last is the superseded single one
    $paths = @($targetPy, $targetBat, $targetLib, $targetVenv)
    $paths += $profiles | ForEach-Object { Join-Path $profileRoot $_ }
    foreach ($p in $paths) {
        if (Test-Path $p) { Remove-Item $p -Recurse -Force; Write-Host "removed $p" }
    }
    Write-Host "Uninstalled." -ForegroundColor Green
    return
}

New-Item -ItemType Directory -Force -Path $extcapDir | Out-Null

# The plugin's floor is host/pyproject.toml's requires-python. An older
# interpreter installs without complaint and then fails to load inside
# Wireshark, where nobody sees the error, so it is refused here instead.
function Assert-PythonFloor([string]$exe, [string]$what) {
    & $exe -c "import sys; sys.exit(sys.version_info < (3, 12))"
    if ($LASTEXITCODE -ne 0) {
        $found = (& $exe -c "import sys; print('%d.%d' % sys.version_info[:2])") -join ''
        throw "$what is Python $found; the plugin needs Python 3.12 or newer. Install it from python.org (in a clone, rebuild host\.venv with it), then re-run this script."
    }
}

# Which layout is this? The repository's virtual environment wins where it
# exists, so a developer's install keeps working exactly as before.
$wheel = Get-ChildItem -Path $PSScriptRoot -Filter 'esp32c6_sniffer-*.whl' -ErrorAction SilentlyContinue |
         Select-Object -First 1

if (Test-Path $venvPython) {
    Assert-PythonFloor $venvPython "The project's environment ($venvPython)"
    $interpreter = $venvPython
    $fromWheel = $false
    if (-not (Test-Path $package)) { throw "Package not found at $package" }
    # Installing from a clone over a previous release install leaves that
    # environment behind with nothing pointing at it: a few tens of megabytes
    # that look load-bearing to anyone who finds them later.
    if (Test-Path $targetVenv) {
        Remove-Item $targetVenv -Recurse -Force
        Write-Host "removed the superseded $targetVenv"
    }
} elseif ($wheel) {
    # A release install. Build the environment the plugin will run in, rather
    # than installing into whatever Python happens to be on PATH: Wireshark
    # launches this with no shell and no activated environment, so the
    # interpreter has to be named by absolute path and has to be stable.
    $bootstrap = (Get-Command py, python3, python -ErrorAction SilentlyContinue |
                  Select-Object -First 1).Source
    if (-not $bootstrap) {
        throw "No Python found on PATH. Install Python 3.12 or newer from python.org, then re-run this script."
    }
    Assert-PythonFloor $bootstrap "The Python on PATH ($bootstrap)"
    Write-Host "creating $targetVenv"
    & $bootstrap -m venv $targetVenv
    if ($LASTEXITCODE -ne 0) { throw "could not create a virtual environment at $targetVenv" }
    $interpreter = Join-Path $targetVenv 'Scripts\python.exe'
    & $interpreter -m pip install --quiet --upgrade pip
    & $interpreter -m pip install --quiet $wheel.FullName
    if ($LASTEXITCODE -ne 0) { throw "could not install $($wheel.Name) into $targetVenv" }
    Write-Host "installed $($wheel.Name)"
    $fromWheel = $true
} else {
    throw "Neither a project virtual environment nor a release wheel was found. In a clone: cd host; py -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e `".[dev]`". From a release: run this script from the unpacked zip, which carries the wheel beside it."
}

# Neither layout copies the package any more. An older development install
# put one in lib\, first on the plugin's import path, and nothing refreshed it:
# a bench was found running host code eleven days behind its own repository.
# Left in place, that copy would go on shadowing whatever is current.
if (Test-Path $targetLib) {
    Remove-Item $targetLib -Recurse -Force
    Write-Host "removed the superseded $targetLib"
}
$libDir = Split-Path -Parent $targetLib
if ((Test-Path $libDir) -and -not (Get-ChildItem $libDir -Force)) { Remove-Item $libDir }

if ($fromWheel) {
    # A release has no repository to point at. The plugin goes beside the
    # launcher, and the package is in the environment's site-packages.
    Copy-Item (Join-Path $PSScriptRoot "$pluginName.py") $targetPy -Force
    Write-Host "installed $targetPy"
    $launchScript = '%~dp0' + "$pluginName.py"
} else {
    # A development install runs the repository's own script, which finds
    # host\src beside it, so Wireshark always runs what the repository holds.
    if (Test-Path $targetPy) {
        Remove-Item $targetPy -Force
        Write-Host "removed the superseded $targetPy"
    }
    $launchScript = Join-Path $PSScriptRoot "$pluginName.py"
}

@"
@echo off
rem Generated by extcap\install.ps1. Re-run that script to regenerate.
"$interpreter" "$launchScript" %*
"@ | Set-Content -Path $targetBat -Encoding ascii
Write-Host "installed $targetBat"

# Wireshark configuration profiles: columns for the radio metadata, colouring
# rules and filter buttons. Without them a capture is dissected correctly but
# reads poorly, since channel, signal strength and link quality are only
# visible by clicking into each frame.
#
# One per radio, because a filter button belongs to the profile rather than to
# the interface: a single shared profile put Zigbee, Thread and 11ax buttons
# on a BLE capture, where none of them can ever match. Each carries an
# auto_switch_filter naming its own interface, so the right one selects itself.
$profileRoot = Join-Path $env:APPDATA 'Wireshark\profiles'

# The superseded single profile matched every interface, so leaving it in
# place would have it competing with all three.
$old = Join-Path $profileRoot 'ESP32-C6 Sniffer'
if (Test-Path $old) {
    Remove-Item $old -Recurse -Force
    Write-Host "removed the superseded '$old'"
}

# A clone keeps them at the top level; a release zip carries them beside this
# script, because the zip has no repository around it.
$profilesSrc = Join-Path $repo 'wireshark-profiles'
if (-not (Test-Path $profilesSrc)) {
    $profilesSrc = Join-Path $PSScriptRoot 'profiles'
}
if (Test-Path $profilesSrc) {
    foreach ($dir in Get-ChildItem $profilesSrc -Directory) {
        $dst = Join-Path $profileRoot $dir.Name
        New-Item -ItemType Directory -Force -Path $dst | Out-Null
        Copy-Item (Join-Path $dir.FullName '*') $dst -Force
        Write-Host "installed $dst"
    }
}

Write-Host ""
Write-Host "Installed. Verify with:" -ForegroundColor Green
Write-Host '  & "C:\Program Files\Wireshark\tshark.exe" -D'
Write-Host "Then restart Wireshark; the interface appears on the welcome screen."
Write-Host ""
Write-Host "A profile per radio is installed, and the matching one selects itself"
Write-Host "for each capture, so its filter buttons are the ones that can match."
Write-Host "If it does not, right-click the profile area at the bottom-right of"
Write-Host "Wireshark's status bar and choose it."
Write-Host "Enable the toolbar: View menu, Interface Toolbars."
