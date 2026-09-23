#!/usr/bin/env bash
# Installs the extcap plugin into Wireshark's per-user plugin directory.
#
#   ./extcap/install.sh
#   ./extcap/install.sh --uninstall
#
# The Windows counterpart is install.ps1. This one covers Linux and macOS,
# where the differences are real rather than cosmetic:
#
#   * Wireshark executes any executable file in the extcap directory, so no
#     .bat launcher is needed -- but the entry point must name THIS project's
#     virtualenv, because the plugin needs pyserial and the system python
#     almost certainly lacks it. A small wrapper script does that. In a clone
#     it runs the repository's own plugin script, so Wireshark never runs a
#     stale copy; a release, having no repository, gets the script beside it.
#   * Serial ports belong to a group. On most Linux distributions that is
#     dialout, on Arch it is uucp; without membership the board is present and
#     unopenable, which looks exactly like a broken plugin. Checked and
#     reported rather than silently assumed.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
plugin_name="esp32c6-sniffer"

# Wireshark reads the same location on Linux and macOS. XDG_CONFIG_HOME wins
# where it is set, which is how a user with a non-default config directory
# ends up with a plugin Wireshark never looks at.
config="${XDG_CONFIG_HOME:-$HOME/.config}/wireshark"
extcap_dir="$config/extcap"
profile_dir="$config/profiles"

venv_python="$repo/host/.venv/bin/python"
package="$repo/host/src/esp32c6_sniffer"

target_sh="$extcap_dir/$plugin_name"
target_py="$extcap_dir/$plugin_name.py"
target_lib="$extcap_dir/lib/esp32c6_sniffer"
target_venv="$extcap_dir/$plugin_name-venv"

profiles=("ESP32-C6 802.15.4" "ESP32-C6 Wi-Fi" "ESP32-C6 BLE" "ESP32-C6 Sniffer")

if [[ "${1:-}" == "--uninstall" ]]; then
    for path in "$target_sh" "$target_py" "$target_lib" "$target_venv"; do
        if [[ -e "$path" ]]; then rm -rf "$path"; echo "removed $path"; fi
    done
    for name in "${profiles[@]}"; do
        if [[ -e "$profile_dir/$name" ]]; then
            rm -rf "$profile_dir/$name"
            echo "removed $profile_dir/$name"
        fi
    done
    echo "Uninstalled."
    exit 0
fi

mkdir -p "$extcap_dir"

# Two layouts run this script and it detects which. A clone has the project's
# virtual environment and wins where it exists, so a developer's install is
# unchanged. A release zip has a wheel beside this script instead, and gets an
# environment of its own inside the extcap directory -- Wireshark launches the
# plugin with no shell and nothing activated, so the interpreter has to be
# named by absolute path and has to stay put.
wheel="$(ls "$here"/esp32c6_sniffer-*.whl 2>/dev/null | head -n1 || true)"
from_wheel=0

# The plugin's floor is host/pyproject.toml's requires-python. An older
# interpreter installs without complaint and then fails to load inside
# Wireshark, where nobody sees the error, so it is refused here instead.
require_python_floor() {
    if ! "$1" -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
        echo "$2 is $("$1" -V 2>&1); the plugin needs Python 3.12 or newer." >&2
        echo "Install it (in a clone, rebuild host/.venv with it), then re-run." >&2
        exit 1
    fi
}

if [[ -x "$venv_python" ]]; then
    require_python_floor "$venv_python" "The project's environment ($venv_python)"
    interpreter="$venv_python"
    [[ -d "$package" ]] || { echo "Package not found at $package" >&2; exit 1; }
    # Installing from a clone over a previous release install leaves that
    # environment behind with nothing pointing at it: a few tens of megabytes
    # that look load-bearing to anyone who finds them later.
    if [[ -d "$target_venv" ]]; then
        rm -rf "$target_venv"
        echo "removed the superseded $target_venv"
    fi
elif [[ -n "$wheel" ]]; then
    bootstrap="$(command -v python3 || command -v python || true)"
    if [[ -z "$bootstrap" ]]; then
        echo "No python3 found on PATH. Install Python 3.12 or newer, then re-run." >&2
        exit 1
    fi
    require_python_floor "$bootstrap" "The Python on PATH ($bootstrap)"
    echo "creating $target_venv"
    "$bootstrap" -m venv "$target_venv"
    interpreter="$target_venv/bin/python"
    "$interpreter" -m pip install --quiet --upgrade pip
    "$interpreter" -m pip install --quiet "$wheel"
    echo "installed $(basename "$wheel")"
    from_wheel=1
else
    echo "Neither a project virtual environment nor a release wheel was found." >&2
    echo "In a clone:" >&2
    echo "  cd $repo/host && python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'" >&2
    echo "From a release: run this script from the unpacked zip, which carries the wheel beside it." >&2
    exit 1
fi

# Neither layout copies the package any more. An older development install
# put one in lib/, first on the plugin's import path, and nothing refreshed it:
# a bench was found running host code eleven days behind its own repository.
# Left in place, that copy would go on shadowing whatever is current.
if [[ -e "$target_lib" ]]; then
    rm -rf "$target_lib"
    echo "removed the superseded $target_lib"
fi
rmdir "$extcap_dir/lib" 2>/dev/null || true

if [[ "$from_wheel" -eq 1 ]]; then
    # A release has no repository to point at. The plugin goes beside the
    # wrapper, and the package is in the environment's site-packages.
    cp "$here/$plugin_name.py" "$target_py"
    echo "installed $target_py"
    launch_script="\$(dirname \"\$0\")/$plugin_name.py"
else
    # A development install runs the repository's own script, which finds
    # host/src beside it, so Wireshark always runs what the repository holds.
    if [[ -e "$target_py" ]]; then
        rm -f "$target_py"
        echo "removed the superseded $target_py"
    fi
    launch_script="$here/$plugin_name.py"
fi

# Wireshark runs executables from this directory, so the entry point is a
# wrapper naming the interpreter explicitly.
cat > "$target_sh" <<WRAPPER
#!/bin/sh
# Generated by extcap/install.sh. Re-run that script to regenerate.
exec "$interpreter" "$launch_script" "\$@"
WRAPPER
chmod +x "$target_sh"
echo "installed $target_sh"

# One configuration profile per radio. Each carries an auto_switch_filter
# naming its own interface, so the right one selects itself and its filter
# buttons are the ones that can match.
old="$profile_dir/ESP32-C6 Sniffer"
if [[ -e "$old" ]]; then
    rm -rf "$old"
    echo "removed the superseded $old"
fi
# A clone keeps them at the top level; a release zip carries them beside this
# script, because the zip has no repository around it.
profiles_src="$repo/wireshark-profiles"
[[ -d "$profiles_src" ]] || profiles_src="$here/profiles"
if [[ -d "$profiles_src" ]]; then
    for dir in "$profiles_src"/*/; do
        name="$(basename "$dir")"
        mkdir -p "$profile_dir/$name"
        cp "$dir"* "$profile_dir/$name/"
        echo "installed $profile_dir/$name"
    done
fi

echo
echo "Installed. Verify with:"
echo "  tshark -D"
echo "Then restart Wireshark; the interfaces appear on the welcome screen."

# Serial permissions. A board that is present but unopenable looks exactly
# like a broken plugin, and the fix is not discoverable from the error.
if [[ "$(uname)" == "Linux" ]]; then
    port="$(ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null | head -n1 || true)"
    if [[ -n "$port" && ! -r "$port" ]]; then
        group="$(stat -c '%G' "$port")"
        echo
        echo "WARNING: $port belongs to group '$group' and you are not in it."
        echo "The board will be visible and impossible to open. Fix with:"
        echo "  sudo usermod -aG $group \$USER"
        echo "then log out and back in -- a new shell is not enough."
    fi
fi
