"""Assembles the Wireshark plugin zip that ships in a GitHub release.

    python extcap/package-release.py --version v0.1.0 --out dist

The zip is what a user who has never cloned this repository unpacks, so it
has to carry everything the installer needs and nothing that assumes a
repository around it:

    esp32c6-sniffer.py              the plugin
    esp32c6_sniffer-<ver>-*.whl     the package and, through it, pyserial
    install.ps1 / install.sh        the same installers the repository uses
    profiles/                       one Wireshark profile per radio
    README.txt                      how to install, and what to flash first

The installers detect which layout they are running in: a clone has
host/.venv and a release has the wheel beside the script. One pair of
installers rather than two means the path a user takes is the path that gets
exercised during development.

The wheel is built here unless --wheel names one, so running this script in a
clone produces exactly what CI produces from the same commit.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXTCAP = REPO / "extcap"
PROFILES = REPO / "wireshark-profiles"

README = """\
ESP32-C6 / nRF54L15 wireless sniffer -- Wireshark plugin {version}

Install
-------

Windows (PowerShell):

    .\\install.ps1

Linux / macOS:

    ./install.sh

The installer creates a Python environment beside the plugin, installs the
bundled wheel into it, and points Wireshark's launcher at it. Nothing is
installed into your system Python. Python 3.10 or newer must be on PATH.

Then restart Wireshark. The interfaces appear on the welcome screen.

Uninstall with `.\\install.ps1 -Uninstall` or `./install.sh --uninstall`.

Flash a board first
-------------------

The plugin talks to firmware; a board without it enumerates as a serial port
that never answers. Both firmwares are in the same release:

    esp32c6-<ver>.bin        ESP32-C6, flash at 0x0 with esptool
    nrf54l15-<ver>.hex       nRF54L15, flash with openocd

The exact commands are in the release notes.

Sniffing is passive. Neither board transmits.
"""


def build_wheel(out_dir: Path) -> Path:
    """Builds the host package wheel and returns its path."""
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(out_dir),
         str(REPO / "host")],
        check=True,
    )
    wheels = sorted(out_dir.glob("esp32c6_sniffer-*.whl"))
    if not wheels:
        raise SystemExit(f"no wheel appeared in {out_dir}")
    return wheels[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True,
                        help="release version, e.g. v0.1.0; names the zip")
    parser.add_argument("--wheel", type=Path,
                        help="a prebuilt wheel; built here when omitted")
    parser.add_argument("--out", type=Path, default=REPO / "dist",
                        help="directory to write the zip into")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    wheel = args.wheel or build_wheel(args.out)
    if not wheel.is_file():
        raise SystemExit(f"wheel not found: {wheel}")

    # The profiles are what make a capture readable -- without them channel,
    # signal strength and link quality are only visible by clicking into each
    # frame -- so a zip missing them installs something that works and reads
    # badly, which is harder to notice than an outright failure.
    if not PROFILES.is_dir():
        raise SystemExit(f"profiles not found at {PROFILES}")

    zip_path = args.out / f"esp32c6-sniffer-plugin-{args.version}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(EXTCAP / "esp32c6-sniffer.py", "esp32c6-sniffer.py")
        z.write(EXTCAP / "install.ps1", "install.ps1")
        z.write(EXTCAP / "install.sh", "install.sh")
        z.write(wheel, wheel.name)
        for profile_dir in sorted(PROFILES.iterdir()):
            if not profile_dir.is_dir():
                continue
            for item in sorted(profile_dir.iterdir()):
                if item.is_file():
                    z.write(item, f"profiles/{profile_dir.name}/{item.name}")
        z.writestr("README.txt", README.format(version=args.version))

    print(f"wrote {zip_path} ({zip_path.stat().st_size} bytes)")
    for name in zipfile.ZipFile(zip_path).namelist():
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
