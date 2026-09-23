"""A development install must run the repository, not a snapshot of it.

The installer once copied the plugin script and the whole host package into
Wireshark's extcap directory, and the copy put its own lib/ first on the
import path. Nothing refreshed it afterwards. Measured on 2026-09-23: the
Wireshark on this bench was running host code from 2026-09-12, eleven days
and every fix since behind the repository, while the test suite and every
bench run -- which use the repository directly -- said all was well.

A development install now generates a launcher that runs the repository's
own script, which finds host/src beside it; nothing is copied, and the copies
an older install left are removed, so a stale package cannot shadow the live
one. A release install is untouched by this: it has no repository to point at.

This runs the real installer into a throwaway APPDATA, so it needs the
Windows installer, PowerShell and the project's own virtual environment --
which CI does not create. It skips there rather than pretend.
"""

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
VENV_PYTHON = REPO / "host" / ".venv" / "Scripts" / "python.exe"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

pytestmark = pytest.mark.skipif(
    os.name != "nt" or not VENV_PYTHON.exists() or POWERSHELL is None,
    reason="needs Windows, PowerShell and host/.venv (a development checkout)")


@pytest.fixture
def installed(tmp_path):
    """Install into a throwaway APPDATA that already holds an old copy-style
    install's leftovers, and return the extcap directory."""
    extcap = tmp_path / "Wireshark" / "extcap"
    stale_lib = extcap / "lib" / "esp32c6_sniffer"
    stale_lib.mkdir(parents=True)
    (stale_lib / "__init__.py").write_text("STALE = True\n")
    (extcap / "esp32c6-sniffer.py").write_text("# a stale copy\n")

    env = dict(os.environ, APPDATA=str(tmp_path))
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(REPO / "extcap" / "install.ps1")],
        env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return extcap


def test_the_launcher_runs_the_repositorys_own_script(installed):
    launcher = (installed / "esp32c6-sniffer.bat").read_text()
    assert str(REPO / "extcap" / "esp32c6-sniffer.py") in launcher, launcher


def test_nothing_is_copied_and_the_old_copies_are_gone(installed):
    assert not (installed / "esp32c6-sniffer.py").exists()
    assert not (installed / "lib").exists()


def test_the_launcher_actually_starts_the_plugin(installed):
    """Wireshark's first call to any extcap: list your interfaces."""
    result = subprocess.run(
        ["cmd", "/c", str(installed / "esp32c6-sniffer.bat"),
         "--extcap-interfaces"],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("extcap {version="), result.stdout
