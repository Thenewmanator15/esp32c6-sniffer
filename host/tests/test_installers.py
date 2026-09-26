"""The installers put the plugin where Wireshark looks, and it runs from there.

Each runs against a throwaway copy of the parts of a clone it reads, with its
own home directory, so nothing here touches the machine's Wireshark.
"""

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]


def _git_bash() -> str | None:
    """A bash that sees Windows paths as they are. WSL's -- System32's --
    runs in another filesystem, where the paths below mean nothing."""
    bash = shutil.which("bash")
    if bash is None or "system32" in bash.lower():
        return None
    return bash


needs_bash = pytest.mark.skipif(_git_bash() is None, reason="no usable bash")


def test_install_sh_is_executable():
    """Committed 100644, so ./extcap/install.sh -- what the README says to
    run -- was refused with "Permission denied" on every Linux and macOS
    clone."""
    out = subprocess.run(["git", "ls-files", "-s", "extcap/install.sh"],
                         cwd=REPO, capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout:
        pytest.skip("not a git checkout")
    assert out.stdout.split()[0] == "100755"


def test_the_release_zip_keeps_install_sh_executable(tmp_path):
    """The zip took each file's mode from the disk it was built on, so a zip
    built on Windows -- or from a checkout of a 100644 file -- unpacked an
    install.sh that ./install.sh could not run."""
    import zipfile

    wheel = tmp_path / "esp32c6_sniffer-0.0.0-py3-none-any.whl"
    wheel.write_bytes(b"")
    subprocess.run([sys.executable, str(REPO / "extcap" / "package-release.py"),
                    "--version", "v0.0.0", "--wheel", str(wheel),
                    "--out", str(tmp_path)], check=True, capture_output=True)
    with zipfile.ZipFile(tmp_path / "esp32c6-sniffer-plugin-v0.0.0.zip") as z:
        mode = z.getinfo("install.sh").external_attr >> 16
        script = z.read("install.sh")
    assert mode & 0o111 == 0o111
    # A Windows checkout has CRLF, and bash reads the \r as part of each line.
    assert b"\r" not in script


def fake_clone(root: pathlib.Path) -> pathlib.Path:
    """What install.sh reads from a clone, with a stand-in interpreter."""
    repo = root / "repo"
    (repo / "extcap").mkdir(parents=True)
    shutil.copy(REPO / "extcap" / "install.sh", repo / "extcap")
    (repo / "extcap" / "esp32c6-sniffer.py").write_text("# plugin\n")
    (repo / "host" / "src" / "esp32c6_sniffer").mkdir(parents=True)
    python = repo / "host" / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\nexit 0\n", newline="\n")
    python.chmod(0o755)
    profile = repo / "wireshark-profiles" / "ESP32-C6 BLE"
    profile.mkdir(parents=True)
    (profile / "preferences").write_text("# prefs\n")
    return repo


def run_install_sh(repo: pathlib.Path, home: pathlib.Path, *args: str):
    env = {k: v for k, v in os.environ.items() if k != "XDG_CONFIG_HOME"}
    env["HOME"] = str(home)
    return subprocess.run([_git_bash(), str(repo / "extcap" / "install.sh"), *args],
                          env=env, capture_output=True, text=True, timeout=60)


@needs_bash
def test_install_sh_installs_where_wireshark_4_1_and_later_look(tmp_path):
    """wsutil/filesystem.c: $HOME/.local/lib/wireshark/extcap since 4.1.0.
    The installer used ~/.config/wireshark/extcap, which no Wireshark since
    reads, so the interfaces never appeared."""
    home = tmp_path / "home"
    home.mkdir()
    result = run_install_sh(fake_clone(tmp_path), home)
    assert result.returncode == 0, result.stderr
    entry = home / ".local" / "lib" / "wireshark" / "extcap" / "esp32c6-sniffer"
    assert entry.is_file()
    assert "esp32c6-sniffer.py" in entry.read_text()
    assert (home / ".config" / "wireshark" / "profiles" / "ESP32-C6 BLE"
            / "preferences").is_file()


@needs_bash
def test_install_sh_keeps_wireshark_4_0_working(tmp_path):
    """4.0 -- Debian 12's -- still reads the old folder, and no later one
    does, so an entry there shows no interface twice."""
    home = tmp_path / "home"
    old = home / ".config" / "wireshark" / "extcap"
    old.mkdir(parents=True)
    # What an earlier release install left in the old folder.
    (old / "esp32c6-sniffer.py").write_text("# old copy\n")
    (old / "esp32c6-sniffer-venv").mkdir()
    result = run_install_sh(fake_clone(tmp_path), home)
    assert result.returncode == 0, result.stderr
    # Git Bash writes the home directory as /tmp/..., so match the tail.
    assert ("/.local/lib/wireshark/extcap/esp32c6-sniffer"
            in (old / "esp32c6-sniffer").read_text())
    assert not (old / "esp32c6-sniffer.py").exists()
    assert not (old / "esp32c6-sniffer-venv").exists()


@needs_bash
def test_install_sh_uninstall_removes_both_entries(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    repo = fake_clone(tmp_path)
    assert run_install_sh(repo, home).returncode == 0
    result = run_install_sh(repo, home, "--uninstall")
    assert result.returncode == 0, result.stderr
    assert not (home / ".local" / "lib" / "wireshark" / "extcap"
                / "esp32c6-sniffer").exists()
    assert not (home / ".config" / "wireshark" / "extcap"
                / "esp32c6-sniffer").exists()
