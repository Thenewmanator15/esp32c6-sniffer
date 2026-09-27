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
        info = z.getinfo("install.sh")
        script = z.read("install.sh")
    assert info.external_attr >> 16 & 0o111 == 0o111
    # And marked as made on Unix: unzip ignores the mode of an entry marked
    # FAT, which is what a zip built on Windows marks every entry.
    assert info.create_system == 3
    # A Windows checkout has CRLF, and bash reads the \r as part of each line.
    assert b"\r" not in script


def _powershells() -> list[str]:
    if os.name != "nt":
        return []
    return [shell for shell in ("powershell", "pwsh") if shutil.which(shell)]


@pytest.fixture(scope="module")
def clone_at_a_non_ascii_path(tmp_path_factory):
    """A clone somewhere the launcher cannot spell in ASCII -- a user name
    like José puts one in every release install's path, under %APPDATA%.
    The last two are outside every OEM code page but one."""
    repo = tmp_path_factory.mktemp("clone") / "José-Ωμέγα-测试"
    (repo / "extcap").mkdir(parents=True)
    for name in ("install.ps1", "esp32c6-sniffer.py"):
        shutil.copy(REPO / "extcap" / name, repo / "extcap")
    shutil.copytree(REPO / "host" / "src" / "esp32c6_sniffer",
                    repo / "host" / "src" / "esp32c6_sniffer",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(REPO / "wireshark-profiles", repo / "wireshark-profiles")
    subprocess.run([sys.executable, "-m", "venv", "--without-pip",
                    str(repo / "host" / ".venv")], check=True)
    return repo


@pytest.mark.parametrize("shell", _powershells() or [
    pytest.param(None, marks=pytest.mark.skip(reason="Windows PowerShell only"))])
def test_the_windows_launcher_runs_from_a_non_ascii_path(
        shell, clone_at_a_non_ascii_path, tmp_path):
    """The .bat was written -Encoding ascii, which turns every character it
    cannot encode into '?', so the launcher named an interpreter and a
    script that do not exist and Wireshark listed no interfaces."""
    repo = clone_at_a_non_ascii_path
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    env = dict(os.environ, APPDATA=str(appdata))
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(repo / "extcap" / "install.ps1")],
        env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    launcher = appdata / "Wireshark" / "extcap" / "esp32c6-sniffer.bat"
    # As Wireshark runs it (wsutil/ws_pipe.c): a console of its own, hidden,
    # with the pipes as its standard handles -- the console is what the
    # launcher's chcp acts on.
    hidden = subprocess.STARTUPINFO()
    hidden.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.STARTF_USESTDHANDLES
    hidden.wShowWindow = 0                                  # SW_HIDE
    listed = subprocess.run(["cmd", "/c", str(launcher), "--extcap-interfaces"],
                            capture_output=True, text=True, timeout=60,
                            creationflags=subprocess.CREATE_NEW_CONSOLE,
                            startupinfo=hidden)
    assert "extcap {version=" in listed.stdout, listed.stdout + listed.stderr


def test_the_windows_installer_is_ascii():
    """Windows PowerShell reads a script with no byte order mark in the ANSI
    code page, so anything else in it is read as something else."""
    (REPO / "extcap" / "install.ps1").read_bytes().decode("ascii")


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


def run_install_sh(repo: pathlib.Path, home: pathlib.Path, *args: str,
                   **extra_env: str):
    env = {k: v for k, v in os.environ.items()
           if k not in ("XDG_CONFIG_HOME", "WIRESHARK_CONFIG_DIR")}
    env["HOME"] = str(home)
    env.update(extra_env)
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


@needs_bash
def test_install_sh_that_fails_leaves_the_old_install_working(tmp_path):
    """The old folder's files were removed before the script knew it had a
    Python to install with, so a reinstall that stopped there broke a
    Wireshark 4.0 install that had been working."""
    home = tmp_path / "home"
    old = home / ".config" / "wireshark" / "extcap"
    (old / "esp32c6-sniffer-venv").mkdir(parents=True)
    (old / "esp32c6-sniffer.py").write_text("# the working copy\n")
    repo = fake_clone(tmp_path)
    shutil.rmtree(repo / "host" / ".venv")        # nothing to install with
    result = run_install_sh(repo, home)
    assert result.returncode != 0
    assert (old / "esp32c6-sniffer.py").exists()
    assert (old / "esp32c6-sniffer-venv").exists()


@needs_bash
def test_install_sh_uses_an_old_style_config_folder_wireshark_uses(tmp_path):
    """Wireshark takes $XDG_CONFIG_HOME/wireshark if it exists, else
    ~/.wireshark if that does (wsutil/filesystem.c). The profiles always went
    to ~/.config/wireshark, which such a Wireshark never reads, and so did
    the entry for 4.0."""
    home = tmp_path / "home"
    (home / ".wireshark").mkdir(parents=True)
    result = run_install_sh(fake_clone(tmp_path), home)
    assert result.returncode == 0, result.stderr
    assert (home / ".wireshark" / "profiles" / "ESP32-C6 BLE"
            / "preferences").is_file()
    assert (home / ".wireshark" / "extcap" / "esp32c6-sniffer").is_file()
    assert not (home / ".config" / "wireshark").exists()


@needs_bash
def test_install_sh_prefers_the_xdg_folder_when_both_exist(tmp_path):
    home = tmp_path / "home"
    (home / ".wireshark").mkdir(parents=True)
    (home / ".config" / "wireshark").mkdir(parents=True)
    assert run_install_sh(fake_clone(tmp_path), home).returncode == 0
    assert (home / ".config" / "wireshark" / "profiles" / "ESP32-C6 BLE").is_dir()
    assert not (home / ".wireshark" / "profiles").exists()


@needs_bash
def test_install_sh_follows_wireshark_config_dir(tmp_path):
    """The variable Wireshark itself reads first."""
    home, chosen = tmp_path / "home", tmp_path / "elsewhere"
    home.mkdir()
    result = run_install_sh(fake_clone(tmp_path), home,
                            WIRESHARK_CONFIG_DIR=str(chosen))
    assert result.returncode == 0, result.stderr
    assert (chosen / "profiles" / "ESP32-C6 BLE").is_dir()


@pytest.mark.parametrize("name", ["install.ps1", "install.sh"])
def test_a_release_install_asks_for_the_aes_speed_up_and_manages_without(name):
    """The fast extra brings cryptography, about fifty times the speed for
    device-key checks. A platform where it will not install must still get
    a working plugin, on the host's own AES."""
    text = (REPO / "extcap" / name).read_text(encoding="utf-8")
    assert "[fast]" in text
    installs = [line for line in text.splitlines()
                if "pip install" in line and "--upgrade pip" not in line]
    assert any("[fast]" in line for line in installs)
    assert any("[fast]" not in line and "wheel" in line.lower() for line in installs)
