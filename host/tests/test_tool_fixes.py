"""Two tool bugs from the 2026-09-26 audit."""

import pathlib
import re
import sys
import threading
import time

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"
CAPTURE = pathlib.Path(__file__).resolve().parents[1] / "src" / "esp32c6_sniffer" / "capture.py"


def wifi_fields() -> list[str]:
    """The Wi-Fi stats block's fields, in the order capture.py unpacks them."""
    text = CAPTURE.read_text(encoding="utf-8")
    block = re.search(r"if self\._radio is Radio\.WIFI:\s*\((.*?)\)\s*=\s*values\[_WIFI_BLOCK_AT",
                      text, re.S).group(1)
    return [re.sub(r"^self\.stats\.", "", f.strip())
            for f in block.split(",") if f.strip()]


def test_abuse_reads_the_wifi_counters_it_names():
    """It printed wifi[9] as the CSI drop count; that is fw_recoveries."""
    fields = wifi_fields()
    text = (TOOLS / "abuse.py").read_text(encoding="utf-8")
    wanted = {"isr_full": "fw_isr_queue_full", "rejected": "fw_link_rejected",
              "csi_dropped": "fw_csi_dropped"}
    got = dict(re.findall(r"(\w+)\s*=\s*wifi\[(\d+)\]", text))
    pair = re.search(r"isr_full, rejected = wifi\[(\d+)\], wifi\[(\d+)\]", text)
    got["isr_full"], got["rejected"] = pair.groups()
    for name, field in wanted.items():
        assert fields[int(got[name])] == field, name


def test_he_probe_moves_on_when_the_reply_arrives(monkeypatch):
    """Each command waited out its whole window, 20 s for most, after the
    reply had arrived: about 80 s of nothing per run."""
    import he_probe
    from test_open_handshake import BridgedPort

    monkeypatch.setattr(he_probe.serial, "Serial",
                        lambda *a, **k: BridgedPort(version=7))
    monkeypatch.setenv("ESP32C6_WIFI_PASSPHRASE", "not-a-real-passphrase")
    monkeypatch.setattr(sys, "argv", ["he_probe", "--port", "COM_UNUSED",
                                      "--ssid", "test-network", "--seconds", "0.1"])
    done = []
    worker = threading.Thread(target=lambda: done.append(he_probe.main()),
                              daemon=True)
    start = time.monotonic()
    worker.start()
    worker.join(15)
    assert done, f"still running after {time.monotonic() - start:.0f} s"


def thread_log(monkeypatch, tmp_path, installed):
    import importlib.util
    from esp32c6_sniffer import thread
    from test_toolbar import PLUGIN, run
    spec = importlib.util.spec_from_file_location("extcap_plugin_thread", PLUGIN)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    monkeypatch.setattr(plugin, "find_board_ports", lambda: [])
    # Never the real Wireshark configuration.
    monkeypatch.setattr(thread, "install_key", lambda key: installed)
    creds = tmp_path / "thread.txt"
    creds.write_text("000102030405060708090a0b0c0d0e0f\n", encoding="utf-8")
    code, written, _ = run(plugin, monkeypatch, "esp32c6-802154", [],
                           "--thread", str(creds))
    assert code == 0
    return "".join(p.decode() for cmd, p in written if cmd == plugin.CTRL_CMD_ADD)


def test_a_newly_installed_thread_key_says_to_restart_wireshark(monkeypatch, tmp_path):
    """Wireshark reads its key table when it starts, so the capture that
    installed a key could not use it; thread_key.py said to restart, the
    option did not."""
    log = thread_log(monkeypatch, tmp_path, ["table"])
    assert "installed into 1 key table" in log
    assert "restart Wireshark" in log


def test_a_key_already_installed_needs_no_restart(monkeypatch, tmp_path):
    log = thread_log(monkeypatch, tmp_path, [])
    assert "already installed" in log
    assert "restart Wireshark" not in log


def test_idf_env_leaves_the_callers_error_preference_alone(tmp_path):
    """Dot-sourced, it set $ErrorActionPreference = 'Stop' in the user's own
    shell and left it there, so any later command error ended whatever they
    ran next. Checked on a failure, which is where it matters most: the
    script throws, and the shell is the user's again."""
    import shutil
    import subprocess
    import pytest
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is not installed")
    script = pathlib.Path(__file__).resolve().parents[2] / "firmware" / "idf-env.ps1"
    nowhere = tmp_path / "no-such-esp-idf-tools"
    # The script's own error must be the one caught: a script that fails to
    # parse never touches the preference, and passed this test once.
    command = (f"$ErrorActionPreference = 'Continue'; "
               f"try {{ . '{script}' -IdfToolsPath '{nowhere}' }} "
               f"catch {{ 'caught: ' + $_.Exception.Message.Split([char]10)[0] }}; "
               f"$ErrorActionPreference")
    out = subprocess.run([pwsh, "-NoProfile", "-Command", command],
                         capture_output=True, text=True, timeout=60)
    lines = out.stdout.strip().splitlines()
    # Either of its own refusals: "ESP-IDF not found" where none is installed
    # (the CI runners), "ESP-IDF tools not found" where one is. Not a parse
    # error, which says nothing of the kind.
    assert any(l.startswith("caught: ESP-IDF") and "not found" in l
               for l in lines), out.stdout + out.stderr
    assert lines[-1] == "Continue", out.stdout + out.stderr
