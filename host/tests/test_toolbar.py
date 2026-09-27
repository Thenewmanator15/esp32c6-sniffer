"""The toolbar is the plugin's, not an interface's.

Checked against Wireshark's extcap.c (master): interfaces are listed with
--extcap-interfaces and --extcap-version only -- never --extcap-interface --
and one toolbar is built per plugin from that output, titled with the
plugin's display name and shared by every interface it lists. So the
toolbar must make sense for every board and every radio at once: with both
boards attached it listed 802.15.4 twice, 46 entries, told the nRF54L15 of an
antenna measurement made on the C6, and put "ESP32-C6" in the nRF's status
bar. And the narrowing to a named interface this file replaces never ran.
"""

import importlib.util
import struct
import threading
import time
from pathlib import Path

import pytest

from esp32c6_sniffer import capture

from test_extcap_stop import ClosedByWireshark, fake_session

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture
def plugin(monkeypatch):
    spec = importlib.util.spec_from_file_location("extcap_plugin_toolbar", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "find_board_ports", lambda: [])
    return module


def toolbar_lines(plugin, capsys):
    plugin.print_interfaces()
    return capsys.readouterr().out.splitlines()


def test_each_radios_channels_are_listed_once(plugin, capsys):
    values = [l for l in toolbar_lines(plugin, capsys)
              if l.startswith("value {control=0}")]
    tokens = [l.split("{value=")[1].split("}")[0] for l in values]
    assert len(tokens) == len(set(tokens))
    assert sum(t.startswith("z") for t in tokens) == 16
    assert sum(t.startswith("w") for t in tokens) == 14


def test_the_antenna_toggle_is_worded_for_any_board(plugin, capsys):
    antenna = next(l for l in toolbar_lines(plugin, capsys)
                   if "display=External antenna" in l)
    assert "on this board" not in antenna
    assert "Measured" not in antenna


def test_a_ble_capture_refuses_a_channel_plainly(plugin):
    with pytest.raises(ValueError, match="BLE has no channel"):
        plugin.parse_channel_token("nrf54l15-ble", "z15")


def test_another_radios_channel_is_refused_by_radio_not_by_board(plugin):
    with pytest.raises(ValueError) as refused:
        plugin.parse_channel_token("nrf54l15-802154", "w6")
    assert "Wi-Fi" in str(refused.value)
    assert "ESP32-C6" not in str(refused.value)


class ScriptedToolbar:
    """Wireshark's control pipe: INITIALIZED, then the messages given, one
    every `gap` seconds, then nothing until the capture ends."""

    def __init__(self, messages, done, gap=0.2):
        self._chunks = [struct.pack(">sBHBB", b"T", 0, 2, 0, 0)]      # INITIALIZED
        for arg, cmd, payload in messages:
            self._chunks.append(struct.pack(">sBHBB", b"T", 0, len(payload) + 2,
                                            arg, cmd) + payload)
        self._buf = b""
        self._done, self._gap = done, gap

    def read(self, n):
        if not self._buf:
            if not self._chunks:
                self._done.wait(5)
                return b""
            time.sleep(self._gap)
            self._buf = self._chunks.pop(0)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        pass


class Sink:
    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass


def run(plugin, monkeypatch, interface, messages, *extra):
    base = fake_session(None)
    done = threading.Event()
    retuned = []

    class Session(base):
        def __init__(self, port, **kw):
            super().__init__(port, **kw)
            self.periodic_needs_extended = False

        def request_channel(self, channel):
            retuned.append(channel)

        def __exit__(self, *exc):
            done.set()
            return super().__exit__(*exc)

    written = []
    monkeypatch.setattr(capture, "CaptureSession", Session)
    monkeypatch.setattr(plugin, "control_write",
                        lambda fp, arg, cmd, payload=b"": written.append((cmd, payload)))
    pipes = {"FIFO": ClosedByWireshark(keep=1),
             "IN": ScriptedToolbar(messages, done), "OUT": Sink()}
    monkeypatch.setattr(plugin, "open", lambda path, mode="r", *a, **k: pipes[path],
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-control-in", "IN", "--extcap-control-out", "OUT",
                        "--extcap-interface", interface, "--port", "COM_UNUSED",
                        *extra])
    return code, written, retuned


def test_the_status_bar_names_the_board_capturing(plugin, monkeypatch):
    code, written, retuned = run(
        plugin, monkeypatch, "nrf54l15-802154",
        [(plugin.CTRL_ARG_CHANNEL, plugin.CTRL_CMD_SET, b"z20")])
    status = [p.decode() for cmd, p in written if cmd == plugin.CTRL_CMD_STATUSBAR]
    assert code == 0 and retuned == [20]
    assert status == ["nRF54L15: channel 20"]


def test_a_ble_capture_does_not_claim_a_channel(plugin, monkeypatch):
    code, written, _ = run(plugin, monkeypatch, "nrf54l15-ble", [])
    log = "".join(p.decode() for cmd, p in written if cmd == plugin.CTRL_CMD_ADD)
    assert code == 0
    assert "capture started" in log
    assert "channel 0" not in log


def test_where_a_capture_listens(plugin):
    from esp32c6_sniffer.control import Radio
    assert plugin.listening_on(Radio.IEEE802154, 15) == "channel 15"
    assert plugin.listening_on(Radio.BLE, 0) == "the advertising channels"
