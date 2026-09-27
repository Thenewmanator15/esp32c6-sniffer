""""Legacy only" with periodic following did nothing, and said nothing.

Legacy scanning reports no periodic trains, and the controller refuses
Create Sync after legacy commands. The dialog cannot grey one option out on
another's value, so the session sends periodic as off and the plugin says
why in the toolbar log, where the other start-up notes go.
"""

from esp32c6_sniffer import capture

from test_extcap_stop import ClosedByWireshark, fake_session, plugin  # noqa: F401


def run_ble(plugin, monkeypatch, *extra):
    base = fake_session(None)

    class Session(base):
        def __init__(self, port, **kw):
            super().__init__(port, **kw)
            self.periodic_needs_extended = (bool(kw.get("ble_periodic"))
                                            and kw.get("ble_phys") == 0)

    logged = []
    monkeypatch.setattr(capture, "CaptureSession", Session)
    monkeypatch.setattr(plugin, "control_write",
                        lambda fp, arg, cmd, payload=b"": logged.append(payload))
    pipe = ClosedByWireshark(keep=1)
    monkeypatch.setattr(plugin, "open", lambda path, mode="r", *a, **k: pipe,
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-interface", "esp32c6-ble",
                        "--port", "COM_UNUSED", *extra])
    return code, b"".join(p for p in logged if isinstance(p, bytes)).decode()


def test_legacy_with_periodic_says_periodic_is_off(plugin, monkeypatch):
    code, logged = run_ble(plugin, monkeypatch, "--ble-phys", "0", "--ble-periodic")
    assert code == 0
    assert "Follow periodic advertising is off" in logged
    assert "Legacy only" in logged


def test_extended_with_periodic_says_nothing_of_the_sort(plugin, monkeypatch):
    code, logged = run_ble(plugin, monkeypatch, "--ble-phys", "1", "--ble-periodic")
    assert code == 0
    assert "Follow periodic advertising is off" not in logged
