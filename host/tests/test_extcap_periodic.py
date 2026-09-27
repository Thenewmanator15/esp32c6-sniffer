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


class LateToolbar:
    """Wireshark's control pipe, sending INITIALIZED only after `delay` --
    as it does once it has replayed the user's toolbar settings -- and then
    nothing until the capture ends."""

    def __init__(self, delay: float, done):
        import time
        self._at = time.monotonic() + delay
        self._sent = False
        self._done = done

    def read(self, n):
        import struct
        import time
        if not self._sent:
            time.sleep(max(0.0, self._at - time.monotonic()))
            self._sent = True
            return struct.pack(">sBHBB", b"T", 0, 2, 0, 0)   # INITIALIZED
        self._done.wait(5)
        return b""

    def close(self):
        pass


class Sink:
    def write(self, data):
        return len(data)

    def flush(self):
        pass

    def close(self):
        pass


def test_start_up_notes_wait_for_the_toolbar(plugin, monkeypatch):
    """The audit found start-up log lines written before Wireshark's
    INITIALIZED, which log() drops: "held rather than logged at once" was
    held for no time at all, and the note above was lost the same way."""
    import threading
    base = fake_session(None)
    done = threading.Event()

    class Session(base):
        def __init__(self, port, **kw):
            super().__init__(port, **kw)
            self.periodic_needs_extended = True

        def __exit__(self, *exc):
            done.set()
            return super().__exit__(*exc)

    logged = []
    monkeypatch.setattr(capture, "CaptureSession", Session)
    monkeypatch.setattr(plugin, "control_write",
                        lambda fp, arg, cmd, payload=b"": logged.append(payload))
    pipes = {"FIFO": ClosedByWireshark(keep=1), "IN": LateToolbar(0.3, done),
             "OUT": Sink()}
    monkeypatch.setattr(plugin, "open", lambda path, mode="r", *a, **k: pipes[path],
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-control-in", "IN", "--extcap-control-out", "OUT",
                        "--extcap-interface", "esp32c6-ble", "--port", "COM_UNUSED",
                        "--ble-phys", "0", "--ble-periodic"])
    text = b"".join(p for p in logged if isinstance(p, bytes)).decode()
    assert code == 0
    assert "capture started" in text          # the toolbar was listening
    assert "Follow periodic advertising is off" in text


def test_the_hopping_note_waits_for_the_toolbar_too(plugin, monkeypatch):
    import threading
    base = fake_session(None)
    done = threading.Event()

    class Session(base):
        def __init__(self, port, **kw):
            super().__init__(port, **kw)
            self.periodic_needs_extended = False

        def request_channel(self, channel):
            pass

        def __exit__(self, *exc):
            done.set()
            return super().__exit__(*exc)

    logged = []
    monkeypatch.setattr(capture, "CaptureSession", Session)
    monkeypatch.setattr(plugin, "control_write",
                        lambda fp, arg, cmd, payload=b"": logged.append(payload))
    pipes = {"FIFO": ClosedByWireshark(keep=1), "IN": LateToolbar(0.3, done),
             "OUT": Sink()}
    monkeypatch.setattr(plugin, "open", lambda path, mode="r", *a, **k: pipes[path],
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-control-in", "IN", "--extcap-control-out", "OUT",
                        "--extcap-interface", "esp32c6-802154", "--port", "COM_UNUSED",
                        "--hop", "1"])
    text = b"".join(p for p in logged if isinstance(p, bytes)).decode()
    assert code == 0
    assert "hopping [" in text
