"""Finding the board, and failing helpfully when it is not where we looked.

The port defaulted to COM3 and was never checked. A user whose board enumerated
elsewhere -- this machine has a second USB serial device that took COM4 -- got
a raw Python traceback in a Wireshark dialog, with nothing in it naming the
port or suggesting a fix.
"""

import importlib.util
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_ports", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


class FakePort:
    def __init__(self, device, vid, pid):
        self.device, self.vid, self.pid = device, vid, pid


def patch_ports(monkeypatch, ports):
    import serial.tools.list_ports as lp
    monkeypatch.setattr(lp, "comports", lambda: ports)


def test_the_board_is_identified_by_vid_and_pid(monkeypatch):
    """Not by port number, and not by name: 'USB Serial Device' is what both
    devices on this machine are called."""
    patch_ports(monkeypatch, [
        FakePort("COM4", 0x2886, 0x0066),      # a different Seeed device
        FakePort("COM3", plugin.ESP32C6_USB_VID, plugin.ESP32C6_USB_PID),
    ])
    assert plugin.find_board_ports() == ["COM3"]


def test_no_board_yields_an_empty_list_not_a_guess(monkeypatch):
    patch_ports(monkeypatch, [FakePort("COM4", 0x2886, 0x0066)])
    assert plugin.find_board_ports() == []


def test_several_boards_are_all_reported(monkeypatch):
    patch_ports(monkeypatch, [
        FakePort("COM3", plugin.ESP32C6_USB_VID, plugin.ESP32C6_USB_PID),
        FakePort("COM7", plugin.ESP32C6_USB_VID, plugin.ESP32C6_USB_PID),
    ])
    assert plugin.find_board_ports() == ["COM3", "COM7"]


def test_a_port_with_no_vid_does_not_crash_the_search(monkeypatch):
    """Virtual and Bluetooth serial ports report None for vid and pid, and
    comparing those to an integer must not raise inside an error handler."""
    patch_ports(monkeypatch, [
        FakePort("COM1", None, None),
        FakePort("COM3", plugin.ESP32C6_USB_VID, plugin.ESP32C6_USB_PID),
    ])
    assert plugin.find_board_ports() == ["COM3"]


def test_enumeration_failing_is_not_fatal(monkeypatch):
    """This is only ever used to improve an error message, so it must never
    become the reason a capture fails."""
    import serial.tools.list_ports as lp

    def boom():
        raise RuntimeError("no serial subsystem")

    monkeypatch.setattr(lp, "comports", boom)
    assert plugin.find_board_ports() == []


def test_the_capture_path_catches_the_wrapped_serial_error():
    """The capture library wraps a serial failure in RuntimeError after its
    retries, so an `except OSError` alone caught nothing and the traceback
    reached the user anyway."""
    import ast

    tree = ast.parse(PLUGIN.read_text(encoding="utf-8"))
    main = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    for node in ast.walk(main):
        if not isinstance(node, ast.Try):
            continue
        calls_capture = any(
            isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
            and inner.func.id == "do_capture" for inner in ast.walk(node))
        if not calls_capture:
            continue
        caught = set()
        for handler in node.handlers:
            names = handler.type.elts if isinstance(handler.type, ast.Tuple) \
                else [handler.type]
            caught.update(n.id for n in names if isinstance(n, ast.Name))
        assert {"OSError", "RuntimeError"} <= caught, (
            f"do_capture's handler catches {sorted(caught)}; it must catch "
            f"RuntimeError too or a bad port still shows a traceback")
        return
    pytest.fail("do_capture is not wrapped in a try in main()")
