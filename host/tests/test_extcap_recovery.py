"""The shared front end must be checked before a Wi-Fi capture opens.

Both radios share one 2.4 GHz front end, and leaving the 802.15.4 radio
*enabled* when a host disconnects leaves the Wi-Fi receiver deaf until the RF
domain is power-gated. The board records that in RTC memory.

This went wrong twice, in opposite directions, and both are worth keeping:

1. The Wireshark plugin never checked at all. `ensure_wifi_ready` was called
   from two survey tools, so the ordinary path -- capture Zigbee in Wireshark,
   switch to Wi-Fi -- produced a file containing nothing, with no error, no
   warning and no log line.

2. `CaptureSession` did have its own inline version, which is why the first
   fix looked redundant. It did not work. It set `recovered_from_802154`
   correctly and still captured zero frames, because power-cycling from inside
   an already-open session does not give the RF domain the settling time and
   clean re-enumeration that doing it around the port does. Measured with the
   session alone, no plugin involved: 0 frames before, 993 after.

So there is now exactly one implementation, it lives in `CaptureSession.open`,
and it runs before the port is opened. These tests hold that shape. They
cannot prove the recovery works -- that needs a poisoned board -- which is why
the numbers above are recorded here.
"""

import ast
import inspect
import pathlib

import pytest

from esp32c6_sniffer import capture

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture(scope="module")
def open_method() -> ast.FunctionDef:
    tree = ast.parse(inspect.getsource(capture.CaptureSession))
    for node in tree.body[0].body:
        if isinstance(node, ast.FunctionDef) and node.name == "open":
            return node
    pytest.fail("CaptureSession.open not found")


def test_the_session_checks_the_front_end(open_method):
    calls = [n for n in ast.walk(open_method)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "ensure_wifi_ready"]
    assert calls, (
        "CaptureSession no longer checks the front end. Without it a Wi-Fi "
        "capture started after an 802.15.4 one returns an empty file with no "
        "error of any kind"
    )


def test_the_check_runs_before_the_port_is_opened(open_method):
    """The whole reason the previous attempt failed. Power-cycling from inside
    an open session detects the condition and does not fix it."""
    order = []
    for node in ast.walk(open_method):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "ensure_wifi_ready":
            order.append(("check", node.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "_connect":
            order.append(("connect", node.lineno))
    order.sort(key=lambda pair: pair[1])
    assert [kind for kind, _ in order][:2] == ["check", "connect"], (
        f"expected the front-end check before _connect, got {order}"
    )


def test_the_check_is_guarded_by_the_radio(open_method):
    """The two radios that cannot poison anything must not be reset."""
    for node in ast.walk(open_method):
        if not isinstance(node, ast.If):
            continue
        if any(isinstance(inner, ast.Call)
               and isinstance(inner.func, ast.Name)
               and inner.func.id == "ensure_wifi_ready"
               for inner in ast.walk(node)) and "WIFI" in ast.dump(node.test):
            return
    pytest.fail("ensure_wifi_ready is not guarded by a Wi-Fi radio check")


def test_there_is_only_one_implementation():
    """Two copies of this existed and the one in the library was the broken
    one. A second inline power-cycle is how that came back."""
    source = inspect.getsource(capture)
    assert source.count("RADIO_POWER_CYCLE") == 0, (
        "CaptureSession power-cycles inline again. That is the version that "
        "detected the condition and did not fix it; use ensure_wifi_ready"
    )


def test_the_plugin_reports_the_recovery_rather_than_repeating_it():
    """It should read the session's flag, not call the recovery a second time
    and pay for another port open."""
    text = PLUGIN.read_text(encoding="utf-8")
    assert "recovered_from_802154" in text, (
        "the plugin no longer reports the power cycle, so a user sees an "
        "unexplained pause and no log line"
    )
    assert "ensure_wifi_ready" not in text, (
        "the plugin calls the recovery itself again; the session already does"
    )
