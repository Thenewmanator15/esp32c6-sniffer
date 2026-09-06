"""The Wi-Fi capture path must check the shared front end before capturing.

Both radios share one 2.4 GHz front end, and leaving the 802.15.4 radio
*enabled* when a host disconnects leaves the Wi-Fi receiver deaf until the RF
domain is power-gated. `ensure_wifi_ready` reads the flag the board keeps in
RTC memory and power-cycles.

It was called from `tools/selftest.py` and `tools/wifi_survey.py` but NOT from
the Wireshark plugin, which is the path almost everybody uses. So the ordinary
sequence -- capture Zigbee in Wireshark, switch to Wi-Fi -- produced a capture
containing nothing at all, with no error, no warning and no log line. Measured
before and after the fix on the same sequence: 0 packets, then 1063.

What this test proves and does not prove: it proves the call is still wired
into the plugin's capture path and still guarded by the radio being Wi-Fi. It
cannot prove the recovery works, because that needs a board with a poisoned
front end. That was verified by hand, and the numbers above are the record.
"""

import ast
import pathlib

import pytest

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture(scope="module")
def do_capture() -> ast.FunctionDef:
    tree = ast.parse(PLUGIN.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "do_capture":
            return node
    pytest.fail("do_capture not found in the plugin")


def test_the_capture_path_checks_the_front_end(do_capture):
    calls = [node for node in ast.walk(do_capture)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name)
             and node.func.id == "ensure_wifi_ready"]
    assert calls, (
        "the plugin no longer calls ensure_wifi_ready. Without it, a Wi-Fi "
        "capture started after an 802.15.4 one returns an empty file with no "
        "error of any kind"
    )


def test_the_check_is_guarded_by_the_radio(do_capture):
    """Power-cycling before every capture would reset the board needlessly on
    the two radios that cannot poison anything."""
    for node in ast.walk(do_capture):
        if not isinstance(node, ast.If):
            continue
        called = any(isinstance(inner, ast.Call)
                     and isinstance(inner.func, ast.Name)
                     and inner.func.id == "ensure_wifi_ready"
                     for inner in ast.walk(node))
        if called and "WIFI" in ast.dump(node.test):
            return
    pytest.fail("ensure_wifi_ready is not guarded by a Wi-Fi radio check")


def test_a_failure_to_check_does_not_stop_the_capture(do_capture):
    """A board too old to answer, or a port that vanishes during the cycle,
    must not prevent capturing: the fault this guards against is visible as
    zero frames, so refusing to start would be the worse failure."""
    for node in ast.walk(do_capture):
        if not isinstance(node, ast.Try):
            continue
        if any(isinstance(inner, ast.Call)
               and isinstance(inner.func, ast.Name)
               and inner.func.id == "ensure_wifi_ready"
               for inner in ast.walk(node)):
            assert node.handlers, "the call is in a try with no handler"
            return
    pytest.fail("ensure_wifi_ready is not wrapped in a try")
