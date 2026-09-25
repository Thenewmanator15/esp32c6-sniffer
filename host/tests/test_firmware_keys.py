"""Device keys are secrets that live for one capture: both firmwares must
forget them when the scan stops, on every path out of stop.

The README says so. The C6 returned early from sn_radio_ble_stop() when its
controller was not up, before the clearing it had; and the nRF54L15 cleared
its own copy but left the keys in its controller's resolving list until the
next capture's reset. These read the C sources, since neither firmware has a
test harness of its own.

The nRF54L15 is a separate repository, a sibling of this one by convention;
NRF54L15_SNIFFER names another checkout of it.
"""

import os
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
C6_BLE = ROOT / "firmware" / "main" / "radio_ble.c"
NRF = pathlib.Path(os.environ.get("NRF54L15_SNIFFER",
                                  ROOT.parent / "nrf54l15-sniffer"))
NRF_BLE = NRF / "src" / "radio_ble.c"


def body_of(path: pathlib.Path, signature: str) -> str:
    """The first definition of a C function, comments removed: from its
    opening brace to the brace that closes it."""
    text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"),
                  flags=re.S)
    start = text.index(signature)
    open_at = text.index("{", start)
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at:i + 1]
    raise AssertionError(f"{signature} never closes")


def test_the_c6_forgets_its_keys_before_any_return_from_stop():
    body = body_of(C6_BLE, "void sn_radio_ble_stop(void)\n{")
    assert "memset(s_keys" in body
    first_return = body.find("return")
    assert first_return == -1 or body.index("memset(s_keys") < first_return


@pytest.mark.skipif(not NRF_BLE.exists(), reason="nrf54l15-sniffer not beside this repository")
def test_the_nrf_clears_its_controllers_resolving_list_on_stop():
    body = body_of(NRF_BLE, "int sn_radio_ble_stop(void)\n{")
    assert "memset(keys" in body
    assert "BT_HCI_OP_LE_CLEAR_RL" in body
