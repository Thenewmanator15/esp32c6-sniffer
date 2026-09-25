"""The nRF54L15 starts every capture as a fresh session.

The ESP32-C6 reboots when its serial port is opened, so each capture begins
from zero whatever happened before. The nRF54L15 sits behind a USB bridge and
does not. So a second capture without a reboot carried the first one's counts
-- a 20 s capture holding 104 frames wrote "509 received" into its statistics
block -- and SET_BLE_PHYS stayed as the last capture left it. And one receive
error, a port opened at the wrong baud rate, stopped it taking commands until
it was reflashed.

Nothing here compiles the firmware, so these read its source, as
test_stats_layout.py does. The counters that must be reset are read out of the
functions that report them, not written down here, so a counter added later
cannot be left counting from boot.
"""

import pathlib
import re

import pytest

NRF_SRC = pathlib.Path(__file__).resolve().parents[2].parent / "nrf54l15-sniffer" / "src"

pytestmark = pytest.mark.skipif(not NRF_SRC.exists(),
                                reason="the nRF54L15 firmware is a separate repository")


def source(name: str) -> str:
    text = (NRF_SRC / name).read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def body(text: str, signature: str) -> str:
    """The body of the function whose definition starts with `signature`."""
    assert signature in text, f"no {signature!r}"
    start = text.index("{", text.index(signature))
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start:i + 1]
    raise AssertionError(f"unterminated {signature!r}")


def reported_counters(text: str, accessor_body: str) -> set[str]:
    """File-scope counters the accessor reads, by name."""
    statics = set(re.findall(r"^static\s+(?:volatile\s+)?(?:uint32_t|atomic_t)\s+(\w+)\s*;",
                             text, flags=re.MULTILINE))
    return {name for name in re.findall(r"\b(\w+)\b", accessor_body) if name in statics}


def zeroed(reset_body: str) -> set[str]:
    return (set(re.findall(r"\b(\w+)\s*=\s*0u?\s*;", reset_body))
            | set(re.findall(r"atomic_set\(\s*&(\w+)\s*,\s*0\s*\)", reset_body))
            | set(re.findall(r"atomic_clear\(\s*&(\w+)\s*\)", reset_body)))


def get_info_case() -> str:
    text = source("control.c")
    start = text.index("case SN_CMD_GET_INFO:")
    end = text.index("case SN_CMD_", start + 1)
    return text[start:end]


RESETS = {
    "link.c": ("void sn_link_reset_counters(void)",
               ["uint32_t sn_link_frames_sent(void)", "uint32_t sn_link_bytes_sent(void)",
                "uint32_t sn_link_frames_dropped(void)", "uint32_t sn_link_high_water(void)"]),
    "batch.c": ("void sn_batch_reset_counters(void)", ["uint32_t sn_batch_dropped(void)"]),
    "radio154.c": ("void sn_radio154_reset_counters(void)",
                   ["uint32_t sn_radio154_captured(void)", "uint32_t sn_radio154_fcs_failed(void)"]),
    "radio_ble.c": ("void sn_radio_ble_reset_counters(void)",
                    ["void sn_radio_ble_get_stats(struct sn_ble_stats *out)"]),
}


@pytest.mark.parametrize("name", sorted(RESETS))
def test_every_reported_counter_is_reset(name):
    text = source(name)
    reset, accessors = RESETS[name]
    counters = set()
    for accessor in accessors:
        counters |= reported_counters(text, body(text, accessor))
    assert counters, f"{name}: no counters found; the parsing here is out of date"
    missing = counters - zeroed(body(text, reset))
    assert not missing, f"{name}: {reset} leaves {sorted(missing)} counting from boot"


def test_a_new_session_resets_every_counter_owner():
    case = get_info_case()
    for call in ("sn_link_reset_counters()", "sn_batch_reset_counters()",
                 "sn_radio154_reset_counters()", "sn_radio_ble_reset_counters()"):
        assert call in case, f"GET_INFO does not call {call}"


def test_a_new_session_puts_the_ble_phys_back():
    """SET_BLE_PHYS persisted into the next capture, as the filter once did."""
    text = source("control.c")
    default = re.search(r"static\s+uint8_t\s+ble_phys\s*=\s*([^;]+);", text)
    assert default, "control.c no longer declares ble_phys with a default"
    assert re.search(r"ble_phys\s*=\s*" + re.escape(default.group(1).strip()) + r"\s*;",
                     get_info_case()), "GET_INFO does not restore ble_phys to its default"


def test_a_receive_error_does_not_end_receiving():
    """After an error the driver disables receive; without re-enabling it the
    board sent STATS and LINK and ignored every command until reflashed."""
    text = source("link.c")
    match = re.search(r"case\s+UART_RX_DISABLED\s*:(.*?)(?:case\s+UART_|default\s*:|\n\t\})",
                      text, flags=re.DOTALL)
    assert match, "link.c does not handle UART_RX_DISABLED"
    assert "uart_rx_enable(" in match.group(1)
