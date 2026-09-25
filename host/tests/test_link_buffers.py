"""The largest thing the host sends at once must fit each board's receive
buffers.

Starting a BLE capture sends the device keys, the filter and START in one
burst. Both firmwares once had buffers sized for five-byte commands: the
nRF54L15's 64-byte UART DMA buffers stalled a 65-byte burst 34 times in 40
until the host happened to send more, and the C6's 128-byte control buffer
could drop the front of a keys frame when a read brought the rest of it and
the next frame together. Neither said so. These read the sizes out of the C
sources, so a buffer shrunk or a frame grown fails here first.

The nRF54L15 is a separate repository, a sibling of this one by convention;
NRF54L15_SNIFFER names another checkout of it.
"""

import os
import pathlib
import re

import pytest

from esp32c6_sniffer.boards import board_by_id
from esp32c6_sniffer.ble_keys import DeviceKey
from esp32c6_sniffer.control import (
    MAX_BLE_FILTER,
    Command,
    encode_ble_filter,
    encode_ble_keys,
    encode_command,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
C6_CONTROL = ROOT / "firmware" / "main" / "control.c"
NRF = pathlib.Path(os.environ.get("NRF54L15_SNIFFER",
                                  ROOT.parent / "nrf54l15-sniffer"))
NRF_LINK = NRF / "src" / "link.c"


def largest_burst(board: str) -> int:
    """Keys, filter and START, each as full as the board allows."""
    keys = [DeviceKey(n, 1, f"de:ad:be:ef:00:{n:02x}", bytes([n + 1] * 16))
            for n in range(board_by_id(board)["ble_keys"])]
    entries = [(1, f"de:ad:be:ef:00:{n:02x}") for n in range(MAX_BLE_FILTER)]
    return (len(encode_ble_keys(keys)) + len(encode_ble_filter(entries))
            + len(encode_command(Command.START)))


def size_of(path: pathlib.Path, pattern: str) -> int:
    match = re.search(pattern, path.read_text(encoding="utf-8"))
    assert match, f"{pattern!r} not found in {path}"
    return int(match.group(1))


def test_the_c6_control_buffer_holds_the_largest_burst():
    assert size_of(C6_CONTROL, r"#define RX_BUF_LEN\s+(\d+)") >= \
        largest_burst("esp32c6")


@pytest.mark.skipif(not NRF_LINK.exists(), reason="nrf54l15-sniffer not beside this repository")
def test_the_nrf_dma_buffers_hold_the_largest_burst():
    assert size_of(NRF_LINK, r"static uint8_t rx_dma\[2\]\[(\d+)\];") >= \
        largest_burst("nrf54l15")


@pytest.mark.skipif(not NRF_LINK.exists(), reason="nrf54l15-sniffer not beside this repository")
def test_the_nrf_reassembly_buffer_holds_the_largest_burst():
    assert size_of(NRF_LINK, r"static uint8_t rx_buf\[(\d+)\];") >= \
        largest_burst("nrf54l15")
