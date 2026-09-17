"""The STATS frame is positional, and its last block is defined in firmware.

The host unpacks four blocks by position and decides from the payload's
length how many counters arrived. Nothing in this repository compiles the
firmware, so a counter inserted rather than appended would be caught by
nobody: every figure after it would decode as its neighbour, confidently and
wrongly. That is what happened to the BLE block once already -- it was sent
for a release and read by no one.

So the order is read back out of the headers and compared with the order the
host assigns in.
"""
import pathlib
import re

import pytest

from esp32c6_sniffer.capture import _STATS_V5

ROOT = pathlib.Path(__file__).resolve().parents[2]
C6_HEADER = ROOT / "firmware" / "main" / "radio_ble.h"
#: A separate repository, and a sibling of this one by convention only.
NRF_HEADER = ROOT.parent / "nrf54l15-sniffer" / "src" / "radio_ble.h"

#: What capture.py's BLE branch assigns, in the order it assigns it.
BLE_FIELDS = [
    "hci_packets",
    "adv_reports",
    "forwarded",
    "oversized",
    "queue_full",
    "link_rejected",
    "command_timeouts",
    "periodic_seen",
    "periodic_synced",
    "periodic_reports",
    "periodic_refused",
]

#: Link, 802.15.4 and Wi-Fi, which sit in front of it.
BLOCKS_BEFORE_BLE = 5 + 3 + 12


def fields_of(header: pathlib.Path, opening: str, closing: str) -> list[str]:
    """The uint32_t members of one struct, in declaration order.

    The two firmwares spell the same block differently -- a typedef on the
    C6, a plain struct on the nRF -- so each says where its own begins.
    """
    text = header.read_text(encoding="utf-8")
    body = text.split(opening, 1)[1].split(closing, 1)[0]
    return re.findall(r"uint32_t\s+(\w+)\s*;", body)


def test_the_c6_declares_the_ble_block_as_the_host_unpacks_it():
    assert fields_of(C6_HEADER, "typedef struct {",
                     "} sn_ble_stats_t;") == BLE_FIELDS


@pytest.mark.skipif(not NRF_HEADER.exists(),
                    reason="the nRF54L15 firmware is a separate repository")
def test_the_nrf_declares_the_same_ble_block():
    """Both boards send one block that the host reads with one branch."""
    assert fields_of(NRF_HEADER, "struct sn_ble_stats {", "};") == BLE_FIELDS


def test_the_widest_tier_is_as_wide_as_the_four_blocks():
    assert _STATS_V5.size // 4 == BLOCKS_BEFORE_BLE + len(BLE_FIELDS)
