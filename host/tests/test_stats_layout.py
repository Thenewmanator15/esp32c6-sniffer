"""The STATS frame is positional, and every block in it is defined in firmware.

The host unpacks four blocks by position and decides from the payload's length
how many counters arrived. Nothing in this repository compiles the firmware,
so a counter inserted rather than appended would be caught by nobody: every
figure after it decodes as its neighbour, confidently and wrongly.

Both halves of that have now happened. The BLE block was sent for a release
and read by no one. Then fcs_length_unknown, appended to the Wi-Fi block and
never read, made the Wi-Fi block thirteen counters wide while this file said
twelve -- so the BLE block was read one counter early and reported a board
that had captured nothing.

Which is why the widths below are read out of the headers rather than written
down here. A number written down is the thing that was wrong.
"""
import pathlib
import re

import pytest

from esp32c6_sniffer.capture import (
    _BLE_BLOCK_AT,
    _STATS_V5,
    _WIFI_BLOCK_AT,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAIN = ROOT / "firmware" / "main"
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


def counters_before(header: pathlib.Path, closing: str) -> list[str]:
    """The uint32_t members of the struct ending at `closing`.

    Anchored on the closing tag because the opening is not distinctive: every
    one of these headers declares a packed metadata struct as well, and both
    begin `typedef struct`. These structs do not nest, so the last opening
    before the close is the one that belongs to it.
    """
    text = header.read_text(encoding="utf-8")
    assert closing in text, f"{header.name} no longer declares {closing}"
    body = text.split(closing)[0]
    body = body[body.rfind("typedef struct"):]
    return re.findall(r"uint32_t\s+(\w+)\s*;", body)


def counters_between(header: pathlib.Path, opening: str,
                     closing: str) -> list[str]:
    """The same, for a plain struct whose opening names it."""
    text = header.read_text(encoding="utf-8")
    assert opening in text, f"{header.name} no longer declares {opening}"
    return re.findall(r"uint32_t\s+(\w+)\s*;",
                      text.split(opening, 1)[1].split(closing, 1)[0])


def blocks() -> dict[str, list[str]]:
    return {
        "link": counters_before(MAIN / "usb_link.h", "} sn_link_stats_t;"),
        "154": counters_before(MAIN / "radio154.h", "} sn_154_stats_t;"),
        "wifi": counters_before(MAIN / "radio80211.h", "} sn_80211_stats_t;"),
        "ble": counters_before(MAIN / "radio_ble.h", "} sn_ble_stats_t;"),
    }


def test_the_c6_declares_the_ble_block_as_the_host_unpacks_it():
    assert blocks()["ble"] == BLE_FIELDS


def test_the_wifi_block_begins_where_the_host_looks_for_it():
    found = blocks()
    assert _WIFI_BLOCK_AT == len(found["link"]) + len(found["154"])


def test_the_ble_block_begins_where_the_host_looks_for_it():
    """The one that was wrong. fcs_length_unknown made the Wi-Fi block
    thirteen wide, and reading BLE from twenty gave every counter its
    neighbour's value -- a board reporting zero captured while packets
    arrived."""
    found = blocks()
    assert _BLE_BLOCK_AT == sum(
        len(found[name]) for name in ("link", "154", "wifi"))


def test_the_widest_tier_holds_every_block():
    found = blocks()
    assert _STATS_V5.size // 4 == sum(len(f) for f in found.values())


@pytest.mark.skipif(not NRF_HEADER.exists(),
                    reason="the nRF54L15 firmware is a separate repository")
def test_the_nrf_declares_the_same_ble_block():
    """Both boards send one block that the host reads with one branch."""
    assert counters_between(NRF_HEADER, "struct sn_ble_stats {",
                            "};") == BLE_FIELDS


#: The nRF builds its frame in main.c, not in the headers the C6 blocks come
#: from, so its placement of each block has to be checked separately.
NRF_MAIN = ROOT.parent / "nrf54l15-sniffer" / "src" / "main.c"


def nrf_stats_frame() -> str:
    text = NRF_MAIN.read_text(encoding="utf-8")
    assert "struct sn_stats_full {" in text, "main.c no longer builds sn_stats_full"
    return text.split("struct sn_stats_full {", 1)[1].split("};", 1)[0]


@pytest.mark.skipif(not NRF_MAIN.exists(),
                    reason="the nRF54L15 firmware is a separate repository")
def test_the_nrf_leads_with_the_link_and_802154_blocks():
    leading = nrf_stats_frame().split("wifi[", 1)[0]
    found = blocks()
    assert len(re.findall(r"uint32_t\s+(\w+)\s*;", leading)) == (
        len(found["link"]) + len(found["154"]))


@pytest.mark.skipif(not NRF_MAIN.exists(),
                    reason="the nRF54L15 firmware is a separate repository")
def test_the_nrf_pads_the_wifi_block_to_the_c6s_width():
    """The nRF has no Wi-Fi radio and sends zeros in its place, so its BLE
    block lands where the host looks only if the padding is exactly as wide
    as the C6's real Wi-Fi block. It was twelve against thirteen after the
    C6's width was corrected, and every nRF BLE counter read its neighbour:
    more advertising reports than HCI packets, which a subset cannot be.
    Checking the nRF's BLE field order, as the test above does, could not
    see it -- the fields were right and in the wrong place."""
    widths = re.findall(r"uint32_t\s+wifi\[(\d+)\]\s*;", nrf_stats_frame())
    assert len(widths) == 1, "expected one wifi[] padding array"
    assert int(widths[0]) == len(blocks()["wifi"])
