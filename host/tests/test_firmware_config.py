"""Firmware settings the host depends on, read out of the firmware sources.

Nothing here compiles either firmware. The nRF54L15's is a separate
repository, a sibling of this one by convention; NRF54L15_SNIFFER names
another checkout of it.
"""

import os
import pathlib
import re

import pytest

from esp32c6_sniffer.capture import EXPECTED_FIRMWARE_VERSIONS

ROOT = pathlib.Path(__file__).resolve().parents[2]
NRF = pathlib.Path(os.environ.get("NRF54L15_SNIFFER",
                                  ROOT.parent / "nrf54l15-sniffer"))

needs_nrf = pytest.mark.skipif(not (NRF / "prj.conf").exists(),
                               reason="nrf54l15-sniffer not beside this repository")


def setting(conf: str, name: str) -> str | None:
    match = re.search(rf"^{name}=(\S+)\s*$", conf, flags=re.MULTILINE)
    return match.group(1) if match else None


@needs_nrf
def test_nrf_802154_frames_arrive_without_their_fcs():
    """Raw mode defaults L2_PKT_INCL_FCS on, and the driver then leaves the
    last two bytes on every frame. Wireshark read them as part of the MIC, so
    no secured frame from an nRF capture ever decrypted: 0 MLE commands from
    a Thread network the C6 decrypted as it stood, and 296 IPv6 frames once
    editcap cut the two bytes off."""
    conf = (NRF / "prj.conf").read_text(encoding="utf-8")
    assert setting(conf, "CONFIG_IEEE802154_RAW_MODE") == "y"
    assert setting(conf, "CONFIG_IEEE802154_L2_PKT_INCL_FCS") == "n"


@needs_nrf
def test_nrf_controller_can_receive_a_stereo_broadcast():
    """The BIS sink count follows BT_ISO_MAX_CHAN, which defaulted to 1, and
    a join asking for more streams than that is refused outright."""
    conf = (NRF / "prj.conf").read_text(encoding="utf-8")
    assert int(setting(conf, "CONFIG_BT_ISO_MAX_CHAN") or "1") >= 2


@pytest.mark.parametrize("board, source", [
    ("esp32c6", ROOT / "firmware" / "main" / "main.c"),
    ("nrf54l15", NRF / "src" / "main.c"),
])
def test_the_host_expects_the_version_the_firmware_reports(board, source):
    if not source.exists():
        pytest.skip(f"{source} not here")
    match = re.search(r"#define\s+SN_FIRMWARE_VERSION\s+(\d+)u?",
                      source.read_text(encoding="utf-8"))
    assert match, f"{source} no longer defines SN_FIRMWARE_VERSION"
    assert EXPECTED_FIRMWARE_VERSIONS[board] == int(match.group(1))
