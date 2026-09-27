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


def fragments() -> list[pathlib.Path]:
    """Every Kconfig fragment a build of the nRF firmware can merge."""
    return sorted(NRF.glob("*.conf")) + sorted((NRF / "boards").glob("*.conf"))


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
    # Nor turned back on by any other fragment the build can merge.
    for fragment in fragments():
        text = fragment.read_text(encoding="utf-8")
        assert setting(text, "CONFIG_IEEE802154_L2_PKT_INCL_FCS") in (None, "n"), fragment


@needs_nrf
def test_nrf_controller_can_receive_a_stereo_broadcast():
    """The BIS sink count follows BT_ISO_MAX_CHAN, which defaulted to 1, and
    a join asking for more streams than that is refused outright."""
    conf = (NRF / "prj.conf").read_text(encoding="utf-8")
    assert int(setting(conf, "CONFIG_BT_ISO_MAX_CHAN") or "1") >= 2
    # The controller reads STREAM_COUNT, which only defaults to MAX_CHAN:
    # a fragment setting it lower would undo the above.
    for fragment in fragments():
        count = setting(fragment.read_text(encoding="utf-8"),
                        "CONFIG_BT_CTLR_SYNC_ISO_STREAM_COUNT")
        assert count is None or int(count) >= 2, fragment


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


C6_MAIN = ROOT / "firmware" / "main"


def _c6(name: str) -> str:
    text = (C6_MAIN / name).read_text(encoding="utf-8")
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _body(text: str, signature: str) -> str:
    start = text.index("{", text.index(signature))
    depth = 0
    for i in range(start, len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[start:i + 1]
    raise AssertionError(signature)


def test_the_c6_hands_its_front_end_back_at_boot():
    """802.15.4 left running deafens Wi-Fi until 802.15.4 is started and
    stopped cleanly (8 in 8; the power-gate 0 in 16). The C6 restarts when
    its port opens, so doing it at boot cures it for every tool that
    connects -- unless built without, for measuring the latch itself."""
    main = _c6("main.c")
    assert "sn_radio154_hand_back()" in main
    assert "SN_154_NO_BOOT_HANDBACK" in (C6_MAIN / "main.c").read_text(encoding="utf-8")
    body = _body(_c6("radio154.c"), "void sn_radio154_hand_back(void)")
    assert "sn_radio154_start(" in body and "sn_radio154_stop()" in body


def test_a_clean_802154_stop_clears_the_flag_and_nothing_else_does():
    """A clean stop is the cure, so it clears the flag -- only with the
    sleep, since the stop without it is what latches. The power cycle's
    timer wake does not: the power-gate does not cure this deafness, and
    clearing the flag there hid it."""
    stop = _body(_c6("radio154.c"), "void sn_radio154_stop(void)")
    sleep_at = stop.index("esp_ieee802154_sleep()")
    clear_at = stop.index("set_front_end_dirty(false)")
    endif_at = stop.index("#endif", sleep_at)
    assert sleep_at < clear_at < endif_at
    assert "sn_radio154_clear_dirty()" not in _c6("main.c")
