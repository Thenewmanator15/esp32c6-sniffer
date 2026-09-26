"""Guards on the shipped Wireshark configuration profiles.

These files are data, not code, and Wireshark's response to a malformed line is
usually to ignore it in silence. A profile that installs cleanly and does
nothing looks exactly like a profile that is working but has nothing to show,
which is why these are worth asserting rather than eyeballing.

The Decode As entry is the sharp case. Its final field must be the dissector's
description ("Matter"), not its display-filter name ("matter"). Measured
against Wireshark 4.6.8, the wrong spelling produces zero dissected frames and
no error at all -- indistinguishable from a missing decryption key.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path

import pytest

PROFILE_ROOT = Path(__file__).resolve().parents[2] / "wireshark-profiles"

# One per radio. A filter button belongs to a profile rather than to an
# interface, so a single shared profile showed Zigbee, Thread and 802.11ax
# buttons to everyone regardless of what they were capturing.
#
# The value is the dissector each profile switches on. It used to be the
# interface name, and that is why these tests changed: keying on hardware
# meant every new board had to be added here and to three profile files, and
# when the nRF54L15 was not, nothing failed. These tests passed for two
# releases over a profile that never loaded for that board -- its captures
# dissected perfectly and showed Wireshark's default columns, so channel,
# RSSI and LQI were in every frame and displayed in none.
#
# Keying on the radio removes the list that could be incomplete.
EXPECTED_PROFILES = {
    "ESP32-C6 802.15.4": "wpan",
    "ESP32-C6 Wi-Fi": "radiotap",
    "ESP32-C6 BLE": "bthci_evt",
}

#: What a board-keyed filter looks like, so the regression cannot return
#: quietly. Any board name would do; these are the two that have existed.
BOARD_PREFIXES = ("esp32c6-", "nrf54l15-")


def profile_dirs() -> list[Path]:
    return sorted(p for p in PROFILE_ROOT.iterdir() if p.is_dir())


def content_lines(path: Path) -> list[str]:
    """Non-empty, non-comment lines."""
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_expected_profiles_are_present():
    assert {p.name for p in profile_dirs()} == set(EXPECTED_PROFILES)


def _switch_filter(name: str) -> str:
    lines = content_lines(PROFILE_ROOT / name / "profile_settings")
    matching = [ln for ln in lines if ln.startswith("auto_switch_filter:")]
    assert len(matching) == 1, f"{name}: expected one auto_switch_filter, got {matching}"
    return matching[0].split(":", 1)[1].strip()


@pytest.mark.parametrize("name,dissector", sorted(EXPECTED_PROFILES.items()))
def test_profile_switches_on_its_own_radio(name, dissector):
    """Each profile must claim its own radio and no other.

    The filter names a dissector rather than an interface, so it follows what
    is being sniffed rather than which board did the sniffing. Both boards'
    802.15.4 captures decode through `wpan` from the first frame, so nothing
    is lost by not naming them.
    """
    expression = _switch_filter(name)
    assert expression == dissector, f"{name}: {expression!r}"

    # A profile that also matched another radio would fight with that radio's
    # own profile, and which one won would depend on load order. Measured on
    # one capture per radio: each filter matches its own and neither other.
    for other in set(EXPECTED_PROFILES.values()) - {dissector}:
        assert other not in expression, f"{name} also claims {other}"


@pytest.mark.parametrize("name", sorted(EXPECTED_PROFILES))
def test_profile_is_not_keyed_to_a_board(name):
    """The regression that made this worth testing, named so it cannot return.

    A filter naming an interface works until a board is added and left out of
    it, and then fails silently: the profile simply never loads.
    """
    expression = _switch_filter(name)
    for prefix in BOARD_PREFIXES:
        assert prefix not in expression, (
            f"{name} switches on the board {prefix!r} rather than the radio: "
            f"{expression!r}. A new board would not load this profile."
        )


@pytest.mark.parametrize("name,dissector", sorted(EXPECTED_PROFILES.items()))
def test_profile_switches_on_the_layer_it_displays(name, dissector):
    """The filter and the columns must name the same layer.

    A profile that switches on one dissector and renders fields from another
    can load for a capture it has nothing to say about, which is the same
    silent-blank-columns failure by a different route.
    """
    preferences = (PROFILE_ROOT / name / "preferences").read_text(encoding="utf-8")
    assert f"{dissector}." in preferences or f"{dissector}-" in preferences, (
        f"{name} switches on {dissector!r} but no column reads a {dissector} field"
    )


@pytest.mark.parametrize("name", sorted(EXPECTED_PROFILES))
def test_filter_buttons_are_well_formed(name):
    """Four CSV fields: enabled, label, filter, description."""
    path = PROFILE_ROOT / name / "dfilter_buttons"
    for line in content_lines(path):
        fields = next(csv.reader(io.StringIO(line)))
        assert len(fields) == 4, f"{name}: {len(fields)} fields in {line!r}"
        assert fields[0] in ("TRUE", "FALSE"), fields[0]
        assert fields[1].strip(), f"{name}: unnamed button"
        assert fields[2].strip(), f"{name}: button {fields[1]!r} has no filter"
        assert fields[3].strip(), f"{name}: button {fields[1]!r} has no description"


@pytest.mark.parametrize("name", sorted(EXPECTED_PROFILES))
def test_colour_filters_are_well_formed(name):
    """Wireshark colour rules are @name@filter@[fg][bg] and fail closed."""
    path = PROFILE_ROOT / name / "colorfilters"
    for line in content_lines(path):
        assert line.startswith("@"), f"{name}: {line!r}"
        parts = line.split("@")
        # Leading empty field from the opening @, then name, filter, colours.
        assert len(parts) == 4, f"{name}: {len(parts) - 1} fields in {line!r}"
        assert parts[1].strip(), f"{name}: unnamed colour rule"
        assert parts[2].strip(), f"{name}: colour rule {parts[1]!r} has no filter"
        assert parts[3].count("[") == 2, f"{name}: {line!r} needs two colours"


def test_matter_decode_as_entry_is_exact():
    """Matter over Thread only dissects if this line is byte-correct.

    Wireshark's Matter dissector registers on Bluetooth alone -- service UUID
    0xFFF6 and the BTP transport -- and claims no UDP port. Thread-carried
    Matter therefore decrypts all the way to UDP and stops there.

    The final field is the dissector description. Substituting the filter name
    "matter" leaves the entry syntactically valid and functionally dead, with
    no diagnostic emitted, so this asserts the exact string.
    """
    path = PROFILE_ROOT / "ESP32-C6 802.15.4" / "decode_as_entries"
    lines = content_lines(path)
    assert lines == ["decode_as_entry: udp.port,5540,(none),Matter"], lines


def test_matter_button_exists_wherever_matter_can_appear():
    """Matter shows up on two radios by two different routes.

    Over BLE it is commissioning advertisements, which Wireshark dissects
    unaided. Over Thread it is operational traffic, which needs both the
    network key and the Decode As entry. Both profiles carry a button; the
    802.15.4 one has to say what else is required, because a button that
    silently matches nothing is worse than no button.
    """
    for name in ("ESP32-C6 802.15.4", "ESP32-C6 BLE"):
        buttons = content_lines(PROFILE_ROOT / name / "dfilter_buttons")
        labels = [next(csv.reader(io.StringIO(b)))[1] for b in buttons]
        assert "Matter" in labels, f"{name}: no Matter button"

    thread_buttons = content_lines(
        PROFILE_ROOT / "ESP32-C6 802.15.4" / "dfilter_buttons"
    )
    matter = [b for b in thread_buttons if next(csv.reader(io.StringIO(b)))[1] == "Matter"]
    description = next(csv.reader(io.StringIO(matter[0])))[3]
    assert "key" in description.lower(), description
    assert "decode as" in description.lower(), description


def test_profiles_carry_no_keys_or_secrets():
    """Key tables are per-machine state and must never be committed.

    Wireshark writes ieee802154_keys into the profile directory it is using,
    which is the same directory the installer populates from here. Nothing
    stops a key table being copied back by accident.
    """
    forbidden = {"ieee802154_keys", "80211_keys", "dtlsdecrypttablefile", "recent"}
    for directory in profile_dirs():
        present = {p.name for p in directory.iterdir()} & forbidden
        assert not present, f"{directory.name} contains {sorted(present)}"


def ble_columns() -> dict[str, str]:
    """The BLE profile's column titles, each with the field it shows."""
    text = (PROFILE_ROOT / "ESP32-C6 BLE" / "preferences").read_text(encoding="utf-8")
    return dict(re.findall(r'"([^"]+)",\s*"%Cus:([^:"]+)', text))


def ble_buttons() -> dict[str, str]:
    rows = (next(csv.reader(io.StringIO(line)))
            for line in content_lines(PROFILE_ROOT / "ESP32-C6 BLE" / "dfilter_buttons"))
    return {row[1]: row[2] for row in rows}


def test_the_ble_profile_tells_devices_apart():
    """Which device, what kind of address and whose, on every advert.

    Wireshark's filter bar cannot hold a list that fills itself from the
    capture, so the devices a capture contains are shown as columns instead:
    sort by one to group them, right-click a cell and Apply as Filter to see
    one device, one maker or one kind of address.
    """
    columns = ble_columns()
    assert columns["Advertiser"] == "bthci_evt.bd_addr"
    assert columns["Address kind"] == "bthci_evt.le_peer_address_type"
    assert columns["Maker"] == "btcommon.eir_ad.entry.company_id"


def test_the_ble_profile_has_a_followed_button_rather_than_apple():
    """One maker's button was the only one the bar had room for. The Maker
    column serves every maker; the button now shows the devices the board is
    following by their device keys -- reported under an identity address,
    public (2) or random (3)."""
    buttons = ble_buttons()
    assert "Apple" not in buttons
    assert buttons["Followed"] == "bthci_evt.le_peer_address_type in {2, 3}"
