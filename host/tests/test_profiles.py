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
from pathlib import Path

import pytest

PROFILE_ROOT = Path(__file__).resolve().parents[2] / "wireshark-profiles"

# One per radio. A filter button belongs to a profile rather than to an
# interface, so a single shared profile showed Zigbee, Thread and 802.11ax
# buttons to everyone regardless of what they were capturing.
EXPECTED_PROFILES = {
    "ESP32-C6 802.15.4": "esp32c6-802154",
    "ESP32-C6 Wi-Fi": "esp32c6-wifi",
    "ESP32-C6 BLE": "esp32c6-ble",
}


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


@pytest.mark.parametrize("name,interface", sorted(EXPECTED_PROFILES.items()))
def test_profile_switches_on_its_own_interface(name, interface):
    """Each profile must claim its own radio and no other.

    The filter matches the interface name rather than a dissector so that it
    works from the first frame, before anything has been decoded.
    """
    settings = PROFILE_ROOT / name / "profile_settings"
    lines = content_lines(settings)
    matching = [ln for ln in lines if ln.startswith("auto_switch_filter:")]
    assert len(matching) == 1, f"{name}: expected one auto_switch_filter, got {matching}"
    assert f'"{interface}"' in matching[0], matching[0]

    # A profile that also matched another radio's interface would fight with
    # that radio's own profile, and which one won would depend on load order.
    others = set(EXPECTED_PROFILES.values()) - {interface}
    for other in others:
        assert other not in matching[0], f"{name} also claims {other}"


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
