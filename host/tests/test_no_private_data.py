"""Nothing identifying about the operator's own network may be committed.

This repository is meant to be published. Developing it against a real network
puts real details into files by accident -- a DHCP lease pasted with a block of
sample output, the board's own MAC copied out of esptool, a neighbour's SSID
used as a convenient test string. None of it is dangerous on its own; all of it
is somebody's home network, and once pushed it is public and archived.

So this test greps every tracked file. It fails on things that look real rather
than on a list of known strings, because a list would have to contain the very
values it is meant to keep out.
"""

import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

#: Addresses that exist to appear in documentation and tests. RFC 5737 reserves
#: 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 for exactly this.
DOCUMENTATION_NETS = re.compile(
    r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0|127\.0\.0\.1|255\.)")

#: Obviously synthetic MACs used as test vectors. Anything outside this is
#: assumed to belong to real hardware.
SYNTHETIC_MACS = {
    "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
    "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff",
    "01:02:03:04:05:06", "de:ad:be:ef:00:01",
}

MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
#: RFC 1918 and the link-local range: a real address from a real network.
PRIVATE_IP = re.compile(
    r"\b(?:192\.168\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b")

SKIP_SUFFIXES = {".pcap", ".pcapng", ".png", ".bin", ".elf"}


def tracked_text_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO,
                         capture_output=True, text=True, check=True).stdout
    for name in out.split("\0"):
        if not name:
            continue
        path = REPO / name
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        # This file necessarily contains the patterns it searches for.
        if path.name == pathlib.Path(__file__).name:
            continue
        try:
            yield name, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue


@pytest.fixture(scope="module")
def tracked():
    return list(tracked_text_files())


def test_no_real_mac_addresses(tracked):
    """The board's own MAC was pasted straight out of esptool into the design
    document, where it identified the operator's hardware."""
    found = []
    for name, text in tracked:
        for line_no, line in enumerate(text.splitlines(), 1):
            for mac in MAC.findall(line):
                if mac.lower() not in SYNTHETIC_MACS:
                    found.append("%s:%d  %s" % (name, line_no, mac))
    assert not found, (
        "MAC addresses that are not obviously synthetic:\n  "
        + "\n  ".join(found)
        + "\nUse one of: " + ", ".join(sorted(SYNTHETIC_MACS)))


def test_no_addresses_from_a_real_network(tracked):
    """A DHCP lease and gateway went into the README with a block of sample
    output. Use the RFC 5737 documentation ranges instead."""
    found = []
    for name, text in tracked:
        for line_no, line in enumerate(text.splitlines(), 1):
            for ip in PRIVATE_IP.findall(line):
                if not DOCUMENTATION_NETS.match(ip):
                    found.append("%s:%d  %s" % (name, line_no, ip))
    assert not found, (
        "addresses from a real network:\n  " + "\n  ".join(found)
        + "\nUse 192.0.2.x, 198.51.100.x or 203.0.113.x (RFC 5737).")
