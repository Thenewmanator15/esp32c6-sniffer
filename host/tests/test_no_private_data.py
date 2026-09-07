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

#: PAN identifiers that exist to be written down. A real one names a real
#: 802.15.4 network, and it is only two bytes, so it reads like any other
#: constant -- which is exactly how the operator's own PAN reached a Thread
#: test fixture, copied out of a live dataset because it was the value to hand.
SYNTHETIC_PANS = {
    0x0000, 0xFFFF,          # the unassigned and broadcast PANs
    0x1234, 0x4321, 0xABCD, 0xBEEF, 0xCAFE, 0xDEAD,
}

#: Matched only where a PAN is plainly meant. A bare four-hex-digit constant is
#: far too common to flag on sight.
#: [=:]{1,2} rather than [=:], so a comparison is caught and not just an
#: assignment. The first version of this missed `pan_id == 0x...`, which was
#: one of the two lines that actually leaked.
PAN_LITERAL = re.compile(r"pan(?:_id)?\s*[=:]{1,2}\s*(0x[0-9a-fA-F]{4})\b",
                         re.IGNORECASE)

#: RFC 1918 and the link-local range: a real address from a real network.
PRIVATE_IP = re.compile(
    r"\b(?:192\.168\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b")

SKIP_SUFFIXES = {".pcap", ".pcapng", ".png", ".bin", ".elf"}


def tracked_text_files():
    """Everything that would be published: committed files AND new ones.

    `git ls-files` alone lists only what is already committed, so a brand new
    file was invisible to this guard. A real device's address reached a test
    file that way, and was caught by an unrelated assertion rather than by the
    check written for exactly that -- the guard passed on a working tree that
    contained it.

    Untracked files are included with --exclude-standard, so anything
    .gitignore covers -- build output, the virtualenv -- is still skipped.
    """
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=REPO,
                            capture_output=True, text=True, check=True).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "-z", "--others", "--exclude-standard"], cwd=REPO,
        capture_output=True, text=True, check=True).stdout
    for name in (listed + untracked).split("\0"):
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


#: Paths that only exist on one developer's machine. A tool carrying one works
#: there and nowhere else, and the failure a user sees is an import error that
#: says nothing about the cause.
#: The character class must contain a BACKSLASH as well as a slash. Written
#: with only the slash it silently matched no Windows path at all -- passing
#: on a repository that did contain one, which is the worst way for a guard to
#: be wrong.
ABSOLUTE_PATH = re.compile(
    r"""["'](?:[A-Za-z]:[\\/]|/home/|/Users/)[^"'\n]{3,}["']""")

#: Absolute paths that are fine: the documented install location of a
#: third-party tool, or a device node, rather than somebody's project folder.
ALLOWED_ABSOLUTE = (r"C:\Program Files", "C:/Program Files", "/usr/",
                    "/dev/tty", "/dev/ttyACM", "/dev/ttyUSB",
                    # Standard install locations searched for, not assumed:
                    # the scripts fall through them and report what they tried.
                    r"C:\Espressif", "/esp/", "\\esp\\",
                    # The conventional placeholder, in documentation examples.
                    "\\path\\to\\", "/path/to/")


def _offending_paths(line: str) -> list[str]:
    return [match for match in ABSOLUTE_PATH.findall(line)
            if not any(allowed in match for allowed in ALLOWED_ABSOLUTE)]


def test_no_paths_from_one_developers_machine(tracked):
    r"""tools/abuse.py carried a hardcoded sys.path pointing at H:\dev, so it
    ran for its author and for nobody else."""
    found = []
    for name, text in tracked:
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in _offending_paths(line):
                found.append("%s:%d  %s" % (name, line_no, match))
    assert not found, (
        "absolute paths that will not exist in a clone:\n  "
        + "\n  ".join(found))


def test_the_path_guard_catches_what_it_is_for():
    r"""A guard whose pattern never fires passes on a repository that is
    broken. This one already did: the character class was missing its
    backslash, so every Windows path went through it untouched."""
    assert _offending_paths(r'sys.path.insert(0, r"H:\dev\projects\thing")')
    assert _offending_paths('open("/home/someone/keys.txt")')
    assert _offending_paths(r'PATH = "C:\Users\Work\captures"')
    assert _offending_paths('data = "/Users/someone/Desktop/out.pcap"')
    # And must stay quiet on the ones that are legitimate.
    assert not _offending_paths(r"TSHARK = r'C:\Program Files\Wireshark\x.exe'")
    assert not _offending_paths(
        'DEFAULT_PORT = "COM3" if os.name == "nt" else "/dev/ttyACM0"')
    assert not _offending_paths('path = os.path.join(here, "..", "src")')


def test_no_real_pan_identifiers(tracked):
    """A PAN ID names a real 802.15.4 network.

    Two bytes, so it reads like any other constant, and the only reason to type
    an unusual one is that it came off a live network. This caught the
    operator's own PAN in a Thread test fixture, where it had been copied
    straight out of a border router's operational dataset -- the guard above
    could not see it, because a PAN is not a MAC or an IP.
    """
    found = []
    for name, text in tracked:
        for line_no, line in enumerate(text.splitlines(), 1):
            for literal in PAN_LITERAL.findall(line):
                if int(literal, 16) not in SYNTHETIC_PANS:
                    found.append("%s:%d  %s" % (name, line_no, literal))
    assert not found, (
        "PAN identifiers that are not obviously synthetic:\n  "
        + "\n  ".join(found)
        + "\nUse one of: "
        + ", ".join("0x%04X" % pan for pan in sorted(SYNTHETIC_PANS)))


def test_the_pan_guard_catches_what_it_is_for():
    """Proved rather than assumed: a guard that matches nothing is not a guard.

    The pattern is deliberately narrow -- it fires only where a PAN is plainly
    being named -- so it needs a test that it fires at all.
    """
    real = [m for m in PAN_LITERAL.findall('creds = dataset(pan=0x7A2C)')
            if int(m, 16) not in SYNTHETIC_PANS]
    assert real == ["0x7A2C"]
    assert PAN_LITERAL.findall("assert creds.pan_id == 0xBEEF") == ["0xBEEF"]
    # And stays quiet on hex that has nothing to do with a PAN.
    assert not PAN_LITERAL.findall("MASK = 0x7A2C")
    assert not PAN_LITERAL.findall("session_id = 0xd3a0")
