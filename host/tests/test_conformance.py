"""Holds firmware frame.c to byte-identical output with framing.py.

Host-only checks run anywhere. The hardware check needs the board attached:

    pytest -m hardware --port COM3
"""

import json
import pathlib
import time

import pytest

from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "golden.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_host_encoder_still_matches_stored_vectors(case):
    """Guards against an accidental wire-format change on the host side."""
    produced = encode_frame(
        FrameType(case["type"]), case["seq"], bytes.fromhex(case["payload"])
    )
    assert produced.hex() == case["encoded"]


def _collect(port, seconds: float, parser: StreamParser) -> list:
    frames = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        frames.extend(parser.feed(port.read(4096)))
    return frames


def _find_burst_start(frames) -> int:
    """The firmware repeats its burst, so anchor on the first vector."""
    first = VECTORS[0]
    for i, frame in enumerate(frames):
        if int(frame.ftype) == first["type"] and frame.seq == first["seq"]:
            if len(frames) - i >= len(VECTORS):
                return i
    return -1


@pytest.mark.hardware
def test_firmware_emits_identical_bytes(sniffer_port):
    """The C encoder must produce exactly what the Python encoder produces."""
    parser = StreamParser()
    frames = _collect(sniffer_port, 8.0, parser)

    start = _find_burst_start(frames)
    assert start >= 0, (
        f"no complete conformance burst seen in {len(frames)} frames"
    )

    for case, frame in zip(VECTORS, frames[start:]):
        rebuilt = encode_frame(frame.ftype, frame.seq, frame.payload)
        assert rebuilt.hex() == case["encoded"], f"mismatch on {case['name']}"


@pytest.mark.hardware
def test_no_unframed_bytes_once_synchronised(sniffer_port):
    """Console output must not leak into the data path.

    Measured only after synchronisation, deliberately. Two effects make a
    zero-from-cold assertion impossible, and neither is a fault:
    attaching mid-stream always costs the partial frame in flight, and the
    firmware discards data after 50 ms whenever no host is draining the port,
    so any gap between opening handles leaves real holes in the stream.

    What must hold is that a continuously-reading host sees nothing outside a
    frame. Any post-sync discard means raw bytes are reaching the data path.
    """
    parser = StreamParser()

    sync_deadline = time.monotonic() + 6.0
    while time.monotonic() < sync_deadline:
        if parser.feed(sniffer_port.read(4096)):
            break
    else:
        pytest.fail("never synchronised to the frame stream")

    baseline = parser.bytes_discarded
    frames = _collect(sniffer_port, 6.0, parser)

    assert frames, "no frames after synchronisation"
    leaked = parser.bytes_discarded - baseline
    assert leaked == 0, f"{leaked} unframed bytes reached the host after sync"
