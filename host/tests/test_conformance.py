"""Holds firmware frame.c to byte-identical output with framing.py.

Host-only checks run anywhere. The hardware checks need the board attached
running the conformance build (SN_MODE=0):

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


def _collect(port, seconds: float, parser: StreamParser):
    """Returns (raw_bytes, frames). Raw is kept for byte-identity checks."""
    raw = bytearray()
    frames = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        chunk = port.read(4096)
        if chunk:
            raw.extend(chunk)
            frames.extend(parser.feed(chunk))
    return bytes(raw), frames


def _find_burst_start(frames) -> int:
    """The firmware repeats its burst, so anchor on the first vector.

    Anchors on type and payload, not sequence number: the link assigns
    sequence numbers at runtime, so they differ between bursts.
    """
    first = VECTORS[0]
    want_payload = bytes.fromhex(first["payload"])
    for i, frame in enumerate(frames):
        if int(frame.ftype) == first["type"] and frame.payload == want_payload:
            if len(frames) - i >= len(VECTORS):
                return i
    return -1


#: Frame types only the capture build emits. Seeing one means the board is
#: flashed for capture rather than conformance, so the golden burst will never
#: arrive -- a build the operator chose, not a fault to report.
CAPTURE_BUILD_FRAMES = {FrameType.STATS, FrameType.HEARTBEAT}


def _looks_like_the_capture_build(frames) -> bool:
    return any(frame.ftype in CAPTURE_BUILD_FRAMES for frame in frames)


@pytest.mark.hardware
def test_firmware_emits_identical_bytes(sniffer_port):
    """The C encoder must produce exactly what the Python encoder produces.

    Sequence numbers come from the link at runtime, so we cannot compare
    against a stored encoding directly. Instead, for each received frame we
    encode the same (type, seq, payload) in Python and require those exact
    bytes to appear in the raw stream. That covers the header layout and the
    CRC, not merely the payload.
    """
    parser = StreamParser()
    raw, frames = _collect(sniffer_port, 8.0, parser)

    start = _find_burst_start(frames)
    if start < 0 and _looks_like_the_capture_build(frames):
        pytest.skip(
            "board is running the capture build (SN_MODE=2), which does not "
            "emit the golden burst; reflash with -DSN_MODE=0 to run this"
        )
    # Deliberately distinguished from the skip above. No burst AND nothing
    # identifying the capture build is a real failure, and reporting that as a
    # skip would hide a broken conformance build behind a convenience.
    assert start >= 0, (
        f"no complete conformance burst in {len(frames)} frames, and no sign "
        f"this is the capture build either"
    )

    for case, frame in zip(VECTORS, frames[start:]):
        assert int(frame.ftype) == case["type"], f"type differs: {case['name']}"
        assert frame.payload.hex() == case["payload"], (
            f"payload differs: {case['name']}"
        )
        expected = encode_frame(frame.ftype, frame.seq, frame.payload)
        assert expected in raw, (
            f"C encoding differs from Python for {case['name']}"
        )


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
    _, frames = _collect(sniffer_port, 6.0, parser)

    assert frames, "no frames after synchronisation"
    leaked = parser.bytes_discarded - baseline
    assert leaked == 0, f"{leaked} unframed bytes reached the host after sync"


@pytest.mark.hardware
def test_log_output_arrives_as_framed_log_messages(sniffer_port):
    """ESP_LOG must travel in-band as LOG frames, not as raw interleaved text.

    With USB-C as the only cable there is no second channel to read a console
    on, so log output is redirected into the frame protocol and the host
    demultiplexes it.
    """
    parser = StreamParser()
    _, frames = _collect(sniffer_port, 8.0, parser)

    log_frames = [f for f in frames if f.ftype is FrameType.LOG]
    assert log_frames, "no LOG frames received"
    for frame in log_frames:
        frame.payload.decode("utf-8", errors="strict")
