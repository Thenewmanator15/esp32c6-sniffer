"""link_probe's analysis: what a raw byte stream says was lost in transit.

Each frame header carries its own CRC, so every intact header is a landmark
and the distance to the next must be exactly HEADER_LEN + length. The board's
STATS frames count the bytes it queued, so between two intact ones the total
lost in transit is exact. These streams are built by hand, with the losses
put in on purpose.
"""

import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import link_probe  # noqa: E402
from esp32c6_sniffer.framing import FrameType, encode_frame  # noqa: E402


def stats(seq, bytes_sent):
    values = [0] * 32
    values[link_probe.BYTES_SENT_INDEX] = bytes_sent
    return encode_frame(FrameType.STATS, seq, struct.pack("<32I", *values))


def packet(seq, size=40):
    return encode_frame(FrameType.PACKET, seq, bytes(size))


def stream(middle, first_count=1000):
    """STATS, the middle frames, STATS -- the second STATS counting exactly
    the bytes the board sent from the first header to the second."""
    head = stats(1, first_count)
    sent = len(head) + sum(len(f) for f in middle)
    return head, middle, stats(1 + len(middle) + 1, first_count + sent)


def test_a_clean_stream_loses_nothing():
    head, middle, tail = stream([packet(2), packet(3), packet(4)])
    report = link_probe.analyse(head + b"".join(middle) + tail)
    assert report.lost_bytes == 0
    assert report.truncated == [] and report.header_gaps == []


def test_a_frame_that_lost_its_tail_is_found_and_counted():
    head, middle, tail = stream([packet(2), packet(3, size=300), packet(4)])
    cut = middle[1][:-20]                      # the bridge kept all but 20 bytes
    report = link_probe.analyse(head + middle[0] + cut + middle[2] + tail)
    assert [(t.frame_type, t.missing) for t in report.truncated] == [("PACKET", 20)]
    assert report.lost_bytes == 20


def test_frames_whose_headers_were_destroyed_show_as_a_gap():
    head, middle, tail = stream([packet(2), packet(3), packet(4), packet(5)])
    report = link_probe.analyse(head + middle[0] + middle[3] + tail)
    assert [g.frames_lost for g in report.header_gaps] == [2]
    assert report.lost_bytes == len(middle[1]) + len(middle[2])


def test_frames_longer_than_the_bridge_holds_are_counted():
    """The SAMD11 holds 319 bytes; a burst past that is what gets cut."""
    head, middle, tail = stream([packet(2, size=500), packet(3), packet(4, size=400)])
    report = link_probe.analyse(head + b"".join(middle) + tail)
    assert report.frames_over_bridge_buffer == 2


def test_without_two_stats_frames_loss_is_unknown_not_zero():
    report = link_probe.analyse(packet(1) + packet(2))
    assert report.lost_bytes is None
