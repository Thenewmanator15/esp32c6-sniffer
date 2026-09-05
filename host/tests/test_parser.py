from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import SequenceTracker, StreamParser


def test_single_whole_frame_is_parsed():
    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.PACKET, 1, b"hello"))
    assert len(frames) == 1
    assert frames[0].payload == b"hello"


def test_two_frames_in_one_chunk():
    parser = StreamParser()
    data = encode_frame(FrameType.PACKET, 1, b"aa") + encode_frame(
        FrameType.PACKET, 2, b"bb"
    )
    frames = parser.feed(data)
    assert [f.payload for f in frames] == [b"aa", b"bb"]


def test_frame_split_across_many_feeds():
    parser = StreamParser()
    data = encode_frame(FrameType.PACKET, 7, bytes(range(100)))
    collected = []
    for i in range(0, len(data), 3):
        collected.extend(parser.feed(data[i : i + 3]))
    assert len(collected) == 1
    assert collected[0].seq == 7


def test_leading_garbage_is_discarded_and_counted():
    parser = StreamParser()
    data = b"\x11\x22\x33\x44" + encode_frame(FrameType.PACKET, 1, b"ok")
    frames = parser.feed(data)
    assert len(frames) == 1
    assert frames[0].payload == b"ok"
    assert parser.bytes_discarded == 4
    assert parser.resync_count == 1


def test_truncated_frame_stalls_until_forced_resync():
    """A valid header whose payload was lost is indistinguishable from one
    still in flight. The parser must wait, and only the caller -- which knows
    it has timed out -- can break the deadlock."""
    good = encode_frame(FrameType.PACKET, 1, b"first")
    truncated = encode_frame(FrameType.PACKET, 2, b"X" * 50)[:20]
    following = encode_frame(FrameType.PACKET, 3, b"third")

    parser = StreamParser()
    first_batch = parser.feed(good + truncated + following)
    assert [f.payload for f in first_batch] == [
        b"first"
    ], "parser must not guess past an incomplete payload"

    recovered = parser.force_resync()
    assert [f.payload for f in recovered] == [b"third"]
    assert parser.resync_count >= 1


def test_false_magic_inside_payload_does_not_desynchronise():
    # A payload containing the magic bytes must not be mistaken for a header.
    payload = b"\xc6\x5a\x01\x00\x00\x00\x10\x00" * 4
    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.PACKET, 1, payload))
    assert len(frames) == 1
    assert frames[0].payload == payload


def test_sequence_tracker_reports_no_loss_when_contiguous():
    tracker = SequenceTracker()
    for seq in range(5):
        assert tracker.observe(seq) == 0
    assert tracker.total_missed == 0


def test_sequence_tracker_counts_a_gap():
    tracker = SequenceTracker()
    tracker.observe(10)
    assert tracker.observe(14) == 3
    assert tracker.total_missed == 3


def test_sequence_tracker_handles_wraparound():
    tracker = SequenceTracker()
    tracker.observe(65534)
    assert tracker.observe(1) == 2
    assert tracker.total_missed == 2
