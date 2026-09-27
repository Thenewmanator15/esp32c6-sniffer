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


def test_a_frame_truncated_in_transit_is_dropped_not_spliced():
    """The nRF54L15's SAMD11 bridge holds 319 bytes and drops the tail of a
    burst past that while its USB side is stalled. The header survives and
    declares the full length, and the next frame's bytes arrive to fill it --
    so without a check the damaged frame decodes with the start of the next
    frame as the end of its payload, and the next frame is lost in its place.
    Measured on the board: 6 of 13 such BLE batches decoded as valid."""
    first = encode_frame(FrameType.PACKET, 1, b"A" * 40)
    damaged = encode_frame(FrameType.PACKET, 2, b"B" * 60)[:10 + 25]
    following = encode_frame(FrameType.PACKET, 3, b"C" * 80)
    after = encode_frame(FrameType.PACKET, 4, b"D" * 10)

    parser = StreamParser()
    frames = parser.feed(first + damaged + following + after)

    assert [(f.seq, f.payload) for f in frames] == [
        (1, b"A" * 40), (3, b"C" * 80), (4, b"D" * 10)]
    assert parser.frames_truncated == 1


def test_a_single_dropped_byte_is_caught_too():
    """The bridge's other failure: one byte overrun at a random position. The
    next header then begins on the damaged frame's last declared byte, so the
    check has to look past the declared end for the rest of it."""
    damaged = encode_frame(FrameType.PACKET, 7, b"B" * 60)[:-1]
    following = encode_frame(FrameType.PACKET, 8, b"C" * 20)

    parser = StreamParser()
    frames = parser.feed(damaged + following)

    assert [(f.seq, f.payload) for f in frames] == [(8, b"C" * 20)]
    assert parser.frames_truncated == 1


def test_a_valid_header_far_off_in_sequence_is_just_payload():
    """A truncation is followed by the next frame, whose sequence number is
    just ahead. A fully valid header carrying any other number is far likelier
    to be payload that happens to look like one, and must not cost a frame."""
    inner = encode_frame(FrameType.PACKET, 500, b"")
    payload = b"x" * 5 + inner + b"y" * 5

    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.PACKET, 2, payload))

    assert [(f.seq, f.payload) for f in frames] == [(2, payload)]
    assert parser.frames_truncated == 0


def test_a_header_inside_captured_bytes_does_not_cut_the_frame():
    """A PACKET's payload is whatever went over the air, and anyone can send
    a radio frame holding a valid sniffer header with a sequence number just
    ahead. The check used to take that for a truncation: the real frame was
    dropped, the transmitter's bytes were parsed as a board frame, and 65536
    sequence gaps were counted. What follows the declared end settles it --
    the next frame in sequence, exactly there, means nothing was lost."""
    injected = encode_frame(FrameType.PACKET, 6, b"INJECTED")
    captured = b"\x41\x88" + injected + b"\x00\x01"
    real = encode_frame(FrameType.PACKET, 5, captured)
    following = encode_frame(FrameType.PACKET, 6, b"next")

    parser = StreamParser()
    frames = parser.feed(real + following)

    assert [(f.seq, f.payload) for f in frames] == [(5, captured), (6, b"next")]
    assert parser.frames_truncated == 0


def test_a_header_inside_captured_bytes_waits_for_what_follows():
    """Until the bytes after the declared end arrive, truncation and
    coincidence cannot be told apart, so the frame waits rather than being
    guessed at either way."""
    injected = encode_frame(FrameType.PACKET, 6, b"INJECTED")
    captured = b"\x41\x88" + injected + b"\x00\x01"
    parser = StreamParser()

    assert parser.feed(encode_frame(FrameType.PACKET, 5, captured)) == []
    frames = parser.feed(encode_frame(FrameType.PACKET, 6, b"next"))
    assert [f.seq for f in frames] == [5, 6] and frames[0].payload == captured


def test_one_large_read_parses_in_linear_time():
    """Each frame used to copy the whole remaining buffer before decoding, so
    a backlog read in one go -- the capture reads all that is waiting when a
    reply is due -- cost time in the square of its size: 1.2 s for 1 MB."""
    import time
    chunk = b"".join(encode_frame(FrameType.PACKET, n % 65536, b"p" * 40)
                     for n in range(21000))                # about 1 MB
    parser = StreamParser()
    started = time.perf_counter()
    frames = parser.feed(chunk)
    elapsed = time.perf_counter() - started
    assert len(frames) == 21000
    # About 0.07 s here; 0.5 leaves room for a busy machine and still
    # fails the quadratic parser by more than half.
    assert elapsed < 0.5, f"{elapsed:.2f} s for {len(chunk) // 1024} KB"


def test_the_check_never_holds_a_frame_back():
    """Only headers already wholly received are examined, so a payload ending
    in what could be the start of one is still delivered at once rather than
    held for bytes that may not come -- the link is often quiet for a second
    at a time, and control replies wait on this path."""
    payload = b"z" * 20 + b"\xc6\x5a"

    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.CONTROL_REPLY, 9, payload))

    assert [(f.seq, f.payload) for f in frames] == [(9, payload)]


def test_a_quiet_link_releases_the_frame_it_was_holding_whole():
    """A frame holding a header-like run waits for what follows its end. On
    a quiet link nothing does, and the stall used to be broken by resyncing
    inside the frame: the real frame was dropped and whatever header a
    transmitter had put in its payload was delivered as a board frame --
    measured through a capture session, the forged packet and 65536
    sequence gaps. A frame wholly received is released as it stands."""
    injected = encode_frame(FrameType.PACKET, 8, b"INJECTED")
    captured = b"\x41\x88" + injected + b"\x00\x01"
    parser = StreamParser()

    assert parser.feed(encode_frame(FrameType.PACKET, 5, captured)) == []
    frames = parser.force_resync()
    assert [(f.seq, f.payload) for f in frames] == [(5, captured)]
    assert parser.buffered == 0


def test_a_frame_cut_short_is_not_joined_to_the_frames_after_it():
    """A frame that lost its tail declares bytes that belong to the frames
    after it. Taking it as intact whenever some later header began exactly
    at its declared end delivered it with them inside and lost them: 107
    joined frames and 116 good ones lost in 20000 simulated truncations.
    Only the very next frame there says nothing was lost."""
    cut = encode_frame(FrameType.PACKET, 5, bytes(75))[:15]
    second = encode_frame(FrameType.PACKET, 6, bytes(20))
    third = encode_frame(FrameType.PACKET, 7, bytes(30))
    fourth = encode_frame(FrameType.PACKET, 8, b"d")
    assert len(cut) + len(second) + len(third) == 10 + 75   # 8 starts at the end

    frames = StreamParser().feed(cut + second + third + fourth)

    assert [f.seq for f in frames] == [6, 7, 8]
