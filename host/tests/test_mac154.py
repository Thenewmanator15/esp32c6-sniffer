"""The 802.15.4 MAC header reader the channel survey uses to name networks.

A survey that counts frames per channel says where traffic is, but not whose.
Reading the header -- PAN ID, addresses, security, command -- and the first
byte after it is enough to tell Zigbee from Thread and to count devices,
without any key. Frames here are built by hand from the standard's layouts;
the FCS is left off, as it plays no part in any of this.
"""

from esp32c6_sniffer.mac154 import MacHeader, parse

# Frame control, little-endian on the air.
DATA_SHORT_SHORT_COMPRESSED = (0x8841).to_bytes(2, "little")      # data, PAN compression, v2003
DATA_SECURED_2006 = (0x9869).to_bytes(2, "little")                # data, security, ack req, PAN compression, v2006
CMD_SECURED_2006 = (0x986B).to_bytes(2, "little")                 # command, same flags


def frame(fcf: bytes, seq: int, *fields: bytes) -> bytes:
    return fcf + bytes([seq]) + b"".join(fields)


def le16(value: int) -> bytes:
    return value.to_bytes(2, "little")


def le64(value: int) -> bytes:
    return value.to_bytes(8, "little")


# A MAC auxiliary security header: level 5, key id mode 1, counter, key index.
AUX_SECURITY = bytes([0x0D]) + (7).to_bytes(4, "little") + bytes([0x01])


def test_secured_data_frame_is_thread():
    psdu = frame(DATA_SECURED_2006, 1, le16(0x1234), le16(0x0400), le16(0xAC0C),
                 AUX_SECURITY, b"\xde\xad\xbe\xef")
    header = parse(psdu)
    assert header == MacHeader(frame_type=1, version=1, secured=True,
                               dst_pan=0x1234, src_pan=0x1234,
                               dst_addr=0x0400, src_addr=0xAC0C, src_is_ext=False,
                               command_id=None, network="Thread")
    assert header.pan == 0x1234


def test_data_request_command_is_recognised():
    psdu = frame(CMD_SECURED_2006, 2, le16(0x1234), le16(0x0400), le16(0xAC0C),
                 AUX_SECURITY, b"\x04")
    header = parse(psdu)
    assert header.frame_type == 3
    assert header.secured
    # In 802.15.4-2006 the command identifier is in the clear even when the
    # command is secured: Thread's sleepy devices poll this way, and a 5-minute
    # capture of one Thread network read 0x04 from 172 of them.
    assert header.command_id == 0x04
    assert header.is_data_request


def test_plain_data_request_is_recognised():
    fcf = (0x8863).to_bytes(2, "little")   # command, ack req, PAN compression, v2003
    psdu = frame(fcf, 3, le16(0x1234), le16(0x0000), le16(0x796F), b"\x04")
    header = parse(psdu)
    assert header.command_id == 0x04
    assert header.is_data_request


def test_unsecured_6lowpan_data_is_thread():
    # MLE travels without MAC security; its 6LoWPAN IPHC header starts 0x7x.
    fcf = (0xDC41).to_bytes(2, "little")   # data, PAN compression, v2006, ext dst and src
    psdu = frame(fcf, 4, le16(0x1234), le64(0x1122334455667788), le64(0xAABBCCDDEEFF0011),
                 b"\x7f\x33\xf0")
    header = parse(psdu)
    assert header.src_is_ext
    assert header.src_addr == 0xAABBCCDDEEFF0011
    assert header.network == "Thread"


def test_zigbee_nwk_data_is_zigbee():
    # Zigbee NWK frame control: data frame, protocol version 2.
    psdu = frame(DATA_SHORT_SHORT_COMPRESSED, 5, le16(0xBEEF), le16(0xFFFF), le16(0x0000),
                 b"\x08\x02\xfc\xff\x00\x00")
    header = parse(psdu)
    assert header.network == "Zigbee"
    assert not header.secured


def test_beacons_name_their_stack():
    fcf = (0x8000).to_bytes(2, "little")   # beacon, short source, v2003
    beacon_fields = b"\xff\xcf" + b"\x00" + b"\x00"   # superframe spec, no GTS, no pending
    zigbee = frame(fcf, 6, le16(0xBEEF), le16(0x0000), beacon_fields, b"\x00\x22\x84")
    thread = frame(fcf, 7, le16(0x1234), le16(0x0000), beacon_fields, b"\x03\x21")
    assert parse(zigbee).network == "Zigbee"
    assert parse(thread).network == "Thread"
    assert parse(zigbee).pan == 0xBEEF


def test_acknowledgement_has_no_pan():
    ack = (0x0002).to_bytes(2, "little") + b"\x09"
    header = parse(ack)
    assert header.frame_type == 2
    assert header.pan is None
    assert header.network is None


def test_2015_frame_without_compression_carries_both_pans():
    # Frame version 2 (802.15.4-2015), short/short, PAN ID compression clear.
    fcf = (0xA801).to_bytes(2, "little")
    psdu = frame(fcf, 8, le16(0x1234), le16(0x0400), le16(0x5678), le16(0xAC0C), b"\x7a")
    header = parse(psdu)
    assert header.version == 2
    assert (header.dst_pan, header.src_pan) == (0x1234, 0x5678)
    assert header.src_addr == 0xAC0C


def test_2015_ext_to_ext_with_compression_has_no_pan():
    fcf = (0xEC41).to_bytes(2, "little")   # data, compression, v2015, ext dst and src
    psdu = frame(fcf, 9, le64(1), le64(2), b"\x7a")
    header = parse(psdu)
    assert header.dst_pan is None and header.src_pan is None
    assert header.src_addr == 2


def test_truncated_frames_are_refused_not_misread():
    whole = frame(DATA_SECURED_2006, 1, le16(0x1234), le16(0x0400), le16(0xAC0C), AUX_SECURITY)
    for cut in range(len(whole) - len(AUX_SECURITY)):
        assert parse(whole[:cut]) is None, cut
    assert parse(b"") is None


def test_reserved_addressing_mode_is_refused():
    fcf = (0x0441).to_bytes(2, "little")   # destination addressing mode 1, reserved
    assert parse(frame(fcf, 1, b"\x00" * 12)) is None
