"""Radio-aware behaviour of CaptureSession, without hardware.

These run offline deliberately. The Wi-Fi receiver on this board goes deaf for
minutes at a time (see docs/2026-09-05-wifi-investigation-postmortem.md), so a
test that needs live traffic would fail for reasons that have nothing to do
with the code under test.
"""

import io
import struct

import pytest

from esp32c6_sniffer.capture import (
    CaptureSession,
    channel_range,
    WIFI_CHANNEL_MAX,
    WIFI_CHANNEL_MIN,
    _BLE_BLOCK_AT,
    _BLE_BLOCK_END,
    _STATS_COUNTERS,
    _STATS_V6,
    _WIFI_BLOCK_AT,
)
from esp32c6_sniffer.control import Radio
from esp32c6_sniffer.pcap import PcapWriter
from esp32c6_sniffer.radiotap import (
    BIT_MCS,
    BIT_RATE,
    CHAN_CCK,
    CHAN_OFDM,
    HEADER_LEN,
    LINKTYPE_IEEE802_11_RADIOTAP,
    MCS_FLAG_SGI,
    MCS_KNOWN_INDEX,
    PhyFormat,
    decode_ht_sig,
    rate_500kbps,
)
from esp32c6_sniffer.tap import CHANNEL_MAX, CHANNEL_MIN, LINKTYPE_IEEE802_15_4_TAP

WIFI_META = struct.Struct("<BbbBQHBBIH")  # ..., orig_len, rate, phy, siga1, siga2
META_154 = struct.Struct("<BBbBQ")

# pcap record header: ts_sec, ts_usec, incl_len, orig_len
PCAP_RECORD = struct.Struct("<IIII")
PCAP_GLOBAL_HEADER_LEN = 24


def wifi_session(channel: int = 6) -> CaptureSession:
    """A session that is never opened, so no port is touched."""
    return CaptureSession("COM_UNUSED", channel=channel, radio=Radio.WIFI)


def session_154(channel: int = 25) -> CaptureSession:
    return CaptureSession("COM_UNUSED", channel=channel, radio=Radio.IEEE802154)


def ble_session() -> CaptureSession:
    """No channel: the controller rotates the three advertising channels."""
    return CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE)


def wifi_payload(body: bytes, on_air_len: int, *, channel=6, rssi=-55,
                 noise=-96, flags=0, timestamp=1234, rate=0xB,
                 phy=PhyFormat.G, siga1=0, siga2=0) -> bytes:
    return WIFI_META.pack(channel, rssi, noise, flags, timestamp,
                          on_air_len, rate, phy, siga1, siga2) + body


#: The firmware strips the FCS, so metadata lengths are four bytes shorter
#: than the ones a signalling field carries.
FCS_LEN = 4


def ht_sig1(mcs: int, length: int, bw40: bool = False) -> int:
    """HT-SIG1: MCS in bits 0-6, 20/40 in bit 7, HT Length in bits 8-23.

    `length` is the PSDU length INCLUDING the four-byte FCS, which is what
    HT Length counts and what the decoder expects.
    """
    return (mcs & 0x7F) | ((1 if bw40 else 0) << 7) | ((length & 0xFFFF) << 8)


def present_bitmap(record: bytes) -> int:
    return struct.unpack_from("<I", record, 4)[0]


def channel_flags(record: bytes) -> int:
    """Reads the radiotap Channel flags out of a built header.

    Field order is TSFT (8, 8-aligned), Flags (1), Rate (1, optional), then
    Channel (two u16, 2-aligned). The optional Rate byte is followed by padding
    when absent, so Channel lands at the same offset either way.
    """
    offset = HEADER_LEN + 8 + 1          # header, TSFT, Flags
    offset += 1 if present_bitmap(record) & (1 << BIT_RATE) else 0
    offset += offset % 2                 # 2-byte alignment
    return struct.unpack_from("<H", record, offset + 2)[0]


def test_channel_ranges_differ_per_radio():
    assert channel_range(Radio.WIFI) == (WIFI_CHANNEL_MIN, WIFI_CHANNEL_MAX)
    assert channel_range(Radio.IEEE802154) == (CHANNEL_MIN, CHANNEL_MAX)


def test_wifi_rejects_an_802154_channel():
    """26 is a valid 802.15.4 channel and an invalid Wi-Fi one."""
    with pytest.raises(ValueError, match="26"):
        wifi_session(26)


def test_802154_rejects_a_wifi_channel():
    with pytest.raises(ValueError, match="6"):
        session_154(6)


def test_linktype_follows_the_radio():
    """A capture written with the wrong link type decodes as noise."""
    assert wifi_session().linktype == LINKTYPE_IEEE802_11_RADIOTAP
    assert session_154().linktype == LINKTYPE_IEEE802_15_4_TAP


def test_wifi_record_carries_a_radiotap_header():
    body = b"\x80\x00" + b"\x11" * 40
    record, body_len, device_us, _original = wifi_session()._build_record(
        wifi_payload(body, len(body))
    )
    assert body_len == len(body)
    assert device_us == 1234
    # Radiotap starts with version 0 and a zero pad byte.
    assert record[0] == 0 and record[1] == 0
    assert record.endswith(body)


def test_truncated_wifi_frame_reports_its_original_length():
    """The regression this exists for.

    The firmware truncates to a snapshot length. If the record is declared at
    its captured length, Wireshark believes the frame is complete and reports
    "length of contained item exceeds length of containing item" on every
    beacon. Measured before the fix: 556 malformed frames out of 746.
    """
    body = b"\x80\x00" + b"\x22" * 254      # cut to the 256-byte snaplen
    on_air = 800                            # what was actually on the air
    record, _body_len, _us, original = wifi_session()._build_record(
        wifi_payload(body, on_air)
    )
    header_len = len(record) - len(body)
    assert original == header_len + on_air
    assert original > len(record), "a truncated frame must declare more than it carries"


def test_untruncated_wifi_frame_declares_its_real_length():
    body = b"\x80\x00" + b"\x33" * 30
    record, _b, _us, original = wifi_session()._build_record(
        wifi_payload(body, len(body))
    )
    assert original == len(record)


def test_802154_record_is_never_truncated():
    psdu = b"\x41\x88" + b"\x44" * 20
    payload = META_154.pack(25, 200, -60, 0, 999) + psdu
    record, body_len, device_us, original = session_154()._build_record(payload)
    assert body_len == len(psdu)
    assert device_us == 999
    assert original == len(record)


def test_short_payloads_are_dropped_not_unpacked():
    """A runt would otherwise raise inside struct.unpack and kill the capture."""
    assert wifi_session()._build_record(b"\x00" * 4) is None
    assert session_154()._build_record(b"\x00" * 4) is None


def _stats_blob(link, radio154, wifi):
    return struct.pack("<16I", *link, *radio154, *wifi)


def test_wifi_session_reads_the_wifi_counters():
    """Reading the 802.15.4 block during a Wi-Fi capture would report a lossy
    capture as lossless: those counters stay at zero while that radio is
    stopped."""
    s = wifi_session()
    s._update_stats(_stats_blob(
        link=(10, 1, 0, 2, 4096),
        radio154=(0, 0, 0),
        wifi=(500, 0, 0, 480, 470, 7, 3, 90000),
    ))
    assert s.stats.fw_frames_captured == 480
    assert s.stats.fw_isr_queue_full == 7
    assert s.stats.fw_link_rejected == 3
    assert s.stats.fw_frames_truncated == 470
    assert s.stats.fw_bytes_dropped_by_snaplen == 90000
    assert not s.stats.lossless


def test_802154_session_reads_the_802154_counters():
    s = session_154()
    s._update_stats(_stats_blob(
        link=(10, 0, 0, 0, 4096),
        radio154=(86, 0, 0),
        wifi=(999, 0, 0, 999, 999, 9, 9, 9),
    ))
    assert s.stats.fw_frames_captured == 86
    assert s.stats.fw_isr_queue_full == 0
    assert s.stats.lossless


def test_truncation_alone_is_not_counted_as_loss():
    """The snapshot length is deliberate, and what it cuts is encrypted."""
    s = wifi_session()
    s._update_stats(_stats_blob(
        link=(10, 0, 0, 0, 4096),
        radio154=(0, 0, 0),
        wifi=(500, 0, 0, 500, 500, 0, 0, 120000),
    ))
    assert s.stats.fw_frames_truncated == 500
    assert s.stats.lossless


def test_old_short_stats_frame_still_parses():
    """Firmware predating the Wi-Fi counters sent only two blocks."""
    s = session_154()
    s._update_stats(struct.pack("<8I", 10, 0, 0, 0, 4096, 42, 0, 0))
    assert s.stats.fw_frames_captured == 42
    assert s.stats.lossless


def _stats_blob_ble(link, radio154, wifi, ble):
    """The whole layout, BLE block included.

    The width is asserted rather than written into the format string. It was
    written in once, as 31, and the Wi-Fi block turned out to be thirteen
    counters rather than twelve -- so these tests agreed with the host and
    both disagreed with the board.
    """
    values = (*link, *radio154, *wifi, *ble)
    assert len(values) == _BLE_BLOCK_END, (
        f"{len(values)} counters, the frame holds {_BLE_BLOCK_END}")
    return struct.pack(f"<{len(values)}I", *values)


#: An idle Wi-Fi block of the right width, for the BLE tests that only need
#: the space in front of the BLE block to be the right size.
WIFI_IDLE = (0,) * (_BLE_BLOCK_AT - _WIFI_BLOCK_AT)

#: A BLE block with nothing wrong in it, for tests that vary one field.
BLE_QUIET = (1500, 1342, 1500, 0, 0, 0, 0, 0, 0, 0, 0)


def test_ble_session_reads_the_ble_counters():
    """The BLE block sits last and was shipped before anything read it, so a
    BLE capture reported the 802.15.4 counters of a stopped radio."""
    s = ble_session()
    s._update_stats(_stats_blob_ble(
        link=(10, 0, 0, 0, 4096),
        radio154=(0, 0, 0),
        wifi=WIFI_IDLE,
        ble=(1500, 1342, 1490, 4, 6, 4, 1, 3, 1, 88, 2),
    ))
    assert s.stats.fw_frames_captured == 1500
    assert s.stats.fw_frames_truncated == 4
    assert s.stats.fw_isr_queue_full == 6
    assert s.stats.fw_link_rejected == 4
    assert s.stats.fw_ble_adv_reports == 1342
    assert s.stats.fw_ble_command_timeouts == 1
    assert s.stats.fw_ble_periodic_seen == 3
    assert s.stats.fw_ble_periodic_synced == 1
    assert s.stats.fw_ble_periodic_reports == 88
    assert s.stats.fw_ble_periodic_refused == 2


def test_a_lossy_ble_capture_is_not_reported_lossless():
    """The defect this exists to prevent. The BLE drop counters were on the
    wire and unread, so `dropped` in the file's statistics block came from
    the 802.15.4 block -- stopped, and therefore zero, no matter what the BLE
    radio threw away."""
    s = ble_session()
    s._update_stats(_stats_blob_ble(
        link=(10, 0, 0, 0, 4096),
        radio154=(0, 0, 0),
        wifi=WIFI_IDLE,
        ble=(1500, 1342, 1400, 0, 60, 40, 0, 0, 0, 0, 0),
    ))
    assert s.stats.fw_isr_queue_full == 60
    assert s.stats.fw_link_rejected == 40
    assert not s.stats.lossless


def test_ble_truncation_alone_is_not_counted_as_loss():
    """An oversized HCI packet is truncated and flagged, not dropped."""
    s = ble_session()
    s._update_stats(_stats_blob_ble(
        link=(10, 0, 0, 0, 4096),
        radio154=(0, 0, 0),
        wifi=WIFI_IDLE,
        ble=(1500, 1342, 1500, 12, 0, 0, 0, 0, 0, 0, 0),
    ))
    assert s.stats.fw_frames_truncated == 12
    assert s.stats.lossless


def test_ble_stats_without_the_refused_counter_still_parse():
    """Firmware that shipped the BLE block before periodic_refused existed
    sends thirty counters, not thirty-one."""
    s = ble_session()
    s._update_stats(struct.pack(
        f"<{_BLE_BLOCK_END - 1}I", 10, 0, 0, 0, 4096, 0, 0, 0, *WIFI_IDLE,
        1500, 1342, 1500, 0, 0, 0, 0, 5, 1, 40,
    ))
    assert s.stats.fw_frames_captured == 1500
    assert s.stats.fw_ble_periodic_seen == 5
    assert s.stats.fw_ble_periodic_reports == 40
    assert s.stats.fw_ble_periodic_refused == 0


def test_the_wifi_block_still_parses_beside_a_ble_one():
    """Adding a block at the end must not move the ones before it."""
    s = wifi_session()
    s._update_stats(_stats_blob_ble(
        link=(10, 1, 0, 2, 4096),
        radio154=(0, 0, 0),
        wifi=(500, 0, 0, 480, 470, 7, 3, 90000, 0, 0, 0, 0, 0),
        ble=BLE_QUIET,
    ))
    assert s.stats.fw_frames_captured == 480
    assert s.stats.fw_isr_queue_full == 7
    assert s.stats.fw_link_rejected == 3
    assert not s.stats.lossless


def test_pcap_declares_the_truncation_end_to_end():
    """Same path the extcap takes, so the fix is checked where it matters."""
    body = b"\x80\x00" + b"\x55" * 254
    on_air = 900
    record, _b, _us, original = wifi_session()._build_record(
        wifi_payload(body, on_air)
    )
    stream = io.BytesIO()
    writer = PcapWriter(stream, LINKTYPE_IEEE802_11_RADIOTAP)
    writer.write_packet(record, 1_700_000_000.0, original_length=original)

    blob = stream.getvalue()
    _sec, _usec, incl_len, orig_len = PCAP_RECORD.unpack_from(
        blob, PCAP_GLOBAL_HEADER_LEN
    )
    assert incl_len == len(record)
    assert orig_len == original
    assert orig_len > incl_len


def test_legacy_ofdm_frame_carries_a_rate():
    """L-SIG rate code 0xB is 6 Mbit/s, which radiotap counts in 500 kbps."""
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(bytes([0x80, 0x00]) + b"\x11" * 20, 22, rate=0xB,
                     phy=PhyFormat.G)
    )
    assert present_bitmap(record) & (1 << BIT_RATE)
    assert rate_500kbps(PhyFormat.G, 0xB) == 12
    assert channel_flags(record) & CHAN_OFDM


def test_11b_frame_is_labelled_cck_not_ofdm():
    """Assuming OFDM for every frame mislabels exactly the older access points
    whose beacons are CCK."""
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(bytes([0x80, 0x00]) + b"\x11" * 20, 22, rate=0, phy=PhyFormat.B)
    )
    assert channel_flags(record) & CHAN_CCK
    assert not channel_flags(record) & CHAN_OFDM
    assert rate_500kbps(PhyFormat.B, 0) == 2      # 1 Mbit/s
    assert rate_500kbps(PhyFormat.B, 3) == 22     # 11 Mbit/s


def test_ht_and_he_frames_omit_the_rate_field():
    """Radiotap's Rate cannot express an MCS index, and a plausible wrong
    number in front of every 11n frame is worse than no number at all."""
    for fmt in (PhyFormat.HT, PhyFormat.VHT, PhyFormat.HE_SU, PhyFormat.HE_MU):
        assert rate_500kbps(fmt, 0xB) is None
        record, _b, _us, _o = wifi_session()._build_record(
            wifi_payload(bytes([0x80, 0x00]) + b"\x11" * 20, 22, rate=0xB, phy=fmt)
        )
        assert not present_bitmap(record) & (1 << BIT_RATE), fmt


def test_unknown_rate_code_is_omitted_rather_than_guessed():
    assert rate_500kbps(PhyFormat.G, 0x0) is None


def test_stall_and_recovery_counters_reach_the_host():
    """Without these a deaf receiver looks the same as a quiet band."""
    s = wifi_session()
    s._update_stats(struct.pack(
        "<18I",
        *(10, 0, 0, 0, 4096),           # link
        *(0, 0, 0),                     # 802.15.4
        *(0, 0, 0, 0, 0, 0, 0, 0),      # wifi counters, all quiet
        15, 3,                          # stalled_seconds, recoveries
    ))
    assert s.stats.fw_stalled_seconds == 15
    assert s.stats.fw_recoveries == 3


def test_firmware_1_stats_still_parse():
    """16-counter frames predate the stall counters."""
    s = wifi_session()
    s._update_stats(struct.pack(
        "<16I", *(10, 0, 0, 0, 4096), *(0, 0, 0),
        *(500, 0, 0, 480, 0, 0, 0, 0),
    ))
    assert s.stats.fw_frames_captured == 480
    assert s.stats.fw_recoveries == 0


def test_ht_frame_carries_a_decoded_mcs():
    body = bytes([0x80, 0x00]) + b"\x11" * 40
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=7, length=len(body) + FCS_LEN),
                     siga2=1 << 7)          # short guard interval
    )
    assert present_bitmap(record) & (1 << BIT_MCS)
    # The MCS triple ends the radiotap header, and the frame body follows it,
    # so measure from the header length rather than the end of the record.
    header_len = struct.unpack_from("<H", record, 2)[0]
    known, flags, mcs = record[header_len - 3:header_len]
    assert mcs == 7
    assert known & MCS_KNOWN_INDEX
    assert flags & MCS_FLAG_SGI


def test_ht_decode_is_rejected_when_the_length_disagrees():
    """The self-check that stops a wrong bit layout reaching every frame.

    HT-SIG carries the frame length, and the receive descriptor reports it
    independently. If the two disagree, the layout assumption is wrong and no
    MCS is claimed at all.
    """
    body = bytes([0x80, 0x00]) + b"\x11" * 40
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=7, length=len(body) + 99))
    )
    assert not present_bitmap(record) & (1 << BIT_MCS)
    assert decode_ht_sig(ht_sig1(7, 100), 0, expected_length=101) is None


def test_impossible_mcs_index_is_rejected():
    assert decode_ht_sig(ht_sig1(120, 50), 0, expected_length=50) is None


def test_non_ht_frames_carry_no_mcs():
    """HE-SIG-A has an MCS too, but radiotap's HE field is not emitted, so
    nothing is claimed rather than something unverified."""
    for fmt in (PhyFormat.B, PhyFormat.G, PhyFormat.HE_SU):
        body = bytes([0x80, 0x00]) + b"\x11" * 40
        record, _b, _us, _o = wifi_session()._build_record(
            wifi_payload(body, len(body), phy=fmt,
                         siga1=ht_sig1(4, len(body) + FCS_LEN))
        )
        assert not present_bitmap(record) & (1 << BIT_MCS), fmt


def test_timestamp_is_64_bit_so_it_survives_the_71_minute_wrap():
    """The radio's counter is 32-bit microseconds; the firmware widens it."""
    beyond_32_bits = (1 << 32) + 5_000_000
    _r, _b, device_us, _o = wifi_session()._build_record(
        wifi_payload(bytes([0x80, 0x00]) + b"\x11" * 10, 12,
                     timestamp=beyond_32_bits)
    )
    assert device_us == beyond_32_bits


def test_ht_length_is_compared_including_the_fcs():
    """The regression this pins down.

    HT Length counts the PSDU with its FCS; the firmware has already stripped
    it. Comparing against the stripped length makes every real frame miss by
    exactly four bytes, so the MCS silently disappears from the capture. It did
    exactly that once, and only a live PHY tally showed it.
    """
    body = bytes([0x80, 0x00]) + bytes([0x11]) * 40
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=5, length=len(body) + FCS_LEN))
    )
    assert present_bitmap(record) & (1 << BIT_MCS)
    header_len = struct.unpack_from("<H", record, 2)[0]
    assert record[header_len - 1] == 5

    # And the stripped length must NOT satisfy it, or the check is vacuous.
    assert wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=5, length=len(body)))
    )[0][-1:] is not None
    bad = wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=5, length=len(body)))
    )[0]
    assert not present_bitmap(bad) & (1 << BIT_MCS)


def test_ampdu_delimiter_does_not_lose_the_mcs():
    """An A-MPDU subframe carries a four-byte delimiter and is padded to a
    four-byte boundary, so HT Length runs slightly over the MPDU. Demanding
    equality threw the MCS away on three of every five 11n frames."""
    body = bytes([0x80, 0x00]) + bytes([0x11]) * 40
    for over in (0, 4, 8):
        record, _b, _us, _o = wifi_session()._build_record(
            wifi_payload(body, len(body), phy=PhyFormat.HT,
                         siga1=ht_sig1(mcs=7,
                                       length=len(body) + FCS_LEN + over))
        )
        assert present_bitmap(record) & (1 << BIT_MCS), over


def test_a_wildly_wrong_length_is_still_rejected():
    """The window must stay narrow enough to catch a wrong bit layout, which
    would put an essentially random 16-bit number in the length field."""
    body = bytes([0x80, 0x00]) + bytes([0x11]) * 40
    for over in (64, 1000, 30000):
        record, _b, _us, _o = wifi_session()._build_record(
            wifi_payload(body, len(body), phy=PhyFormat.HT,
                         siga1=ht_sig1(mcs=7,
                                       length=len(body) + FCS_LEN + over))
        )
        assert not present_bitmap(record) & (1 << BIT_MCS), over


def test_a_length_below_the_frame_is_rejected():
    """HT Length can exceed the MPDU but never fall short of it."""
    body = bytes([0x80, 0x00]) + bytes([0x11]) * 40
    record, _b, _us, _o = wifi_session()._build_record(
        wifi_payload(body, len(body), phy=PhyFormat.HT,
                     siga1=ht_sig1(mcs=7, length=len(body)))
    )
    assert not present_bitmap(record) & (1 << BIT_MCS)


# --- per-board firmware versions -------------------------------------------
#
# The version handshake existed because an older board packs its metadata
# differently, so every field would decode to a confident wrong number rather
# than an error. With two boards there are two firmwares, each with its own
# version, and telling an operator to run idf.py at an nRF misleads twice
# over: the wrong toolchain, and a version number that then looks like a fault
# rather than a stale flash.

def test_each_board_has_its_own_expected_firmware_version():
    from esp32c6_sniffer.capture import EXPECTED_FIRMWARE_VERSIONS
    # 7 when device keys arrived: older firmware ignores frame type 15, so a
    # key file sent to it would give a capture that never resolves anything.
    assert EXPECTED_FIRMWARE_VERSIONS["esp32c6"] == 7
    # 3 when that board began batching BLE: a host without BLE_BATCH skips
    # the frame type it does not know, so an unbumped mismatch would present
    # as a capture that runs happily and shows nothing at all. 4 when its
    # STATS frame gained the FCS-failure count after the BLE block.
    assert EXPECTED_FIRMWARE_VERSIONS["nrf54l15"] == 4


def test_the_old_constant_still_names_the_c6():
    """Existing callers, docs and the README refer to it by the old name."""
    from esp32c6_sniffer.capture import (EXPECTED_FIRMWARE_VERSION,
                                         EXPECTED_FIRMWARE_VERSIONS)
    assert EXPECTED_FIRMWARE_VERSION == EXPECTED_FIRMWARE_VERSIONS["esp32c6"]


def test_the_mismatch_message_names_the_board():
    from esp32c6_sniffer.capture import version_mismatch_message
    assert "nrf54l15" in version_mismatch_message("nrf54l15", found=0)
    assert "esp32c6" in version_mismatch_message("esp32c6", found=0)


def test_the_mismatch_message_carries_both_version_numbers():
    """Naming only one leaves the operator to guess which end is stale."""
    from esp32c6_sniffer.capture import version_mismatch_message
    message = version_mismatch_message("esp32c6", found=3)
    assert "3" in message and "6" in message


def test_the_mismatch_message_names_that_boards_own_toolchain():
    from esp32c6_sniffer.capture import version_mismatch_message
    nrf = version_mismatch_message("nrf54l15", found=0)
    assert "west" in nrf
    assert "idf.py" not in nrf

    c6 = version_mismatch_message("esp32c6", found=0)
    assert "idf.py" in c6
    assert "west" not in c6
    # The whole command, not just the tool's name: this string once carried a
    # form feed where the \f of .\flash.ps1 belonged, and told every operator
    # with a stale board to run a script that does not exist.
    assert r".\flash.ps1 -Port" in c6


def test_a_session_defaults_to_the_board_that_existed_first():
    """Every existing caller constructs a session without naming a board."""
    import inspect
    from esp32c6_sniffer.capture import CaptureSession
    assert inspect.signature(CaptureSession).parameters["board"].default == "esp32c6"


# --- Frames the radio discarded as corrupt (nRF54L15 firmware 4) ------------

def _stats_blob_nrf(radio154, fcs_failed):
    """The nRF54L15's frame: every block, then the FCS-failure count."""
    values = (10, 0, 0, 0, 4096, *radio154, *WIFI_IDLE, *BLE_QUIET, fcs_failed)
    assert len(values) == _STATS_V6.size // 4 == _STATS_COUNTERS
    return struct.pack(f"<{len(values)}I", *values)


def test_the_nrf_reports_frames_discarded_as_corrupt():
    s = session_154()
    s._update_stats(_stats_blob_nrf((86, 0, 0), 7))
    assert s.stats.fw_frames_captured == 86
    assert s.stats.fw_fcs_failed == 7
    # Never received, so never loss: the capture delivered everything it got.
    assert s.stats.lossless
    assert s.stats.fcs_failure_note() == (
        "7 frames failed their FCS at the radio and were not captured")


def test_a_board_without_the_counter_reports_not_measured():
    """The ESP32-C6's driver cannot see these, and zero would be invented."""
    s = session_154()
    s._update_stats(_stats_blob(link=(10, 0, 0, 0, 4096), radio154=(86, 0, 0),
                                wifi=(0,) * 8))
    assert s.stats.fw_fcs_failed is None
    assert s.stats.fcs_failure_note() is None


def test_a_ble_capture_does_not_claim_the_802154_counter():
    s = ble_session()
    s._update_stats(_stats_blob_nrf((0, 0, 0), 7))
    assert s.stats.fw_fcs_failed is None


def test_zero_corrupt_frames_is_still_said():
    """Measured and zero is information; the note says so rather than vanishing."""
    s = session_154()
    s._update_stats(_stats_blob_nrf((86, 0, 0), 0))
    assert s.stats.fcs_failure_note() == (
        "0 frames failed their FCS at the radio and were not captured")

