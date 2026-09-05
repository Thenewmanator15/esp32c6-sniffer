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
)
from esp32c6_sniffer.control import Radio
from esp32c6_sniffer.pcap import PcapWriter
from esp32c6_sniffer.radiotap import LINKTYPE_IEEE802_11_RADIOTAP
from esp32c6_sniffer.tap import CHANNEL_MAX, CHANNEL_MIN, LINKTYPE_IEEE802_15_4_TAP

WIFI_META = struct.Struct("<BbbBIHH")
META_154 = struct.Struct("<BBbBQ")

# pcap record header: ts_sec, ts_usec, incl_len, orig_len
PCAP_RECORD = struct.Struct("<IIII")
PCAP_GLOBAL_HEADER_LEN = 24


def wifi_session(channel: int = 6) -> CaptureSession:
    """A session that is never opened, so no port is touched."""
    return CaptureSession("COM_UNUSED", channel=channel, radio=Radio.WIFI)


def session_154(channel: int = 25) -> CaptureSession:
    return CaptureSession("COM_UNUSED", channel=channel, radio=Radio.IEEE802154)


def wifi_payload(body: bytes, on_air_len: int, *, channel=6, rssi=-55,
                 noise=-96, flags=0, timestamp=1234) -> bytes:
    return WIFI_META.pack(channel, rssi, noise, flags, timestamp,
                          on_air_len, 0) + body


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
