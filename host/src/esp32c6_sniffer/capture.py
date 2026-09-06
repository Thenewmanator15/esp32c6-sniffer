"""Live capture session, 802.15.4 or Wi-Fi.

Opens the board, selects a radio, channel and antenna, and yields records ready
for a pcap stream: IEEE 802.15.4 TAP records, or radiotap-prefixed 802.11
frames. Used by both the command-line tool and the Wireshark extcap plugin, so
the two cannot drift apart.

One radio at a time. The C6 has a single 2.4 GHz front end and the firmware
stops the other radio when one is selected.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterator

import serial

from .control import (
    Antenna,
    Bandwidth,
    Command,
    CtrlFilter,
    FrameFilter,
    Radio,
    decode_reply,
    encode_command,
)
from .framing import FrameType
from .parser import SequenceTracker, StreamParser
from .csi import parse_csi_record
from .radiotap import (
    LINKTYPE_IEEE802_11_RADIOTAP,
    MCS_BW_20,
    MCS_BW_20L,
    MCS_BW_20U,
    PhyFormat,
    build_radiotap,
    decode_he_sig_a,
    decode_ht_sig,
    rate_500kbps,
)
from .tap import (
    CHANNEL_MAX,
    CHANNEL_MIN,
    LINKTYPE_IEEE802_15_4_TAP,
    FcsType,
    build_tap_record,
)

WIFI_CHANNEL_MIN = 1
WIFI_CHANNEL_MAX = 14

#: How far the device-derived time may drift from the host clock before the
#: anchor is reset. Generous against real drift, which is parts per million,
#: and tight enough to catch a restarted or corrupted counter immediately.
MAX_CLOCK_SKEW_S = 60.0

#: Wire format this host code speaks, matching SN_FIRMWARE_VERSION in
#: firmware/main/main.c. Checked at open() because the failure it prevents is
#: silent: an older board packs its metadata differently, so every field would
#: decode to a confident wrong number rather than an error.
EXPECTED_FIRMWARE_VERSION = 5

# Matches sn_154_meta_t in firmware/main/radio154.h
_META = struct.Struct("<BBbBQ")  # channel, lqi, rssi_dbm, flags, timestamp_us
META_LEN = _META.size

# Matches sn_80211_meta_t in firmware/main/radio80211.h.
#
# The timestamp is 64-bit here even though the radio reports 32: the firmware
# counts the wraps, because it sees every frame in order. Before that, a
# capture running past 71 minutes had time jump backwards by an hour.
_WIFI_META = struct.Struct("<BbbBQHBBIH")
WIFI_META_LEN = _WIFI_META.size

FLAG_HAS_FCS = 0x01

WIFI_FLAG_TRUNCATED = 0x01
WIFI_FLAG_RX_ERROR = 0x02
WIFI_FLAG_AMPDU = 0x04

#: The 802.11 frame check sequence the firmware strips. Some signalling fields
#: count it and some do not, so it has to be added back deliberately.
FCS_LEN = 4


# The capture build emits this once a second: sn_link_stats_t (5 x uint32),
# then sn_154_stats_t (3), then sn_80211_stats_t (8). Older firmware sent only
# the first two blocks, so the short form is still accepted.
_STATS = struct.Struct("<8I")
_STATS_FULL = struct.Struct("<16I")
# Firmware 2 added the stall and recovery counters to the Wi-Fi block, and
# firmware 4 the CSI counters.
_STATS_V2 = struct.Struct("<18I")
_STATS_V4 = struct.Struct("<20I")


#: PHY formats that carry HE-SIG-A rather than HT-SIG.
_HE_FORMATS = (
    PhyFormat.HE_SU,
    PhyFormat.HE_MU,
    PhyFormat.HE_ERSU,
    PhyFormat.HE_TB,
)

#: wifi_second_chan_t: 0 none, 1 above, 2 below.
_SECOND_ABOVE = 1
_SECOND_BELOW = 2


def _apply_secondary(mcs: tuple[int, int, int], secondary: int):
    """Refines the radiotap MCS bandwidth using the secondary channel.

    HT-SIG only distinguishes 20 from 40 MHz. Where the secondary channel sits
    says which half of a 40 MHz channel a 20 MHz frame occupied, which is the
    difference between "somewhere in 40 MHz" and a specific 20 MHz slot.
    """
    known, flags, index = mcs
    if flags & 0x03 != MCS_BW_20:
        return mcs      # already says 40 MHz; nothing to refine
    if secondary == _SECOND_ABOVE:
        return known, (flags & ~0x03) | MCS_BW_20L, index
    if secondary == _SECOND_BELOW:
        return known, (flags & ~0x03) | MCS_BW_20U, index
    return mcs


def channel_range(radio: Radio) -> tuple[int, int]:
    """Inclusive channel bounds for a radio.

    802.15.4 uses 11-26 and Wi-Fi 1-14, and the two overlap numerically without
    overlapping in meaning, so a bare channel number is ambiguous unless the
    radio travels with it.
    """
    if radio is Radio.WIFI:
        return WIFI_CHANNEL_MIN, WIFI_CHANNEL_MAX
    return CHANNEL_MIN, CHANNEL_MAX


@dataclass
class CaptureStats:
    frames: int = 0
    bytes_captured: int = 0
    sequence_gaps: int = 0
    resyncs: int = 0
    bytes_discarded: int = 0
    # Reported by the board. Any non-zero drop here is a defect on this radio,
    # not a bandwidth limit: a saturated channel is about a twenty-fifth of
    # what the link carries.
    fw_frames_captured: int = 0
    fw_isr_queue_full: int = 0
    fw_link_rejected: int = 0
    fw_frames_dropped_ringfull: int = 0
    fw_tx_stalls: int = 0
    # Wi-Fi only. Truncation is deliberate, set by the snapshot length, so it
    # is reported but deliberately NOT counted as loss.
    fw_frames_truncated: int = 0
    fw_bytes_dropped_by_snaplen: int = 0
    # This board's Wi-Fi receiver goes deaf for minutes at a time. These make
    # that visible instead of indistinguishable from a quiet channel.
    fw_stalled_seconds: int = 0
    fw_recoveries: int = 0
    fw_csi_records: int = 0
    fw_csi_dropped: int = 0
    csi_malformed: int = 0
    #: Frames whose metadata could not be turned into a record: an impossible
    #: channel, a length that cannot be right. Counted rather than raised,
    #: because one bad frame must not end a capture.
    malformed_metadata: int = 0
    #: Times the device clock had to be re-pinned to the host clock, because
    #: the board's counter restarted or a timestamp was corrupt.
    timestamp_reanchors: int = 0

    @property
    def lossless(self) -> bool:
        return (
            self.sequence_gaps == 0
            and self.fw_isr_queue_full == 0
            and self.fw_link_rejected == 0
            and self.fw_frames_dropped_ringfull == 0
        )


class CaptureSession:
    """One capture run against the board.

    Timestamps need anchoring. The board reports microseconds from its own
    boot, so the first frame's device time is pinned to the host clock and
    every later frame is offset from that. This keeps inter-frame spacing at
    the board's resolution while putting the capture at a sensible wall-clock
    time. It does not correct for clock drift between the two.
    """

    def __init__(
        self,
        port: str,
        channel: int,
        antenna: Antenna = Antenna.INTERNAL,
        timeout: float = 0.05,
        radio: Radio = Radio.IEEE802154,
        snaplen: int | None = None,
        frame_filter: FrameFilter | None = None,
        bandwidth: Bandwidth | None = None,
        ctrl_filter: CtrlFilter | None = None,
        csi_sink=None,
    ) -> None:
        self._port_name = port
        self._radio = radio
        low, high = channel_range(radio)
        if not low <= channel <= high:
            raise ValueError(
                f"channel {channel} outside the {radio.name} range {low}-{high}"
            )
        self._channel = channel
        self._antenna = antenna
        self._timeout = timeout
        self._serial: serial.Serial | None = None
        self._parser = StreamParser()
        self._tracker = SequenceTracker()
        self.firmware_version: int | None = None
        #: Set when the session had to power-cycle the board because the
        #: 802.15.4 radio had been used since boot.
        self.recovered_from_802154 = False
        self._t0_device: int | None = None
        self._last_stamp: float | None = None
        self._t0_host: float = 0.0
        self._snaplen = snaplen
        self._frame_filter = frame_filter
        self._bandwidth = bandwidth
        self._ctrl_filter = ctrl_filter
        # Called for each CSI record. CSI has no place in a pcap, so it leaves
        # by a different door rather than being forced into one.
        self._csi_sink = csi_sink
        self._pending_channel: int | None = None
        self._pending_antenna: int | None = None
        self._pending_lock = threading.Lock()
        # Lets another thread end a capture without closing the port from
        # under the one doing the reading. Closing a serial port while a
        # second thread sits inside read() crashes the interpreter outright on
        # Windows -- an access violation, not an exception -- which is how the
        # self-test discovered it needed this.
        self._stop = threading.Event()
        # Frames that arrive while waiting for a command reply. Without this
        # they were parsed and dropped, so every channel change silently lost
        # whatever was in flight, showing up as sequence gaps the board could
        # not account for.
        self._deferred: list = []
        self.stats = CaptureStats()

    @property
    def radio(self) -> Radio:
        return self._radio

    @property
    def channel(self) -> int:
        return self._channel

    @property
    def linktype(self) -> int:
        """The pcap link type this session's records are in.

        Exposed so a caller opens its PcapWriter with the right one rather than
        hard-coding a link type that only suits one radio.
        """
        return (
            LINKTYPE_IEEE802_11_RADIOTAP
            if self._radio is Radio.WIFI
            else LINKTYPE_IEEE802_15_4_TAP
        )

    def __enter__(self) -> "CaptureSession":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        self._connect()

        info = self._command(Command.GET_INFO)
        self.firmware_version = info["value"]
        if self.firmware_version != EXPECTED_FIRMWARE_VERSION:
            raise RuntimeError(
                f"board is running firmware version {self.firmware_version}, "
                f"this host expects {EXPECTED_FIRMWARE_VERSION}. "
                f"Rebuild and reflash: "
                f"idf.py -DSN_MODE=2 build then .\flash.ps1 -Port <port>"
            )

        # Using the 802.15.4 radio leaves the Wi-Fi receiver deaf until the RF
        # domain is power-gated. Measured: 633 Wi-Fi frames before an 802.15.4
        # capture and 0 after, while idling the same 30 seconds cost nothing.
        # Without this a Wi-Fi capture started after an 802.15.4 one silently
        # returns nothing at all, which is exactly the failure that cost a day.
        if self._radio is Radio.WIFI:
            dirty = self._command(Command.RADIO_DIRTY)
            if dirty["value"]:
                self.recovered_from_802154 = True
                self._command(Command.RADIO_POWER_CYCLE)
                # The board resets and the USB device re-enumerates.
                self._serial.close()
                self._serial = None
                time.sleep(6.0)
                self._connect()

        self._configure()

    def _connect(self) -> None:
        """Opens the port, retrying while the device re-enumerates."""
        deadline = time.monotonic() + 30.0
        last: Exception | None = None
        ser = None
        while time.monotonic() < deadline:
            try:
                ser = serial.Serial(self._port_name, 115200,
                                    timeout=self._timeout)
                break
            except (OSError, serial.SerialException) as exc:
                last = exc
                time.sleep(0.5)
        if ser is None:
            raise RuntimeError(f"cannot open {self._port_name}: {last}")
        try:
            # pyserial opens Windows ports with only a 4 KB receive buffer, and
            # the board discards data when the host stops draining.
            ser.set_buffer_size(rx_size=1 << 20)
        except (AttributeError, OSError):
            pass
        ser.reset_input_buffer()
        self._serial = ser
        self._parser = StreamParser()
        self._deferred = []

    def _configure(self) -> None:
        """Sends the per-session settings, in the order the board needs."""
        # Radio first. SET_CHANNEL is interpreted against whichever radio is
        # selected, so choosing it afterwards would validate channel 6 against
        # the 802.15.4 range and be rejected.
        self._command(Command.SET_RADIO, int(self._radio))
        self._command(Command.SET_ANTENNA, int(self._antenna))
        # Both before the channel, because SET_CHANNEL starts the radio and
        # these two are what it starts with.
        if self._snaplen is not None:
            self._command(Command.SET_SNAPLEN, self._snaplen)
        if self._frame_filter is not None:
            self._command(Command.SET_FILTER, int(self._frame_filter))
        if self._ctrl_filter is not None:
            self._command(Command.SET_CTRL_FILTER, int(self._ctrl_filter))
        if self._bandwidth is not None:
            self._command(Command.SET_BANDWIDTH, int(self._bandwidth))
        if self._csi_sink is not None:
            self._command(Command.SET_CSI, 1)
        self._command(Command.SET_CHANNEL, self._channel)

        # Start counting from here, not from whatever was in the buffer when
        # the port opened.
        #
        # Opening the port resets the board, so the first bytes read can be
        # the tail of the previous session at a high sequence number, followed
        # by the new session starting again at zero. The tracker cannot tell
        # that from loss and called it 914 dropped frames in one measurement,
        # which made stats.lossless report False on a capture that had not
        # lost anything at all.
        #
        # Nothing capturable is discarded: the radio does not start until the
        # SET_CHANNEL above, so anything deferred before this point is a log,
        # a stats frame or a command reply, none of which records() yields.
        self._tracker = SequenceTracker()
        self._deferred = []
        self.stats.sequence_gaps = 0

    def request_stop(self) -> None:
        """Asks records() to finish, safely from another thread.

        Only sets a flag: the capture loop owns the serial port and closing it
        from elsewhere is what caused the crash this exists to prevent.
        """
        self._stop.set()

    def close(self) -> None:
        self._stop.set()
        if self._serial is None:
            return
        try:
            self._serial.write(encode_command(Command.STOP))
            self._serial.flush()
        except (serial.SerialException, OSError):
            pass
        self._serial.close()
        self._serial = None

    def _command(self, command: Command, value: int = 0, timeout: float = 5.0) -> dict:
        assert self._serial is not None
        self._serial.write(encode_command(command, value, radio=self._radio))
        self._serial.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for frame in self._parser.feed(self._serial.read(4096)):
                # Every frame is deferred, replies included, so records()
                # observes them all in arrival order. Two rules matter here and
                # both were learned the hard way. Replies consume a sequence
                # number on the board, so skipping them entirely invents gaps.
                # And observing a reply here while earlier frames wait in the
                # deferred list feeds the tracker out of order, which the
                # modulo-65536 arithmetic turns into gaps of tens of thousands.
                self._deferred.append(frame)
                if frame.ftype is not FrameType.CONTROL_REPLY:
                    continue
                reply = decode_reply(frame.payload)
                if reply["command"] is command:
                    if not reply["ok"]:
                        raise RuntimeError(
                            f"{command.name} failed, status {reply['status']}"
                        )
                    return reply
        raise TimeoutError(f"no reply to {command.name} within {timeout}s")

    def request_channel(self, channel: int) -> None:
        """Ask for a channel change from another thread.

        Deliberately does not touch the serial port. The capture loop owns it,
        and two threads writing commands into the same stream would interleave
        bytes mid-frame. This only sets a flag; records() applies it between
        reads.

        A retune costs frames. Measured over 5 minutes with a change every
        20 seconds: 7 sequence gaps across 14 retunes, against 0 gaps in 1920
        frames with no retuning. That is roughly half a frame per change,
        lost in flight while the radio is briefly off-channel. It is inherent
        rather than a defect, but it means `stats.lossless` will read False
        after any retune, and that is honest rather than broken.
        """
        low, high = channel_range(self._radio)
        if not low <= channel <= high:
            raise ValueError(f"channel {channel} outside {low}-{high}")
        with self._pending_lock:
            self._pending_channel = channel

    def request_antenna(self, antenna: int) -> None:
        """Switch antenna mid-capture, from another thread.

        Useful as a live A/B on the same traffic: the external antenna measured
        +6.0 dB over the onboard one on this board, and toggling during a
        capture shows that on frames you can compare directly, rather than
        across two separate runs where the traffic itself has changed.
        """
        if antenna not in (0, 1):
            raise ValueError(f"antenna {antenna} is not 0 (internal) or 1 (external)")
        with self._pending_lock:
            self._pending_antenna = antenna

    def _apply_pending(self) -> None:
        with self._pending_lock:
            antenna = self._pending_antenna
            self._pending_antenna = None
        if antenna is not None:
            self._command(Command.SET_ANTENNA, antenna)
            self._antenna = Antenna(antenna)
        self._apply_pending_channel()

    def _apply_pending_channel(self) -> int | None:
        with self._pending_lock:
            channel = self._pending_channel
            self._pending_channel = None
        if channel is None:
            return None
        self._command(Command.SET_CHANNEL, channel)
        self._channel = channel
        # Timestamps are anchored to the first frame; retuning does not restart
        # the board's clock, so the anchor stays valid.
        return channel

    def _anchor(self, device_us: int) -> float:
        """Maps the board's microsecond counter onto the host clock.

        Pinning the first frame and offsetting from it keeps inter-frame
        spacing at the board's resolution, which is the point: the host clock
        is far too coarse to time frames against.

        It needs two guards, because the device counter is not as
        well-behaved as that assumes.

        It restarts. The stall recovery rebuilds the Wi-Fi driver on purpose,
        and enabling 802.15.4 restarts its counter too, so a capture spanning
        either would run backwards in the middle of the file. And a corrupted
        timestamp -- one bad byte in the metadata -- put a frame 292,805 years
        into the future in testing, which makes a capture unreadable in any
        viewer that scales its time axis.

        So whenever the implied time drifts further from the host clock than
        any real drift could account for, the anchor is reset. Normal
        operation never trips it: the two clocks advance together to within
        milliseconds. The result is then held non-decreasing, because frames
        arrive in order and a pcap that says otherwise is simply wrong.
        """
        now = time.time()
        if self._t0_device is None:
            self._t0_device = device_us
            self._t0_host = now

        stamp = self._t0_host + (device_us - self._t0_device) / 1_000_000.0
        if abs(stamp - now) > MAX_CLOCK_SKEW_S:
            self._t0_device = device_us
            self._t0_host = now
            self.stats.timestamp_reanchors += 1
            stamp = now

        if self._last_stamp is not None and stamp < self._last_stamp:
            stamp = self._last_stamp
        self._last_stamp = stamp
        return stamp

    def records(self) -> Iterator[tuple[bytes, float, int]]:
        """Yields (record, wall_clock_timestamp, original_length).

        The record is an IEEE 802.15.4 TAP record, or a radiotap header plus
        802.11 frame, matching `linktype`.

        `original_length` is what the record WOULD have been had the firmware
        not truncated it, and must reach the pcap. Without it a truncated Wi-Fi
        frame is declared complete, and Wireshark reports "length of contained
        item exceeds length of containing item" on every beacon instead of
        marking it sliced.
        """
        assert self._serial is not None, "call open() first"
        while self._serial is not None and not self._stop.is_set():
            self._apply_pending()
            chunk = self._serial.read(8192)
            frames = self._deferred + self._parser.feed(chunk)
            self._deferred = []
            if not frames:
                continue
            for frame in frames:
                gap = self._tracker.observe(frame.seq)
                self.stats.sequence_gaps += gap

                if frame.ftype is FrameType.STATS:
                    self._update_stats(frame.payload)
                    continue

                if frame.ftype is FrameType.CSI:
                    if self._csi_sink is not None:
                        try:
                            self._csi_sink(parse_csi_record(frame.payload))
                        except ValueError:
                            # A malformed record must not end a capture; the
                            # board's own counters say how many were sent.
                            self.stats.csi_malformed += 1
                    continue

                if frame.ftype is not FrameType.PACKET:
                    continue

                # Length is checked inside _build_record, which knows which
                # metadata layout applies. The two happen to be the same size,
                # so a shared check here would look correct and stop being so
                # the moment either changes.
                built = self._build_record(frame.payload)
                if built is None:
                    continue
                record, body_len, device_us, original_len = built

                self.stats.frames += 1
                self.stats.bytes_captured += body_len
                self.stats.resyncs = self._parser.resync_count
                self.stats.bytes_discarded = self._parser.bytes_discarded
                yield record, self._anchor(device_us), original_len

    def _update_stats(self, payload: bytes) -> None:
        """Copies the board's counters into stats, from the active radio.

        Reading the 802.15.4 block during a Wi-Fi capture is how a lossy
        capture would report itself lossless: those counters stay at zero
        because that radio is stopped.
        """
        if len(payload) >= _STATS_V4.size:
            values = _STATS_V4.unpack_from(payload)
        elif len(payload) >= _STATS_V2.size:
            values = _STATS_V2.unpack_from(payload) + (0, 0)
        elif len(payload) >= _STATS_FULL.size:
            values = _STATS_FULL.unpack_from(payload) + (0,) * 4
        elif len(payload) >= _STATS.size:
            values = _STATS.unpack_from(payload) + (0,) * 12
        else:
            return

        (
            _sent,
            self.stats.fw_frames_dropped_ringfull,
            _short,
            self.stats.fw_tx_stalls,
            _bytes,
        ) = values[:5]

        if self._radio is Radio.WIFI:
            (
                _callbacks,
                _misc,
                _zerolen,
                self.stats.fw_frames_captured,
                self.stats.fw_frames_truncated,
                self.stats.fw_isr_queue_full,
                self.stats.fw_link_rejected,
                self.stats.fw_bytes_dropped_by_snaplen,
                self.stats.fw_stalled_seconds,
                self.stats.fw_recoveries,
                self.stats.fw_csi_records,
                self.stats.fw_csi_dropped,
            ) = values[8:20]
        else:
            (
                self.stats.fw_frames_captured,
                self.stats.fw_isr_queue_full,
                self.stats.fw_link_rejected,
            ) = values[5:8]

    def _build_record(self, payload: bytes):
        """Turns one PACKET payload into
        (record, body_len, device_us, original_len), or None.

        Returns None for anything it cannot make sense of: a payload too short
        to hold its own metadata, or metadata that decodes to an impossible
        value such as channel 0. Both would otherwise raise -- struct.unpack on
        the first, the radiotap builder's own range check on the second -- and
        a raise here ends the capture.

        That matters more than it sounds. The channel field is four bits wide
        in the radio's receive descriptor, so 0 and 15 are representable and
        neither is a real 2.4 GHz channel; fuzzing the metadata killed the
        capture loop outright. A sniffer exists to look at malformed traffic,
        so dying on a malformed frame is the one thing it must not do.
        """
        try:
            return self._build_record_inner(payload)
        except (ValueError, struct.error):
            self.stats.malformed_metadata += 1
            return None

    def _build_record_inner(self, payload: bytes):
        if self._radio is Radio.WIFI:
            if len(payload) <= WIFI_META_LEN:
                return None
            (
                channel,
                rssi,
                noise,
                flags,
                device_us,
                on_air_len,
                rate_code,
                phy,
                siga1,
                siga2,
            ) = _WIFI_META.unpack_from(payload)
            body = payload[WIFI_META_LEN:]
            phy_format = phy & 0x0F
            secondary = (phy >> 4) & 0x0F
            mcs = (
                # HT Length counts the PSDU including its FCS, which the
                # firmware has already removed, so it goes back on here.
                decode_ht_sig(siga1, siga2, on_air_len + FCS_LEN)
                if phy_format == PhyFormat.HT
                else None
            )
            if mcs is not None:
                # The radio reports where the secondary channel sits, which is
                # what turns "40 MHz" into "which 20 MHz half". HT-SIG only
                # says 20 or 40.
                mcs = _apply_secondary(mcs, secondary)
            he = (
                decode_he_sig_a(siga1, siga2)
                if phy_format in _HE_FORMATS
                else None
            )
            # The firmware strips the FCS and says so, which is true. Claiming
            # an FCS that is not there makes Wireshark mark every frame Bad
            # FCS, as the 802.15.4 path already learned the hard way.
            #
            # Modulation comes from the radio rather than being assumed: 11b is
            # CCK, and labelling it OFDM -- which this did for every frame --
            # is wrong for exactly the older access points whose beacons use
            # it. HT/VHT/HE frames carry an MCS index that the radiotap Rate
            # field cannot express, so the rate is omitted rather than guessed.
            header = build_radiotap(
                channel=channel,
                rssi_dbm=rssi,
                noise_dbm=noise,
                timestamp_us=device_us,
                ofdm=(phy_format != PhyFormat.B),
                bad_fcs=bool(flags & WIFI_FLAG_RX_ERROR),
                fcs_present=False,
                rate_500kbps_units=rate_500kbps(phy_format, rate_code),
                mcs=mcs,
                he=he,
                # One aggregate is one transmission opportunity. Wireshark
                # groups subframes by this reference; the timestamp is shared
                # across an A-MPDU's subframes and differs between aggregates,
                # so it identifies them without the firmware having to count.
                ampdu_reference=(
                    device_us & 0xFFFFFFFF
                    if flags & WIFI_FLAG_AMPDU else None
                ),
            )
            # on_air_len is the length before the firmware's snapshot cut, so
            # the pcap can declare the frame sliced rather than complete.
            return (header + body, len(body), device_us,
                    len(header) + on_air_len)

        if len(payload) <= META_LEN:
            return None
        channel, lqi, rssi, flags, device_us = _META.unpack_from(payload)
        psdu = payload[META_LEN:]
        fcs = FcsType.CRC16 if flags & FLAG_HAS_FCS else FcsType.NONE
        record = build_tap_record(
            psdu,
            channel=channel,
            rssi_dbm=float(rssi),
            lqi=lqi,
            fcs_type=fcs,
        )
        # Never truncated: a full 802.15.4 frame is 127 bytes at most.
        return record, len(psdu), device_us, len(record)
