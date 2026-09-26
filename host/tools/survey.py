"""Full channel survey: energy floor and actual traffic, side by side.

Answers "which channel are the networks on, and which channel is clean", which
takes a lot of manual work otherwise. Nordic have an open feature request for
exactly this on their own sniffer, with the rationale that discovering an
unknown network's channel is otherwise slow guesswork.

The two halves measure genuinely different things and neither substitutes for
the other:

* **Energy** is measured by the radio's detector and sees anything radiating,
  including the Wi-Fi that overlaps most 802.15.4 channels. It works on a
  channel carrying nothing decodable.
* **Traffic** is decoded frames. A channel can be electrically noisy and carry
  no 802.15.4 at all, or be quiet and carry a network talking softly.

Read them together. A quiet channel occupied by a strong neighbouring network
is a worse choice than a noisier empty one.

    python tools/survey.py --port COM3
    python tools/survey.py --port COM3 --dwell 15 --channels 11,15,20,25
"""

from __future__ import annotations

import argparse
import statistics
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass

from esp32c6_sniffer import mac154
from esp32c6_sniffer.batch import BatchError, decode_packet_batch
from esp32c6_sniffer.boards import BoardLink
from esp32c6_sniffer.control import Command, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.tap import CHANNEL_MAX, CHANNEL_MIN

_META = struct.Struct("<BBbBQ")

ZIGBEE_PREFERRED = {11, 15, 20, 25, 26}
WIFI_OVERLAP = {
    **{c: "Wi-Fi 1" for c in range(11, 15)},
    **{c: "Wi-Fi 6" for c in range(16, 20)},
    **{c: "Wi-Fi 11" for c in range(21, 25)},
}


def channel_mhz(channel: int) -> int:
    return 2405 + 5 * (channel - CHANNEL_MIN)


def _packets(frame) -> tuple[int | None, list[tuple[int, bytes]]]:
    """The channel a frame's packets were heard on, and the packets, decoded
    once for both packet_entries and heard_on. No channel and no packets for
    any other frame, or for a batch that does not decode whole."""
    if frame.ftype is FrameType.PACKET and len(frame.payload) > _META.size:
        channel, _lqi, rssi, _flags, _ts = _META.unpack_from(frame.payload)
        return channel, [(rssi, frame.payload[_META.size:])]
    if frame.ftype is FrameType.PACKET_BATCH:
        try:
            channel, entries = decode_packet_batch(frame.payload)
        except BatchError:
            return None, []
        return channel, [(entry.rssi_dbm, entry.psdu) for entry in entries]
    return None, []


def packet_entries(frame) -> list[tuple[int, bytes]]:
    """The signal strength and bytes of every 802.15.4 packet a frame carries.

    One for a PACKET, one per entry for a PACKET_BATCH -- which is how the
    nRF54L15 sends most of what it captures, so counting PACKET frames alone
    surveyed every channel on that board as quiet. Nothing for any other frame,
    or for a batch that does not decode whole.
    """
    return _packets(frame)[1]


def heard_on(frame, channel: int) -> list[tuple[int, bytes]]:
    """The packets in a frame that were heard on `channel`, as packet_entries.

    Every packet carries the channel it was heard on, and that is what counts,
    not the channel the survey was on when the frame arrived: the nRF54L15
    batches its packets, so a batch from the channel just left can arrive
    after the retune. Counted as the new channel's, it put a channel-15
    network on channel 20. Such a batch is dropped rather than credited back:
    its channel has already been reported, so that channel undercounts a
    little instead.
    """
    heard, entries = _packets(frame)
    return entries if heard == channel else []


def packet_rssis(frame) -> list[int]:
    """The signal strength of every 802.15.4 packet a frame carries."""
    return [rssi for rssi, _psdu in packet_entries(frame)]


@dataclass(frozen=True)
class NetworkRow:
    channel: int
    pan: int
    network: str
    frames: int
    #: Distinct source addresses, not devices: one device heard under both
    #: its short and its 64-bit address counts twice.
    addresses: int
    #: Sources seen polling their parent with a Data Request.
    sleepy: int
    rssi: int


def networks(per_channel: dict[int, list[tuple[int, bytes]]]) -> list[NetworkRow]:
    """The PANs heard on each channel, named and counted from their headers.

    Frames that carry no PAN ID -- acknowledgements, chiefly -- belong to no
    row. A PAN is Thread or Zigbee by the most common verdict among its frames,
    and "unknown" when none of them names a stack.
    """
    rows = []
    for channel in sorted(per_channel):
        by_pan: dict[int, list[tuple[int, mac154.MacHeader]]] = defaultdict(list)
        for rssi, psdu in per_channel[channel]:
            header = mac154.parse(psdu)
            if header is not None and header.pan is not None:
                by_pan[header.pan].append((rssi, header))
        for pan in sorted(by_pan):
            heard = by_pan[pan]
            verdicts = Counter(h.network for _rssi, h in heard if h.network)
            sources = {(h.src_is_ext, h.src_addr) for _rssi, h in heard if h.src_addr is not None}
            polling = {(h.src_is_ext, h.src_addr) for _rssi, h in heard
                       if h.is_data_request and h.src_addr is not None}
            rows.append(NetworkRow(
                channel=channel, pan=pan,
                network=verdicts.most_common(1)[0][0] if verdicts else "unknown",
                frames=len(heard), addresses=len(sources), sleepy=len(polling),
                rssi=round(statistics.median(rssi for rssi, _h in heard))))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description="802.15.4 channel survey")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--dwell", type=float, default=8.0,
                    help="seconds listening for traffic per channel")
    ap.add_argument("--energy-passes", type=int, default=3)
    ap.add_argument("--channels", default="",
                    help="comma-separated subset, e.g. 11,15,20,25")
    args = ap.parse_args()

    if args.channels:
        channels = [int(c) for c in args.channels.split(",")]
    else:
        channels = list(range(CHANNEL_MIN, CHANNEL_MAX + 1))
    symbols = int(20_000 / 16)  # 20 ms per energy sample

    link = BoardLink(args.port).open()
    ser, parser = link.ser, link.parser
    energy: dict[int, list[int]] = {c: [] for c in channels}
    traffic: dict[int, dict] = {}

    total = len(channels) * args.dwell + args.energy_passes * len(channels) * 0.1
    print(f"surveying {len(channels)} channels on the {link.board['display']} "
          f"on {args.port}, about {total/60:.1f} minutes")

    try:
        print(f"phase 1: energy, {args.energy_passes} passes")
        for _ in range(args.energy_passes):
            for channel in channels:
                reply = link.command(Command.ENERGY_DETECT,
                                     channel | (symbols << 8))
                if reply["ok"]:
                    raw = reply["value"] & 0xFF
                    energy[channel].append(raw - 256 if raw > 127 else raw)

        print(f"phase 2: traffic, {args.dwell:.0f} s per channel")
        for channel in channels:
            # No drain after the retune: heard_on drops whatever arrives from
            # the channel just left, by the channel each packet carries.
            link.command(Command.SET_CHANNEL, channel)
            heard: list[tuple[int, bytes]] = []
            end = time.monotonic() + args.dwell
            while time.monotonic() < end:
                for frame in parser.feed(ser.read(8192)):
                    heard += heard_on(frame, channel)
            rssis = [rssi for rssi, _psdu in heard]
            frames = len(rssis)
            traffic[channel] = {"frames": frames, "rssis": rssis, "packets": heard}
            marker = f"{frames} frames" if frames else "quiet"
            print(f"  channel {channel:>2}: {marker}")
    finally:
        ser.write(encode_command(Command.STOP))
        ser.flush()
        link.close()

    print()
    print(f"{'ch':>3} {'MHz':>5} {'noise':>6} {'frames':>7} {'/s':>6} "
          f"{'signal':>7}  notes")
    busy = []
    for channel in channels:
        e = energy[channel]
        t = traffic[channel]
        noise = f"{statistics.median(e):.0f}" if e else "-"
        rate = t["frames"] / args.dwell
        sig = f"{statistics.median(t['rssis']):.0f}" if t["rssis"] else "-"
        notes = []
        if t["frames"]:
            notes.append("NETWORK")
            busy.append((t["frames"], channel))
        if channel in WIFI_OVERLAP:
            notes.append(WIFI_OVERLAP[channel])
        if channel in ZIGBEE_PREFERRED:
            notes.append("Zigbee-preferred")
        print(f"{channel:>3} {channel_mhz(channel):>5} {noise:>6} "
              f"{t['frames']:>7} {rate:>6.1f} {sig:>7}  {', '.join(notes)}")

    print()
    if busy:
        busy.sort(reverse=True)
        found = ", ".join(f"ch {c} ({n} frames)" for n, c in busy)
        print(f"networks found on: {found}")
        rows = networks({c: traffic[c]["packets"] for c in channels})
        if rows:
            print()
            print("networks, read from their frame headers without any key:")
            print(f"{'ch':>3} {'PAN':>6} {'stack':>7} {'frames':>7} {'addrs':>6} "
                  f"{'sleepy':>7} {'signal':>7}")
            for r in rows:
                print(f"{r.channel:>3} 0x{r.pan:04x} {r.network:>7} {r.frames:>7} "
                      f"{r.addresses:>6} {r.sleepy:>7} {r.rssi:>7}")
            print("addrs counts source addresses, not devices: a device heard under")
            print("both its short and its 64-bit address counts twice. sleepy counts")
            print("sources polling their parent with Data Requests.")
    else:
        print("no 802.15.4 traffic seen on any channel during the dwell.")
        print("That may be genuine, or the networks may simply have been idle:")
        print("a longer --dwell finds sparse traffic that a short one misses.")


if __name__ == "__main__":
    main()
