"""Associate with an access point, then look for 11ax frames.

The HE decoder in this project has never seen a real 802.11ax frame. Not
because it does not work, but because there is nothing to decode: beacons and
probe responses are sent at legacy rates by design, and the 11ax clients on a
typical network are steered to 5 GHz, which this radio cannot reach. So a
2.4 GHz capture is legacy and 11n, and the HE path is exercised only by tests.

Associating fixes that by putting an 11ax client on the 2.4 GHz channel: this
board. Once associated, the access point has someone to speak HE to, and
promiscuous capture keeps running throughout -- measured, because Espressif's
sniffer examples all use a mode that cannot associate and whether the two
coexist is documented nowhere.

    python tools/he_probe.py --port COM3 --ssid "My Network"

The passphrase is read interactively and never taken as an argument, so it does
not reach shell history, a process list, or a log. The board holds it in RAM
and its Wi-Fi driver is set to RAM storage, so nothing is written to flash.

Generating traffic helps: once this reports "associated", load something on
another device, or let this run while the board itself is pulled at by the
network. An idle association produces few data frames and HE is only used for
data.
"""

from __future__ import annotations

import argparse
import collections
import getpass
import os
import struct
import sys
import time

import serial

from esp32c6_sniffer.control import (
    Command,
    Radio,
    decode_reply,
    encode_command,
    encode_credentials,
)
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.radiotap import PhyFormat, decode_he_sig_a, decode_ht_sig

META = struct.Struct("<BbbBQHBBIH")
FCS_LEN = 4

PHY_NAMES = {
    0: "11b (CCK)",
    1: "11g/a (OFDM)",
    2: "HT, 11n",
    3: "VHT, 11ac",
    4: "HE SU, 11ax",
    5: "HE MU, 11ax",
    6: "HE ER SU, 11ax",
    7: "HE TB, 11ax",
    11: "VHT MU",
}
HE_FORMATS = (4, 5, 6, 7)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--seconds", type=float, default=45.0)
    args = ap.parse_args()

    passphrase = os.environ.get("ESP32C6_WIFI_PASSPHRASE")
    if passphrase is None:
        passphrase = getpass.getpass(f"Passphrase for {args.ssid!r}: ")

    ser = serial.Serial(args.port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    parser = StreamParser()
    formats: collections.Counter = collections.Counter()
    he_decoded = 0
    he_rejected = 0
    time.sleep(2.0)

    def pump(seconds: float, collect: bool = False):
        nonlocal he_decoded, he_rejected
        replies = []
        end = time.time() + seconds
        while time.time() < end:
            for frame in parser.feed(ser.read(8192)):
                if frame.ftype is FrameType.CONTROL_REPLY:
                    replies.append(decode_reply(frame.payload))
                elif frame.ftype is FrameType.LOG:
                    text = frame.payload.decode("utf-8", "replace").rstrip()
                    if "radio80211" in text:
                        print("   ", text, flush=True)
                elif (collect and frame.ftype is FrameType.PACKET
                      and len(frame.payload) > META.size):
                    (_ch, _rssi, _nf, _fl, _ts, on_air, _rate, phy,
                     siga1, siga2) = META.unpack_from(frame.payload)
                    fmt = phy & 0x0F
                    formats[fmt] += 1
                    if fmt in HE_FORMATS:
                        if decode_he_sig_a(siga1, siga2) is not None:
                            he_decoded += 1
                        else:
                            he_rejected += 1
        return replies

    def command(cmd, value=0, wait=20.0):
        ser.write(encode_command(cmd, value, radio=Radio.WIFI))
        ser.flush()
        for reply in pump(wait):
            if reply["command"] is cmd:
                return reply
        return None

    print("selecting the Wi-Fi radio and starting capture", flush=True)
    command(Command.SET_RADIO, int(Radio.WIFI))
    command(Command.SET_CHANNEL, 6)

    print(f"sending credentials for {args.ssid!r}", flush=True)
    ser.write(encode_credentials(args.ssid, passphrase))
    ser.flush()
    pump(1.0)

    print("associating", flush=True)
    reply = command(Command.WIFI_CONNECT)
    if reply is None or not reply["ok"]:
        print("\nAssociation failed. The board logs the reason code above; "
              "203 is a wrong passphrase, 201 no such network on 2.4 GHz.")
        ser.close()
        return 1
    channel = reply["value"]
    print(f"associated on channel {channel}", flush=True)

    # Associated is not enough. 802.11ax is used for data frames, so an idle
    # link produces none however long it is watched: the first run of this
    # tool associated cleanly and saw 915 frames without a single HE one,
    # because the board had no address and nothing to say.
    traffic = command(Command.WIFI_TRAFFIC, 1, wait=5.0)
    if traffic is None or not traffic["ok"]:
        print("could not start traffic generation; the link will stay idle "
              "and 11ax frames are unlikely", flush=True)
    else:
        print("pulling data from the gateway, to give the access point "
              "something to send", flush=True)

    print(f"\ncapturing {args.seconds:.0f} s", flush=True)
    pump(args.seconds, collect=True)

    pulled = command(Command.WIFI_TRAFFIC, 1, wait=5.0)
    if pulled is not None and pulled["ok"]:
        print(f"\n{pulled['value']} bytes pulled from the gateway")

    command(Command.WIFI_TRAFFIC, 0, wait=3.0)
    command(Command.WIFI_DISCONNECT, wait=3.0)
    command(Command.STOP, wait=3.0)
    ser.close()

    total = sum(formats.values())
    print(f"\n{total} frames on channel {channel}")
    for fmt, n in formats.most_common():
        print(f"  {PHY_NAMES.get(fmt, f'format {fmt}'):16s} {n:6d}  "
              f"{100.0 * n / max(total, 1):5.1f}%")

    he_total = sum(formats[f] for f in HE_FORMATS)
    print()
    if he_total == 0:
        print("No 11ax frames. If bytes were pulled from the gateway above "
              "then the link was not idle, and this access point simply does "
              "not use HE on 2.4 GHz for this client. The HE decoder remains "
              "unverified against real traffic; that is not evidence it is "
              "broken.")
    else:
        print(f"{he_total} 11ax frames: {he_decoded} decoded, "
              f"{he_rejected} rejected by the decoder's own checks.")
        if he_decoded:
            print("The HE decoder has now been exercised against real frames.")
        else:
            print("Every one was rejected, which means the HE-SIG-A bit layout "
                  "assumed here is wrong. The decoder fails closed, so no wrong "
                  "modulation reached the capture, but it needs fixing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
