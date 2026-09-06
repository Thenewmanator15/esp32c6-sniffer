"""Abuse the firmware: hostile commands, stress and backpressure.

    python tools/abuse.py --port COM3

Every check ends the same way: is the board still alive and still capturing? A
sniffer that can be wedged by one bad byte is not usable unattended, and it
sits on a shared band listening to equipment nobody controls.

The host library validates its own commands, so testing the firmware's own
checking means building the frames by hand and bypassing it. That is what
Link.raw() is for.

This complements tools/selftest.py, which asks whether each feature works.
This one asks whether they can be broken. It found two faults on its first run:
the board refused an unknown command correctly, and the HOST crashed decoding
the refusal, which would have ended a live capture.
"""
import sys, time, struct, serial
sys.path.insert(0, r"H:\dev\projects\esp32c6-sniffer\host\src")

from esp32c6_sniffer.control import Command, Radio, encode_command, decode_reply
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser

import argparse

_args = argparse.ArgumentParser(description=__doc__)
_args.add_argument("--port", default="COM3")
PORT = _args.parse_args().port
results = []


def record(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""),
          flush=True)


class Link:
    def __init__(self):
        self.ser = serial.Serial(PORT, 115200, timeout=0.05)
        try:
            self.ser.set_buffer_size(rx_size=1 << 20)
        except Exception:
            pass
        self.ser.reset_input_buffer()
        self.parser = StreamParser()
        time.sleep(2.0)

    def raw(self, command_id, value):
        """Bypasses the host-side validation to test the board's own."""
        payload = struct.pack("<BI", command_id, value)
        self.ser.write(encode_frame(FrameType.CONTROL_CMD, 0, payload))
        self.ser.flush()

    def send(self, cmd, value=0, radio=Radio.WIFI):
        self.ser.write(encode_command(cmd, value, radio=radio))
        self.ser.flush()

    def pump(self, seconds, count=None):
        end = time.time() + seconds
        replies = []
        while time.time() < end:
            for f in self.parser.feed(self.ser.read(8192)):
                if f.ftype is FrameType.CONTROL_REPLY:
                    replies.append(decode_reply(f.payload))
                elif f.ftype is FrameType.PACKET and count is not None:
                    count[0] += 1
        return replies

    def alive(self, seconds=3.0):
        """GET_INFO must still answer with the right version."""
        self.send(Command.GET_INFO)
        for r in self.pump(seconds):
            if r["command"] is Command.GET_INFO:
                return r["value"]
        return None

    def close(self):
        self.ser.close()


print("hostile command values (host validation bypassed)")
link = Link()
bad = [
    ("channel 0",        Command.SET_CHANNEL.value, 0),
    ("channel 255",      Command.SET_CHANNEL.value, 255),
    ("channel 2^32-1",   Command.SET_CHANNEL.value, 0xFFFFFFFF),
    ("antenna 7",        Command.SET_ANTENNA.value, 7),
    ("radio 5",          Command.SET_RADIO.value, 5),
    ("snaplen 0",        Command.SET_SNAPLEN.value, 0),
    ("snaplen 65535",    Command.SET_SNAPLEN.value, 65535),
    ("bandwidth 255",    Command.SET_BANDWIDTH.value, 255),
    ("csi 2",            Command.SET_CSI.value, 2),
    ("energy detect 0",  Command.ENERGY_DETECT.value, 0),
]
refused = 0
for name, cid, value in bad:
    link.raw(cid, value)
    replies = link.pump(2.0)
    matching = [r for r in replies if r["command"] == cid]
    if matching and not matching[0]["ok"]:
        refused += 1
    elif not matching:
        print(f"    (no reply to {name})", flush=True)
record("hostile values refused", refused >= 8,
       f"{refused} of {len(bad)} rejected with a failure status")
record("alive after hostile values", link.alive() is not None)

print("\nunknown command identifiers")
unknown_ok = 0
for cid in (16, 99, 255):
    link.raw(cid, 0)
    replies = link.pump(1.5)
    if any(r["command"] == cid and not r["ok"] for r in replies):
        unknown_ok += 1
record("unknown commands refused", unknown_ok == 3, f"{unknown_ok} of 3")
record("alive after unknown commands", link.alive() is not None)

print("\ngarbage and truncated frames on the command stream")
link.ser.write(bytes(range(256)) * 8)          # pure noise
link.ser.write(b"\xc6\x5a" * 64)               # near-magic, wrong order
partial = encode_command(Command.GET_INFO)[:6]  # truncated mid-header
link.ser.write(partial)
link.ser.flush()
link.pump(2.0)
record("alive after garbage on the command stream", link.alive() is not None)

print("\ncommand flood")
for _ in range(200):
    link.send(Command.GET_INFO)
link.pump(3.0)
record("alive after 200 back-to-back commands", link.alive() is not None)
link.close()

print("\nchannel-change storm during a live capture")
link = Link()
link.send(Command.SET_RADIO, int(Radio.WIFI))
link.pump(1.5)
link.send(Command.SET_CHANNEL, 6)
link.pump(2.0)
count = [0]
for i in range(60):
    link.send(Command.SET_CHANNEL, (i % 13) + 1)
    link.pump(0.15, count)
link.send(Command.SET_CHANNEL, 6)
link.pump(1.0)
count[0] = 0
link.pump(6.0, count)
record("capturing after 60 rapid retunes", count[0] > 0, f"{count[0]} frames")
link.close()

print("\nradio switching storm")
link = Link()
for i in range(20):
    link.send(Command.SET_RADIO, i % 2)
    link.pump(0.2)
link.send(Command.SET_RADIO, int(Radio.IEEE802154), radio=Radio.IEEE802154)
link.pump(1.0)
link.send(Command.SET_CHANNEL, 25, radio=Radio.IEEE802154)
link.pump(2.0)
count = [0]
link.pump(8.0, count)
record("802.15.4 captures after 20 radio switches", count[0] > 0,
       f"{count[0]} frames")
# Hand the front end back, or Wi-Fi is poisoned for the next test.
link.send(Command.STOP, 0, radio=Radio.IEEE802154)
link.pump(1.5)
link.close()

print("\nbackpressure: stop reading, then resume")
link = Link()
link.send(Command.SET_RADIO, int(Radio.WIFI))
link.pump(1.5)
link.send(Command.SET_CHANNEL, 6)
link.pump(2.0)
time.sleep(10.0)                    # never touching read(): the board must cope
count = [0]
link.pump(6.0, count)
record("still streaming after a 10 s stall", count[0] > 0, f"{count[0]} frames")
record("link resynchronised cleanly",
       link.parser.resync_count < 50,
       f"{link.parser.resync_count} resyncs, "
       f"{link.parser.bytes_discarded} bytes discarded")
record("alive after backpressure", link.alive() is not None)

print("\nredundant and out-of-order control")
link.send(Command.STOP)
link.pump(1.0)
link.send(Command.STOP)             # stop twice
link.pump(1.0)
record("double STOP tolerated", link.alive() is not None)
link.send(Command.SET_CHANNEL, 6)   # restart by selecting a channel
link.pump(2.0)
count = [0]
link.pump(5.0, count)
record("capture restarts after STOP", count[0] > 0, f"{count[0]} frames")
link.send(Command.STOP)
link.pump(1.0)
link.close()

passed = sum(1 for _n, ok, _d in results if ok)
print(f"\n{passed} passed, {len(results) - passed} failed")
