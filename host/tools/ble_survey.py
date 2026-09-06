"""BLE survey: what is advertising nearby, and how anonymously.

The counterpart to wifi_survey.py. It listens for a window and summarises what
it heard: who is advertising, how loudly, how often, and -- the part that
matters for interpreting the rest -- whether each address is one that can be
tracked at all.

    python tools/ble_survey.py --port COM3
    python tools/ble_survey.py --port COM3 --seconds 60 --legacy

Most modern phones and watches rotate a resolvable private address every
fifteen minutes or so, so counting addresses would count one phone many times
over. Those are listed separately and counted separately, because a total that
mixes them is a number about nothing.

Scanning is passive and extended by default, so the sniffer never transmits and
BLE 5 extended advertisements are included. --legacy forces the older scan for
comparison; it cannot see extended advertisements at all.
"""

from __future__ import annotations

import argparse
import collections
import threading
import time

from esp32c6_sniffer.adv import AddressType, parse_advertising_reports
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Radio


def bar(rssi: int, width: int = 20) -> str:
    """-100 dBm or worse is empty, -40 dBm or better is full."""
    fraction = max(0.0, min(1.0, (rssi + 100) / 60.0))
    filled = round(fraction * width)
    return "#" * filled + "." * (width - filled)


class Device:
    def __init__(self, report) -> None:
        self.address = report.address
        self.address_type = report.address_type
        self.best_rssi = report.rssi_dbm
        self.count = 0
        self.name: str | None = None
        self.company: str | None = None
        self.extended_pdu = False
        self.services: set[str] = set()

    def update(self, report) -> None:
        self.count += 1
        self.best_rssi = max(self.best_rssi, report.rssi_dbm)
        # Keep the first name seen: some devices alternate between a complete
        # name and a shortened one, and the longer is the more useful.
        if report.name and (self.name is None or len(report.name) > len(self.name)):
            self.name = report.name
        if report.company:
            self.company = report.company
        self.extended_pdu = self.extended_pdu or report.extended_pdu
        self.services.update(report.services)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--legacy", action="store_true",
                    help="force legacy scanning, which cannot see BLE 5 "
                         "extended advertisements. For comparison only")
    args = ap.parse_args()

    devices: dict[str, Device] = {}
    payloads: list[bytes] = []

    print(f"listening {args.seconds:.0f} s, "
          f"{'legacy' if args.legacy else 'extended'} passive scan", flush=True)

    with CaptureSession(args.port, channel=0, radio=Radio.BLE,
                        ble_phys=0 if args.legacy else 1) as session:
        original = session._build_record

        def spy(payload):
            payloads.append(payload)
            return original(payload)

        session._build_record = spy

        def pump() -> None:
            try:
                for _rec, _ts, _orig in session.records():
                    pass
            except Exception:
                pass

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        thread.join(args.seconds)
        session.request_stop()
        thread.join(5.0)

    for payload in payloads:
        for report in parse_advertising_reports(payload):
            device = devices.get(report.address)
            if device is None:
                device = devices[report.address] = Device(report)
            device.update(report)

    if not devices:
        print("\nNothing advertising within range.")
        return 0

    trackable = [d for d in devices.values()
                 if d.address_type in (AddressType.PUBLIC,
                                       AddressType.RANDOM_STATIC)]
    private = [d for d in devices.values() if d not in trackable]

    def show(group, title):
        if not group:
            return
        print(f"\n{title}")
        print(f"{'RSSI':>5}  {'signal':<20}  {'adv/s':>5}  {'address':<17}  "
              f"name / vendor")
        for d in sorted(group, key=lambda d: -d.best_rssi):
            label = d.name or d.company or ""
            if d.name and d.company:
                label = f"{d.name}  ({d.company})"
            rate = d.count / args.seconds
            print(f"{d.best_rssi:>5}  {bar(d.best_rssi):<20}  {rate:>5.1f}  "
                  f"{d.address:<17}  {label}")

    show(trackable, "Stable addresses (public or random static)")
    show(private, "Rotating addresses (privacy enabled, not one device each)")

    reports = sum(d.count for d in devices.values())
    extended = sum(1 for d in devices.values() if d.extended_pdu)
    print(f"\n{reports} reports from {len(devices)} addresses: "
          f"{len(trackable)} stable, {len(private)} rotating")
    if not args.legacy:
        # Counting reports that ARRIVED through the extended path would count
        # everything, because extended scanning reports legacy advertisements
        # that way too. Only the PDU type says anything.
        print(f"{extended} of those addresses used a BLE 5 extended "
              f"advertising PDU, which legacy scanning cannot see at all")
    print("\nRotating addresses change every few minutes, so the count of "
          "those is an upper bound on devices, not a device count.")

    types = collections.Counter(d.address_type for d in devices.values())
    for kind, n in types.most_common():
        print(f"  {n:3d}  {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
