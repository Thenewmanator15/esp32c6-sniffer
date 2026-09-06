# esp32c6-sniffer

A passive tri-radio wireless sniffer on a Seeed Studio XIAO ESP32-C6, streaming into
Wireshark over USB-C.

One radio at a time: **IEEE 802.15.4** (Zigbee/Thread/Matter), **Wi-Fi** (802.11
2.4 GHz), **BLE advertisements**. The board appears in Wireshark as three capture
interfaces; picking one selects the radio.

**Passive capture only.** No transmit, no deauthentication, no injection. Intended for
networks and devices you own or are authorised to test.

## Status

**802.15.4 capture works.** The board appears in Wireshark's interface list and
captures live Zigbee and Thread traffic.

**Wi-Fi capture works and appears in Wireshark as a second interface**, with
its own radiotap link type and a 1-14 channel selector. Measured on channel 6:
731 frames in 15 s, management and data, RSSI -50 to -96 dBm, no drops,
decoding as radiotap.

**One quirk, now understood and handled automatically.** Both radios share a
single 2.4 GHz front end, and leaving the 802.15.4 radio *enabled* when the
host disconnects leaves the Wi-Fi receiver deaf until the RF domain is
power-gated. Measured, three arms, each starting from a working Wi-Fi radio:

| what happened | Wi-Fi frames before | after |
|---|---|---|
| 802.15.4 left running | 389 | **0** |
| 802.15.4 stopped properly | 564 | 449 |
| idle for the same time | 425 | 539 |

So it is not using the radio that does it, it is walking away with it still on.
A capture session stops the radio on close, so ordinary use is unaffected; a
crashed or force-killed host is what leaves it poisoned. Nothing short of
power-gating recovers it -- not a driver rebuild, not a reflash, not a full
`erase-flash`.

The board records the condition in RTC memory, where it survives the reset that
opening the serial port causes, and the host power-cycles before a Wi-Fi
capture when it sees the flag. It is automatic:

```
802.15.4 had been used; power-cycled the radio domain first.
```

Getting here took several confident wrong conclusions, including "the radio is
faulty, claim warranty". Written up in
[docs/2026-09-05-wifi-investigation-postmortem.md](docs/2026-09-05-wifi-investigation-postmortem.md),
because the way the mistakes were made is more useful than the fix.

| Milestone | State |
|---|---|
| 1. USB transport and throughput benchmark | Done, measured at ~810 kB/s |
| 2. IEEE 802.15.4 into Wireshark | Done, all exit criteria met |
| 3. Wi-Fi | Done, in Wireshark; receiver is intermittently deaf, see above |
| 4. BLE advertisements | Done, in Wireshark as HCI |

Beyond capture, it also does things other 802.15.4 sniffers do not:

- **Mid-capture channel changes** from a Wireshark toolbar, with no restart.
  Nordic's equivalent has sat unmerged since 2019 and no shipping tool has it.
- **A spectrum survey** using the radio's energy detector, which sees the Wi-Fi
  that overlaps most 802.15.4 channels and is invisible to a packet capture.
- **Drop counters** published by the board, so "did I miss anything" is
  answerable. Measured 0 sequence gaps in 1920 frames.
- **Timestamps good to ~0.5 microseconds**, measured against the standard's
  fixed acknowledgement turnaround.

Read the design first: [docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md](docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md)

It records the verified hardware constraints, the measured transport budget, and
a table of traps: plausible-sounding claims that turned out to be false,
including several that would have silently corrupted or crippled captures.

## Capturing

```powershell
cd firmware
. .\idf-env.ps1
idf.py -DSN_MODE=2 build     # 2 = capture; 0 = conformance tests, 1 = benchmark
.\flash.ps1 -Port COM3
cd ..
.\extcap\install.ps1
```

Flash and install together. The two halves share a wire format, and the host
checks the board's reported firmware version when a capture opens: a mismatch
stops with a message naming both versions rather than decoding older metadata
into confident nonsense.

Restart Wireshark. Both interfaces appear on the welcome screen, with channel
and antenna selectable in their options. Zigbee commonly uses channels 11, 15,
20 and 25; Thread uses anything from 11 to 26.

The sniffer is passive, so it only shows traffic that already exists. If a
channel looks empty, it probably is -- though on Wi-Fi, check the toolbar log
before believing it, because this board's receiver goes deaf for minutes at a
time and the log says when that is happening.

### Wi-Fi options

The Wi-Fi interface has three settings the 802.15.4 one does not need, because
a busy 802.11 channel produces roughly twenty-five times what the USB link
carries. They are throughput controls, not preferences.

| Option | Default | What it does |
|---|---|---|
| Snapshot length | 256 B | Bytes kept per frame. What is cut is encrypted payload; the headers worth having are at the front. Truncation is declared in the pcap, so Wireshark marks frames sliced rather than malformed. |
| Frame types | Management and data | Control frames are the most numerous and least informative. Dropping them buys link budget cheaply. |
| Channel hop | Off | Sweeps 1/6/11 or all of 1-13 at a chosen dwell. Each frame carries its own channel in radiotap, so a hopped capture stays self-describing. |
| Channel width | 20 MHz | Watching a 40 MHz network on its primary channel alone sees half of it, so this must match the network. |
| Drop acknowledgements | Off | ACKs dominate control-frame volume and carry almost nothing. Only relevant when control frames are captured. |
| CSI sidecar file | Off | Per-subcarrier channel response, written beside the pcap. See below. |

Hopping trades completeness for coverage: you will miss whatever arrives while
the radio is on another channel. A beacon interval is about 100 ms, so a dwell
below roughly 300 ms starts losing beacons from the very networks you are
trying to find.

## Finding the networks

Don't guess at channels. The survey measures both halves of the question:

```powershell
cd host
.\.venv\Scripts\python.exe tools\survey.py --port COM3
```

Energy detection sees anything radiating, including the Wi-Fi that overlaps
most 802.15.4 channels and is invisible to a packet capture. Traffic counting
sees decoded frames. A channel can be electrically noisy and carry no 802.15.4
at all, or be quiet and carry a network talking softly, so read them together.

`tools/spectrum.py` runs the energy half alone and faster.
`tools/antenna_compare.py` measures the two antennas against the same traffic.

For Wi-Fi, `tools/wifi_survey.py` asks the receiver what it can identify rather
than measuring energy, and prints access points with their channel, signal,
security and the 802.15.4 channels each one overlaps:

```powershell
.\.venv\Scripts\python.exe tools\wifi_survey.py --port COM3 --repeat 3
```

Use `--repeat` and mean it. This board's Wi-Fi receiver goes deaf for minutes at
a time, so an empty result is not evidence of an empty band. `spectrum.py` uses
the 802.15.4 radio and keeps working when Wi-Fi does not, which makes it a
useful second opinion.

For BLE, `tools/ble_survey.py` summarises what is advertising nearby:

```powershell
.\.venv\Scripts\python.exe toolsle_survey.py --port COM3 --seconds 60
```

It separates **stable addresses** from **rotating** ones, and that separation is
the point. Most modern phones and watches rotate a resolvable private address
every fifteen minutes or so, so a count of addresses counts one phone many times
over; the rotating total is an upper bound on devices, not a device count. Each
entry shows signal, advertising rate, vendor from the manufacturer data, and the
name where one is advertised.

A sample run: 868 reports from 7 addresses, 2 stable and 5 rotating, split
three resolvable private, two non-resolvable private and two random static.

It also reports how many advertisers used a genuine BLE 5 extended PDU. That
number is deliberately not "how many arrived through the extended report path",
which under extended scanning is all of them: extended scanning reports legacy
advertisements too, with an event-type bit saying so. Reading the report format
instead of that bit made every device look like a BLE 5 device, which is a
statistic about nothing.

### Channel state information

Every frame's radiotap header carries an RSSI: one number for the whole
channel. CSI is what that number summarises -- amplitude and phase for each
subcarrier individually, which is the raw channel response. It is the basis of
Wi-Fi sensing work, because a person moving through a room changes the
multipath long before it shows up in RSSI.

No pcap link type has anywhere to put it, and inventing a place inside radiotap
would produce captures only this project could read. So it goes to a CSV beside
the capture, sharing the capture's timestamps so the two line up afterwards.

Measured on a 25 s capture here: 600 records, 64 subcarriers for legacy OFDM
frames and 128 for 11n, with the nulls at the DC and guard subcarriers where
802.11 puts them. It costs a few hundred bytes per frame on a link measured at
~810 kB/s, so it is off unless you ask for it.

Values are signed 8-bit pairs, **imaginary first**, which is the opposite of
what most people assume; `esp32c6_sniffer.csi` swaps them so a phase computed
downstream has the sign you expect.

### Bluetooth LE

The third interface captures BLE advertisements. The board runs its Bluetooth
controller with no host stack and drives it over HCI directly, so what reaches
Wireshark is the controller's own HCI events byte for byte, dissected by
Wireshark's own HCI dissector. Nothing about the BLE payload is interpreted
here, which is the point: there is no bespoke format to get wrong.

**It captures advertisements, not connections.** A real BLE sniffer locks onto
a connection request and hops the data channels with it; that needs raw
link-layer access the controller does not expose to an application. A device
that connects goes quiet here the moment it stops advertising. Anyone needing
connection capture wants a dedicated sniffer, and this is the advertising half
done honestly rather than a claim to be the whole thing.

Scanning is passive: the controller never sends a scan request, so the sniffer
stays silent. Scan responses appear only when some other device solicits them,
which is the trade for not announcing yourself.

Scanning is **extended** by default, which is what BLE 5 needs. Legacy
scanning reports only legacy advertisements -- 31 bytes on the 1M PHY -- and
silently omits every extended advertisement, of which there can be up to 1650
bytes. Extended scanning reports both, so nothing is lost by preferring it, and
a controller without BLE 5 falls back with a warning rather than failing.

The Coded (long range) PHY is available too, and off by default: the controller
time-shares between the PHYs it scans, so adding Coded costs 1M coverage. There
is also a legacy-only setting, which exists so the difference can be measured
rather than asserted.

Measured: 446 HCI packets in 20 s, every one dissected as an LE Advertising
Report, five distinct advertisers.

**Measured, and worth stating because it is a negative result:** extended
scanning found nothing here that legacy did not. Two alternating rounds, 20 s
each, gave 1379 reports and 8 advertisers on legacy against 1368 and 7 on
extended, with no device seen only by extended. The board's log confirms
extended scanning really was running (`extended scanning, PHYs 0x01`), so this
is an empty room for BLE 5 rather than a feature that does not work. The
capability is there for a room that has some.

Unlike 802.15.4, leaving BLE running does not poison the shared front end --
Wi-Fi kept working afterwards in both arms of the test, so that fault really is
specific to the 802.15.4 driver.

The C6 is Bluetooth 5.0 LE, certified to 5.3. Bluetooth 6.0 features such as
Channel Sounding are not present in this silicon: its `soc_caps.h` defines
`SOC_BLE_50_SUPPORTED` and no BLE 6 capability at all.

## What you will and will not see

Everything the radio delivers is captured, and every frame is dissected as far
as it can be. Verified over a 90 s capture: 87 frames, zero dropped in the
receive interrupt, zero refused by the link, zero buffer overruns, zero
sequence gaps, and **zero data frames left stuck at the MAC layer**.

Two genuine limits, neither fixable in software here:

**Frames that fail their checksum never arrive.** The ESP-IDF 802.15.4 driver
exposes only a receive-done callback, with no failure equivalent, so corrupt
frames are discarded in hardware before we could see them. Some sniffers show
them; this one cannot.

**Payloads are encrypted.** Zigbee and Thread both encrypt above the MAC layer,
so you see frame structure, addresses and routing but not contents. Wireshark
reports this honestly as "Encrypted Payload" and "No encryption key set".

### Decrypting your own network

`install.ps1` does not touch keys, but the project adds the well-known default
Zigbee Trust Center link key to `%APPDATA%\Wireshark\zigbee_pc_keys`. That key
is public and ships with every Zigbee analyser. It does **not** decrypt
arbitrary traffic: it only lets Wireshark read the key-transport message sent
when a device joins, and derive that network's key from it.

To read your own Zigbee network, start a capture on its channel and put a
device into pairing mode. Wireshark picks up the network key from the join and
decrypts from then on. For a network whose key you already know, add it to that
file directly.

### Matter and Thread

Matter over Thread is already captured: those frames arrive and Wireshark
identifies them. Reading them needs your Thread network key, because Thread
encrypts at the MAC layer.

```powershell
cd host
.\.venv\Scripts\python.exe tools	hread_key.py --key <32 hex chars>
```

The key comes from your border router, and only for a network you control.
Home Assistant exposes it under Settings, Devices & Services, Thread. Apple's
Home app can share Thread credentials to a Mac. An OpenThread border router
answers `ot-ctl networkkey`.

With it installed, frames resolve through 6LoWPAN and IPv6 to UDP, and Matter
traffic to its message layer: which node talks to which, session identifiers,
counters, acknowledgements. Wireshark has dissectors for Matter, its Bluetooth
transport and its advertising data built in.

**The Matter payload itself stays encrypted.** It is protected by session keys
negotiated during commissioning, and Wireshark's built-in Matter dissector has
no key table at all, so there is nowhere to supply them. A separate
experimental plugin from the Matter project can decrypt, but it is Linux-only
and built for Wireshark 3.6. That is a real ceiling, not a configuration
problem.

Commissioning itself happens over Bluetooth before a device joins Thread, and
inside a connection, so this chip cannot capture it at all.

## Honest capability ceilings

| Radio | What you actually get |
|---|---|
| 802.15.4 | Strong. Full promiscuous capture with RSSI, LQI and channel. |
| Wi-Fi | Good. Full payloads except MIMO frames. 2.4 GHz only. Encrypted payloads stay encrypted. |
| BLE | Weak. Advertisements only. It cannot follow connections; this is a scanner, not a link-layer sniffer. |

The three radios share one RF front end and **cannot** capture simultaneously.

## Prerequisites

- A Seeed Studio XIAO ESP32-C6.
- **ESP-IDF v6.1**, installed at `H:\dev\tools\.espressif\v6.1\esp-idf` with tools
  under `H:\dev\tools\.espressif`, matching the `IDF_TOOLS_PATH` that
  `H:\dev\setup-caches.ps1` sets.
- Wireshark, for milestone 2 onwards. Npcap is **not** required, because frames
  arrive over USB rather than from a local network adapter.

## Building

```powershell
cd firmware
. .\idf-env.ps1      # dot-sourced, not run
idf.py build
idf.py -p COM3 flash
```

`idf-env.ps1` pins `IDF_TOOLS_PATH` and `IDF_PATH` so a build never depends on
whatever ESP-IDF version happens to be active in the shell.

If flashing fails, hold BOOT, tap RESET, release BOOT, and retry.

## Testing

```powershell
cd host
.\.venv\Scripts\python.exe -m pytest tests\ -q -m "not hardware"   # no board needed
.\.venv\Scripts\python.exe -m pytest tests\ -q -m hardware --port COM3
```

The hardware tests hold the firmware's C frame encoder to byte-identical output
with the Python one, using shared vectors in `host/tests/vectors/golden.json`.
The Python implementation is authoritative; if they disagree, fix the C.

Two more suites run against the board, and they ask different questions.

```powershell
.\.venv\Scripts\python.exe tools\selftest.py --port COM3   # does each feature work?
.\.venv\Scripts\python.exe toolsbuse.py    --port COM3   # can it be broken?
```

`selftest.py` drives every feature and reports PASS, FAIL or SKIP, where SKIP
means the check could not be run here and is never counted as a pass. Its
checks are differential where an absolute one would lie: a snapshot length is
proved by records getting smaller, not by any particular size, because a size
threshold would only measure how big the frames on air happened to be.

`abuse.py` does the opposite. It sends out-of-range values, unknown command
identifiers, garbage and truncated frames, floods, retune and radio-switch
storms, and stops reading mid-capture to apply backpressure. Every check ends
by asking whether the board is still alive and still capturing. It builds its
frames by hand, because the host library validates its own commands and would
otherwise never let the firmware's checking be tested.

Between them they have found more real defects than review did, including two
that the ordinary tests could not see: a snapshot length that was silently
discarded on every channel change, and a host crash on a reply the board was
right to send.
