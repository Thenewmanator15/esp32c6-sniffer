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
- **Captures that describe themselves.** pcapng, carrying the board, the
  radio, the channel, the board's own drop counters and -- for Zigbee -- the
  decryption key, all inside the file. See below.

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

## What the capture file carries

Output is pcapng, not classic pcap, because classic pcap carries a link type
and a snapshot length and nothing else. Everything worth knowing lived outside
the file and was lost the moment a capture was handed to anybody:

```
Capture hardware:    Seeed Studio XIAO ESP32-C6
Capture application: esp32c6-sniffer extcap
                     Name = esp32c6-wifi
                     Description = ESP32-C6 Wi-Fi 2.4 GHz (802.11) (Wi-Fi), channel 6
                     Number of stat entries = 16
```

Those stat entries are the board's own receive and drop counts, written once a
second rather than only at the end. That is not tidiness: **Wireshark stops a
capture by closing the pipe**, so anything written in a cleanup path is written
into a pipe nobody is reading and never reaches the file. dumpcap writes them
periodically for the same reason. Verified by killing a capture outright, with
no cleanup at all, and finding sixteen of them in the file.

So "did I miss anything?" is answerable from the file months later, instead of
from a toolbar log nobody kept. A capture with no drop record cannot be told
apart from a quiet channel.

### Keys inside the capture

An 802.15.4 capture can carry its Zigbee keys, in a Decryption Secrets Block:

```
--keys keys.txt     # or the "Zigbee key file" option in the interface dialog
```

One key per line, 32 hex digits, optionally prefixed `nwk` or `aps`; `#`
comments and blank lines ignored. The capture then decrypts on any machine,
without the recipient pasting a key into their own Wireshark preferences.

A **path** is taken rather than the key itself, because an extcap argument
reaches the process list and Wireshark's saved configuration. A malformed key
is refused before the capture starts, naming the line, because a wrong key
produces a file that simply does not decrypt and hunting that afterwards --
with the traffic long gone -- is far worse.

The block layout and the secret-type codes were taken from Wireshark rather
than from memory: a file written by `editcap --inject-secrets` was parsed back,
the statistics block was compared byte-for-byte against one dumpcap wrote, and
the Zigbee type codes were read out of the shipped `libwiretap.dll` and
`libwireshark.dll`.

**Not verified end to end:** that a real Zigbee network decrypts from an
embedded key. The 802.15.4 traffic in range here is Thread, not Zigbee, and
Thread does not use this mechanism -- it takes a key through Wireshark's
802.15.4 key table, which is what `tools/thread_key.py` installs. What is
verified is that the block is written, that Wireshark counts it
(`Number of decryption secrets in file: 2`), and that both the file-format and
dissector libraries carry the type codes.

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

**Periodic advertising sync** follows the trains that carry LE Audio and
Auracast broadcasts. A periodic advertiser announces its train in an extended
advertisement, and the contents are only visible after synchronising to it. It
is off by default, because syncing costs radio time that would otherwise be
spent scanning, and capped at two concurrent syncs.

Measured here: 1342 advertising reports processed, and **no periodic
advertisers at all** -- seen 0, synced 0. Nothing in range broadcasts one. The
detection path ran on every report without incident; there is simply nothing to
follow in this room.

The C6 is Bluetooth 5.0 LE, certified to 5.3. Bluetooth 6.0 features such as
Channel Sounding are not present in this silicon: its `soc_caps.h` defines
`SOC_BLE_50_SUPPORTED` and no BLE 6 capability at all.

### Verifying the 11ax decoder

The HE decoder has never seen a real 802.11ax frame, and not because it is
broken. There is nothing to decode: beacons and probe responses go out at
legacy rates by design, and a network's 11ax clients are steered to 5 GHz,
which this radio cannot reach. A 2.4 GHz capture is therefore legacy and 11n.

`tools/he_probe.py` closes that by putting an 11ax client on the channel: this
board. It associates, keeps promiscuous capture running throughout, and reports
the PHY of every frame it then sees.

```powershell
.\.venv\Scripts\python.exe tools\he_probe.py --port COM3 --ssid "Your Network"
```

Measured first, because Espressif's sniffer examples all use a mode that cannot
associate and whether the two coexist is documented nowhere: promiscuous
capture keeps working in station mode, 630 frames in 10 s against 486 in 8 s
before the switch.

**It works, and the HE decoder is now verified against real traffic.** The
first attempt associated cleanly and still saw no 11ax at all -- 915 frames,
none of them HE -- because the board had no address and an idle link gives an
access point nothing to send. With DHCP and a trickle of fetches from the
gateway to pull data down:

```
address 192.0.2.238, gateway 192.0.2.1
111410 bytes pulled from the gateway

1321 frames on channel 6
  HE SU, 11ax         599   45.3%
  11g/a (OFDM)        402   30.4%
  11b (CCK)           230   17.4%
  HT, 11n              90    6.8%

599 11ax frames: 599 decoded, 0 rejected by the decoder's own checks
```

That the decoder ran without rejecting anything is not verification. Reading
`radiotap.he.data_3.data_mcs` back in Wireshark is not either: that field
contains this project's own decoded value, so the check confirms only that
Wireshark and this code agree on where the byte goes. Three checks that are
not circular, against a 45 s capture of 2595 frames:

* **BSS colour, from two different parts of the frame.** HE-SIG-A sits in the
  PHY preamble; a beacon advertises the same colour in its management body,
  dissected by unrelated Wireshark code. We decode `0x1e` on all 1437 HE
  frames, and the access point they all come from advertises `0x1e`. The five
  other access points in range advertise 0x04, 0x10 and 0x0b, so the match is
  not everything reading one number.
* **Direction.** UL/DL decodes as downlink on every frame, and every frame has
  that access point as its transmitter.
* **Bandwidth.** 20 MHz on all of them, which is the only width a 2.4 GHz link
  uses. A wrong bit offset would read 40, 80 or 160.

Doing this found three faults, all silent -- no exception, no malformed
capture, just fields that were wrong or absent:

| | before | after |
|---|---|---|
| bandwidth | not displayed at all | 20 MHz |
| guard interval | 1.6 us | 0.8 us |
| LTF symbol size | not displayed | 2x |
| claims to know the LTF symbol count | yes, and it was zero | no |

The bandwidth known-bit is data1 bit 14, not data2 bit 2; data2 bit 2 says the
LTF *symbol count* is known, which HE-SIG-A does not carry, so the capture
published a confident zero for it whilst the bandwidth it did decode went
undeclared and was never shown. Separately, HE-SIG-A carries one combined
"GI + LTF Size" field and radiotap has two with different encodings, so
copying it across got three of its four values wrong -- including the one this
network uses.

The bit positions now come from Wireshark's own field registry
(`tshark -G fields`) rather than from memory, and a synthetic capture
round-trips all four guard intervals and all four bandwidths back through
tshark. `host/tests/test_radiotap.py` holds one regression test per fault.

The passphrase is read interactively and never accepted as an argument, so it
stays out of shell history and process lists. The board holds it in RAM and its
Wi-Fi driver is set to RAM storage, so nothing reaches flash.

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
