# Using the Wireshark plugin

A task-oriented guide. For installation see the [README](../README.md#install);
this assumes the firmware is flashed, `extcap\install.ps1` has been run and
Wireshark has been restarted.

Everything here is passive. The sniffer transmits nothing.

---

## Your first capture

1. Open Wireshark. Three interfaces appear on the welcome screen:

   - **ESP32-C6 IEEE 802.15.4 (Zigbee/Thread)**
   - **ESP32-C6 Wi-Fi 2.4 GHz (802.11)**
   - **ESP32-C6 Bluetooth LE (advertisements)**

2. The right profile should select itself. There is one per radio —
   **ESP32-C6 802.15.4**, **ESP32-C6 Wi-Fi**, **ESP32-C6 BLE** — and each
   carries a filter matching its own interface name. If none does, right-click
   the profile name at the **bottom-right** of the status bar and choose it.
   Without a profile a capture is dissected correctly, but channel and signal
   strength are only visible by clicking into each frame.

3. Double-click **Bluetooth LE**. It needs no configuration and there is
   almost always something advertising, so it is the quickest proof that
   everything works. You should see `HCI_EVT` frames within a second or two.

If nothing appears, jump to [When nothing arrives](#when-nothing-arrives).

The three radios share one antenna and **cannot run at once**. Starting a
second interface while one is capturing fails to open the port; that is the
hardware, not a bug.

## Do not guess the channel

A passive sniffer shows only traffic that already exists, so an empty capture
usually means an empty channel rather than a broken setup. Two commands answer
"where is the traffic?" before you spend a capture finding out:

```powershell
cd host
.\.venv\Scripts\python.exe tools\survey.py   --port COM3   # who is on air
.\.venv\Scripts\python.exe tools\spectrum.py --port COM3   # where the energy is
```

`survey.py` lists the Wi-Fi networks with their channels and signal strengths.
`spectrum.py` uses the radio's energy detector, which sees the Wi-Fi that
overlaps most 802.15.4 channels and is invisible to a packet capture.

Zigbee commonly sits on channels 11, 15, 20 and 25; Thread uses anything from
11 to 26. The difference is real: on this bench channel 11 yielded 2 frames in
15 seconds while channel 25 yielded 135 in the same window. **Channel 11 is the
default and is often the quietest one.**

## Setting options

Click the **gear icon** beside an interface before starting, or use
*Capture → Options*.

### Shared by all three

| Option | What it does |
|---|---|
| **Serial port** | Filled in for you. The board is found by its USB id (`303A:1001`), so this is right even if it is not COM3. Change it only if you have more than one board. |
| **Antenna** | Onboard ceramic, or external U.FL if you have fitted one. Measured **+6.0 dB** on this board. |

### IEEE 802.15.4

| Option | Notes |
|---|---|
| **Channel** | 11–26, each shown with its frequency. Also changeable mid-capture from the toolbar. |
| **Zigbee key file** | Embeds your network keys *in the capture*, so it decrypts on any machine. See [Decrypting your own traffic](#decrypting-your-own-traffic). |

### Wi-Fi

These are throughput controls, not preferences: a busy 802.11 channel produces
roughly twenty-five times what the USB link carries.

| Option | Default | Notes |
|---|---|---|
| **Channel** | 6 | 1–14. |
| **Snapshot length** | 256 B | Bytes kept per frame. What is cut is encrypted payload; the headers are at the front. Truncation is declared in the file, so Wireshark marks frames sliced rather than malformed. Measured: largest frame 116 B at a snaplen of 80, 436 B at 400. |
| **Frame types** | Management and data | *Everything, including control* adds ACKs, RTS/CTS and block-acks — numerous and rarely informative. *Management only* is beacons and probes, the cheapest way to survey. |
| **Channel hop** | Off | Sweeps 1/6/11 or all of 1–13. Each frame carries its own channel, so a hopped capture stays self-describing. |
| **Hop dwell** | 500 ms | Below roughly 300 ms you start missing beacons from the very networks you are looking for, since a beacon interval is about 100 ms. |
| **Channel width** | 20 MHz | Must match the network. Watching a 40 MHz network on its primary channel alone sees half of it. |
| **Drop acknowledgements** | Off | Only relevant when control frames are captured. |
| **CSI sidecar file** | Off | Per-subcarrier channel response, written beside the capture as CSV. No pcap link type can carry it. |

### Bluetooth LE

| Option | Default | Notes |
|---|---|---|
| **Scan interval** / **window** | 60 / 60 ms | Equal values mean continuous listening, which is what a sniffer wants. Measured: 670 reports at 60/60 against 59 at 50/500, so a low duty cycle costs you most of the traffic. |
| **Advertising PHYs** | Extended | Extended scanning reports legacy advertisements too. Legacy-only cannot see BLE 5 extended advertisements at all, and exists so the difference can be measured. |

There is **no channel option** for BLE: the controller rotates the three
advertising channels itself, so offering one would be a promise it cannot keep.

## The toolbar: retuning without restarting

Turn it on with **View → Interface Toolbars → ESP32-C6**. It gives you:

- a **channel selector that retunes the radio mid-capture**, with no restart
  and no new file;
- an **antenna toggle**, making the +6 dB difference a live A/B on the same
  traffic rather than a comparison across two runs;
- a **log window** showing frame counts and the board's own drop counters.

Measured on a live capture: started on channel 6, sent a change to 11 partway
through, and the frames move from 2437 MHz to 2462 MHz at 19 seconds in a
single continuous capture.

Toolbar channel values carry a radio prefix — `z25` for 802.15.4, `w6` for
Wi-Fi. Channels 11 to 14 exist in **both** radios and mean different
frequencies, so a bare number would be ambiguous and a mis-click would
silently retune to the wrong band.

`tshark` has no toolbar, which is why the channel is also an ordinary option.

## Reading the capture

There is **one profile per radio**, because a filter button belongs to the
profile rather than to the interface. A single shared profile put Zigbee,
Thread and 11ax buttons on a BLE capture, where none of them can ever match,
so each radio now has its own and selects itself.

**Columns.** Each profile shows only what its radio actually reports, so an
empty column means no signal rather than a field it never had:

| | 802.15.4 | Wi-Fi | BLE |
|---|---|---|---|
| Channel | yes | yes | — (the controller rotates the three advertising channels itself) |
| RSSI | yes | yes | yes |
| LQI | yes | — | — |
| Rate | — | yes | — |
| Advertiser / Name | — | — | yes, in place of the useless "controller → host" |

On an 802.15.4 capture that turns

```
1  0.000000  0x5f4a -> Broadcast  ZigBee 79 Command
```

into

```
1  0.000000  25  -88 dBm  8  esp32c6-802154  0x5f4a -> Broadcast  ZigBee 79 Command
```

**Filter buttons**, each set matching only what that radio produces:

| 802.15.4 | Wi-Fi | BLE |
|---|---|---|
| Zigbee | Beacons | Adverts |
| Thread | Probes | Named |
| Data | Named | Connectable |
| No acks | Data | Discoverable |
| Beacons | Management | Extended (BLE 5 PDUs) |
| Encrypted | No acks | Apple |
| Strong | Encrypted | Strong |
| | 11ax | |
| | Strong | |

Every one was run against a real capture before being shipped, which is how
two earlier ones were caught: `No acks` combined two `!=` tests, and in
Wireshark a `!=` on an *absent* field is false, so on a capture with only one
radio it matched nothing at all; and `Named BLE` used a field that exists but
never appears in an advertising report.

**Colouring**, first match winning, per radio. On a 135-frame 802.15.4 capture
the rules accounted for every frame: 68 Zigbee, 67 acknowledgements, with a
separate shade below −95 dBm so a weak transmitter shows without reading the
column. The Wi-Fi profile separates 11ax, encrypted data, beacons, probes and
control frames; the BLE one separates extended PDUs, named and connectable
advertisers.

The 802.15.4 profile also sets one dissector preference: Thread works out its
own key sequence counter once it has seen enough traffic, so you do not have
to supply it.

Useful filters that are not buttons:

```
wlan.ssid                      # frames naming a network
wlan.ta == aa:bb:cc:dd:ee:ff   # one transmitter
radiotap.dbm_antsignal > -60   # strong signals only
wpan.dst_pan == 0x1234         # one 802.15.4 network
btcommon.eir_ad.entry.company_id == 0x004c   # Apple advertisers
```

## Did I miss anything?

Capture files are pcapng and carry the board's own receive and drop counters,
written once a second. **Statistics → Capture File Properties** shows them,
along with which board and radio produced the file.

That matters because a capture with no drop record cannot be told apart later
from a quiet channel. The counters are written *during* the capture, not at the
end: Wireshark stops a capture by closing the pipe, so anything written in a
cleanup path would never reach the file.

The toolbar log reports the same figures live, and raises a warning in
Wireshark if the board ever drops a frame.

## Decrypting your own traffic

**Zigbee**, for a network you own: put your keys in a text file, one per line,
32 hex digits, optionally prefixed `nwk` or `aps`:

```
# living-room network
nwk 000102030405060708090a0b0c0d0e0f
aps 0f0e0d0c0b0a09080706050403020100
```

Select it as the **Zigbee key file** option. The keys are embedded in the
capture itself, so it decrypts on any machine without the recipient pasting
anything into their own Wireshark. A path is taken rather than the key, because
an option value would reach the process list and Wireshark's saved
configuration. A malformed key is refused before the capture starts, naming the
line.

**Thread** uses a different mechanism — Wireshark's 802.15.4 key table rather
than a key inside the file:

```powershell
.\.venv\Scripts\python.exe tools\thread_key.py --key <32 hex digits>
```

**Wi-Fi** payloads stay encrypted. WPA2 can be decrypted in Wireshark with the
passphrase, but only for sessions whose four-way handshake you captured, which
means capturing at the moment a device joins.

## When nothing arrives

| Symptom | Cause |
|---|---|
| No interfaces in Wireshark | The plugin is not installed, or Wireshark was not restarted. Check with `tshark -D`. |
| Board is not a COM port at all | A charge-only USB-C cable. It enumerates nothing and looks exactly like a dead board. |
| `cannot capture on COM3` | The board is elsewhere; the message names the port it found. |
| `could not open port` | Something else holds it — another capture, a serial monitor, or a previous run that has not exited. |
| Wi-Fi empty, 802.15.4 fine | The 802.15.4 radio was left enabled by a crashed host, leaving the shared front end deaf. The host power-cycles automatically when it sees the flag; the toolbar log says when it has. |
| A channel looks empty | It probably is. Run `survey.py` and `spectrum.py` before believing a capture. |

## What you will not get

| Radio | Ceiling |
|---|---|
| 802.15.4 | Strong. Full promiscuous capture with RSSI, LQI and channel. |
| Wi-Fi | Good, but **2.4 GHz only** — the chip has no 5 GHz radio. Encrypted payloads stay encrypted. |
| BLE | **Advertisements only.** It cannot follow connections; this is a scanner, not a link-layer sniffer. |

The three cannot capture simultaneously.
