# Following a BLE device through address changes

## What this is

Phones, Macs and most modern BLE devices advertise under a resolvable private
address that changes every few minutes. "Only these devices" filters on an
address, so the filter loses such a device at its first rotation. This design
lets the user give the capture each device's identity resolving key (IRK). The
board's own controller then recognises the device under any address it rotates
to, reports it under its fixed identity address, and filters on that identity
in hardware, so the rest of the room still never crosses the USB link.

Everything the user does happens in Wireshark: choosing the key file, filtering,
and checking that a key is right. The only step outside it is copying the key
out of the Mac it lives on.

It touches both firmwares, the host package, the extcap, and `shared/`.

## What was measured, 2026-09-24

A throwaway spike, run on both boards and kept outside both repositories.

**Both controllers resolve and filter by identity while scanning passively.**
One board ran a raw-HCI advertiser rotating three private addresses made from
a test IRK every 15 s. The other ran a throwaway sniffer build that loaded that
IRK into the controller's resolving list, turned address resolution on, and put
the advertiser's made-up random static identity address in the accept list.

| Scanner | Advertiser | Unfiltered | Filtered on the identity, 50 s |
|---|---|---|---|
| ESP32-C6 | XIAO nRF54L15 | 190 reports, all under the identity | 466 reports, 0.1 to 49.9 s; 0 from anyone else |
| XIAO nRF54L15 | ESP32-C6 | 96 reports, all under the identity | 224 reports, 0.2 to 49.9 s; 0 from anyone else |

In the unfiltered runs no report arrived under a private address. The
controller replaced every one with the identity.

**The IRK goes to the controller least significant byte first**, as HCI
carries every multi-byte value. That order was tested on both controllers.

**Bluedroid will not advertise a manually set private address** ("invalid
random address"), so the C6-side advertiser used raw VHCI. This concerns only
the throwaway transmitter; the sniffers do not advertise.

**Capacity, from the build configurations.**

| | ESP32-C6 | nRF54L15 |
|---|---|---|
| Resolving list | 4 by default; Kconfig allows 1 to 5 | 8 (`CONFIG_BT_CTLR_RL_SIZE`) |
| Accept list | 12 in the controller; the firmware keeps 8 | 8 (`CONFIG_BT_CTLR_FAL_SIZE`) |

**A defect in the shipped filter, found while designing this.** The extcap
passes typed addresses as bare strings, and `encode_ble_filter()` sends a bare
string as a *public* address. The accept list matches on address type as well
as address. On the C6, with the room's busiest random-address advertiser (a
neighbouring device with a random static address), 20 s each:

- typed into "Only these devices" (sent as public): 0 reports;
- sent explicitly as random: 10 reports.

So today the filter cannot follow any device whose address is random, which is
most phones and anything using privacy. This design fixes it.

## Decisions made with the user

- **Wire format:** a new frame type, not a change to an existing one. The
  earlier rule was "do not change the wire format"; adding a type number
  changes nothing that exists.
- **What a key file does:** keyed devices appear under their identity address
  throughout the capture, filtered or not. "Only these devices" still chooses
  what to follow.
- **Where the user works:** entirely in Wireshark. There is no separate
  command-line tool.

## Wire format

A new frame type in `shared/frame.h`, mirrored in `framing.py`:

```c
/* Host to board: identity resolving keys, so the controller reports and
 * filters a device that changes its address under its fixed identity
 * address instead. Payload is N x 23 bytes -- identity address type
 * (0 public, 1 random), the identity address, the 16-byte key, both least
 * significant byte first as HCI carries them. An empty payload clears the
 * keys. Kept in RAM only and never logged. */
SN_FRAME_BLE_KEYS = 15,
```

N is at most 8. A board refuses more than its resolving list holds (see
Firmware). The frame gets a golden vector in `host/tests/vectors/golden.json`
like every other.

## Firmware, both boards

**Receiving.** `control.c` on each board dispatches `SN_FRAME_BLE_KEYS` to a
new `sn_radio_ble_set_keys()`, beside the existing filter handler. The keys are
copied into a static array. The key bytes are never logged; the count is:
"device keys: 2".

**Applying.** `apply_filter()` already runs on every scan start, and loads the
accept list. It gains a step before that, in this order:

1. LE Set Address Resolution Enable (0x202D), off. The resolving list cannot be
   changed while resolution is on.
2. LE Clear Resolving List (0x2029).
3. For each key, LE Add Device To Resolving List (0x2027): identity type,
   identity address, the key as the peer IRK, and sixteen zero bytes as the
   local IRK, since the sniffer has no identity of its own.
4. For each key, LE Set Privacy Mode (0x204E), device privacy mode. In the
   default network privacy mode, the controller drops advertisements from a
   device in the resolving list that uses its identity address instead of a
   private one. A sniffer should hear those too.
5. LE Set Address Resolution Enable, on, if there is at least one key.

Steps 1 to 3 and 5 are what the spike ran on both controllers. Step 4 is new.
The Zephyr controller implements it (`BT_HCI_OP_LE_SET_PRIVACY_MODE` in
`hci.c`). The C6's controller is closed source, so step 4 is verified on air
there, including that an identity-address advertisement is heard with it and
dropped without it. A controller refusing any of these commands fails the scan
start, which the host already reports as a failed START. Nothing is skipped
silently.

**Lifetime.** Like the filter, the keys are forgotten when the capture stops.
A capture that sends no keys therefore never inherits the last one's.

**Capacity.** The C6's `CONFIG_BT_LE_LL_RESOLV_LIST_SIZE` goes from 4 to 5,
its Kconfig maximum. The nRF stays at 8. Each firmware refuses a frame with
more entries than that, and logs the refusal. The host enforces the same limit
first, from the board table, so the user is told in Wireshark before anything
is sent.

**Versions.** The C6 firmware goes to 7 and the nRF firmware to 4. Both
firmwares silently ignore a frame type they do not know. Without a version
check, a key file sent to older firmware would give a capture that looks normal
but never resolves, and a filtered one would be empty.

## Host package

**`ble_keys.py`** (new):

- `parse_key_file(path)` returns a list of `DeviceKey(line, address_type,
  address, irk)`, with `irk` held most significant byte first. Format:

  ```
  # identity address   [public|random]   key
  11:22:33:44:55:66                      ec0234a357c8ad05341010a60a397d9b
  de:ad:be:ef:00:01    random            YWJjZGVmZ2hpamtsbW5vcA==
  ```

  - Blank lines and `#` comments are allowed.
  - The type is optional and defaults to public: phones and Apple devices use
    their public address as their identity.
  - A key is either 32 hex digits, read most significant byte first as the
    Core specification and BlueZ write it, or 24 characters of base64 as
    macOS Keychain shows it. The order of the base64 form is settled by
    measurement (see Byte order).
  - Errors name the line and never contain the key text. Rejected cases: a
    malformed address, an unknown type word, a key of the wrong length, an
    all-zero key (HCI's "no key"), a repeated identity, and more entries than
    8.
- `aes128_encrypt(key, block)`: one-block AES-128 encryption in pure Python.
  The standard library has no AES. A compiled dependency for one function would
  add an install step on every platform, including the free-threaded 3.14t CI
  job. This code runs a few hundred times per capture at most.
- `ah(irk, prand)` and `resolves(irk, address)`: the Core specification's
  random address hash, and whether a resolvable private address belongs to a
  key.

**`control.py`:** `encode_ble_keys(keys)` beside `encode_ble_filter()`.

**The filter fix**, in the code that turns typed addresses into accept-list
entries:

- A typed address that matches an identity in the key file takes that
  identity's type: one slot.
- Any other typed address is entered twice, as public and as random: two
  slots. The type cannot be read from the address, because a public address
  may have any leading bits.
- More entries than the board's accept list holds (8 on both) is refused
  with a message saying how many fit.
- This part needs no new firmware: the filter frame has always carried a
  type.

The type in the key file matters in exactly one case. A device that sometimes
advertises under its identity address directly is matched on the type it
actually uses on air. For a device that only ever uses private addresses, a
wrong type changes nothing but the label Wireshark shows, because the
resolving list and the filter both take it from the same line.

**`boards.py`:** each board gains `ble_keys` (its resolving list size: 5 and 8)
and `ble_keys_firmware` (the first firmware version that understands the frame:
7 and 4).

**`CaptureSession`:**

- A `ble_keys=` parameter. When given, the keys frame is written just before
  the filter frame. If the board's firmware version, from GET_INFO, is older
  than `ble_keys_firmware`, opening raises with the version needed.
- `request_key_check()`, applied between reads like `request_channel()`. It
  sends STOP, empty keys and an empty filter, then START. After 20 s it sends
  STOP, the real keys and filter, and START again. Records arriving between
  the two START replies are handed to the checker rather than returned to the
  caller. The board answers a command only after acting on it, and the stream
  is ordered, so those replies are clean boundaries.

**`adv.py`:** the report parser names address types 2 and 3 "public identity"
and "random identity". The survey tools use it.

## Wireshark

**Device keys option.** A file picker on every BLE interface of a board with
`ble_filter`, next to "Only these devices". Its tooltip says:

- the file holds secrets: anyone with it can follow those devices;
- the keys go to the board's RAM for the length of the capture, and never
  into the capture file (pcapng has no Bluetooth key type);
- the format, and where to get a key.

A file that fails to parse stops the capture before it starts, with the
parser's message. So does older firmware, naming the version needed.

**The filter tooltip** is rewritten: four plain addresses, or as many
identities from the key file as the board holds keys (five on the ESP32-C6,
eight on the nRF54L15).

**Check keys button.** A new toolbar control, `CTRL_ARG_CHECK_KEYS = 3`,
`type=button`, placed after Log on the toolbar that already carries Channel,
Antenna and Log. Pressing it calls `request_key_check()`. Wireshark declares
the toolbar once for every interface this extcap offers. So on a capture that
is not BLE, or has no key file, pressing it only logs why nothing happened.

When the 20 s are up, each key line gets one result. It is written to the log
and shown in a pop-up (`CTRL_CMD_INFORMATION`):

- **correct:** N private addresses resolved with the key as written;
- **backwards:** N resolved only with its bytes reversed, so the file's key is
  in the wrong order;
- **nothing matched:** the device was not nearby or not advertising, or the
  key is wrong.

Periodic trains being followed may drop while scanning is stopped. Whether
they do, and how long they take to come back, is measured in implementation
and stated in the log message and the README.

**Automatic backwards-key check.** A keyed device whose key is right arrives
already resolved. So in any capture with keys, each distinct private address
that still arrives unresolved is tested against every key with its bytes
reversed. Seen addresses are cached, so each costs a handful of AES
operations once. A match raises a pop-up, a log line, and a packet comment on
the report, filterable later with `pkt_comment`. The message names the line:
"key on line 2 of keys.txt is byte-reversed, so this device is not being
followed". It is raised once per line per capture. A match with the key *as
written*, which should be impossible, is logged as a board fault.

**The silent case.** If a filtered capture includes a keyed identity and hears
nothing from it for 30 s, the log says so once and suggests Check keys.

## Byte order

- In hex, a key is most significant byte first. The host reverses it for HCI.
- For Keychain's base64 the order is not documented by Apple, and write-ups
  disagree, so it is measured. The user extracts a key on their Mac, loads the
  file, and presses Check keys with that device nearby. "Correct" or
  "backwards" fixes the conversion in `parse_key_file` and the docs for good.
  Until that result exists, base64 keys are not presented as supported.
- Keychain asks for the Mac login password at *Show password*. The user types
  it; Claude never does. The user may run the check themselves and report
  only the one-line result.

## Documentation

- **README in both repositories:** a section on following a device that
  changes its address. It covers the key file format, the Check keys button,
  and getting a key from a Mac: Keychain Access, Local Items, search
  "Bluetooth", open the device's entry, *Show password*, "Remote IRK". It also
  covers finding the identity address; on an iPhone that is Settings, General,
  About, Bluetooth. Only the Mac route is described as tested. Other sources
  are mentioned only as "a 32-digit hex key".
- **A security note:** what a key allows, where it goes, where it does not.
- **`shared/`:** frame 15 is documented with the other frames.
- The private-data guard test keeps real keys out of both repositories. Test
  data uses only the Core specification's sample key,
  `ec0234a357c8ad05341010a60a397d9b`.

## Testing

**Host, written test first:**

- AES-128 against the FIPS-197 appendix C.1 vector.
- `ah()` against the Core specification sample: that key with prand `0x708194`
  gives hash `0x0dfbaa`.
- The parser: hex, base64, the default type, comments, and each rejected case.
  Every error message is checked not to contain the key text.
- `encode_ble_keys()` against a new golden vector, including the empty clear
  frame.
- The filter fix: a keyed identity takes one slot, a plain address two, and a
  list that does not fit is refused per board. Existing `test_ble_filter.py`
  cases that assumed bare strings meant public are updated.
- The firmware-version refusal.
- Backwards-key detection on synthetic reports built from the sample key:
  pop-up, log line and packet comment each appear once.
- The Check keys flow through a fake serial port and the control pipe, as
  Wireshark drives it. This covers the command sequence, excluding the
  checked records from the capture, and each of the three results.

**On the boards, both directions**, reusing the spike's throwaway advertisers
(outside both repositories), through the extcap with a key file:

- unfiltered, the advertiser appears only under its identity;
- filtered on the identity, it is followed through rotations and nothing else
  arrives;
- the advertiser switched to its identity address is heard with device
  privacy mode (step 4). On the C6 this is also where step 4 is shown to be
  supported;
- a reversed key raises the backwards warning;
- Check keys gives correct, backwards and nothing-matched in the matching
  setups;
- 5 keys load on the C6 and 8 on the nRF, and one more is refused;
- tshark shows the identity address type decoded.

Board time is agreed with the other session first, as for the spike.

**With the user, once each:** the Keychain byte-order measurement, and pressing
Check keys in the Wireshark window, which a script cannot do in the real
application.

## Out of scope

- Resolving on the host and rewriting packets. The controller does it, and the
  capture shows what the controller reported.
- Recording keys in the capture file.
- Tested extraction steps for Windows, Linux, Android or iOS.
- Following a keyed device's connections or periodic trains by identity.
