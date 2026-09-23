# Wireshark: decode LE Audio unicast announcements

## What this is

A second patch for Wireshark itself, following
[the broadcast announcement patch](2026-09-19-wireshark-le-audio-broadcast-design.md).
Like that one, it is prepared here, submitted upstream by the user, and reaches
their Wireshark in a later major release. This repository gains only this spec
and, later, a documentation note.

The broadcast patch decodes what an Auracast-style broadcaster announces.
This patch decodes what an LE Audio device that accepts connections announces:
earbuds and headsets say in their advertisements whether they want a
connection, which audio contexts they can take right now, and which LE Audio
roles they play. The sniffer captures all of it, because it is advertising
data. Wireshark shows it as raw service data.

## What was checked, 2026-09-23

Wireshark `master` at 2026-09-19 (`7caf6e0b96`), and the `le-audio-broadcast`
branch built on it, register no dissector on `btcommon.eir_ad.entry.uuid` for
`184e`, `1853`, `1855` or `1858`. Service data for those UUIDs is shown as
bytes.

The Resolvable Set Identifier (AD type 0x2E) is handled in
`packet-bthci_cmd.c`, but only as one 6-byte field,
`btcommon.eir_ad.entry.rsi`. Its two halves are not split.

The payload layouts below were read from Zephyr in NCS v3.4.0: the
`tmap_peripheral`, `bap_unicast_server`, `cap_acceptor` and `hap_ha` samples,
`subsys/bluetooth/audio/shell/gmap.c`, `csip_set_member.c`, and the role
enumerations in `include/zephyr/bluetooth/audio/tmap.h` and `gmap.h`. The
implementation takes the definitions from the specifications themselves (see
"The patch"). Zephyr is the cross-check and the source of the test capture.

The Hearing Access Service (0x1854) was considered and dropped. The Hearing
Access Profile puts its UUID in a service UUID list, not in service data, so
there is no payload to decode, and Wireshark already names the UUID.

## Dependency on the broadcast patch

This patch reuses the broadcast patch's `btad_le_audio` protocol, its
metadata decoder (`dissect_le_audio_metadata`), its audio context bitmask
fields, and its `bluetooth.le_audio.length_overrun` expert info. It cannot be
submitted before that patch is merged.

- The work is on a branch `le-audio-unicast` off `le-audio-broadcast` in the
  same WSL clone (`~/src/wireshark`).
- Once the broadcast merge request is merged, the branch is rebased onto
  `master`, rebuilt and retested, and only then handed over.
- If review changes the broadcast patch's names or helpers, this patch follows
  them. Where this spec names a broadcast-patch symbol, it means whatever that
  symbol is called when it merges.

## The patch

Three commits in one merge request, each building and passing tests on its
own. Every field name below is under `bluetooth.le_audio.` unless it says
otherwise.

### 1. `BT Common: dissect ASCS and CAS announcements`

In `packet-bluetooth.c`, two new dissectors in the `btad_le_audio` protocol.

**`184e`, Audio Stream Control Service announcement** (Basic Audio Profile,
"Connectable mode" advertising data):

| Field | Bytes | Shown as |
|---|---|---|
| `ascs.announcement_type` | 1 | value string: 0x00 General, 0x01 Targeted, otherwise Reserved |
| `ascs.available_sink_contexts` | 2 | the broadcast patch's context bitmask, one field per context type |
| `ascs.available_source_contexts` | 2 | the same bitmask |
| `metadata.length` | 1 | then the metadata, decoded by the broadcast patch's code |

**`1853`, Common Audio Service announcement** (Common Audio Profile):

| Field | Bytes | Shown as |
|---|---|---|
| `cas.announcement_type` | 1 | the same value string as `ascs.announcement_type` |

Both announcement type fields share a single value string. The protocol item
names the service and the type, e.g. "ASCS, Targeted Announcement", so the
tree says something without being expanded.

The protocol was registered as "Bluetooth LE Audio Broadcast Announcements".
Now that it covers unicast announcements too, this commit renames it to
"Bluetooth LE Audio Announcements". The filter name, `bluetooth.le_audio`, does
not change.

### 2. `BT Common: dissect TMAP and GMAP roles`

In `packet-bluetooth.c`, two more dissectors in the same protocol.

**`1855`, Telephony and Media Audio Service** (TMAP): `tmap.role`, 16-bit,
little-endian, a bitmask with one field per bit:

| Bit | Field | Role |
|---|---|---|
| 0 | `tmap.role.cg` | Call Gateway |
| 1 | `tmap.role.ct` | Call Terminal |
| 2 | `tmap.role.ums` | Unicast Media Sender |
| 3 | `tmap.role.umr` | Unicast Media Receiver |
| 4 | `tmap.role.bms` | Broadcast Media Sender |
| 5 | `tmap.role.bmr` | Broadcast Media Receiver |
| 6–15 | `tmap.role.reserved` | |

**`1858`, Gaming Audio Service** (GMAP): `gmap.role`, 8-bit, a bitmask with
one field per bit:

| Bit | Field | Role |
|---|---|---|
| 0 | `gmap.role.ugg` | Unicast Game Gateway |
| 1 | `gmap.role.ugt` | Unicast Game Terminal |
| 2 | `gmap.role.bgs` | Broadcast Game Sender |
| 3 | `gmap.role.bgr` | Broadcast Game Receiver |
| 4–7 | `gmap.role.reserved` | |

The bit meanings come from the current editions of TMAP and GMAP. The commit
message cites the editions and sections used. If an edition newer than the
one Zephyr v3.4.0 follows defines more bits, the patch follows the
specification and the reserved mask shrinks to match.

### 3. `Bluetooth HCI: split the Resolvable Set Identifier`

In `packet-bthci_cmd.c`, case `0x2e`. The existing
`btcommon.eir_ad.entry.rsi` field stays as the parent, so existing filters
keep working. When the length is 6, two subfields are added beneath it:

| Field | Bytes | Shown as |
|---|---|---|
| `btcommon.eir_ad.entry.rsi.hash` | 0–2 | 24-bit, little-endian, hex |
| `btcommon.eir_ad.entry.rsi.prand` | 3–5 | 24-bit, little-endian, hex |

The Coordinated Set Identification Service requires the two most significant
bits of prand to be `0` then `1`. Zephyr's `generate_prand` forces them that
way. If they are anything else, the RSI raises expert info
`btcommon.eir_ad.entry.rsi.bad_prand` (protocol, warning). If the length is
not 6, only the parent field is shown, as today, and it raises the existing
`btcommon.eir_ad.invalid_length` (protocol, warning) rather than a new
expert info of its own.

Resolving an RSI against a Set Identity Resolving Key is out of scope (below).

### Bad input

The rules are the broadcast patch's rules:

- Nothing reads past the service data, and nothing throws.
- A payload too short for a fixed field, or a `Metadata_Length` or LTV length
  that runs past the service data, raises `bluetooth.le_audio.length_overrun`.
  Decoding stops there.
- Bytes left over after a fixed-size announcement (CAS, TMAS, GMAS) are shown
  as `bluetooth.le_audio.trailing_data`, as the Broadcast Audio Announcement
  already does.

## Testing

### Capture

One pcapng file, added to `test/captures/`:

- `bt-le-audio-tmap-peripheral.pcapng`: Zephyr's `tmap_peripheral` sample,
  a throwaway build for the XIAO nRF54L15 with `EXTRA_CONF_FILE=duo.conf`,
  which turns on CSIP set membership and so the RSI. Flashed with
  `west flash --runner openocd --verify`, because NCS v3.4.0's openocd
  script leaves the end of the image unwritten. Captured by the ESP32-C6's
  BLE interface with extended scanning for 30 s, then trimmed with `tshark -Y`
  to the sample's own advertising reports, selected by its device name
  "TMAP Peripheral", and cut to ten of them. Every other device's frames are
  removed. The sample sets `CONFIG_BT_PRIVACY`, so its address is a
  resolvable private address that rotates and identifies no board.

Its advertising data, from the sample's source, carries all of these at once:

- ASCS: Targeted, available sink contexts 0x001F and available source
  contexts 0x001F (Unspecified, Conversational, Media, Game and
  Instructional, while both an ASE sink and an ASE source are configured),
  metadata length 0.
- CAS: Targeted.
- TMAS: role 0x000A (Unicast Media Receiver and Call Terminal).
- An RSI.

The values are confirmed against the capture before the tests are written. If
the capture disagrees with the source, the capture is right and this section
is corrected.

### Tests in `test/suite_dissection.py`

Added to the broadcast patch's `TestDissectBluetoothLeAudio` class. Each test
runs `tshark -T fields` or `-V` and asserts exact values:

1. ASCS decodes from the capture: announcement type 0x01, sink contexts
   0x001F, source contexts 0x001F, metadata length 0.
2. CAS decodes from the capture: announcement type 0x01.
3. An ASCS announcement with metadata (`text2pcap`): a Streaming Audio
   Contexts entry inside it decodes through the shared metadata code.
4. A truncated ASCS announcement that stops after the sink contexts
   (`text2pcap`) raises `bluetooth.le_audio.length_overrun`, and
   `_ws.malformed` is absent.
5. An announcement type of 0x02 (`text2pcap`) shows as Reserved.
6. TMAS decodes from the capture: role 0x000A, `tmap.role.umr` and
   `tmap.role.ct` set, the others clear.
7. A GMAS role (`text2pcap`, because no Zephyr sample advertises one): 0x02,
   `gmap.role.ugt` set.
8. The RSI from the capture splits into hash and prand, and raises no
   `rsi.bad_prand`.
9. An RSI whose prand has its top bits set to `11` (`text2pcap`) raises
   `rsi.bad_prand`.

Each commit brings the tests and captures for what it adds:

- **Commit 1:** tests 1 to 5, plus the capture.
- **Commit 2:** tests 6 and 7.
- **Commit 3:** tests 8 and 9.

### Upstream's own checks

The same as the broadcast patch, run on the changed files before handing
over:

- `tools/checkAPIs.pl`, `tools/checkhf.pl`, `tools/checkfiltername.pl`;
- `tools/check_typed_item_calls.py`, `tools/check_spelling.py`;
- `tools/fuzz-test.sh` over the new capture;
- the full `test/suite_dissection.py`, not only the new tests.

## Build environment

As for the broadcast patch: the WSL Ubuntu 26.04 build in `~/src/wireshark`,
`tshark` and the test programs only, Qt off. The build dependencies are
already installed.

## Handing over

- The deliverable is a `git format-patch` series of the three commits plus a
  merge request description, left in the clone and copied to this session's
  scratch folder. The series is made only after the rebase onto a `master`
  that contains the broadcast patch.
- Commit messages follow the repository's `.gitmessage` template, and each
  carries an `Assisted-by:` trailer naming Claude Code, as `CONTRIBUTING.md`
  asks. Both are re-read at commit time.
- Opening the merge request is the user's decision, from their GitLab
  account. It publishes the capture and puts their name on the change.
  Nothing is posted from here.
- This repository gets one change once the merge request exists: a line in
  `docs/using-wireshark.md`, beside the broadcast patch's note, naming the
  new filter fields and linking the merge request.

## Out of scope

- **Hearing Access Service.** Its UUID is advertised in a service UUID list,
  which Wireshark already names; there is no service data to decode.
- **Resolving RSIs.** Matching an RSI to a set needs the Set Identity
  Resolving Key, which is exchanged over an encrypted connection this sniffer
  cannot see. Like Broadcast Code decryption, it would need its own
  key-handling design.
- **GMAP features and TMAP/GMAP characteristics over ATT.** They concern
  connections, which this sniffer does not follow.
- **Other undecoded AD types:** Advertising Interval - long (0x2F), Encrypted
  Advertising Data (0x31) and Electronic Shelf Label (0x34). They are
  unrelated to LE Audio and are left for a separate patch.
