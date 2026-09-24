# Wireshark: decode LE Audio broadcast announcements

## What this is

A patch for Wireshark itself, not for this repository. It is prepared here,
submitted upstream by the user, and reaches their Wireshark in the next major
release. This repository gains only this spec and a short documentation note
(below).

It makes Wireshark show what an Auracast-style broadcast announces: which
broadcast, what codec, how many streams, which channel each stream carries,
and what the broadcast is about. Today all of that arrives in the capture and
none of it is shown.

## What was measured, 2026-09-19

The measurement used a throwaway build of Zephyr's `bap_broadcast_source` sample
on the XIAO nRF54L15. It broadcast one subgroup of two LC3 streams, 16 kHz, with
Broadcast ID 0x123456. The ESP32-C6 captured it with `--ble-periodic` for 30 s,
into a capture kept outside the repository. The C6 synced in the first second and took
482 periodic reports at the 60 ms interval, which is essentially all of them. So
the capture side is complete, and the gap is in Wireshark alone.

Wireshark 4.6.8 renders the two halves of the broadcast differently:

- **The extended advertisement** is split into its AD structures. The service
  UUID is named "Broadcast Audio Announcement" and the Broadcast Name is shown.
  The Broadcast ID is not decoded: it appears as `Service Data: 563412`.
- **The periodic advertising report**, which carries the BASE, is not split at
  all. The whole payload is one field, `Data: 33165118409c0001…`.

Decoded by hand, that payload is a Service Data AD structure for UUID 0x1851
(Basic Audio Announcement) holding:

| Field | Bytes | Value |
|---|---|---|
| Presentation delay | `40 9c 00` | 40 000 µs |
| Subgroups | `01` | 1 |
| BIS in subgroup | `02` | 2 |
| Codec ID | `06 0000 0000` | LC3 |
| Codec config (16 B) | `02 01 03` | sampling frequency 16 kHz |
| | `02 02 01` | frame duration 10 ms |
| | `05 03 03000000` | channel allocation front left + front right |
| | `03 04 2800` | 40 octets per codec frame |
| Metadata (4 B) | `03 02 0100` | streaming audio contexts: unspecified |
| BIS 1 config | `05 03 01000000` | front left |
| BIS 2 config | `05 03 02000000` | front right |

Upstream `master` was checked on the same date and is no different. The
periodic report case (`packet-bthci_evt.c`, subevents 0x0F and 0x25) ends in
`proto_tree_add_item(tree, hf_bthci_evt_data, …)`. Nothing in the tree decodes
LC3 configuration, audio locations or audio contexts: not the HCI dissectors,
not ATT's PACS/ASCS/BASS handling. A newer Wireshark will not help.

## What upstream already provides, and what this reuses

- `btcommon.eir_ad.ad` parses AD structures when given a
  `bluetooth_eir_ad_data_t`. It asserts on that pointer, so it cannot be
  called without one.
- Service data is dispatched by UUID string on the dissector table
  `btcommon.eir_ad.entry.uuid`. `packet-bluetooth.c` already hangs small
  per-service protocols there: `btad_gaen` on `fd6f`, `btad_matter` on `fff6`.
  This patch follows that pattern exactly.
- `bthci_evt_codec_id_vals` (exported in `packet-bthci_evt.h`, includes
  `0x06 LC3`) and `bluetooth_company_id_vals_ext` (exported in
  `packet-bluetooth.h`) are reused, not duplicated.

## The patch

Three commits in one merge request, each building and passing tests on its
own.

### 1. `Bluetooth HCI Event: dissect periodic advertising data`

In `packet-bthci_evt.c`, cases 0x0F and 0x25: the data of a periodic report
is advertising data, and it goes to `btcommon_ad_handle` with a
`bluetooth_eir_ad_data_t` built the way the extended advertising report case
builds one (interface and adapter ids, `bd_addr = NULL`, because a periodic
report carries a sync handle and no address).

**A large train arrives in pieces, and the pieces are reassembled.** A
controller delivers periodic data longer than one report as a chain: reports
with Data Status 0x01 (incomplete, more to come), ended by one with 0x00
(complete) or 0x02 (truncated). The last piece of a chain says Complete too,
while holding only the tail. The first version of this commit decoded any
Complete report as a whole, which was measured wrong on 2026-09-24. A test
advertiser sent 1,008 bytes of periodic data, which arrived in 9 reports per
chain. All 279 chain tails were flagged as malformed packets, where Wireshark
4.6.8, leaving them as bytes, flagged none. The same run showed the chains
themselves are sound: every complete chain matched the sent bytes exactly, and
3 of 282 ended truncated.

So the reports are reassembled with Wireshark's reassembly support
(`fragment_add_seq_next`), keyed by the sync handle combined with the interface
and adapter ids:

- **0x01:** the piece is added to the chain. The report shows its bytes as a
  fragment, with a link to the frame that completes it.
- **0x00 after earlier pieces:** the last piece. The frame shows the reassembled
  data, decoded once as a whole, and lists the frames it came from.
- **0x00 with no earlier pieces:** decoded directly, as a single report.
- **0x02:** the controller has abandoned the chain. The pieces gathered so far
  are discarded, the report's bytes stay raw, and expert info
  `bthci_evt.periodic_data_truncated` (protocol, warning) says the data is
  incomplete. No malformed packet is reported.
- **Data length 0** (for example Data Status 0xFF, failed to receive) adds an
  empty `hf_bthci_evt_data`, as today.

The PAwR response report case upstream hands data to the AD parser whatever
the Data Status; that is not changed here.

### 2. `BT Common: dissect the Basic Audio Announcement (BASE)`

A new protocol in `packet-bluetooth.c`, beside `btad_matter`:
`proto_btad_le_audio`, "Bluetooth LE Audio Broadcast Announcements", filter
name `bluetooth.le_audio`, just as `btad_matter` uses `bluetooth.matter`. The
Broadcast Audio Announcement and Public Broadcast Announcement dissectors in
commit 3 share its fields, because metadata and codec configuration mean the
same thing in all three. It is registered on `btcommon.eir_ad.entry.uuid` for
`1851`.

What it decodes follows the BASE definition in the Basic Audio Profile. The
value meanings come from the Assigned Numbers document's generic-audio
sections: Audio Location Definitions, Context Type, Codec_Specific_Configuration
types and Metadata types. The implementation takes every value from the
current editions of both documents, and the commit message cites the editions
and section numbers it used:

- `bluetooth.le_audio.base.presentation_delay`: 24-bit, µs.
- `bluetooth.le_audio.base.num_subgroups`, then one `bluetooth.le_audio.base.subgroup`
  subtree per subgroup:
  - `bluetooth.le_audio.base.subgroup.num_bis`;
  - codec ID: `bluetooth.le_audio.codec_id.coding_format` (reusing
    `bthci_evt_codec_id_vals`), `bluetooth.le_audio.codec_id.company_id`,
    `bluetooth.le_audio.codec_id.vendor_codec_id`;
  - `bluetooth.le_audio.codec_config.length`, then the configuration;
  - `bluetooth.le_audio.metadata.length`, then the metadata;
  - one `bluetooth.le_audio.base.bis` subtree per BIS:
    `bluetooth.le_audio.base.bis.index`, `bluetooth.le_audio.codec_config.length`, and
    that BIS's configuration.

**Codec configuration** is decoded as LTV only when the coding format is LC3
(0x06). For any other format its layout is vendor-defined, and it is shown as
`bluetooth.le_audio.codec_config.raw`. For LC3:

| Type | Field | Shown as |
|---|---|---|
| 0x01 | `.codec_config.sampling_frequency` | value string: 8000 … 384000 Hz |
| 0x02 | `.codec_config.frame_duration` | 7.5 ms, 10 ms |
| 0x03 | `.codec_config.audio_channel_allocation` | 32-bit bitmask, one field per audio location |
| 0x04 | `.codec_config.octets_per_codec_frame` | 16-bit |
| 0x05 | `.codec_config.codec_frame_blocks_per_sdu` | 8-bit |
| other | `.ltv.value` | bytes |

**Metadata** is always LTV:

| Type | Field | Shown as |
|---|---|---|
| 0x01 | `.metadata.preferred_audio_contexts` | 16-bit bitmask, one field per context type |
| 0x02 | `.metadata.streaming_audio_contexts` | same bitmask |
| 0x03 | `.metadata.program_info` | UTF-8 string |
| 0x04 | `.metadata.language` | 3-character ISO 639-3 code |
| 0x05 | `.metadata.ccid` | one 8-bit field per CCID |
| 0x06 | `.metadata.parental_rating` | as Assigned Numbers defines it |
| 0x07 | `.metadata.program_info_uri` | UTF-8 string |
| 0x08 | `.metadata.audio_active_state` | value string |
| 0x09 | `.metadata.broadcast_audio_immediate_rendering` | present, no value |
| 0x0A | `.metadata.assisted_listening_stream` | value string |
| 0x0B | `.metadata.broadcast_name` | UTF-8 string |
| 0xFE | `.metadata.extended_type` + `.ltv.value` | 16-bit type, bytes |
| 0xFF | `.metadata.vendor_company_id` + `.ltv.value` | company, bytes |
| other | `.ltv.value` | bytes |

All field names above are under `bluetooth.le_audio.`. The LTV length and type are
fields too (`.ltv.length`, `.codec_config.type`, `.metadata.type`), so a
display filter can find, say, every broadcast whose metadata carries a
language.

**Bad input never reads past the service data** and never throws:

- Expert info `bluetooth.le_audio.length_overrun` (malformed, error): a declared
  length (subgroup counts, `Codec_Specific_Configuration_Length`,
  `Metadata_Length`, or an LTV's length) runs past its container. Decoding of
  that container stops there.
- Expert info `bluetooth.le_audio.ltv.bad_length` (protocol, warning): a known type
  whose value length is not the one the specification fixes. The value is
  shown as bytes.

### 3. `BT Common: dissect Broadcast and Public Broadcast Announcements`

The same protocol, registered on two more UUIDs:

- `1852`, Broadcast Audio Announcement: `bluetooth.le_audio.broadcast_id`, 24-bit,
  hex. Any bytes after it are shown as `bluetooth.le_audio.trailing_data`.
- `1856`, Public Broadcast Announcement, as the Public Broadcast Profile
  defines it:
  `bluetooth.le_audio.pba.features`, a bitmask of `.pba.features.encrypted`,
  `.pba.features.standard_quality`, `.pba.features.high_quality` and reserved
  bits, then `bluetooth.le_audio.metadata.length` and metadata decoded by commit 2's
  code.

## Testing

### Captures

Two small pcapng files, added to `test/captures/`:

- `bt-le-audio-bap-broadcast.pcapng`: from the run above, trimmed with
  `tshark -Y` to the broadcaster's own frames: its extended advertising
  reports, the Sync Established event and about ten periodic reports. The
  frames of every other device in the room are removed. The broadcaster's
  addresses are random and belong to a throwaway build.
- `bt-le-audio-pbp-broadcast.pcapng`: captured the same way from Zephyr's
  `pbp_public_broadcast_source` sample, also a throwaway build on the XIAO.
  Its Public Broadcast Announcement carries features High Quality (0x04) on
  the first start, Program Info `PBP`, and Broadcast Name `PBP Source Demo`.
  The sample's source suggests its per-BIS sampling frequency is packed into
  two octets where the specification fixes one. If the capture confirms it,
  that is a real `ltv.bad_length` case. If not, the test for it is built by
  hand instead.
- `bt-le-periodic-chained.pcapng` (added 2026-09-24): a throwaway test
  advertiser on the XIAO sending 1,008 bytes of periodic data, which arrives
  in 9 reports per chain. The data is a device name and four manufacturer data
  structures under company ID 0xFFFF, reserved for testing, carrying a
  counting byte pattern. Trimmed to the Sync Established event and two
  complete chains, 18 reports. The address is a non-resolvable private one.

### Tests in `test/suite_dissection.py`

A new class `TestDissectBluetoothLeAudio`. Each test runs `tshark -T fields` or
`-V` and asserts exact values:

1. Periodic report data is split into AD structures: a 0x0F event has a
   `btcommon.eir_ad.entry.type == 0x16` entry with UUID 0x1851.
2. The BASE decodes to the table above: delay 40000, one subgroup, two BIS,
   LC3, 16 kHz, 10 ms, 40 octets, allocation 0x00000003, streaming contexts
   0x0001, BIS 1 at 0x00000001, BIS 2 at 0x00000002.
3. The Broadcast ID is 0x123456.
4. The Public Broadcast Announcement decodes features, Program Info `PBP`,
   and the Broadcast ID present in the fixture.
5. A periodic report with Data Status 0x01 is not decoded as advertising
   data on its own: no `btcommon.eir_ad.entry` in that frame (built with
   `text2pcap`, as the suite's existing hand-made tests do).
5a. The chained capture: both chains reassemble, each to 1,008 bytes whose
   four manufacturer data structures are 248 octets each; the 16 non-final
   pieces carry no `btcommon.eir_ad.entry` and point to their reassembly frame;
   no `_ws.malformed` and no exception anywhere in the file.
5b. A BASE split across two hand-built reports (0x01 then 0x00) decodes in
   the second frame exactly as an unsplit one does.
5c. A chain ended by Data Status 0x02 raises
   `bthci_evt.periodic_data_truncated`, with no `_ws.malformed`, and the next
   single Complete report on the same sync handle decodes on its own.
5d. Two sync handles interleaving their pieces reassemble separately, each to
   its own data.
6. A BASE whose `Codec_Specific_Configuration_Length` overruns raises
   `bluetooth.le_audio.length_overrun`, and `_ws.malformed` is absent: the
   dissector reported it and did not throw (`text2pcap`).
7. A BASE with a vendor coding format (0xFF) shows `codec_config.raw` and no
   LC3 fields (`text2pcap`).

Each commit brings the tests and captures for what it adds, so every commit
passes on its own:

- **Commit 1:** tests 1, 5 and 5a-5d, plus the BAP and chained captures.
  (5b builds its BASE by hand and asserts only that the service data entry
  for UUID 0x1851 appears in the completing frame, since the BASE dissector
  arrives in commit 2; commit 2 extends it to the decoded fields.)
- **Commit 2:** tests 2, 6 and 7.
- **Commit 3:** tests 3 and 4, plus the PBP capture.

### Upstream's own checks

These are run on the changed files before handing over:

- `tools/checkAPIs.pl`, `tools/checkhf.pl`, `tools/checkfiltername.pl`;
- `tools/check_typed_item_calls.py`, `tools/check_spelling.py`;
- `tools/fuzz-test.sh -p 200` over every LE Audio capture (`-P` is the plugin count, not the passes);
- the full `test/suite_dissection.py`, not only the new class.

## Build environment

Built in the WSL Ubuntu 26.04 already on this machine, not on Windows. It needs
only `tshark` and the test programs (the Qt GUIs off), and the Linux build needs
none of Wireshark's Windows toolchain. The clone lives in WSL's own filesystem
(`~/src/wireshark`), outside both repositories, on a branch
`le-audio-broadcast` off `master`.

Dependencies come from `tools/debian-setup.sh --install-test-deps`. It uses
`sudo`. If `sudo` asks for a password, the user runs that one command
themselves; nothing here enters passwords.

## Handing over

- The deliverable is a `git format-patch` series of the three commits plus a
  merge request description, left in the clone and copied to this session's
  scratch folder.
- Commit messages follow the repository's `.gitmessage` template.
  `CONTRIBUTING.md` on `master` asks for AI assistance to be declared with an
  `Assisted-by:` trailer, and each commit carries one naming Claude Code. The
  template is re-read at commit time in case the wording has changed.
- Opening the merge request is the user's decision and done from their GitLab
  account: it publishes the two captures and puts their name on the change.
  Nothing is posted from here.
- This repository gets one change: `docs/using-wireshark.md` says that
  periodic advertising data and the BASE show as raw bytes in Wireshark 4.6,
  that a patch is submitted upstream, and which filter fields to use once a
  release carries it. Written once the merge request exists, with its link.

## Out of scope

- **Chained extended advertising reports.** The same problem exists upstream
  for LE Extended Advertising Reports (0x0D), which every Wireshark release
  decodes piece by piece: on 2026-09-24, 4.6.8 flagged 2,381 of 2,396 pieces of
  a chained extended advertisement as errors or malformed. The fix is the
  same reassembly keyed by address and SID, and it belongs in its own merge
  request, since the bug predates this one.
- **Encrypted Advertising Data and Broadcast Code decryption.** A separate
  feature with its own key-handling design.
- **PACS/ASCS/BASS in ATT.** They would reuse this LTV code, but they concern
  connections, which this sniffer does not follow.
- **A Lua plugin for Wireshark 4.6** in the meantime. It was considered and
  declined on 2026-09-19 in favour of fixing Wireshark itself.
