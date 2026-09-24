# Wireshark: reassemble chained extended advertising reports

## What this is

A third patch for Wireshark itself, separate from the LE Audio series and
based on `master`, because the bug it fixes predates that series and affects
every capture of a large BLE 5 advertisement, whatever captured it.

## What was measured, 2026-09-24

A throwaway advertiser on the XIAO nRF54L15 sent 1,008 bytes of extended
advertising data: a device name and four manufacturer data structures under
the test company ID 0xFFFF, carrying a counting byte pattern. The ESP32-C6
captured it for 30 s. The controller delivered each advertisement as a chain of
LE Extended Advertising Reports: pieces with Data Status 0x01 (incomplete, more
to come), ended by 0x00 (complete) or 0x02 (truncated). Reading the capture's
bytes directly: 274 chains, 259 complete and every one of them matching the
sent bytes exactly, 15 truncated.

Wireshark 4.6.8, and `master` on the same date, decode every report's data as
if it were a whole advertisement (`packet-bthci_evt.c`, subevent 0x0D, which
hands `length` bytes to `btcommon_ad_handle` whatever the Data Status). A piece
ends mid-structure, so 2,381 of the advertiser's 2,396 reports were flagged
as errors or malformed packets. The data is intact; the decoding is not.

## The patch

One commit, `Bluetooth HCI Event: reassemble chained extended advertising
reports`, in `packet-bthci_evt.c`, case 0x0D.

**The key.** An extended advertisement is identified by its advertiser, not a
handle: interface id, adapter id, the address type and address, the
Advertising SID, and whether the report is a scan response (event type bit 3),
since a scan response's chain runs separately from the advertisement's. That
key is wider than the 32-bit id `fragment_add_seq_next` takes, so this follows
the pattern `packet-btle.c` uses for the same problem (`adi_to_first_frame_tree`):
on the first pass, a `wmem_map` in file scope maps the full key to the number
of the frame holding the chain's first piece, and that number is the
reassembly id, with `addresses_reassembly_table_functions`. The map entry is
removed when the chain ends.

**Per report**, inside the existing `num_reports` loop:

- **Legacy PDU** (event type bit 4): never chained. Decoded directly, as today.
- **Data Status 0x01:** added as a piece. Its bytes are shown as
  `bthci_evt.data`, and not decoded as advertising data.
- **Data Status 0x00:** ends the chain. After earlier pieces, the reassembled
  data is decoded once, in the frame that completes it, with the fragment tree
  listing the frames it came from; with none, the report is decoded directly,
  exactly as today, so a single-report advertisement looks unchanged.
- **Data Status 0x02:** the controller abandoned the chain. The pieces are
  discarded and the map entry removed; the report's bytes are shown as
  `bthci_evt.data` with expert info
  `bthci_evt.expert.ext_adv_data_truncated` (protocol, warning); no
  malformed packet.
- **A report declaring more data than the event carries:** the chain is
  discarded first, then the data item reports the overrun as today.
- `save_remote_device_name` is given the data it decodes: the reassembled
  data for a completed chain, nothing for a piece.

Fields: `bthci_evt.ext_adv_data.fragments`, `.fragment`, the standard
overlap/tail/error/count fields, `.reassembled.in`, `.reassembled.length`,
registered and named as the periodic patch names its own.

**Two passes.** Table changes happen on the first pass only; later passes use
the reassembled table, as in the periodic patch.

## Testing

`test/suite_dissection.py`, a new class `TestDissectBluetoothExtAdvReassembly`:

1. **Real chains:** a fixture cut from the 2026-09-24 capture,
   `bt-le-ext-adv-chained.pcapng`: two complete 9-report chains from the test
   advertiser (a non-resolvable private address) and the frames between them
   from other devices removed. Both reassemble to 1,008 bytes whose AD entries
   are the name and four 249-length manufacturer structures; no piece decodes
   as advertising data; no malformed packet or exception anywhere; the same
   on a second pass.
2. **Interleaved advertisers:** two addresses' pieces alternating reassemble
   separately (`text2pcap`).
3. **Same address, two SIDs:** kept apart.
4. **Scan response chain beside an advertising chain** from one advertiser:
   kept apart.
5. **Truncated chain:** warning, raw bytes, no malformed packet; the next
   complete report from that advertiser decodes on its own.
6. **Two reports in one event**, one a piece of a chain and one a legacy
   advertisement: the legacy one decodes, the piece does not.
7. **Legacy PDU with Data Status bits set** (which a legacy PDU should never
   have): decoded directly, never chained.
8. **Single complete report:** decodes exactly as before, with no fragment
   fields (guards today's behaviour for the common case).

Upstream checks as for the LE Audio series: `check_apis.py`, `checkhf.pl`,
`checkfiltername.pl`, `check_typed_item_calls.py`, `check_spelling.py`,
`fuzz-test.sh -p 200` over the new capture and the existing Bluetooth
captures, and the full `suite_dissection.py`.

## Handing over

A `git format-patch` series of the one commit plus a merge request description,
left in the clone (branch `ext-adv-reassembly` off `master`) and copied to the
session scratchpad. Opening the merge request is the user's decision. It is
independent of the LE Audio series; both touch `packet-bthci_evt.c` in
different cases, so whichever merges second may need a trivial rebase.

This repository gets one change once the merge request exists: the sentence
in `docs/using-wireshark.md` saying extended chains are "not yet covered"
points at it.

## Out of scope

- **Periodic advertising reports:** covered by the LE Audio series' commit 1.
- **Link-layer captures** (`btle`, from a link-layer sniffer): `packet-btle.c`
  already reassembles AUX_CHAIN_IND itself.
- **Extended advertising reports carrying the older advertising report
  subevent (0x02):** that event cannot chain.
