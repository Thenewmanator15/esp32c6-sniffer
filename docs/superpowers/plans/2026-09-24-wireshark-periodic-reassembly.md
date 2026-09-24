# Wireshark Periodic Advertising Reassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix commit 1 of the unsubmitted `le-audio-broadcast` Wireshark series so that periodic advertising data arriving as a chain of reports is reassembled, not decoded piece by piece into false malformed packets. Then carry commits 2-3 and the `le-audio-unicast` series over to the fixed commit.

**Architecture:** In `packet-bthci_evt.c`, periodic advertising reports (subevents 0x0F and 0x25) feed their data to Wireshark's reassembly support (`fragment_add_seq_next`), keyed by sync handle, interface and adapter. The reassembled data goes to the existing AD dissector. A truncated chain is discarded with an expert warning, and so is a chain whose sync is lost. The work is done by amending commit 1 in place on a branch cut from it, then replaying commits 2-3 and the unicast series on top.

**Tech Stack:** C (Wireshark dissector and reassembly APIs, `master` at `7caf6e0b96`), CMake + Ninja, pytest (`test/suite_dissection.py`), `text2pcap`/`editcap`, WSL Ubuntu 26.04.

**Spec:** `docs/superpowers/specs/2026-09-19-wireshark-le-audio-broadcast-design.md`. Section "1." and the Testing and Out of scope sections were updated on 2026-09-24.

## Global Constraints

- **Work happens in WSL**, clone `~/src/wireshark`, build directory `~/src/wsbuild`. Nothing is pushed or posted. The deliverable is two regenerated patch series on disk.
- **Branches.** `le-audio-broadcast` (commits `6da62ec4d4` → `16d00e07c6` → `19c7d2fd55` today) and `le-audio-unicast` (3 commits on top) are rewritten. Before touching them, tag the current tips: `le-audio-broadcast-before-reassembly`, `le-audio-unicast-before-reassembly`.
- **Commit 1 keeps its subject**, `Bluetooth HCI Event: dissect periodic advertising data`. Its body is rewritten (Task 2, Step 8).
- **Names.**
  - Expert info: `bthci_evt.expert.periodic_data_truncated` (PI_PROTOCOL, PI_WARN), matching the file's `bthci_evt.expert.*` style.
  - Fields: `bthci_evt.periodic_data.fragments`, `.fragment`, `.fragment.overlap`, `.fragment.overlap.conflicts`, `.fragment.multiple_tails`, `.fragment.too_long_fragment`, `.fragment.error`, `.fragment.count`, `.reassembled.in`, `.reassembled.length`.
  - C symbols: `periodic_adv_reassembly_table`, `periodic_adv_frag_items`, `periodic_adv_reassembly_id()`, `periodic_adv_discard()`, `dissect_periodic_adv_data()`.
- **Reassembly key.** `((interface_id & 0xFF) << 24) | ((adapter_id & 0xFF) << 16) | (sync_handle & 0xFFFF)`, used with `addresses_reassembly_table_functions`.
- **Data Status handling** (spec, section 1):
  - 0x01 adds a piece.
  - 0x00 ends a chain. With no earlier pieces it is a single report, decoded directly.
  - 0x02 discards the chain, shows its bytes raw and raises the warning.
  - Anything else (0xFF) shows the bytes raw, as today.
  - Sync Lost (0x10) discards the handle's pending pieces.
  - Table changes happen on the first pass only (`!PINFO_FD_VISITED(pinfo)`).
- **Existing tests stay unchanged.** In particular, `test_incomplete_periodic_report_stays_raw`, `test_periodic_report_without_data_keeps_its_data_field` and `test_periodic_report_data_is_dissected` keep passing as they are.
- **Test fixture:** `test/captures/bt-le-periodic-chained.pcapng`, mode 100644, exactly 19 frames: frame 1 the Sync Established event, frames 2-10 one chain and frames 11-19 another (9 reports each, the last in each with Data Status 0x00).
- **Commit trailers** stay as the existing commits have them (`Assisted-by:` and `Co-Authored-By:`), with the model named as in the existing commit.
- **The scratchpad is written `$SW` below:** `/mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad` in WSL, `$S` in Git Bash. `wsl.exe -- bash -lc '...'` expands `$VARS` in the outer shell, so multi-line WSL work goes in a script file under `$S`, run with `MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash <file>`.
- **The source capture** is `bigadv1.pcapng` in the scratchpad, taken on 2026-09-24 from the throwaway `app_bigadv` advertiser: 2524 periodic reports, 282 chains, 279 complete and each matching the sent 1,008 bytes.

## Review Focus

- **The sync is lost mid-chain.** Pieces from before a Sync Lost event must not be glued to the next chain on the same handle. Pinned by Task 2 (`test_sync_lost_mid_chain_discards_the_pieces`).
- **A chain ends with an empty Complete report.** The controller may close a chain with a 0-byte tail, and the chain must still reassemble. Pinned by Task 2 (`test_empty_complete_report_ends_a_chain`).
- **The file is dissected twice.** The GUI and `tshark -2` dissect again after the first pass, and must show the same reassembly without re-adding pieces. Pinned by Task 2 (`test_chained_reports_survive_a_second_pass`).
- **Version 2 reports (0x25) are chained.** They share the code path but have a different layout. Pinned by Task 2 (`test_v2_reports_are_reassembled`).
- **A truncated report with no earlier pieces.** Just the warning and raw bytes, with no malformed packet. Pinned by Task 2 (`test_truncated_report_on_its_own`).

---

### Task 1: The chained-report fixture

**Files:**
- Create: `~/src/wireshark/test/captures/bt-le-periodic-chained.pcapng` (committed in Task 2)
- Create (throwaway): `$S/chain_frames.py`

**Interfaces:**
- Consumes: `$S/bigadv1.pcapng`.
- Produces: the 19-frame fixture described in Global Constraints.

- [ ] **Step 1: Find the first two complete chains after the sync**

Write `$S/chain_frames.py`:

```python
"""Throwaway: frame numbers of the Sync Established event and the first two
complete chains of periodic reports after it, in bigadv1.pcapng."""
import subprocess
import sys

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
rows = subprocess.check_output(
    [TSHARK, "-r", sys.argv[1], "-Y",
     "bthci_evt.le_meta_subevent in {0x0e, 0x0f}",
     "-T", "fields", "-e", "frame.number", "-e", "bthci_evt.le_meta_subevent",
     "-e", "bthci_evt.data_status"],
    encoding="utf-8", stderr=subprocess.DEVNULL).split("\n")
sync = None
chains, current = [], []
for row in filter(None, rows):
    number, sub, status = (row.split("\t") + ["", ""])[:3]
    if sub == "0x0e":
        sync = number
        continue
    current.append((number, status))
    if status != "0x01":
        if status == "0x00" and len(current) == 9:
            chains.append([n for n, _ in current])
        current = []
    if len(chains) == 2:
        break
print(sync, " ".join(chains[0]), " ".join(chains[1]))
```

Run:

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && cd $S && python chain_frames.py bigadv1.pcapng
```

Expected: one Sync Established frame number, then 18 frame numbers. If the first chain after the sync is not a complete 9-report chain, the script skips it. That is intended, because the fixture must hold two whole chains.

- [ ] **Step 2: Cut the fixture**

With the 19 numbers from Step 1 as `N1 ... N19`:

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && cd $S && "/c/Program Files/Wireshark/editcap.exe" -r bigadv1.pcapng bt-le-periodic-chained.pcapng N1 N2 N3 N4 N5 N6 N7 N8 N9 N10 N11 N12 N13 N14 N15 N16 N17 N18 N19 && "/c/Program Files/Wireshark/tshark.exe" -r bt-le-periodic-chained.pcapng -T fields -e frame.number -e bthci_evt.le_meta_subevent -e bthci_evt.data_status -e bthci_evt.data_length -e bthci_evt.bd_addr 2>/dev/null
```

Expected: 19 rows. Row 1 is `0x0e`. Rows 2-9 and 11-18 are `0x0f 0x01`, and rows 10 and 19 are `0x0f 0x00`. The data lengths add up to 1008 within each chain.

- [ ] **Step 3: Check nothing identifying is in it, and put it in the clone**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && cd $S && "/c/Program Files/Wireshark/capinfos.exe" bt-le-periodic-chained.pcapng | grep -i -E "hardware|application|os|comment|interface|Name|Descr" ; "/c/Program Files/Wireshark/tshark.exe" -r bt-le-periodic-chained.pcapng -Y 'frame.comment' 2>/dev/null | wc -l; MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash -c 'cp /mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad/bt-le-periodic-chained.pcapng ~/src/wireshark/test/captures/ && chmod 644 ~/src/wireshark/test/captures/bt-le-periodic-chained.pcapng && stat -c "%A %s" ~/src/wireshark/test/captures/bt-le-periodic-chained.pcapng'
```

Expected:
- Only the board model, `esp32c6-sniffer extcap` and `esp32c6-ble@COM3` as metadata, and 0 comments.
- `-rw-r--r--` and a size of a few kilobytes.
- In Step 2's output, frame 1's address (Sync Established carries the advertiser's) is a non-resolvable private address: the top two bits of its first octet are `00`, so that octet is between 0x00 and 0x3F.

---

### Task 2: Reassemble chained periodic reports (amend commit 1)

**Files:**
- Modify: `~/src/wireshark/epan/dissectors/packet-bthci_evt.c` (includes near line 25-39; LE Meta cases 0x0F/0x25 near line 3645 and 0x10 near line 3693; registration near line 8218, `ei[]` near 12035, `ett[]` near 12049)
- Modify: `~/src/wireshark/test/suite_dissection.py` (class `TestDissectBluetoothLeAudio`, appended at the end of commit 1's version of the file)
- Add: `~/src/wireshark/test/captures/bt-le-periodic-chained.pcapng`

**Interfaces:**
- Consumes: Task 1's fixture. The commit 1 test helpers `_hci_frame(cmd_text2pcap, result_file, base_env, name, hex_bytes) -> path` and `_frames(cmd_tshark, test_env, capture, display_filter) -> list[str]`.
- Produces: branch `periodic-reassembly` whose single new commit replaces commit 1. Test helpers `_hci_frames(cmd_text2pcap, result_file, base_env, name, frames_hex) -> path` (several packets in one file), `_periodic(handle, status, data_hex, v2=False) -> str` (hex of one H4 periodic report) and `_fields(cmd_tshark, test_env, capture, display_filter, field, two_pass=False) -> list[str]`, which Task 3 uses. The constant `SPLIT_BASE` (the captured BASE's 52 AD bytes) is a class attribute.

- [ ] **Step 1: Tag the tips and cut the work branch from commit 1**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git status --porcelain --untracked-files=no && git tag -f le-audio-broadcast-before-reassembly le-audio-broadcast && git tag -f le-audio-unicast-before-reassembly le-audio-unicast && git switch -c periodic-reassembly 6da62ec4d4 && git log --oneline -2 && cd ~/src/wsbuild && ninja tshark text2pcap >/dev/null 2>&1; pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -1'
```

Expected: an empty status, the branch switched to, commit 1 on top of `7caf6e0b96`, and `4 passed`. If the status is not empty, stop and report it. The untracked `le-audio-*-patches/` directories are fine.

- [ ] **Step 2: Write the failing tests**

Append to the end of `test/suite_dissection.py`, which in this checkout ends with commit 1's `test_periodic_report_without_data_keeps_its_data_field`:

```python

    # The captured BASE of Zephyr bap_broadcast_source, as one AD structure.
    SPLIT_BASE = ('33165118409c00010206000000001002010302020105030300000003042800'
                  '040302010001060503010000000206050302000000')

    @staticmethod
    def _periodic(handle, status, data_hex, v2=False):
        '''The hex of one LE Periodic Advertising Report H4 packet, v1 (0x0F) or v2 (0x25).'''
        data = bytes.fromhex(data_hex)
        head = handle.to_bytes(2, 'little') + bytes([0x7f, 0xbe, 0xff])
        if v2:
            params = bytes([0x25]) + head + bytes([0x00, 0x00, 0xff, status, len(data)]) + data
        else:
            params = bytes([0x0f]) + head + bytes([status, len(data)]) + data
        return (bytes([0x04, 0x3e, len(params)]) + params).hex()

    @staticmethod
    def _hci_frames(cmd_text2pcap, result_file, base_env, name, frames_hex):
        '''Writes several received HCI H4 packets (LINKTYPE 201) into one capture file, in order.'''
        text_file = result_file(name + '.txt')
        pcap_file = result_file(name + '.pcap')
        with open(text_file, 'w') as f:
            for hex_bytes in frames_hex:
                data = bytes.fromhex(hex_bytes)
                for offset in range(0, len(data), 16):
                    chunk = data[offset:offset + 16]
                    f.write('%08x  %s\n' % (offset, ' '.join('%02x' % b for b in chunk)))
        subprocess.check_call((cmd_text2pcap, '-l', '201', text_file, pcap_file), env=base_env)
        return pcap_file

    @staticmethod
    def _fields(cmd_tshark, test_env, capture, display_filter, field, two_pass=False):
        '''One line per matching frame: the field's values, comma-separated.'''
        args = [cmd_tshark, '-r', capture, '-Tfields', '-e', field, '-Y', display_filter]
        if two_pass:
            args.insert(1, '-2')
        stdout = subprocess.check_output(args, encoding='utf-8', env=test_env)
        return stdout.split()

    def test_chained_periodic_reports_are_reassembled(self, cmd_tshark, capture_file, test_env):
        # Two chains of nine reports carrying 1008 bytes each: a device name
        # and four manufacturer data structures of 249 octets.
        capture = capture_file('bt-le-periodic-chained.pcapng')
        assert self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.periodic_data.reassembled.length == 1008'
                ' && btcommon.eir_ad.entry.device_name == "bigadv"') == ['10', '19']
        assert self._fields(cmd_tshark, test_env, capture,
                'frame.number == 10', 'btcommon.eir_ad.entry.length') == ['7,249,249,249,249']
        assert self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.data_status == 0x01 && btcommon.eir_ad.entry') == []
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.malformed || _ws.expert.message contains "Exception occurred"') == []

    def test_chained_reports_survive_a_second_pass(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-periodic-chained.pcapng')
        assert self._fields(cmd_tshark, test_env, capture,
                'bthci_evt.periodic_data.reassembled.length', 'frame.number', two_pass=True) == ['10', '19']
        # Only a second pass can point each piece at the frame that completes it.
        assert len(self._fields(cmd_tshark, test_env, capture,
                'bthci_evt.data_status == 0x01 && bthci_evt.periodic_data.reassembled.in',
                'frame.number', two_pass=True)) == 16
        assert self._fields(cmd_tshark, test_env, capture,
                '_ws.malformed || (btcommon.eir_ad.entry.device_name && bthci_evt.data_status == 0x01)',
                'frame.number', two_pass=True) == []

    def test_base_split_across_two_reports(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        base = self.SPLIT_BASE
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-split', [
                self._periodic(0x0001, 0x01, base[:40]),
                self._periodic(0x0001, 0x00, base[40:])])
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.uuid_16 == 0x1851') == ['2']
        assert self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.periodic_data.reassembled.length == 52') == ['2']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_truncated_chain_is_discarded(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # A piece, then Data Status 0x02, then a whole name on its own.
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-truncated', [
                self._periodic(0x0001, 0x01, '07096269'),
                self._periodic(0x0001, 0x02, '6761'),
                self._periodic(0x0001, 0x00, '0709626967616476')])
        assert self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.expert.periodic_data_truncated') == ['2']
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "bigadv"'
                ' && !bthci_evt.periodic_data.fragment') == ['3']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.malformed || _ws.expert.message contains "Exception occurred"') == []

    def test_interleaved_syncs_reassemble_separately(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-interleaved', [
                self._periodic(0x0001, 0x01, '0709616c70'),   # "alp"
                self._periodic(0x0002, 0x01, '0709627261'),   # "bra"
                self._periodic(0x0001, 0x00, '686131'),       # "ha1"
                self._periodic(0x0002, 0x00, '766f32')])      # "vo2"
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "alpha1"') == ['3']
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "bravo2"') == ['4']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_sync_lost_mid_chain_discards_the_pieces(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-lost', [
                self._periodic(0x0001, 0x01, '0709626967'),
                '043e03100100',                               # Sync Lost, handle 0x0001
                self._periodic(0x0001, 0x00, '0709626967616476')])
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "bigadv"'
                ' && !bthci_evt.periodic_data.fragment') == ['3']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_empty_complete_report_ends_a_chain(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-empty-tail', [
                self._periodic(0x0001, 0x01, '0709626967616476'),
                self._periodic(0x0001, 0x00, '')])
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "bigadv"'
                ' && bthci_evt.periodic_data.reassembled.length == 8') == ['2']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_v2_reports_are_reassembled(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-v2-chain', [
                self._periodic(0x0001, 0x01, '0709626967', v2=True),
                self._periodic(0x0001, 0x00, '616476', v2=True)])
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.device_name == "bigadv"') == ['2']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_truncated_report_on_its_own(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-truncated-alone', [
                self._periodic(0x0001, 0x02, '0709626967')])
        assert self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.expert.periodic_data_truncated && bthci_evt.data') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry || _ws.malformed') == []
```

- [ ] **Step 3: Run them and watch them fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -12'
```

Expected: the 4 existing tests pass and the 9 new ones fail. Most fail because tshark rejects the unknown `bthci_evt.periodic_data.*` and `bthci_evt.expert.periodic_data_truncated` fields (exit status 4). Record the failure reason of each new test in the ledger.

- [ ] **Step 4: Declarations**

In `packet-bthci_evt.c`, add after `#include <epan/proto_data.h>`:

```c
#include <epan/reassemble.h>
```

Next to the other `static int hf_bthci_evt_*` declarations (after `static int hf_bthci_evt_data;`):

```c
static int hf_bthci_evt_periodic_data_fragments;
static int hf_bthci_evt_periodic_data_fragment;
static int hf_bthci_evt_periodic_data_fragment_overlap;
static int hf_bthci_evt_periodic_data_fragment_overlap_conflicts;
static int hf_bthci_evt_periodic_data_fragment_multiple_tails;
static int hf_bthci_evt_periodic_data_fragment_too_long_fragment;
static int hf_bthci_evt_periodic_data_fragment_error;
static int hf_bthci_evt_periodic_data_fragment_count;
static int hf_bthci_evt_periodic_data_reassembled_in;
static int hf_bthci_evt_periodic_data_reassembled_length;
```

Next to the `static int ett_bthci_evt*` declarations:

```c
static int ett_bthci_evt_periodic_data_fragment;
static int ett_bthci_evt_periodic_data_fragments;
```

Next to the `static expert_field ei_*` declarations:

```c
static expert_field ei_periodic_data_truncated;
```

After those declarations, and before the first function:

```c
/* Periodic advertising data longer than one report arrives as a chain of
 * reports; they are reassembled per sync. */
static reassembly_table periodic_adv_reassembly_table;

static const fragment_items periodic_adv_frag_items = {
    &ett_bthci_evt_periodic_data_fragment,
    &ett_bthci_evt_periodic_data_fragments,
    &hf_bthci_evt_periodic_data_fragments,
    &hf_bthci_evt_periodic_data_fragment,
    &hf_bthci_evt_periodic_data_fragment_overlap,
    &hf_bthci_evt_periodic_data_fragment_overlap_conflicts,
    &hf_bthci_evt_periodic_data_fragment_multiple_tails,
    &hf_bthci_evt_periodic_data_fragment_too_long_fragment,
    &hf_bthci_evt_periodic_data_fragment_error,
    &hf_bthci_evt_periodic_data_fragment_count,
    &hf_bthci_evt_periodic_data_reassembled_in,
    &hf_bthci_evt_periodic_data_reassembled_length,
    NULL,
    "Periodic advertising data fragments"
};
```

- [ ] **Step 5: The reassembly helpers**

Immediately before the function `dissect_bthci_evt_le_meta` (find it with `grep -n "^dissect_bthci_evt_le_meta" packet-bthci_evt.c`, then insert above its `static` line):

```c
/* A sync handle is only unique within one controller, so the chain's key also
 * carries the interface and adapter. */
static uint32_t
periodic_adv_reassembly_id(const bluetooth_data_t *bluetooth_data, uint32_t sync_handle)
{
    return ((bluetooth_data->interface_id & 0xFF) << 24) |
           ((bluetooth_data->adapter_id & 0xFF) << 16) |
           (sync_handle & 0xFFFF);
}

/* Drops the pieces of a chain that will never be completed. */
static void
periodic_adv_discard(packet_info *pinfo, uint32_t id)
{
    tvbuff_t *leftover;

    leftover = fragment_delete(&periodic_adv_reassembly_table, pinfo, id, NULL);
    if (leftover != NULL)
        tvb_free(leftover);
}

/* The data of one periodic advertising report. A report whose Data Status is
 * Incomplete is one piece of a chain, ended by a Complete report holding the
 * tail, or abandoned by a Truncated one. Only the whole of a chain holds whole
 * AD structures, so the data is decoded once, in the frame that completes it.
 */
static void
dissect_periodic_adv_data(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree,
        bluetooth_data_t *bluetooth_data, uint32_t sync_handle, uint8_t data_status, uint8_t length)
{
    bluetooth_eir_ad_data_t *ad_data;
    fragment_head *head;
    proto_item *data_item;
    tvbuff_t *data_tvb;
    uint32_t id;

    id = periodic_adv_reassembly_id(bluetooth_data, sync_handle);

    if (data_status == 0x02) {
        data_item = proto_tree_add_item(tree, hf_bthci_evt_data, tvb, offset, length, ENC_NA);
        expert_add_info(pinfo, data_item, &ei_periodic_data_truncated);
        if (!PINFO_FD_VISITED(pinfo))
            periodic_adv_discard(pinfo, id);
        return;
    }
    if (data_status != 0x00 && data_status != 0x01) {
        proto_tree_add_item(tree, hf_bthci_evt_data, tvb, offset, length, ENC_NA);
        return;
    }

    head = fragment_add_seq_next(&periodic_adv_reassembly_table, tvb, offset, pinfo, id, NULL,
            length, data_status == 0x01);

    if (head != NULL && head->next != NULL && head->next->next == NULL) {
        /* A chain of one: a single Complete report, decoded as it stands. */
        if (length == 0) {
            proto_tree_add_item(tree, hf_bthci_evt_data, tvb, offset, length, ENC_NA);
            return;
        }
        data_tvb = tvb_new_subset_length(tvb, offset, length);
    } else {
        proto_tree_add_item(tree, hf_bthci_evt_data, tvb, offset, length, ENC_NA);
        data_tvb = process_reassembled_data(tvb, offset, pinfo,
                "Reassembled Periodic Advertising Data", head, &periodic_adv_frag_items, NULL, tree);
    }
    if (data_tvb == NULL || tvb_reported_length(data_tvb) == 0)
        return;

    /* A periodic report carries a sync handle rather than an address, so
     * there is no bd_addr to pass on. */
    ad_data = wmem_new0(pinfo->pool, bluetooth_eir_ad_data_t);
    ad_data->interface_id = bluetooth_data->interface_id;
    ad_data->adapter_id = bluetooth_data->adapter_id;
    ad_data->bd_addr = NULL;

    call_dissector_with_data(btcommon_ad_handle, data_tvb, pinfo, tree, ad_data);
}
```

If `bluetooth_data_t`'s `interface_id` or `adapter_id` has a different type than `uint32_t`, keep the masks. The build in Step 7 shows it.

- [ ] **Step 6: Use them in the report and Sync Lost cases**

In `dissect_bthci_evt_le_meta`, case 0x0F/0x25, add `uint32_t sync_handle;` to the block's declarations (beside `uint8_t data_status;`), and change the first line of the block from

```c
            proto_tree_add_item(tree, hf_bthci_evt_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
```

to

```c
            proto_tree_add_item_ret_uint(tree, hf_bthci_evt_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sync_handle);
```

Replace the whole `if (length > 0 && data_status == 0x00) { ... } else { ... }` statement that commit 1 added with:

```c
            dissect_periodic_adv_data(tvb, offset, pinfo, tree, bluetooth_data, sync_handle, data_status, length);
```

(`offset += length;` after it stays.)

Replace the Sync Lost case:

```c
        case 0x10: /* LE Periodic Advertising Sync Lost */
            proto_tree_add_item(tree, hf_bthci_evt_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
```

with:

```c
        case 0x10: /* LE Periodic Advertising Sync Lost */
            {
            uint32_t sync_handle;

            proto_tree_add_item_ret_uint(tree, hf_bthci_evt_sync_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN, &sync_handle);
            offset += 2;
            /* A lost sync ends its chain without a closing report, and the
             * handle may be given to a later sync. */
            if (!PINFO_FD_VISITED(pinfo))
                periodic_adv_discard(pinfo, periodic_adv_reassembly_id(bluetooth_data, sync_handle));
            }
            break;
```

- [ ] **Step 7: Register, build, run**

In `proto_register_bthci_evt`, append to the main `hf[]` array (after the `hf_bthci_evt_data` entry):

```c
        { &hf_bthci_evt_periodic_data_fragments,
          { "Periodic advertising data fragments", "bthci_evt.periodic_data.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment,
          { "Periodic advertising data fragment", "bthci_evt.periodic_data.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_overlap,
          { "Fragment overlap", "bthci_evt.periodic_data.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_overlap_conflicts,
          { "Fragment overlapping with conflicting data", "bthci_evt.periodic_data.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_multiple_tails,
          { "Multiple tail fragments", "bthci_evt.periodic_data.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_too_long_fragment,
          { "Fragment too long", "bthci_evt.periodic_data.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_error,
          { "Defragmentation error", "bthci_evt.periodic_data.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_fragment_count,
          { "Fragment count", "bthci_evt.periodic_data.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_reassembled_in,
          { "Reassembled in", "bthci_evt.periodic_data.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthci_evt_periodic_data_reassembled_length,
          { "Reassembled periodic advertising data length", "bthci_evt.periodic_data.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
```

Append to `ei[]`:

```c
        { &ei_periodic_data_truncated,    { "bthci_evt.expert.periodic_data_truncated",          PI_PROTOCOL, PI_WARN,      "Periodic advertising data truncated by the controller: the chain it ends is incomplete", EXPFILL }},
```

Append to `ett[]`:

```c
        &ett_bthci_evt_periodic_data_fragment,
        &ett_bthci_evt_periodic_data_fragments,
```

At the end of `proto_register_bthci_evt`, before its closing brace:

```c
    reassembly_table_register(&periodic_adv_reassembly_table, &addresses_reassembly_table_functions);
```

Then:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | grep -E "error|warning" | head -10; pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: no compiler errors or warnings, and `13 passed`. If `test_empty_complete_report_ends_a_chain` fails because `fragment_add_seq_next` rejects a zero-length tail, do not special-case it silently. Find out what the reassembly code does with it (`epan/reassemble.c`, `fragment_add_seq_common`) and handle it explicitly, with a comment saying why.

- [ ] **Step 8: Check the measurement, then amend commit 1**

Rerun the fault this fixes, against the full source capture:

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash -c 'T=~/src/wsbuild/run/tshark; F=/mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad/bigadv1.pcapng; echo "periodic flagged: $($T -r $F -Y "bthci_evt.le_meta_subevent == 0x0f && (_ws.malformed || _ws.expert.severity >= 8388608)" | wc -l)"; echo "reassembled 1008: $($T -r $F -Y "bthci_evt.periodic_data.reassembled.length == 1008" | wc -l)"; echo "truncated warnings: $($T -r $F -Y bthci_evt.expert.periodic_data_truncated | wc -l)"'
```

Expected: `periodic flagged: 0` (it was 279), `reassembled 1008: 279`, `truncated warnings: 3`.

Then commit, replacing commit 1:

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash -c 'cd ~/src/wireshark && git log -1 --format=%B HEAD | grep -E "^(Assisted-by|Co-Authored-By):" > ~/trailers.txt && cat > ~/msg-c1.txt <<"EOF"
Bluetooth HCI Event: dissect periodic advertising data

The data in an LE Periodic Advertising Report holds advertising structures,
as the data in an extended advertising report does, but it was added to the
tree as one block of bytes. Hand it to the AD dissector, so that what a
broadcast announces in its periodic train is dissected rather than shown as
hex.

Periodic data longer than one report arrives as a chain: Incomplete reports
ended by a Complete or a Truncated one. The Complete report that ends a chain
holds only its tail, so reports are reassembled by sync handle and the data
is dissected once, in the frame that completes it. A Truncated report, or the
loss of the sync, discards the pieces gathered so far, and a Truncated report
is flagged. Decoding each Complete report on its own instead flagged every
chain tail as malformed: 279 of 279 in a capture of a 1008-byte train.

The captures are an LE Audio broadcast from Zephyr bap_broadcast_source and a
test advertiser sending 1008 bytes of periodic data, both taken with an
ESP32-C6 sniffer.

EOF
cat ~/trailers.txt >> ~/msg-c1.txt && git add epan/dissectors/packet-bthci_evt.c test/suite_dissection.py test/captures/bt-le-periodic-chained.pcapng && git commit -q --amend -F ~/msg-c1.txt && git log --oneline -2 && git ls-files -s test/captures/bt-le-periodic-chained.pcapng | cut -c1-6'
```

Expected: a new commit 1 on top of `7caf6e0b96`, and `100644`.

---

### Task 3: Replay commits 2 and 3, and prove the split BASE decodes

**Files:**
- Modify (by rebase): branch `le-audio-broadcast`
- Modify: `test/suite_dissection.py` in commit 2
- Create (throwaway): `$S/resolve_both.py`, `$S/replay_broadcast.sh`

**Interfaces:**
- Consumes: branch `periodic-reassembly` (Task 2), and `_hci_frames`, `_periodic` and `SPLIT_BASE` from its tests.
- Produces: `le-audio-broadcast` = new commit 1, then commits 2 and 3, with `test_base_split_across_two_reports_decodes` in commit 2.

- [ ] **Step 1: The conflict resolver**

Commits 2 and 3 append their tests at the end of the file, and so did Task 2, so git sees both sides adding at the same place. Write `$S/resolve_both.py`:

```python
"""Resolves a conflict where both sides appended tests at the end of the
class: keeps ours (the earlier commit's), then theirs."""
import os

p = os.path.expanduser('~/src/wireshark/test/suite_dissection.py')
lines = open(p, encoding='utf-8').read().split('\n')
starts = [i for i, l in enumerate(lines) if l.startswith('<<<<<<< ')]
assert len(starts) == 1, starts
start = starts[0]
mid = next(i for i, l in enumerate(lines) if l == '=======')
end = next(i for i, l in enumerate(lines) if l.startswith('>>>>>>> '))
ours = lines[start + 1:mid]
theirs = lines[mid + 1:end]
while ours and ours[-1] == '':
    ours.pop()
while theirs and theirs[0] == '':
    theirs.pop(0)
out = lines[:start] + ours + [''] + theirs + lines[end + 1:]
open(p, 'w', encoding='utf-8').write('\n'.join(out))
print('kept', len(ours), 'lines of ours and', len(theirs), 'of theirs')
```

- [ ] **Step 2: Replay commit 2, stopping to add its test**

Write `$S/replay_broadcast.sh`:

```bash
#!/bin/bash
# Replays commits 2 and 3 of le-audio-broadcast onto the new commit 1.
set -uo pipefail
SW=/mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad
cd ~/src/wireshark || exit 1
git switch -q le-audio-broadcast || exit 1
git rebase -q --onto periodic-reassembly 6da62ec4d4 le-audio-broadcast
while git status --porcelain | grep -q '^UU'; do
    python3 "$SW/resolve_both.py" || exit 1
    git add test/suite_dissection.py
    GIT_EDITOR=true git rebase --continue >/dev/null 2>&1
done
git log --oneline -4
git status --short
```

Run it:

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash /mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad/replay_broadcast.sh
```

Expected: `resolve_both.py` reports each conflict it resolved (one or two), and the log shows commits 3, 2 and new 1 on `7caf6e0b96`, with a clean status apart from the untracked patch directories.

- [ ] **Step 3: Add commit 2's split-BASE test, failing first**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git log --format="%h %s" -3'
```

Mark commit 2 for editing: `GIT_SEQUENCE_EDITOR='sed -i "s/^pick \(.*Basic Audio Announcement\)/edit \1/"' git rebase -i periodic-reassembly`. Then append to the end of `test/suite_dissection.py`, which at that stop ends with commit 2's last test:

```python

    def test_base_split_across_two_reports_decodes(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        base = self.SPLIT_BASE
        capture = self._hci_frames(cmd_text2pcap, result_file, base_env, 'le-audio-base-split', [
                self._periodic(0x0001, 0x01, base[:40]),
                self._periodic(0x0001, 0x00, base[40:])])
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.base.presentation_delay == 40000'
                ' && bluetooth.le_audio.base.subgroup.num_bis == 2'
                ' && bluetooth.le_audio.codec_config.sampling_frequency == 0x03'
                ' && bluetooth.le_audio.base.bis.index == 2') == ['2']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.malformed') == []
```

Run it against the build of this stop:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap >/dev/null 2>&1; pytest ../wireshark/test/suite_dissection.py -k "split_across_two_reports" --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: both split tests pass. This test adds no production code, so it has no failing run of its own. The code it exercises, the reassembly, was proven failing-first by commit 1's `test_base_split_across_two_reports` in Task 2, Step 3. This one shows that the BASE dissector of commit 2 decodes reassembled data exactly as it decodes a single report. Record that reasoning in the ledger.

Then:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git add test/suite_dissection.py && git commit -q --amend --no-edit && GIT_EDITOR=true git rebase --continue 2>&1 | tail -2; git status --short | grep "^UU"'
```

If commit 3 conflicts at the end of the file, run `python3 $SW/resolve_both.py`, `git add test/suite_dissection.py`, `GIT_EDITOR=true git rebase --continue` (inside a WSL script file, as above).

- [ ] **Step 4: Each commit passes on its own**

Write and run `$S/per_commit_broadcast.sh`:

```bash
#!/bin/bash
# Builds and tests each commit of le-audio-broadcast alone.
cd ~/src/wireshark || exit 1
for c in $(git rev-list --reverse master..le-audio-broadcast); do
    git checkout -q "$c" || exit 1
    (cd ~/src/wsbuild && ninja tshark text2pcap >/dev/null 2>&1 || echo "BUILD FAILED")
    echo "$(git log -1 --format='%h %s') -> $(cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -1)"
done
git checkout -q le-audio-broadcast
```

Expected: `13 passed`, then `23 passed`, then `26 passed`.

---

### Task 4: Carry the unicast series over, check, and regenerate both series

**Files:**
- Modify (by rebase): branch `le-audio-unicast`
- Modify: `$S/le-audio-broadcast-patches/merge-request.md`
- Create: both patch series in the clone and the scratchpad

**Interfaces:**
- Consumes: `le-audio-broadcast` from Task 3, and the tag `le-audio-broadcast-before-reassembly`.
- Produces: `le-audio-unicast` on the new broadcast branch; `le-audio-broadcast-patches/` and `le-audio-unicast-patches/` regenerated.

- [ ] **Step 1: Rebase the unicast series**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git rebase -q --onto le-audio-broadcast le-audio-broadcast-before-reassembly le-audio-unicast; git status --short | grep "^UU"; git log --oneline -7'
```

Expected: no conflicts, because the unicast tests append after commit 3's, which did not move. The log shows 3 unicast commits, 3 broadcast commits, then `7caf6e0b96`. If a conflict appears at the end of `suite_dissection.py`, resolve it with `resolve_both.py` as in Task 3.

- [ ] **Step 2: Check each unicast commit and the full suite**

Run `$S/per_commit.sh` (it tests `le-audio-broadcast..le-audio-unicast`), then the full suite on the tip:

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-26.04 -- bash /mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad/per_commit.sh; wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -1'
```

Expected: `32 passed`, `37 passed`, `41 passed`. The full suite passes with only its usual 22 environment skips.

- [ ] **Step 3: Upstream checks and the fuzz run**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && python3 tools/check_apis.py epan/dissectors/packet-bthci_evt.c 2>&1 | tail -2; perl tools/checkhf.pl epan/dissectors/packet-bthci_evt.c; perl tools/checkfiltername.pl epan/dissectors/packet-bthci_evt.c; python3 tools/check_typed_item_calls.py --file epan/dissectors/packet-bthci_evt.c 2>&1 | tail -4; ~/spellenv/bin/python tools/check_spelling.py --file epan/dissectors/packet-bthci_evt.c 2>&1 | grep -E " : [0-9]+$"; cd ~/src/wsbuild && ../wireshark/tools/fuzz-test.sh -b ./run -p 200 ../wireshark/test/captures/bt-le-periodic-chained.pcapng ../wireshark/test/captures/bt-le-audio-bap-broadcast.pcapng ../wireshark/test/captures/bt-le-audio-pbp-broadcast.pcapng ../wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng > ~/fuzz-reassembly.log 2>&1; echo "fuzz rc=$?"; grep -c -i failed ~/fuzz-reassembly.log; tail -5 ~/fuzz-reassembly.log'
```

Expected: `0 warnings found` from `check_apis.py`, and nothing from the two Perl checks. The typed-item and spelling checks name nothing on lines this change added; compare against `git diff 7caf6e0b96 -- epan/dissectors/packet-bthci_evt.c` if unsure. The fuzz run exits 0 with 0 failures, and the last pass lists all four captures as OK. Fix anything the checks name on new lines with a fixup to commit 1 (`git commit --fixup=<commit 1>`, `GIT_SEQUENCE_EDITOR=true git rebase -i --autosquash master` on `le-audio-broadcast`, then repeat Step 1 onto the new tip).

- [ ] **Step 4: Update the broadcast merge request text**

In `$S/le-audio-broadcast-patches/merge-request.md`, replace item 1 of the list with:

```markdown
1. **Periodic advertising data goes through the AD dissector**, as extended
   advertising data already does. Data longer than one report arrives as a
   chain of reports; the chain is reassembled by sync handle and dissected once,
   in the frame that completes it. A truncated chain, or a lost sync, discards
   the pieces, and a truncated report is flagged
   (`bthci_evt.expert.periodic_data_truncated`). Decoding each report on its own
   instead flagged every chain tail as malformed.
```

In the Testing section, change the counts and captures to match:
- `26 tests over three new captures`
- a bullet for `bt-le-periodic-chained.pcapng` (19 frames: a sync established event and two chains of nine reports carrying 1008 bytes each, from a test advertiser)
- the hand-built list extended with chained, truncated, interleaved, sync-lost, empty-tail and version 2 chains
- per-commit counts `13, 23 and 26`
- `tools/fuzz-test.sh -p 200` over the three captures

- [ ] **Step 5: Regenerate both series**

Write and run `$S/make_both_series.sh`:

```bash
#!/bin/bash
# Writes both patch series with their merge request texts, and copies them to the scratchpad.
set -e
SW=/mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad
cd ~/src/wireshark
cp "$SW/le-audio-broadcast-patches/merge-request.md" /tmp/mr-broadcast.md
cp "$SW/merge-request-unicast.md" /tmp/mr-unicast.md
rm -rf le-audio-broadcast-patches le-audio-unicast-patches
git format-patch -q -o le-audio-broadcast-patches master..le-audio-broadcast
git format-patch -q -o le-audio-unicast-patches le-audio-broadcast..le-audio-unicast
cp /tmp/mr-broadcast.md le-audio-broadcast-patches/merge-request.md
cp /tmp/mr-unicast.md le-audio-unicast-patches/merge-request.md
rm -rf "$SW/le-audio-broadcast-patches" "$SW/le-audio-unicast-patches"
cp -r le-audio-broadcast-patches le-audio-unicast-patches "$SW/"
ls "$SW/le-audio-broadcast-patches" "$SW/le-audio-unicast-patches"
grep -h "^new file mode" le-audio-broadcast-patches/*.patch le-audio-unicast-patches/*.patch | sort | uniq -c
```

Expected: three patches plus `merge-request.md` in each directory. Every `new file mode` line is `100644`: four captures, all non-executable.

---

### Task 5: What the measurement means for someone using the sniffer

**Files:**
- Modify: `G:\dev\projects\esp32c6-sniffer\docs\using-wireshark.md` (the Bluetooth LE part of "Reading the capture")

**Interfaces:**
- Consumes: the measurements already made on 2026-09-24. No code.
- Produces: one committed docs paragraph in this repository.

- [ ] **Step 1: Write the paragraph**

After the paragraph that ends "Wireshark 4.6 has no LC3 decoder, so it can neither interpret nor play the sound.", add:

```markdown
**Large advertisements arrive in pieces.** Advertising data longer than one
report — a big extended advertisement, or a large periodic train such as a
multi-language Auracast announcement — reaches Wireshark as a chain of
reports, each holding part of it. Measured with a test advertiser sending
1,008 bytes, both kinds took nine reports, and every complete chain carried
the sent bytes exactly; a few ended truncated (15 of 274 extended chains, 3 of
282 periodic), which is the controller giving up, not a capture fault.
Wireshark 4.6 decodes each piece of an extended advertisement as if it were
whole, so a chained one shows as a run of malformed packets, 2,381 of 2,396
pieces in that test: the data is intact, the decoding is not. A patch that
reassembles periodic chains is being prepared for upstream Wireshark;
extended ones are not yet covered.
```

- [ ] **Step 2: Check and commit**

```bash
cd /g/dev/projects/esp32c6-sniffer && host/.venv/Scripts/python.exe -m pytest -q host/tests/test_no_private_data.py host/tests/test_no_stray_control_characters.py 2>&1 | tail -1 && git add docs/using-wireshark.md && git commit -q -m "docs: large advertisements arrive in pieces, and Wireshark 4.6 misreads them" -m "Measured with a test advertiser sending 1,008 bytes: nine reports per chain, every complete chain intact, and 2,381 of 2,396 extended advertising pieces flagged malformed by Wireshark 4.6.8." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && git log --oneline -1
```

Expected: `7 passed` and the commit.
