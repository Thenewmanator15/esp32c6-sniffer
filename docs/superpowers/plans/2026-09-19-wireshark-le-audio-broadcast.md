# Wireshark LE Audio Broadcast Announcements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach Wireshark to decode what an LE Audio broadcast announces -- the BASE in periodic advertising, the Broadcast ID and the Public Broadcast features -- and hand the change to the user as a merge request series for upstream Wireshark.

**Architecture:** Three commits on a branch of Wireshark's `master`. The first makes periodic advertising data go through Wireshark's existing advertising-data parser, which then dispatches service data by UUID. The second and third hang a new protocol, `bluetooth.le_audio`, on that dispatch for UUIDs 0x1851, 0x1852 and 0x1856, in `packet-bluetooth.c` beside the existing Matter and Exposure Notification decoders. Tests are Wireshark's own: `test/suite_dissection.py`, over two captures taken from real broadcasts plus hand-built frames for bad input.

**Tech Stack:** C (Wireshark dissector APIs, `master` branch), CMake + Ninja, Python/pytest (Wireshark's test suite), `text2pcap` for hand-built frames, WSL Ubuntu 26.04 for the build, Zephyr sample firmware on the XIAO nRF54L15 and the ESP32-C6 sniffer for the captures.

**Spec:** `docs/superpowers/specs/2026-09-19-wireshark-le-audio-broadcast-design.md`

## Global Constraints

- **Work happens in WSL**, in the clone `~/src/wireshark` on branch `le-audio-broadcast` off `master`. Nothing in `G:\dev\projects\esp32c6-sniffer` or `G:\dev\projects\nrf54l15-sniffer` changes during this plan, except this plan file.
- **Protocol filter name is `bluetooth.le_audio`**, matching the house pattern (`bluetooth.matter`, `bluetooth.gaen`). Every field name starts with `bluetooth.le_audio.`; C identifiers use the `btad_le_audio` prefix.
- **UUID registration keys are the strings `"1851"`, `"1852"`, `"1856"`** on the dissector table `btcommon.eir_ad.entry.uuid`.
- **Periodic reports are dissected as advertising data only when Data Status is 0x00 (Complete).** Status 0x01 and 0x02 keep today's raw `hf_bthci_evt_data`.
- **Reuse, do not duplicate:** `bthci_evt_codec_id_vals` (from `packet-bthci_evt.h`) for the coding format, `bluetooth_company_id_vals_ext` (from `packet-bluetooth.h`) for company IDs.
- **Bad input never throws.** Every declared length or count is checked against what remains before any item is added. Overruns raise `bluetooth.le_audio.length_overrun`; a known type with the wrong value length raises `bluetooth.le_audio.ltv.bad_length`. `_ws.malformed` must never appear for input this code reads.
- **C style is Wireshark's:** 4-space indent, no tabs, declarations at the top of a block, `unsigned` offsets and lengths (master's `proto_tree_add_item` takes `const unsigned start, int length`).
- **Commit messages** follow the repository's `.gitmessage` template, and each carries an `Assisted-by: Claude Code (Claude Opus 5)` trailer, as `CONTRIBUTING.md` on `master` asks, plus `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- **Nothing is posted anywhere.** No merge request, no push to any remote, no capture uploaded. The deliverable is a patch series on disk.
- **Values come from the Bluetooth documents**, verified on 2026-09-19 against Zephyr's `include/zephyr/bluetooth/assigned_numbers.h` and `include/zephyr/bluetooth/audio/pbp.h`: 28 audio locations (bits 0-27), 12 context types (bits 0-11), codec configuration types 0x01-0x05, sampling frequencies 0x01-0x0D, frame durations 0x00-0x01, metadata types 0x01-0x0B plus 0xFE and 0xFF, parental ratings 0x00-0x0F, Public Broadcast feature bits 0-2.

## Review Focus

- **A version 2 periodic report (subevent 0x25).** Task 2 changes that code path, but every frame in the capture is version 1. A v2 report with complete data must decode its advertising data the same way. Pinned by Task 2, Step 4.
- **A BASE announcing zero subgroups.** Legal, and the loop must simply not run: presentation delay shown, no subgroup, no warning. Pinned by Task 3, Step 1.
- **A subgroup count larger than the data.** The count is attacker-controlled; decoding must stop at the first subgroup that does not fit and flag the count, not read past the end. Pinned by Task 3, Step 1.
- **An LTV whose length byte is zero.** It carries no type, and a loop that trusts the length to advance will spin forever on it. Pinned by Task 3, Step 1.
- **Service data too short to hold even the BASE header.** Four bytes are read before anything else; two bytes of service data must produce a warning, not an exception. Pinned by Task 3, Step 1.

---

### Task 1: Build environment and baseline

**Files:**
- Create: `~/src/wireshark` (clone, in WSL)
- Create: `~/src/wsbuild` (build directory, in WSL)

**Interfaces:**
- Consumes: nothing.
- Produces: the branch `le-audio-broadcast` in `~/src/wireshark`; built programs in `~/src/wsbuild/run/` (`tshark`, `text2pcap`, `editcap`, `capinfos`); the command form every later task uses to run tests.

- [ ] **Step 1: Clone Wireshark and branch**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'mkdir -p ~/src && cd ~/src && git clone https://gitlab.com/wireshark/wireshark.git && cd wireshark && git switch -c le-audio-broadcast && git log --oneline -1'
```

Expected: a clone, then one commit line from `master`.

- [ ] **Step 2: Install build and test dependencies**

`sudo` in this WSL is passwordless (checked 2026-09-19), so this runs unattended. If it ever asks for a password, stop and ask the user to run it.

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && sudo tools/debian-setup.sh --install-test-deps -y'
```

- [ ] **Step 3: Configure and build**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'mkdir -p ~/src/wsbuild && cd ~/src/wsbuild && cmake -G Ninja -DBUILD_wireshark=OFF ../wireshark && ninja'
```

Expected: a build with no errors. It takes several minutes the first time.

- [ ] **Step 4: Confirm the programs and the test runner work**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ./run/tshark --version | head -1 && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: a `master` version string, and the dissection suite passing before any change.

- [ ] **Step 5: Record the baseline**

No commit. Note the `master` commit hash from Step 1 in the merge request notes later.

---

### Task 2: Commit 1 -- periodic advertising data as advertising structures

**Files:**
- Create: `~/src/wireshark/test/captures/bt-le-audio-bap-broadcast.pcapng`
- Modify: `~/src/wireshark/epan/dissectors/packet-bthci_evt.c` (subevent cases 0x0F and 0x25)
- Test: `~/src/wireshark/test/suite_dissection.py` (new class `TestDissectBluetoothLeAudio`)

**Interfaces:**
- Consumes: the build from Task 1.
- Produces: the capture fixture `bt-le-audio-bap-broadcast.pcapng` containing exactly 2 extended advertising reports, 1 sync established event and 10 periodic advertising reports from the broadcaster, whose address the capture gives (`aa:bb:cc:dd:ee:ff` stands in for it here); the test class `TestDissectBluetoothLeAudio` with helpers `_hci_frame(cmd_text2pcap, result_file, base_env, name, hex_bytes) -> path` and `_frames(cmd_tshark, test_env, capture, display_filter) -> list[str]`, which Tasks 3 and 4 add tests to.

- [ ] **Step 1: Build the capture fixture**

The source capture is the 30 s run recorded on 2026-09-19 at `G:\dev\scratch\nrf\base1.pcapng`. Run on Windows, with Wireshark 4.6.8:

```bash
cd /g/dev/scratch/nrf && "/c/Program Files/Wireshark/tshark.exe" -r base1.pcapng -Y '(bthci_evt.le_meta_subevent == 0x0d && bthci_evt.bd_addr == aa:bb:cc:dd:ee:ff) || bthci_evt.le_meta_subevent == 0x0e || (bthci_evt.le_meta_subevent == 0x0f && bthci_evt.sync_handle == 0x0000)' -w bap-all.pcapng && "/c/Program Files/Wireshark/tshark.exe" -r bap-all.pcapng -T fields -e frame.number -e bthci_evt.le_meta_subevent | head -20
```

Expected: a list of frame numbers with their subevents, extended reports (0x0d) and the sync established (0x0e) before the periodic reports (0x0f).

- [ ] **Step 2: Trim to 13 frames and check it is clean**

Pick the first 2 frames with subevent 0x0d, the single 0x0e, and the first 10 frames with 0x0f, then keep exactly those, in file order:

```bash
cd /g/dev/scratch/nrf && python - <<'EOF'
import subprocess
TS = r"C:\Program Files\Wireshark\tshark.exe"
rows = subprocess.check_output([TS, "-r", "bap-all.pcapng", "-T", "fields",
                                "-e", "frame.number", "-e", "bthci_evt.le_meta_subevent"],
                               encoding="utf-8").split()
pairs = list(zip(rows[0::2], rows[1::2]))
ext = [n for n, s in pairs if s == "0x0d"][:2]
est = [n for n, s in pairs if s == "0x0e"][:1]
per = [n for n, s in pairs if s == "0x0f"][:10]
keep = sorted(set(ext + est + per), key=int)
print("keeping", keep)
subprocess.check_call([r"C:\Program Files\Wireshark\editcap.exe", "-r", "bap-all.pcapng",
                       "bt-le-audio-bap-broadcast.pcapng", *keep])
EOF
"/c/Program Files/Wireshark/tshark.exe" -r bt-le-audio-bap-broadcast.pcapng -Y 'frame.comment' -T fields -e frame.number; "/c/Program Files/Wireshark/capinfos.exe" -c -E bt-le-audio-bap-broadcast.pcapng
```

Expected: no frame numbers from the comment filter (this capture carries no comments), and `capinfos -c` reporting 13 packets.

- [ ] **Step 3: Copy the fixture into the clone**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cp /mnt/g/dev/scratch/nrf/bt-le-audio-bap-broadcast.pcapng ~/src/wireshark/test/captures/ && ls -l ~/src/wireshark/test/captures/bt-le-audio-bap-broadcast.pcapng'
```

- [ ] **Step 4: Write the failing tests**

Append to `~/src/wireshark/test/suite_dissection.py`, at the end of the file:

```python
class TestDissectBluetoothLeAudio:
    '''LE Audio broadcast announcements, and the periodic advertising that carries them.'''

    @staticmethod
    def _hci_frame(cmd_text2pcap, result_file, base_env, name, hex_bytes):
        '''Writes one received HCI H4 packet (LINKTYPE 201) into a capture file.

        hex_bytes starts with the four-byte direction pseudo-header.
        '''
        data = bytes.fromhex(hex_bytes)
        text_file = result_file(name + '.txt')
        pcap_file = result_file(name + '.pcap')
        with open(text_file, 'w') as f:
            for offset in range(0, len(data), 16):
                chunk = data[offset:offset + 16]
                f.write('%08x  %s\n' % (offset, ' '.join('%02x' % b for b in chunk)))
        subprocess.check_call((cmd_text2pcap, '-l', '201', text_file, pcap_file), env=base_env)
        return pcap_file

    @staticmethod
    def _frames(cmd_tshark, test_env, capture, display_filter):
        '''Frame numbers matching a display filter, as a list of strings.'''
        stdout = subprocess.check_output((cmd_tshark,
                '-r', capture,
                '-Tfields',
                '-eframe.number',
                '-Y', display_filter,
            ), encoding='utf-8', env=test_env)
        return stdout.split()

    def test_periodic_report_data_is_dissected(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-bap-broadcast.pcapng')
        decoded = self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.le_meta_subevent == 0x0f && btcommon.eir_ad.entry.uuid_16 == 0x1851')
        assert len(decoded) == 10
        raw = self._frames(cmd_tshark, test_env, capture,
                'bthci_evt.le_meta_subevent == 0x0f && bthci_evt.data')
        assert raw == []

    def test_periodic_report_v2_data_is_dissected(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Subevent 0x25, complete data, carrying a Broadcast Audio Announcement.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-v2',
                '00000001043e12250000 7fbeff 0500 ff 00 07 06165218563412')
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.uuid_16 == 0x1852') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, 'bthci_evt.data') == []

    def test_incomplete_periodic_report_stays_raw(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Data Status 0x01: a fragment, which may end in the middle of a structure.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-periodic-partial',
                '00000001043e0c0f0000 7fbeff 01 04 03165218')
        assert self._frames(cmd_tshark, test_env, capture, 'bthci_evt.data') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, 'btcommon.eir_ad.entry') == []
```

- [ ] **Step 5: Run the tests to verify they fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -15'
```

Expected: `test_periodic_report_data_is_dissected` and `test_periodic_report_v2_data_is_dissected` FAIL, because the data is still one raw field: no `btcommon.eir_ad` entries, and `bthci_evt.data` present. `test_incomplete_periodic_report_stays_raw` passes already, which is correct: it pins behaviour that must not change.

- [ ] **Step 6: Change the dissector**

In `~/src/wireshark/epan/dissectors/packet-bthci_evt.c`, find the `case 0x0F:` / `case 0x25:` block (search for `LE Periodic Advertising Report [v1]`). Add `data_status` to that block's declarations:

```c
            uint8_t length;
            uint8_t data_status;
```

Then replace the three statements from the Data Status item through the `hf_bthci_evt_data` item with:

```c
            item = proto_tree_add_item_ret_uint8(tree, hf_bthci_evt_data_status, tvb, offset, 1, ENC_NA, &data_status);
            if (data_status == 0xff)
                    proto_item_append_text(item, " (Failed to receive)");
            offset += 1;
            proto_tree_add_item_ret_uint8(tree, hf_bthci_evt_data_length, tvb, offset, 1, ENC_NA, &length);
            offset += 1;
            if (length > 0 && data_status == 0x00) {
                bluetooth_eir_ad_data_t *ad_data;

                /* Only a complete report holds whole AD structures: a fragment
                 * of a chained report may end in the middle of one. A periodic
                 * report carries a sync handle rather than an address, so there
                 * is no bd_addr to pass on.
                 */
                ad_data = wmem_new0(pinfo->pool, bluetooth_eir_ad_data_t);
                ad_data->interface_id = bluetooth_data->interface_id;
                ad_data->adapter_id = bluetooth_data->adapter_id;
                ad_data->bd_addr = NULL;

                call_dissector_with_data(btcommon_ad_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree, ad_data);
            } else if (length > 0) {
                proto_tree_add_item(tree, hf_bthci_evt_data, tvb, offset, length, ENC_NA);
            }
            offset += length;
```

- [ ] **Step 7: Rebuild and run the tests**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap >/dev/null && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -5'
```

Expected: 3 passed.

- [ ] **Step 8: Check nothing else broke**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: the whole dissection suite passes.

- [ ] **Step 9: Commit**

Read the repository's commit template first, then commit in its shape:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && cat .gitmessage'
```

Write the message to a file and commit with it (this avoids nesting quotes):

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg1.txt <<MSG
Bluetooth HCI Event: dissect periodic advertising data

The data in an LE Periodic Advertising Report holds advertising structures,
as the data in an extended advertising report does, but it was added to the
tree as one block of bytes. Hand it to the AD dissector, so that what a
broadcast announces in its periodic train is dissected rather than shown as
hex.

Only a report whose Data Status is Complete is dissected this way. A fragment
of a chained report can end in the middle of a structure, and reassembly by
sync handle is not implemented here.

The capture is an LE Audio broadcast from Zephyr bap_broadcast_source, taken
with an ESP32-C6 sniffer.

Assisted-by: Claude Code (Claude Opus 5)
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
cd ~/src/wireshark && git add epan/dissectors/packet-bthci_evt.c test/suite_dissection.py test/captures/bt-le-audio-bap-broadcast.pcapng && git commit -F /tmp/msg1.txt && git log --oneline -1'
```

---

### Task 3: Commit 2 -- the Basic Audio Announcement (BASE)

**Files:**
- Modify: `~/src/wireshark/epan/dissectors/packet-bluetooth.c` (two includes; new protocol after the `btad_matter` handoff)
- Test: `~/src/wireshark/test/suite_dissection.py` (`TestDissectBluetoothLeAudio`)

**Interfaces:**
- Consumes: Task 2's test class and its helpers `_hci_frame` and `_frames`; the fixture `bt-le-audio-bap-broadcast.pcapng`.
- Produces: `proto_btad_le_audio`, filter name `bluetooth.le_audio`; `ett_btad_le_audio`; the expert fields `ei_btad_le_audio_length_overrun` and `ei_btad_le_audio_ltv_bad_length`; and three helpers Task 4 reuses:
  - `static bool le_audio_fits(tvbuff_t *tvb, packet_info *pinfo, proto_item *culprit, unsigned offset, unsigned len)`
  - `static void dissect_le_audio_ltvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, unsigned length, le_audio_ltv_kind_t kind)`
  - `static bool dissect_le_audio_metadata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset)`

- [ ] **Step 1: Write the failing tests**

Add to `TestDissectBluetoothLeAudio`:

```python
    def test_base_from_a_real_broadcast(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-bap-broadcast.pcapng')
        decoded = self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.base.presentation_delay == 40000'
                ' && bluetooth.le_audio.base.num_subgroups == 1'
                ' && bluetooth.le_audio.base.subgroup.num_bis == 2'
                ' && bluetooth.le_audio.codec_id.coding_format == 0x06'
                ' && bluetooth.le_audio.codec_config.sampling_frequency == 0x03'
                ' && bluetooth.le_audio.codec_config.frame_duration == 0x01'
                ' && bluetooth.le_audio.codec_config.octets_per_codec_frame == 40'
                ' && bluetooth.le_audio.codec_config.audio_channel_allocation == 0x00000003'
                ' && bluetooth.le_audio.codec_config.audio_channel_allocation == 0x00000001'
                ' && bluetooth.le_audio.codec_config.audio_channel_allocation == 0x00000002'
                ' && bluetooth.le_audio.metadata.streaming_audio_contexts == 0x0001'
                ' && bluetooth.le_audio.base.bis.index == 1'
                ' && bluetooth.le_audio.base.bis.index == 2')
        assert len(decoded) == 10
        complained = self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || bluetooth.le_audio.ltv.bad_length || _ws.malformed')
        assert complained == []
```


Then the bad and unusual input. Each frame is one complete periodic report whose data is a single Service Data structure for UUID 0x1851:

```python
    def test_base_codec_config_length_overruns(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Codec_Specific_Configuration_Length says 16, three octets follow.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-base-overrun',
                '00000001043e1a0f0000 7fbeff 00 12'
                '1116511840 9c00 01 01 0600000000 10 020103')
        assert self._frames(cmd_tshark, test_env, capture, 'bluetooth.le_audio.length_overrun') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_base_subgroup_count_overruns(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Num_Subgroups says three; there is data for one.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-base-count',
                '00000001043e180f0000 7fbeff 00 10'
                '0f16511840 9c00 03 00 0600000000 00 00')
        assert self._frames(cmd_tshark, test_env, capture, 'bluetooth.le_audio.length_overrun') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.base.subgroup.num_bis == 0') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_base_too_short_for_its_header(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Two octets of service data, where the header needs four.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-base-short',
                '00000001043e0e0f0000 7fbeff 00 06'
                '0516511840 9c')
        assert self._frames(cmd_tshark, test_env, capture, 'bluetooth.le_audio.length_overrun') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, 'bluetooth.le_audio.base.presentation_delay') == []
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_base_without_subgroups(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Num_Subgroups is zero: legal, and nothing follows.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-base-empty',
                '00000001043e100f0000 7fbeff 00 08'
                '0716511840 9c00 00')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.base.num_subgroups == 0 && !bluetooth.le_audio.base.subgroup') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || bluetooth.le_audio.ltv.bad_length || _ws.malformed') == []

    def test_empty_ltv_does_not_stall_the_walk(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # A zero-length LTV, then a real one: the walk must get past the first.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-empty-ltv',
                '00000001043e1c0f0000 7fbeff 00 14'
                '1316511840 9c00 01 00 0600000000 04 00020103 00')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.codec_config.sampling_frequency == 0x03'
                ' && bluetooth.le_audio.ltv.length == 0') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.malformed') == []

    def test_ltv_with_the_wrong_value_length(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Sampling Frequency in two octets, where the specification fixes one.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-ltv-length',
                '00000001043e1e0f0000 7fbeff 00 16'
                '1516511840 9c00 01 01 0600000000 00 00 01 04 03010800')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.ltv.bad_length'
                ' && bluetooth.le_audio.ltv.value == 08:00'
                ' && !bluetooth.le_audio.codec_config.sampling_frequency') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []

    def test_vendor_codec_configuration_stays_bytes(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Coding format 0xFF: the configuration's layout is the vendor's.
        capture = self._hci_frame(cmd_text2pcap, result_file, base_env, 'le-audio-vendor-codec',
                '00000001043e1d0f0000 7fbeff 00 15'
                '1416511840 9c00 01 01 ff59000100 03 020103 00 01 00')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.codec_config.raw == 02:01:03'
                ' && !bluetooth.le_audio.codec_config.sampling_frequency') == ['1']
        assert self._frames(cmd_tshark, test_env, capture, '_ws.malformed') == []
```

- [ ] **Step 2: Run them to verify they fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k test_base_from_a_real --disable-capture --disable-gui -q 2>&1 | tail -6'
```

Expected: FAIL, with tshark rejecting the filter because those fields do not exist.

- [ ] **Step 3: Add the includes**

In `packet-bluetooth.c`, with the other `#include <epan/...>` lines:

```c
#include <epan/expert.h>
#include "packet-bthci_evt.h"
```

- [ ] **Step 4: Add the protocol's declarations**

Insert after `proto_reg_handoff_btad_matter()`, before the editor modelines at the end of `packet-bluetooth.c`:

```c
/*
 * LE Audio broadcast announcements.
 *
 * A broadcast source announces itself in service data: the Broadcast Audio
 * Announcement (0x1852) and the Public Broadcast Announcement (0x1856) in its
 * extended advertising, and the Basic Audio Announcement (0x1851) -- the BASE
 * -- in its periodic advertising. The BASE describes the codec, the subgroups
 * and the streams a receiver can join.
 *
 * Basic Audio Profile, Public Broadcast Profile, and the Generic Audio section
 * of Assigned Numbers.
 */

#define LE_AUDIO_CODING_FORMAT_LC3 0x06

#define LE_AUDIO_CODEC_CONFIG_SAMPLING_FREQUENCY        0x01
#define LE_AUDIO_CODEC_CONFIG_FRAME_DURATION            0x02
#define LE_AUDIO_CODEC_CONFIG_AUDIO_CHANNEL_ALLOCATION  0x03
#define LE_AUDIO_CODEC_CONFIG_OCTETS_PER_CODEC_FRAME    0x04
#define LE_AUDIO_CODEC_CONFIG_FRAME_BLOCKS_PER_SDU      0x05

#define LE_AUDIO_METADATA_PREFERRED_AUDIO_CONTEXTS      0x01
#define LE_AUDIO_METADATA_STREAMING_AUDIO_CONTEXTS      0x02
#define LE_AUDIO_METADATA_PROGRAM_INFO                  0x03
#define LE_AUDIO_METADATA_LANGUAGE                      0x04
#define LE_AUDIO_METADATA_CCID_LIST                     0x05
#define LE_AUDIO_METADATA_PARENTAL_RATING               0x06
#define LE_AUDIO_METADATA_PROGRAM_INFO_URI              0x07
#define LE_AUDIO_METADATA_AUDIO_ACTIVE_STATE            0x08
#define LE_AUDIO_METADATA_IMMEDIATE_RENDERING           0x09
#define LE_AUDIO_METADATA_ASSISTED_LISTENING_STREAM     0x0A
#define LE_AUDIO_METADATA_BROADCAST_NAME                0x0B
#define LE_AUDIO_METADATA_EXTENDED                      0xFE
#define LE_AUDIO_METADATA_VENDOR                        0xFF

typedef enum {
    LE_AUDIO_LTV_CODEC_CONFIG,
    LE_AUDIO_LTV_METADATA
} le_audio_ltv_kind_t;

static int proto_btad_le_audio;

static int hf_btad_le_audio_presentation_delay;
static int hf_btad_le_audio_num_subgroups;
static int hf_btad_le_audio_subgroup;
static int hf_btad_le_audio_subgroup_num_bis;
static int hf_btad_le_audio_coding_format;
static int hf_btad_le_audio_company_id;
static int hf_btad_le_audio_vendor_codec_id;
static int hf_btad_le_audio_codec_config_length;
static int hf_btad_le_audio_codec_config_raw;
static int hf_btad_le_audio_codec_config_type;
static int hf_btad_le_audio_metadata_length;
static int hf_btad_le_audio_metadata_type;
static int hf_btad_le_audio_bis;
static int hf_btad_le_audio_bis_index;
static int hf_btad_le_audio_ltv_length;
static int hf_btad_le_audio_ltv_value;
static int hf_btad_le_audio_sampling_frequency;
static int hf_btad_le_audio_frame_duration;
static int hf_btad_le_audio_audio_channel_allocation;
static int hf_btad_le_audio_octets_per_codec_frame;
static int hf_btad_le_audio_codec_frame_blocks_per_sdu;
static int hf_btad_le_audio_preferred_audio_contexts;
static int hf_btad_le_audio_streaming_audio_contexts;
static int hf_btad_le_audio_program_info;
static int hf_btad_le_audio_language;
static int hf_btad_le_audio_ccid;
static int hf_btad_le_audio_parental_rating;
static int hf_btad_le_audio_program_info_uri;
static int hf_btad_le_audio_audio_active_state;
static int hf_btad_le_audio_immediate_rendering;
static int hf_btad_le_audio_assisted_listening_stream;
static int hf_btad_le_audio_broadcast_name;
static int hf_btad_le_audio_extended_type;
static int hf_btad_le_audio_vendor_company_id;

static int hf_btad_le_audio_location_front_left;
static int hf_btad_le_audio_location_front_right;
static int hf_btad_le_audio_location_front_center;
static int hf_btad_le_audio_location_low_frequency_effects_1;
static int hf_btad_le_audio_location_back_left;
static int hf_btad_le_audio_location_back_right;
static int hf_btad_le_audio_location_front_left_of_center;
static int hf_btad_le_audio_location_front_right_of_center;
static int hf_btad_le_audio_location_back_center;
static int hf_btad_le_audio_location_low_frequency_effects_2;
static int hf_btad_le_audio_location_side_left;
static int hf_btad_le_audio_location_side_right;
static int hf_btad_le_audio_location_top_front_left;
static int hf_btad_le_audio_location_top_front_right;
static int hf_btad_le_audio_location_top_front_center;
static int hf_btad_le_audio_location_top_center;
static int hf_btad_le_audio_location_top_back_left;
static int hf_btad_le_audio_location_top_back_right;
static int hf_btad_le_audio_location_top_side_left;
static int hf_btad_le_audio_location_top_side_right;
static int hf_btad_le_audio_location_top_back_center;
static int hf_btad_le_audio_location_bottom_front_center;
static int hf_btad_le_audio_location_bottom_front_left;
static int hf_btad_le_audio_location_bottom_front_right;
static int hf_btad_le_audio_location_front_left_wide;
static int hf_btad_le_audio_location_front_right_wide;
static int hf_btad_le_audio_location_left_surround;
static int hf_btad_le_audio_location_right_surround;
static int hf_btad_le_audio_location_reserved;

static int hf_btad_le_audio_context_unspecified;
static int hf_btad_le_audio_context_conversational;
static int hf_btad_le_audio_context_media;
static int hf_btad_le_audio_context_game;
static int hf_btad_le_audio_context_instructional;
static int hf_btad_le_audio_context_voice_assistants;
static int hf_btad_le_audio_context_live;
static int hf_btad_le_audio_context_sound_effects;
static int hf_btad_le_audio_context_notifications;
static int hf_btad_le_audio_context_ringtone;
static int hf_btad_le_audio_context_alerts;
static int hf_btad_le_audio_context_emergency_alarm;
static int hf_btad_le_audio_context_reserved;

static int ett_btad_le_audio;
static int ett_btad_le_audio_subgroup;
static int ett_btad_le_audio_bis;
static int ett_btad_le_audio_ltv;
static int ett_btad_le_audio_location;
static int ett_btad_le_audio_contexts;

static expert_field ei_btad_le_audio_length_overrun;
static expert_field ei_btad_le_audio_ltv_bad_length;

static dissector_handle_t btad_le_audio_base;

void proto_register_btad_le_audio(void);
void proto_reg_handoff_btad_le_audio(void);
```

- [ ] **Step 5: Add the value tables and bit lists**

Continue in the same place. Every value here was checked on 2026-09-19 against Zephyr's `assigned_numbers.h`:

```c
static const value_string le_audio_codec_config_type_vals[] = {
    { LE_AUDIO_CODEC_CONFIG_SAMPLING_FREQUENCY,       "Sampling Frequency" },
    { LE_AUDIO_CODEC_CONFIG_FRAME_DURATION,           "Frame Duration" },
    { LE_AUDIO_CODEC_CONFIG_AUDIO_CHANNEL_ALLOCATION, "Audio Channel Allocation" },
    { LE_AUDIO_CODEC_CONFIG_OCTETS_PER_CODEC_FRAME,   "Octets per Codec Frame" },
    { LE_AUDIO_CODEC_CONFIG_FRAME_BLOCKS_PER_SDU,     "Codec Frame Blocks per SDU" },
    { 0, NULL }
};

static const value_string le_audio_metadata_type_vals[] = {
    { LE_AUDIO_METADATA_PREFERRED_AUDIO_CONTEXTS,  "Preferred Audio Contexts" },
    { LE_AUDIO_METADATA_STREAMING_AUDIO_CONTEXTS,  "Streaming Audio Contexts" },
    { LE_AUDIO_METADATA_PROGRAM_INFO,              "Program Info" },
    { LE_AUDIO_METADATA_LANGUAGE,                  "Language" },
    { LE_AUDIO_METADATA_CCID_LIST,                 "CCID List" },
    { LE_AUDIO_METADATA_PARENTAL_RATING,           "Parental Rating" },
    { LE_AUDIO_METADATA_PROGRAM_INFO_URI,          "Program Info URI" },
    { LE_AUDIO_METADATA_AUDIO_ACTIVE_STATE,        "Audio Active State" },
    { LE_AUDIO_METADATA_IMMEDIATE_RENDERING,       "Broadcast Audio Immediate Rendering" },
    { LE_AUDIO_METADATA_ASSISTED_LISTENING_STREAM, "Assisted Listening Stream" },
    { LE_AUDIO_METADATA_BROADCAST_NAME,            "Broadcast Name" },
    { LE_AUDIO_METADATA_EXTENDED,                  "Extended Metadata" },
    { LE_AUDIO_METADATA_VENDOR,                    "Vendor Specific" },
    { 0, NULL }
};

static const value_string le_audio_sampling_frequency_vals[] = {
    { 0x01, "8000 Hz" },
    { 0x02, "11025 Hz" },
    { 0x03, "16000 Hz" },
    { 0x04, "22050 Hz" },
    { 0x05, "24000 Hz" },
    { 0x06, "32000 Hz" },
    { 0x07, "44100 Hz" },
    { 0x08, "48000 Hz" },
    { 0x09, "88200 Hz" },
    { 0x0A, "96000 Hz" },
    { 0x0B, "176400 Hz" },
    { 0x0C, "192000 Hz" },
    { 0x0D, "384000 Hz" },
    { 0, NULL }
};

static const value_string le_audio_frame_duration_vals[] = {
    { 0x00, "7.5 ms" },
    { 0x01, "10 ms" },
    { 0, NULL }
};

static const value_string le_audio_parental_rating_vals[] = {
    { 0x00, "No rating" },
    { 0x01, "Any age" },
    { 0x02, "Age 5 or above" },
    { 0x03, "Age 6 or above" },
    { 0x04, "Age 7 or above" },
    { 0x05, "Age 8 or above" },
    { 0x06, "Age 9 or above" },
    { 0x07, "Age 10 or above" },
    { 0x08, "Age 11 or above" },
    { 0x09, "Age 12 or above" },
    { 0x0A, "Age 13 or above" },
    { 0x0B, "Age 14 or above" },
    { 0x0C, "Age 15 or above" },
    { 0x0D, "Age 16 or above" },
    { 0x0E, "Age 17 or above" },
    { 0x0F, "Age 18 or above" },
    { 0, NULL }
};

static const value_string le_audio_audio_active_state_vals[] = {
    { 0x00, "No audio data is being transmitted" },
    { 0x01, "Audio data is being transmitted" },
    { 0, NULL }
};

static const value_string le_audio_assisted_listening_stream_vals[] = {
    { 0x00, "Unspecified audio enhancement" },
    { 0, NULL }
};

static int * const le_audio_location_bits[] = {
    &hf_btad_le_audio_location_front_left,
    &hf_btad_le_audio_location_front_right,
    &hf_btad_le_audio_location_front_center,
    &hf_btad_le_audio_location_low_frequency_effects_1,
    &hf_btad_le_audio_location_back_left,
    &hf_btad_le_audio_location_back_right,
    &hf_btad_le_audio_location_front_left_of_center,
    &hf_btad_le_audio_location_front_right_of_center,
    &hf_btad_le_audio_location_back_center,
    &hf_btad_le_audio_location_low_frequency_effects_2,
    &hf_btad_le_audio_location_side_left,
    &hf_btad_le_audio_location_side_right,
    &hf_btad_le_audio_location_top_front_left,
    &hf_btad_le_audio_location_top_front_right,
    &hf_btad_le_audio_location_top_front_center,
    &hf_btad_le_audio_location_top_center,
    &hf_btad_le_audio_location_top_back_left,
    &hf_btad_le_audio_location_top_back_right,
    &hf_btad_le_audio_location_top_side_left,
    &hf_btad_le_audio_location_top_side_right,
    &hf_btad_le_audio_location_top_back_center,
    &hf_btad_le_audio_location_bottom_front_center,
    &hf_btad_le_audio_location_bottom_front_left,
    &hf_btad_le_audio_location_bottom_front_right,
    &hf_btad_le_audio_location_front_left_wide,
    &hf_btad_le_audio_location_front_right_wide,
    &hf_btad_le_audio_location_left_surround,
    &hf_btad_le_audio_location_right_surround,
    &hf_btad_le_audio_location_reserved,
    NULL
};

static int * const le_audio_context_bits[] = {
    &hf_btad_le_audio_context_unspecified,
    &hf_btad_le_audio_context_conversational,
    &hf_btad_le_audio_context_media,
    &hf_btad_le_audio_context_game,
    &hf_btad_le_audio_context_instructional,
    &hf_btad_le_audio_context_voice_assistants,
    &hf_btad_le_audio_context_live,
    &hf_btad_le_audio_context_sound_effects,
    &hf_btad_le_audio_context_notifications,
    &hf_btad_le_audio_context_ringtone,
    &hf_btad_le_audio_context_alerts,
    &hf_btad_le_audio_context_emergency_alarm,
    &hf_btad_le_audio_context_reserved,
    NULL
};
```

- [ ] **Step 6: Add the length check and the LTV walker**

```c
/* True when len octets remain at offset. Otherwise flags the count or length
 * that promised them, and returns false.
 */
static bool
le_audio_fits(tvbuff_t *tvb, packet_info *pinfo, proto_item *culprit, unsigned offset, unsigned len)
{
    if (tvb_reported_length_remaining(tvb, offset) >= len)
        return true;

    expert_add_info(pinfo, culprit, &ei_btad_le_audio_length_overrun);
    return false;
}

/* The value of one Codec_Specific_Configuration structure. len_item is the
 * LTV's length, which is what gets flagged when the value is the wrong size.
 */
static void
le_audio_codec_config_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_item *len_item, unsigned type, unsigned offset, unsigned length)
{
    unsigned expected;

    switch (type) {
    case LE_AUDIO_CODEC_CONFIG_SAMPLING_FREQUENCY:
    case LE_AUDIO_CODEC_CONFIG_FRAME_DURATION:
    case LE_AUDIO_CODEC_CONFIG_FRAME_BLOCKS_PER_SDU:
        expected = 1;
        break;
    case LE_AUDIO_CODEC_CONFIG_OCTETS_PER_CODEC_FRAME:
        expected = 2;
        break;
    case LE_AUDIO_CODEC_CONFIG_AUDIO_CHANNEL_ALLOCATION:
        expected = 4;
        break;
    default:
        if (length > 0)
            proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset, length, ENC_NA);
        return;
    }

    if (length != expected) {
        expert_add_info(pinfo, len_item, &ei_btad_le_audio_ltv_bad_length);
        if (length > 0)
            proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset, length, ENC_NA);
        return;
    }

    switch (type) {
    case LE_AUDIO_CODEC_CONFIG_SAMPLING_FREQUENCY:
        proto_tree_add_item(tree, hf_btad_le_audio_sampling_frequency, tvb, offset, 1, ENC_NA);
        break;
    case LE_AUDIO_CODEC_CONFIG_FRAME_DURATION:
        proto_tree_add_item(tree, hf_btad_le_audio_frame_duration, tvb, offset, 1, ENC_NA);
        break;
    case LE_AUDIO_CODEC_CONFIG_AUDIO_CHANNEL_ALLOCATION:
        proto_tree_add_bitmask(tree, tvb, offset, hf_btad_le_audio_audio_channel_allocation,
                ett_btad_le_audio_location, le_audio_location_bits, ENC_LITTLE_ENDIAN);
        break;
    case LE_AUDIO_CODEC_CONFIG_OCTETS_PER_CODEC_FRAME:
        proto_tree_add_item(tree, hf_btad_le_audio_octets_per_codec_frame, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        break;
    case LE_AUDIO_CODEC_CONFIG_FRAME_BLOCKS_PER_SDU:
        proto_tree_add_item(tree, hf_btad_le_audio_codec_frame_blocks_per_sdu, tvb, offset, 1, ENC_NA);
        break;
    }
}

/* The value of one Metadata structure. */
static void
le_audio_metadata_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_item *len_item, unsigned type, unsigned offset, unsigned length)
{
    unsigned expected;
    unsigned i;

    switch (type) {
    case LE_AUDIO_METADATA_PREFERRED_AUDIO_CONTEXTS:
    case LE_AUDIO_METADATA_STREAMING_AUDIO_CONTEXTS:
        expected = 2;
        break;
    case LE_AUDIO_METADATA_LANGUAGE:
        expected = 3;
        break;
    case LE_AUDIO_METADATA_PARENTAL_RATING:
    case LE_AUDIO_METADATA_AUDIO_ACTIVE_STATE:
    case LE_AUDIO_METADATA_ASSISTED_LISTENING_STREAM:
        expected = 1;
        break;
    case LE_AUDIO_METADATA_IMMEDIATE_RENDERING:
        expected = 0;
        break;
    case LE_AUDIO_METADATA_PROGRAM_INFO:
        proto_tree_add_item(tree, hf_btad_le_audio_program_info, tvb, offset, length, ENC_UTF_8);
        return;
    case LE_AUDIO_METADATA_PROGRAM_INFO_URI:
        proto_tree_add_item(tree, hf_btad_le_audio_program_info_uri, tvb, offset, length, ENC_UTF_8);
        return;
    case LE_AUDIO_METADATA_BROADCAST_NAME:
        proto_tree_add_item(tree, hf_btad_le_audio_broadcast_name, tvb, offset, length, ENC_UTF_8);
        return;
    case LE_AUDIO_METADATA_CCID_LIST:
        for (i = 0; i < length; i++)
            proto_tree_add_item(tree, hf_btad_le_audio_ccid, tvb, offset + i, 1, ENC_NA);
        return;
    case LE_AUDIO_METADATA_EXTENDED:
    case LE_AUDIO_METADATA_VENDOR:
        if (length < 2) {
            expert_add_info(pinfo, len_item, &ei_btad_le_audio_ltv_bad_length);
            if (length > 0)
                proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset, length, ENC_NA);
            return;
        }
        if (type == LE_AUDIO_METADATA_EXTENDED)
            proto_tree_add_item(tree, hf_btad_le_audio_extended_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(tree, hf_btad_le_audio_vendor_company_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        if (length > 2)
            proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset + 2, length - 2, ENC_NA);
        return;
    default:
        if (length > 0)
            proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset, length, ENC_NA);
        return;
    }

    if (length != expected) {
        expert_add_info(pinfo, len_item, &ei_btad_le_audio_ltv_bad_length);
        if (length > 0)
            proto_tree_add_item(tree, hf_btad_le_audio_ltv_value, tvb, offset, length, ENC_NA);
        return;
    }

    switch (type) {
    case LE_AUDIO_METADATA_PREFERRED_AUDIO_CONTEXTS:
        proto_tree_add_bitmask(tree, tvb, offset, hf_btad_le_audio_preferred_audio_contexts,
                ett_btad_le_audio_contexts, le_audio_context_bits, ENC_LITTLE_ENDIAN);
        break;
    case LE_AUDIO_METADATA_STREAMING_AUDIO_CONTEXTS:
        proto_tree_add_bitmask(tree, tvb, offset, hf_btad_le_audio_streaming_audio_contexts,
                ett_btad_le_audio_contexts, le_audio_context_bits, ENC_LITTLE_ENDIAN);
        break;
    case LE_AUDIO_METADATA_LANGUAGE:
        proto_tree_add_item(tree, hf_btad_le_audio_language, tvb, offset, 3, ENC_UTF_8);
        break;
    case LE_AUDIO_METADATA_PARENTAL_RATING:
        proto_tree_add_item(tree, hf_btad_le_audio_parental_rating, tvb, offset, 1, ENC_NA);
        break;
    case LE_AUDIO_METADATA_AUDIO_ACTIVE_STATE:
        proto_tree_add_item(tree, hf_btad_le_audio_audio_active_state, tvb, offset, 1, ENC_NA);
        break;
    case LE_AUDIO_METADATA_ASSISTED_LISTENING_STREAM:
        proto_tree_add_item(tree, hf_btad_le_audio_assisted_listening_stream, tvb, offset, 1, ENC_NA);
        break;
    case LE_AUDIO_METADATA_IMMEDIATE_RENDERING:
        proto_tree_add_item(tree, hf_btad_le_audio_immediate_rendering, tvb, offset, 0, ENC_NA);
        break;
    }
}

/* Walks the LTV structures in [offset, offset + length). The caller has
 * checked that those octets are there.
 */
static void
dissect_le_audio_ltvs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        unsigned offset, unsigned length, le_audio_ltv_kind_t kind)
{
    unsigned end = offset + length;

    while (offset < end) {
        proto_item *ltv_item;
        proto_item *len_item;
        proto_tree *ltv_tree;
        unsigned ltv_length;
        unsigned type;
        unsigned value_length;

        ltv_length = tvb_get_uint8(tvb, offset);
        ltv_tree = proto_tree_add_subtree(tree, tvb, offset,
                MIN(1 + ltv_length, end - offset), ett_btad_le_audio_ltv, &ltv_item, "LTV");
        len_item = proto_tree_add_item(ltv_tree, hf_btad_le_audio_ltv_length, tvb, offset, 1, ENC_NA);

        if (1 + ltv_length > end - offset) {
            expert_add_info(pinfo, len_item, &ei_btad_le_audio_length_overrun);
            return;
        }
        offset += 1;

        if (ltv_length == 0) {
            /* No room for a type: an empty structure, and nothing to show. */
            proto_item_append_text(ltv_item, ": empty");
            continue;
        }

        type = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(ltv_tree,
                kind == LE_AUDIO_LTV_CODEC_CONFIG ? hf_btad_le_audio_codec_config_type
                                                  : hf_btad_le_audio_metadata_type,
                tvb, offset, 1, ENC_NA);
        proto_item_append_text(ltv_item, ": %s", val_to_str_const(type,
                kind == LE_AUDIO_LTV_CODEC_CONFIG ? le_audio_codec_config_type_vals
                                                  : le_audio_metadata_type_vals,
                "Unknown"));
        offset += 1;
        value_length = ltv_length - 1;

        if (kind == LE_AUDIO_LTV_CODEC_CONFIG)
            le_audio_codec_config_value(tvb, pinfo, ltv_tree, len_item, type, offset, value_length);
        else
            le_audio_metadata_value(tvb, pinfo, ltv_tree, len_item, type, offset, value_length);

        offset += value_length;
    }
}
```

- [ ] **Step 7: Add the BASE structure itself**

```c
/* Codec_ID: coding format, company ID, vendor codec ID. Returns the coding
 * format, which decides how the configuration that follows is read.
 */
static uint32_t
dissect_le_audio_codec_id(tvbuff_t *tvb, proto_tree *tree, unsigned offset)
{
    uint32_t coding_format;

    proto_tree_add_item_ret_uint(tree, hf_btad_le_audio_coding_format, tvb, offset, 1, ENC_NA, &coding_format);
    proto_tree_add_item(tree, hf_btad_le_audio_company_id, tvb, offset + 1, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_btad_le_audio_vendor_codec_id, tvb, offset + 3, 2, ENC_LITTLE_ENDIAN);

    return coding_format;
}

/* Codec_Specific_Configuration_Length and what it covers. The caller has
 * checked that the length octet is there.
 */
static bool
dissect_le_audio_codec_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        unsigned *offset, uint32_t coding_format)
{
    proto_item *len_item;
    uint32_t length;

    len_item = proto_tree_add_item_ret_uint(tree, hf_btad_le_audio_codec_config_length,
            tvb, *offset, 1, ENC_NA, &length);
    *offset += 1;

    if (!le_audio_fits(tvb, pinfo, len_item, *offset, length))
        return false;

    if (length > 0) {
        if (coding_format == LE_AUDIO_CODING_FORMAT_LC3)
            dissect_le_audio_ltvs(tvb, pinfo, tree, *offset, length, LE_AUDIO_LTV_CODEC_CONFIG);
        else
            /* Any other codec defines its own layout. */
            proto_tree_add_item(tree, hf_btad_le_audio_codec_config_raw, tvb, *offset, length, ENC_NA);
    }

    *offset += length;
    return true;
}

/* Metadata_Length and what it covers. The caller has checked that the length
 * octet is there.
 */
static bool
dissect_le_audio_metadata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset)
{
    proto_item *len_item;
    uint32_t length;

    len_item = proto_tree_add_item_ret_uint(tree, hf_btad_le_audio_metadata_length,
            tvb, *offset, 1, ENC_NA, &length);
    *offset += 1;

    if (!le_audio_fits(tvb, pinfo, len_item, *offset, length))
        return false;

    dissect_le_audio_ltvs(tvb, pinfo, tree, *offset, length, LE_AUDIO_LTV_METADATA);
    *offset += length;
    return true;
}

/* One subgroup: its streams' shared codec and metadata, then each stream. */
static bool
dissect_le_audio_subgroup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_item *count_item, unsigned *offset, unsigned index)
{
    proto_item *subgroup_item;
    proto_item *num_bis_item;
    proto_tree *subgroup_tree;
    uint32_t coding_format;
    uint32_t num_bis;
    uint32_t i;

    /* Num_BIS, Codec_ID and Codec_Specific_Configuration_Length. */
    if (!le_audio_fits(tvb, pinfo, count_item, *offset, 1 + 5 + 1))
        return false;

    subgroup_item = proto_tree_add_none_format(tree, hf_btad_le_audio_subgroup, tvb, *offset, -1,
            "Subgroup %u", index);
    subgroup_tree = proto_item_add_subtree(subgroup_item, ett_btad_le_audio_subgroup);

    num_bis_item = proto_tree_add_item_ret_uint(subgroup_tree, hf_btad_le_audio_subgroup_num_bis,
            tvb, *offset, 1, ENC_NA, &num_bis);
    *offset += 1;

    coding_format = dissect_le_audio_codec_id(tvb, subgroup_tree, *offset);
    *offset += 5;

    if (!dissect_le_audio_codec_config(tvb, pinfo, subgroup_tree, offset, coding_format))
        return false;

    if (!le_audio_fits(tvb, pinfo, subgroup_item, *offset, 1))
        return false;
    if (!dissect_le_audio_metadata(tvb, pinfo, subgroup_tree, offset))
        return false;

    for (i = 0; i < num_bis; i++) {
        proto_item *bis_item;
        proto_tree *bis_tree;
        uint32_t bis_index;

        /* BIS_index and Codec_Specific_Configuration_Length. */
        if (!le_audio_fits(tvb, pinfo, num_bis_item, *offset, 2))
            return false;

        bis_item = proto_tree_add_item(subgroup_tree, hf_btad_le_audio_bis, tvb, *offset, -1, ENC_NA);
        bis_tree = proto_item_add_subtree(bis_item, ett_btad_le_audio_bis);

        proto_tree_add_item_ret_uint(bis_tree, hf_btad_le_audio_bis_index, tvb, *offset, 1, ENC_NA, &bis_index);
        proto_item_append_text(bis_item, " %u", bis_index);
        *offset += 1;

        if (!dissect_le_audio_codec_config(tvb, pinfo, bis_tree, offset, coding_format))
            return false;

        proto_item_set_end(bis_item, tvb, *offset);
    }

    proto_item_set_end(subgroup_item, tvb, *offset);
    return true;
}

static int
dissect_btad_le_audio_base(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *main_item;
    proto_item *count_item;
    proto_tree *main_tree;
    unsigned offset = 0;
    uint32_t num_subgroups;
    uint32_t i;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": Basic Audio Announcement");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    /* Presentation_Delay and Num_Subgroups. */
    if (!le_audio_fits(tvb, pinfo, main_item, offset, 3 + 1))
        return tvb_captured_length(tvb);

    proto_tree_add_item(main_tree, hf_btad_le_audio_presentation_delay, tvb, offset, 3, ENC_LITTLE_ENDIAN);
    offset += 3;
    count_item = proto_tree_add_item_ret_uint(main_tree, hf_btad_le_audio_num_subgroups,
            tvb, offset, 1, ENC_NA, &num_subgroups);
    offset += 1;

    for (i = 0; i < num_subgroups; i++) {
        if (!dissect_le_audio_subgroup(tvb, pinfo, main_tree, count_item, &offset, i))
            break;
    }

    return tvb_captured_length(tvb);
}
```

- [ ] **Step 8: Register the protocol**

```c
void
proto_register_btad_le_audio(void)
{
    static hf_register_info hf[] = {
        { &hf_btad_le_audio_presentation_delay,
          { "Presentation Delay", "bluetooth.le_audio.base.presentation_delay",
            FT_UINT24, BASE_DEC|BASE_UNIT_STRING, UNS(&units_microsecond_microseconds), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_num_subgroups,
          { "Number of Subgroups", "bluetooth.le_audio.base.num_subgroups",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_subgroup,
          { "Subgroup", "bluetooth.le_audio.base.subgroup",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_subgroup_num_bis,
          { "Number of BIS", "bluetooth.le_audio.base.subgroup.num_bis",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_coding_format,
          { "Coding Format", "bluetooth.le_audio.codec_id.coding_format",
            FT_UINT8, BASE_HEX, VALS(bthci_evt_codec_id_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_company_id,
          { "Company ID", "bluetooth.le_audio.codec_id.company_id",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_vendor_codec_id,
          { "Vendor Codec ID", "bluetooth.le_audio.codec_id.vendor_codec_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_codec_config_length,
          { "Codec Specific Configuration Length", "bluetooth.le_audio.codec_config.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_codec_config_raw,
          { "Codec Specific Configuration", "bluetooth.le_audio.codec_config.raw",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Configuration for a codec whose layout the vendor defines", HFILL }
        },
        { &hf_btad_le_audio_codec_config_type,
          { "Type", "bluetooth.le_audio.codec_config.type",
            FT_UINT8, BASE_HEX, VALS(le_audio_codec_config_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_metadata_length,
          { "Metadata Length", "bluetooth.le_audio.metadata.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_metadata_type,
          { "Type", "bluetooth.le_audio.metadata.type",
            FT_UINT8, BASE_HEX, VALS(le_audio_metadata_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_bis,
          { "BIS", "bluetooth.le_audio.base.bis",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_bis_index,
          { "BIS Index", "bluetooth.le_audio.base.bis.index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_ltv_length,
          { "Length", "bluetooth.le_audio.ltv.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_ltv_value,
          { "Value", "bluetooth.le_audio.ltv.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_sampling_frequency,
          { "Sampling Frequency", "bluetooth.le_audio.codec_config.sampling_frequency",
            FT_UINT8, BASE_HEX, VALS(le_audio_sampling_frequency_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_frame_duration,
          { "Frame Duration", "bluetooth.le_audio.codec_config.frame_duration",
            FT_UINT8, BASE_HEX, VALS(le_audio_frame_duration_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_audio_channel_allocation,
          { "Audio Channel Allocation", "bluetooth.le_audio.codec_config.audio_channel_allocation",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_octets_per_codec_frame,
          { "Octets per Codec Frame", "bluetooth.le_audio.codec_config.octets_per_codec_frame",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_codec_frame_blocks_per_sdu,
          { "Codec Frame Blocks per SDU", "bluetooth.le_audio.codec_config.codec_frame_blocks_per_sdu",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_preferred_audio_contexts,
          { "Preferred Audio Contexts", "bluetooth.le_audio.metadata.preferred_audio_contexts",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_streaming_audio_contexts,
          { "Streaming Audio Contexts", "bluetooth.le_audio.metadata.streaming_audio_contexts",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_program_info,
          { "Program Info", "bluetooth.le_audio.metadata.program_info",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_language,
          { "Language", "bluetooth.le_audio.metadata.language",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "An ISO 639-3 language code", HFILL }
        },
        { &hf_btad_le_audio_ccid,
          { "CCID", "bluetooth.le_audio.metadata.ccid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_parental_rating,
          { "Parental Rating", "bluetooth.le_audio.metadata.parental_rating",
            FT_UINT8, BASE_HEX, VALS(le_audio_parental_rating_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_program_info_uri,
          { "Program Info URI", "bluetooth.le_audio.metadata.program_info_uri",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_audio_active_state,
          { "Audio Active State", "bluetooth.le_audio.metadata.audio_active_state",
            FT_UINT8, BASE_HEX, VALS(le_audio_audio_active_state_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_immediate_rendering,
          { "Broadcast Audio Immediate Rendering", "bluetooth.le_audio.metadata.broadcast_audio_immediate_rendering",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Present when the broadcast is meant to be rendered immediately", HFILL }
        },
        { &hf_btad_le_audio_assisted_listening_stream,
          { "Assisted Listening Stream", "bluetooth.le_audio.metadata.assisted_listening_stream",
            FT_UINT8, BASE_HEX, VALS(le_audio_assisted_listening_stream_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_broadcast_name,
          { "Broadcast Name", "bluetooth.le_audio.metadata.broadcast_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_extended_type,
          { "Extended Metadata Type", "bluetooth.le_audio.metadata.extended_type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_vendor_company_id,
          { "Company ID", "bluetooth.le_audio.metadata.vendor_company_id",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING, &bluetooth_company_id_vals_ext, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info hf_location[] = {
        { &hf_btad_le_audio_location_front_left,
          { "Front Left", "bluetooth.le_audio.audio_location.front_left",
            FT_BOOLEAN, 32, NULL, 0x00000001, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_right,
          { "Front Right", "bluetooth.le_audio.audio_location.front_right",
            FT_BOOLEAN, 32, NULL, 0x00000002, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_center,
          { "Front Center", "bluetooth.le_audio.audio_location.front_center",
            FT_BOOLEAN, 32, NULL, 0x00000004, NULL, HFILL } },
        { &hf_btad_le_audio_location_low_frequency_effects_1,
          { "Low Frequency Effects 1", "bluetooth.le_audio.audio_location.low_frequency_effects_1",
            FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL } },
        { &hf_btad_le_audio_location_back_left,
          { "Back Left", "bluetooth.le_audio.audio_location.back_left",
            FT_BOOLEAN, 32, NULL, 0x00000010, NULL, HFILL } },
        { &hf_btad_le_audio_location_back_right,
          { "Back Right", "bluetooth.le_audio.audio_location.back_right",
            FT_BOOLEAN, 32, NULL, 0x00000020, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_left_of_center,
          { "Front Left of Center", "bluetooth.le_audio.audio_location.front_left_of_center",
            FT_BOOLEAN, 32, NULL, 0x00000040, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_right_of_center,
          { "Front Right of Center", "bluetooth.le_audio.audio_location.front_right_of_center",
            FT_BOOLEAN, 32, NULL, 0x00000080, NULL, HFILL } },
        { &hf_btad_le_audio_location_back_center,
          { "Back Center", "bluetooth.le_audio.audio_location.back_center",
            FT_BOOLEAN, 32, NULL, 0x00000100, NULL, HFILL } },
        { &hf_btad_le_audio_location_low_frequency_effects_2,
          { "Low Frequency Effects 2", "bluetooth.le_audio.audio_location.low_frequency_effects_2",
            FT_BOOLEAN, 32, NULL, 0x00000200, NULL, HFILL } },
        { &hf_btad_le_audio_location_side_left,
          { "Side Left", "bluetooth.le_audio.audio_location.side_left",
            FT_BOOLEAN, 32, NULL, 0x00000400, NULL, HFILL } },
        { &hf_btad_le_audio_location_side_right,
          { "Side Right", "bluetooth.le_audio.audio_location.side_right",
            FT_BOOLEAN, 32, NULL, 0x00000800, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_front_left,
          { "Top Front Left", "bluetooth.le_audio.audio_location.top_front_left",
            FT_BOOLEAN, 32, NULL, 0x00001000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_front_right,
          { "Top Front Right", "bluetooth.le_audio.audio_location.top_front_right",
            FT_BOOLEAN, 32, NULL, 0x00002000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_front_center,
          { "Top Front Center", "bluetooth.le_audio.audio_location.top_front_center",
            FT_BOOLEAN, 32, NULL, 0x00004000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_center,
          { "Top Center", "bluetooth.le_audio.audio_location.top_center",
            FT_BOOLEAN, 32, NULL, 0x00008000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_back_left,
          { "Top Back Left", "bluetooth.le_audio.audio_location.top_back_left",
            FT_BOOLEAN, 32, NULL, 0x00010000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_back_right,
          { "Top Back Right", "bluetooth.le_audio.audio_location.top_back_right",
            FT_BOOLEAN, 32, NULL, 0x00020000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_side_left,
          { "Top Side Left", "bluetooth.le_audio.audio_location.top_side_left",
            FT_BOOLEAN, 32, NULL, 0x00040000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_side_right,
          { "Top Side Right", "bluetooth.le_audio.audio_location.top_side_right",
            FT_BOOLEAN, 32, NULL, 0x00080000, NULL, HFILL } },
        { &hf_btad_le_audio_location_top_back_center,
          { "Top Back Center", "bluetooth.le_audio.audio_location.top_back_center",
            FT_BOOLEAN, 32, NULL, 0x00100000, NULL, HFILL } },
        { &hf_btad_le_audio_location_bottom_front_center,
          { "Bottom Front Center", "bluetooth.le_audio.audio_location.bottom_front_center",
            FT_BOOLEAN, 32, NULL, 0x00200000, NULL, HFILL } },
        { &hf_btad_le_audio_location_bottom_front_left,
          { "Bottom Front Left", "bluetooth.le_audio.audio_location.bottom_front_left",
            FT_BOOLEAN, 32, NULL, 0x00400000, NULL, HFILL } },
        { &hf_btad_le_audio_location_bottom_front_right,
          { "Bottom Front Right", "bluetooth.le_audio.audio_location.bottom_front_right",
            FT_BOOLEAN, 32, NULL, 0x00800000, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_left_wide,
          { "Front Left Wide", "bluetooth.le_audio.audio_location.front_left_wide",
            FT_BOOLEAN, 32, NULL, 0x01000000, NULL, HFILL } },
        { &hf_btad_le_audio_location_front_right_wide,
          { "Front Right Wide", "bluetooth.le_audio.audio_location.front_right_wide",
            FT_BOOLEAN, 32, NULL, 0x02000000, NULL, HFILL } },
        { &hf_btad_le_audio_location_left_surround,
          { "Left Surround", "bluetooth.le_audio.audio_location.left_surround",
            FT_BOOLEAN, 32, NULL, 0x04000000, NULL, HFILL } },
        { &hf_btad_le_audio_location_right_surround,
          { "Right Surround", "bluetooth.le_audio.audio_location.right_surround",
            FT_BOOLEAN, 32, NULL, 0x08000000, NULL, HFILL } },
        { &hf_btad_le_audio_location_reserved,
          { "Reserved", "bluetooth.le_audio.audio_location.reserved",
            FT_BOOLEAN, 32, NULL, 0xF0000000, NULL, HFILL } },
    };

    static hf_register_info hf_context[] = {
        { &hf_btad_le_audio_context_unspecified,
          { "Unspecified", "bluetooth.le_audio.context.unspecified",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL } },
        { &hf_btad_le_audio_context_conversational,
          { "Conversational", "bluetooth.le_audio.context.conversational",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL } },
        { &hf_btad_le_audio_context_media,
          { "Media", "bluetooth.le_audio.context.media",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL } },
        { &hf_btad_le_audio_context_game,
          { "Game", "bluetooth.le_audio.context.game",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL } },
        { &hf_btad_le_audio_context_instructional,
          { "Instructional", "bluetooth.le_audio.context.instructional",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL } },
        { &hf_btad_le_audio_context_voice_assistants,
          { "Voice Assistants", "bluetooth.le_audio.context.voice_assistants",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL } },
        { &hf_btad_le_audio_context_live,
          { "Live", "bluetooth.le_audio.context.live",
            FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL } },
        { &hf_btad_le_audio_context_sound_effects,
          { "Sound Effects", "bluetooth.le_audio.context.sound_effects",
            FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL } },
        { &hf_btad_le_audio_context_notifications,
          { "Notifications", "bluetooth.le_audio.context.notifications",
            FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL } },
        { &hf_btad_le_audio_context_ringtone,
          { "Ringtone", "bluetooth.le_audio.context.ringtone",
            FT_BOOLEAN, 16, NULL, 0x0200, NULL, HFILL } },
        { &hf_btad_le_audio_context_alerts,
          { "Alerts", "bluetooth.le_audio.context.alerts",
            FT_BOOLEAN, 16, NULL, 0x0400, NULL, HFILL } },
        { &hf_btad_le_audio_context_emergency_alarm,
          { "Emergency Alarm", "bluetooth.le_audio.context.emergency_alarm",
            FT_BOOLEAN, 16, NULL, 0x0800, NULL, HFILL } },
        { &hf_btad_le_audio_context_reserved,
          { "Reserved", "bluetooth.le_audio.context.reserved",
            FT_BOOLEAN, 16, NULL, 0xF000, NULL, HFILL } },
    };

    static ei_register_info ei[] = {
        { &ei_btad_le_audio_length_overrun,
          { "bluetooth.le_audio.length_overrun", PI_MALFORMED, PI_ERROR,
            "A declared length or count runs past the end of the announcement", EXPFILL }
        },
        { &ei_btad_le_audio_ltv_bad_length,
          { "bluetooth.le_audio.ltv.bad_length", PI_PROTOCOL, PI_WARN,
            "This type's value is not the size the specification fixes for it", EXPFILL }
        },
    };

    static int *ett[] = {
        &ett_btad_le_audio,
        &ett_btad_le_audio_subgroup,
        &ett_btad_le_audio_bis,
        &ett_btad_le_audio_ltv,
        &ett_btad_le_audio_location,
        &ett_btad_le_audio_contexts,
    };

    expert_module_t *expert_btad_le_audio;

    proto_btad_le_audio = proto_register_protocol("Bluetooth LE Audio Broadcast Announcements",
            "LE Audio Announcement", "bluetooth.le_audio");
    proto_register_field_array(proto_btad_le_audio, hf, array_length(hf));
    proto_register_field_array(proto_btad_le_audio, hf_location, array_length(hf_location));
    proto_register_field_array(proto_btad_le_audio, hf_context, array_length(hf_context));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btad_le_audio = expert_register_protocol(proto_btad_le_audio);
    expert_register_field_array(expert_btad_le_audio, ei, array_length(ei));

    btad_le_audio_base = register_dissector("bluetooth.le_audio.base", dissect_btad_le_audio_base,
            proto_btad_le_audio);
}

void
proto_reg_handoff_btad_le_audio(void)
{
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1851", btad_le_audio_base);
}
```

- [ ] **Step 9: Build and run every LE Audio test**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | tail -5 && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -8'
```

Expected: a clean build, then all of them pass, including the bad-input tests from Step 1. If any fails, fix the dissector rather than the test, and rerun.

- [ ] **Step 10: See it with your own eyes once**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ./run/tshark -r ../wireshark/test/captures/bt-le-audio-bap-broadcast.pcapng -Y "bluetooth.le_audio" -V -c 1 | sed -n "/LE Audio/,\$p" | head -40'
```

Expected: the announcement tree, with the delay, the subgroup, LC3, 16000 Hz, 10 ms, the channel allocation bits and both streams.

- [ ] **Step 11: Check nothing else broke**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: the whole dissection suite passes.

- [ ] **Step 12: Commit**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg2.txt <<MSG
Bluetooth: dissect the Basic Audio Announcement

A broadcast source describes its streams in a Basic Audio Announcement (BASE),
service data for UUID 0x1851 carried in its periodic advertising: the
presentation delay, the subgroups with their codec and metadata, and each
stream with its own configuration. It was shown as bytes.

Dissect it, including the LC3 codec configuration and the metadata as
length-type-value structures, with the audio locations and audio contexts
broken out as flags. A configuration for any other codec is vendor-defined
and stays bytes.

Lengths and counts come from the air, so each is checked against what remains
before it is used; an overrun is reported as an expert info rather than read.

Assisted-by: Claude Code (Claude Opus 5)
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
cd ~/src/wireshark && git add epan/dissectors/packet-bluetooth.c test/suite_dissection.py && git commit -F /tmp/msg2.txt && git log --oneline -1'
```


---

### Task 4: Commit 3 -- Broadcast Audio and Public Broadcast Announcements

**Files:**
- Create: `~/src/wireshark/test/captures/bt-le-audio-pbp-broadcast.pcapng`
- Modify: `~/src/wireshark/epan/dissectors/packet-bluetooth.c`
- Test: `~/src/wireshark/test/suite_dissection.py` (`TestDissectBluetoothLeAudio`)
- Create (throwaway, outside both repositories): a build of Zephyr's `pbp_public_broadcast_source` in `G:\dev\scratch\nrf\bpbp`

**Interfaces:**
- Consumes: `le_audio_fits`, `dissect_le_audio_metadata`, `proto_btad_le_audio`, `ett_btad_le_audio` from Task 3.
- Produces: the dissectors `dissect_btad_le_audio_broadcast` and `dissect_btad_le_audio_public_broadcast`, registered for `"1852"` and `"1856"`; the fixture `bt-le-audio-pbp-broadcast.pcapng` with 2 extended advertising reports from the Public Broadcast source.

- [ ] **Step 1: Write the failing test for the Broadcast ID**

Add to `TestDissectBluetoothLeAudio`:

```python
    def test_broadcast_id_from_a_real_broadcast(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-bap-broadcast.pcapng')
        assert len(self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.broadcast_id == 0x123456')) == 2
```

- [ ] **Step 2: Run it to verify it fails**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k test_broadcast_id --disable-capture --disable-gui -q 2>&1 | tail -5'
```

Expected: FAIL, the field is unknown.

- [ ] **Step 3: Add both dissectors**

In `packet-bluetooth.c`, add the declarations beside Task 3's:

```c
static int hf_btad_le_audio_broadcast_id;
static int hf_btad_le_audio_trailing_data;
static int hf_btad_le_audio_pba_features;
static int hf_btad_le_audio_pba_features_encrypted;
static int hf_btad_le_audio_pba_features_standard_quality;
static int hf_btad_le_audio_pba_features_high_quality;
static int hf_btad_le_audio_pba_features_reserved;

static int ett_btad_le_audio_pba_features;

static dissector_handle_t btad_le_audio_broadcast;
static dissector_handle_t btad_le_audio_public_broadcast;
```

Then, after `dissect_btad_le_audio_base()`:

```c
static int
dissect_btad_le_audio_broadcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned trailing;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": Broadcast Audio Announcement");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    if (!le_audio_fits(tvb, pinfo, main_item, 0, 3))
        return tvb_captured_length(tvb);

    proto_tree_add_item(main_tree, hf_btad_le_audio_broadcast_id, tvb, 0, 3, ENC_LITTLE_ENDIAN);

    trailing = tvb_reported_length_remaining(tvb, 3);
    if (trailing > 0)
        proto_tree_add_item(main_tree, hf_btad_le_audio_trailing_data, tvb, 3, trailing, ENC_NA);

    return tvb_captured_length(tvb);
}

static int
dissect_btad_le_audio_public_broadcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int * const features[] = {
        &hf_btad_le_audio_pba_features_encrypted,
        &hf_btad_le_audio_pba_features_standard_quality,
        &hf_btad_le_audio_pba_features_high_quality,
        &hf_btad_le_audio_pba_features_reserved,
        NULL
    };
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": Public Broadcast Announcement");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    /* The features, and the Metadata_Length that follows them. */
    if (!le_audio_fits(tvb, pinfo, main_item, offset, 2))
        return tvb_captured_length(tvb);

    proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_le_audio_pba_features,
            ett_btad_le_audio_pba_features, features, ENC_NA);
    offset += 1;

    dissect_le_audio_metadata(tvb, pinfo, main_tree, &offset);

    return tvb_captured_length(tvb);
}
```

- [ ] **Step 4: Register them**

Add to the `hf[]` array in `proto_register_btad_le_audio()`:

```c
        { &hf_btad_le_audio_broadcast_id,
          { "Broadcast ID", "bluetooth.le_audio.broadcast_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_trailing_data,
          { "Trailing Data", "bluetooth.le_audio.trailing_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_pba_features,
          { "Features", "bluetooth.le_audio.pba.features",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_pba_features_encrypted,
          { "Encrypted", "bluetooth.le_audio.pba.features.encrypted",
            FT_BOOLEAN, 8, NULL, 0x01,
            "Set when the streams need a Broadcast Code", HFILL }
        },
        { &hf_btad_le_audio_pba_features_standard_quality,
          { "Standard Quality Public Broadcast Audio", "bluetooth.le_audio.pba.features.standard_quality",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_pba_features_high_quality,
          { "High Quality Public Broadcast Audio", "bluetooth.le_audio.pba.features.high_quality",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_pba_features_reserved,
          { "Reserved", "bluetooth.le_audio.pba.features.reserved",
            FT_BOOLEAN, 8, NULL, 0xF8,
            NULL, HFILL }
        },
```

Add `&ett_btad_le_audio_pba_features,` to the `ett[]` array, and at the end of `proto_register_btad_le_audio()`:

```c
    btad_le_audio_broadcast = register_dissector("bluetooth.le_audio.broadcast",
            dissect_btad_le_audio_broadcast, proto_btad_le_audio);
    btad_le_audio_public_broadcast = register_dissector("bluetooth.le_audio.public_broadcast",
            dissect_btad_le_audio_public_broadcast, proto_btad_le_audio);
```

And in `proto_reg_handoff_btad_le_audio()`:

```c
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1852", btad_le_audio_broadcast);
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1856", btad_le_audio_public_broadcast);
```

- [ ] **Step 5: Build and run the Broadcast ID test**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | tail -5 && pytest ../wireshark/test/suite_dissection.py -k test_broadcast_id --disable-capture --disable-gui -q 2>&1 | tail -4'
```

Expected: PASS.

- [ ] **Step 6: Build the Public Broadcast source firmware**

This is throwaway firmware for a throwaway board, outside both repositories. It goes on the XIAO nRF54L15, which currently runs the `bap_broadcast_source` sample from the spec's measurement.

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad && sed 's#zephyr/samples/bluetooth/bap_broadcast_source#zephyr/samples/bluetooth/pbp_public_broadcast_source#; s#G:/dev/scratch/nrf/bsrc#G:/dev/scratch/nrf/bpbp#' $S/xiao_bsrc_build.ps1 > $S/xiao_pbp_build.ps1 && powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w $S/xiao_pbp_build.ps1)" 2>&1 | tail -5
```

Expected: a FLASH/RAM summary and no errors.

- [ ] **Step 7: Flash it and confirm it is broadcasting**

The flash script commits the RRAM write buffer, which NCS v3.4.0's own openocd script does not (see the nRF sniffer's README).

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad && PYTHONIOENCODING=utf-8 /g/dev/projects/esp32c6-sniffer/host/.venv/Scripts/python.exe $S/flash_and_watch.py "$(cygpath -w $S/xiao_flash_commit.ps1)" G:/dev/scratch/nrf/bpbp/zephyr/zephyr.hex 12 | sed 's/\x1b\[[0-9;]*m//g' | tail -20
```

Expected: `verified` from openocd, then the sample's console showing the broadcast starting.

- [ ] **Step 8: Capture it with the ESP32-C6**

```bash
cd /g/dev/projects/esp32c6-sniffer && timeout 30 host/.venv/Scripts/python.exe extcap/esp32c6-sniffer.py --capture --extcap-interface esp32c6-ble@COM3 --fifo G:/dev/scratch/nrf/pbp1.pcapng --ble-periodic; "/c/Program Files/Wireshark/tshark.exe" -r G:/dev/scratch/nrf/pbp1.pcapng -Y 'btcommon.eir_ad.entry.uuid_16 == 0x1856' -T fields -e frame.number -e bthci_evt.bd_addr | head -5
```

Expected: several frames, all from one address: the Public Broadcast source. If nothing appears, check the board's console again before going on.

- [ ] **Step 9: Trim to the fixture**

Use the address from Step 8 in place of `AA:BB:CC:DD:EE:FF`:

```bash
cd /g/dev/scratch/nrf && "/c/Program Files/Wireshark/tshark.exe" -r pbp1.pcapng -Y 'btcommon.eir_ad.entry.uuid_16 == 0x1856 && bthci_evt.bd_addr == AA:BB:CC:DD:EE:FF' -w pbp-all.pcapng && "/c/Program Files/Wireshark/editcap.exe" -r pbp-all.pcapng bt-le-audio-pbp-broadcast.pcapng 1-2 && "/c/Program Files/Wireshark/capinfos.exe" -c -E bt-le-audio-pbp-broadcast.pcapng
```

Expected: 2 packets.

- [ ] **Step 10: Read the values the test will assert**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cp /mnt/g/dev/scratch/nrf/bt-le-audio-pbp-broadcast.pcapng ~/src/wireshark/test/captures/ && cd ~/src/wsbuild && ./run/tshark -r ../wireshark/test/captures/bt-le-audio-pbp-broadcast.pcapng -T fields -e bluetooth.le_audio.pba.features -e bluetooth.le_audio.metadata.program_info -e bluetooth.le_audio.broadcast_id'
```

Expected, from the sample's source: features `0x04` (High Quality, not encrypted), program info `PBP`, and a Broadcast ID, which that sample randomises at each start. Note the Broadcast ID value for Step 11. If the features are not `0x04`, the board has restarted its broadcast more than once (the sample alternates quality on each start); reset it and recapture rather than writing a different value into the test.

- [ ] **Step 11: Write the Public Broadcast test**

Use the Broadcast ID from Step 10 in place of `0xNNNNNN`:

```python
    def test_public_broadcast_announcement(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-pbp-broadcast.pcapng')
        assert len(self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.pba.features.high_quality == 1'
                ' && bluetooth.le_audio.pba.features.encrypted == 0'
                ' && bluetooth.le_audio.metadata.program_info == "PBP"'
                ' && bluetooth.le_audio.broadcast_id == 0xNNNNNN')) == 2
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.malformed') == []
```

- [ ] **Step 12: Run the whole class, then the whole suite**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -5 && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: the LE Audio class passes, and so does the whole dissection suite.

- [ ] **Step 13: Commit**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg3.txt <<MSG
Bluetooth: dissect Broadcast and Public Broadcast Announcements

A broadcast source advertises a Broadcast Audio Announcement (UUID 0x1852)
holding the Broadcast ID a receiver uses to pick it out, and a public one may
add a Public Broadcast Announcement (UUID 0x1856) with its features and
metadata. Both were shown as service data bytes.

Dissect them, reusing the metadata decoding added for the Basic Audio
Announcement.

The capture is Zephyr pbp_public_broadcast_source, taken with an ESP32-C6
sniffer.

Assisted-by: Claude Code (Claude Opus 5)
Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
MSG
cd ~/src/wireshark && git add epan/dissectors/packet-bluetooth.c test/suite_dissection.py test/captures/bt-le-audio-pbp-broadcast.pcapng && git commit -F /tmp/msg3.txt && git log --oneline -3'
```

---

### Task 5: The checks upstream runs, and the patch series

**Files:**
- Modify (only if a check demands it): `~/src/wireshark/epan/dissectors/packet-bluetooth.c`, `~/src/wireshark/epan/dissectors/packet-bthci_evt.c`
- Create: `C:\Users\Work\AppData\Local\Temp\claude\G--dev-projects-esp32c6-sniffer\c6487d68-b757-46b6-adf7-eaf5cd7bc607\scratchpad\wireshark-le-audio\` (the patch series and the merge request description)

**Interfaces:**
- Consumes: the three commits from Tasks 2, 3 and 4.
- Produces: `0001-*.patch`, `0002-*.patch`, `0003-*.patch` and `merge-request.md` in the scratch folder.

- [ ] **Step 1: Run Wireshark's source checks on the changed files**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && tools/checkAPIs.pl epan/dissectors/packet-bluetooth.c epan/dissectors/packet-bthci_evt.c; tools/checkhf.pl epan/dissectors/packet-bluetooth.c; tools/checkfiltername.pl epan/dissectors/packet-bluetooth.c; python3 tools/check_typed_item_calls.py --file epan/dissectors/packet-bluetooth.c; python3 tools/check_spelling.py epan/dissectors/packet-bluetooth.c'
```

Expected: no errors. Fix anything reported, rebuild, rerun the LE Audio tests, and amend the commit the fix belongs to.

- [ ] **Step 2: Fuzz both captures**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ../wireshark/tools/fuzz-test.sh -b ./run -P 200 ../wireshark/test/captures/bt-le-audio-bap-broadcast.pcapng ../wireshark/test/captures/bt-le-audio-pbp-broadcast.pcapng 2>&1 | tail -10'
```

Expected: passes with no crash. A crash file, if any, is written by the script and names the input that caused it; fix the dissector and rerun.

- [ ] **Step 3: Confirm each commit builds and tests on its own**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && for rev in HEAD~2 HEAD~1 HEAD; do git checkout -q $rev -- . 2>/dev/null; git stash -q -u 2>/dev/null; git checkout -q $rev; cd ~/src/wsbuild && ninja tshark text2pcap >/dev/null 2>&1 && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -2; cd ~/src/wireshark; done; git checkout -q le-audio-broadcast'
```

Expected: each of the three checkouts builds and its tests pass. End back on `le-audio-broadcast`, which `git log --oneline -3` should confirm.

- [ ] **Step 4: Produce the patch series**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && mkdir -p /tmp/le-audio-patches && git format-patch -3 -o /tmp/le-audio-patches && ls /tmp/le-audio-patches' && mkdir -p "/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad/wireshark-le-audio" && wsl.exe -d Ubuntu-26.04 -- bash -lc 'cp /tmp/le-audio-patches/*.patch "/mnt/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad/wireshark-le-audio/"'
```

- [ ] **Step 5: Write the merge request description**

Write `scratchpad/wireshark-le-audio/merge-request.md`, filling in the `master` commit the branch is based on (from Task 1, Step 1) and the observed values from the captures:

```markdown
# Bluetooth: dissect LE Audio broadcast announcements

An LE Audio broadcast source announces itself in three service data
structures. Wireshark named the UUIDs but decoded none of their contents, and
the Basic Audio Announcement was invisible: it rides in periodic advertising,
whose data was added to the tree as one block of bytes rather than as the
advertising structures it holds.

This series dissects all three:

1. Periodic advertising data goes through the AD dissector, as extended
   advertising data already does. Only reports whose Data Status is Complete:
   a fragment of a chained report can end mid-structure, and reassembly by
   sync handle is left for later.
2. The Basic Audio Announcement (0x1851): presentation delay, subgroups,
   codec, LC3 configuration, metadata, and each stream.
3. The Broadcast Audio Announcement (0x1852) and Public Broadcast
   Announcement (0x1856).

## Testing

Two captures are included, both from Zephyr sample broadcasters recorded with
an ESP32-C6 sniffer, and `test/suite_dissection.py` gains a class that asserts
the decoded values. Hand-built frames cover a fragment, a version 2 report, an
overrunning length, an overrunning count, service data too short for its
header, an empty LTV, a wrongly sized value, and a vendor codec.

`tools/fuzz-test.sh` passes over both captures.

Based on master at <commit>.
```

- [ ] **Step 6: Show the user the series**

Print the file list and the subject lines, so the hand-off message can quote them:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git log --oneline -3 && git diff --stat HEAD~3'
```

---

### Task 6: Put the sniffer back on the XIAO

**Files:**
- None in either repository.

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a XIAO running the sniffer firmware again, answering on COM4.

- [ ] **Step 1: Flash the sniffer build**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad && powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w $S/nrf_flash_verify.ps1)" 2>&1 | grep -vE '^\s*$'
```

Expected: `downloaded` and `verified`, with no diff lines.

- [ ] **Step 2: Confirm it answers and captures**

```bash
cd /g/dev/projects/esp32c6-sniffer/host && timeout 50 .venv/Scripts/python.exe /c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/c6487d68-b757-46b6-adf7-eaf5cd7bc607/scratchpad/sniff_check.py
```

Expected: firmware 3 on both radios, and BLE records arriving. (802.15.4 counts depend on traffic: channel 25 carried it on 2026-09-19, channel 18 none.)

---

## After this plan

The spec's last piece waits on the user: once they open the merge request, `docs/using-wireshark.md` in this repository gains a note saying that periodic advertising data and the BASE show as raw bytes in Wireshark 4.6, that the fix is submitted upstream, and which filter fields to use once a release carries it. It needs the merge request's link, so it cannot be written before then.
