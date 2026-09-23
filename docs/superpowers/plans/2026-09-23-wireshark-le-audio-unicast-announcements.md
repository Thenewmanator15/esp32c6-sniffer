# Wireshark LE Audio Unicast Announcements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach Wireshark to decode what a connectable LE Audio device announces in its advertising — the ASCS and CAS announcements, its TMAP and GMAP roles, and the two halves of its Resolvable Set Identifier — and hand the change to the user as a second merge request series for upstream Wireshark.

**Architecture:** Three commits on a branch `le-audio-unicast` stacked on the existing `le-audio-broadcast` branch in the WSL clone. Commits 1 and 2 add four dissectors to the broadcast patch's `btad_le_audio` protocol in `packet-bluetooth.c`, registered on the `btcommon.eir_ad.entry.uuid` table for `"184e"`, `"1853"`, `"1855"` and `"1858"`, reusing its context bitmask, metadata decoder, overrun check and trailing-data helper. Commit 3 splits the RSI in the advertising-data parser in `packet-bthci_cmd.c`. Tests are Wireshark's own `test/suite_dissection.py`, over one capture from a Zephyr sample plus hand-built frames.

**Tech Stack:** C (Wireshark dissector APIs, `master` plus the broadcast patch), CMake + Ninja, Python/pytest (Wireshark's test suite), `text2pcap` for hand-built frames, WSL Ubuntu 26.04 for the build, Zephyr `tmap_peripheral` on the XIAO nRF54L15 and the ESP32-C6 sniffer for the capture.

**Spec:** `docs/superpowers/specs/2026-09-23-wireshark-le-audio-unicast-announcements-design.md`

## Global Constraints

- **Work happens in WSL**, in the clone `~/src/wireshark`, on a branch `le-audio-unicast` created from `le-audio-broadcast`. The build directory is `~/src/wsbuild`. Nothing in `G:\dev\projects\esp32c6-sniffer` or `G:\dev\projects\nrf54l15-sniffer` changes, except this plan and the spec.
- **The branch `le-audio-broadcast` is not modified.** Its three commits are the base; if review of that merge request changes them, this branch is rebased (Task 6) and follows the new names.
- **Filter prefix stays `bluetooth.le_audio`.** New fields: `bluetooth.le_audio.ascs.announcement_type`, `.ascs.available_sink_contexts`, `.ascs.available_source_contexts`, `.cas.announcement_type`, `.tmap.role` and `.tmap.role.{cg,ct,ums,umr,bms,bmr,reserved}`, `.gmap.role` and `.gmap.role.{ugg,ugt,bgs,bgr,reserved}`. RSI fields: `btcommon.eir_ad.entry.rsi.hash`, `btcommon.eir_ad.entry.rsi.prand`; expert info `btcommon.eir_ad.entry.rsi.bad_prand`. A wrong-length RSI reuses the existing `btcommon.eir_ad.invalid_length`.
- **Protocol is renamed** from "Bluetooth LE Audio Broadcast Announcements" to "Bluetooth LE Audio Announcements"; short name "LE Audio Announcement" and filter name unchanged.
- **UUID registration keys are the lowercase strings `"184e"`, `"1853"`, `"1855"`, `"1858"`.** The Hearing Access Service (`1854`) is not registered.
- **Bit meanings:** TMAP role bits 0-5 = CG, CT, UMS, UMR, BMS, BMR, bits 6-15 reserved; GMAP role bits 0-3 = UGG, UGT, BGS, BGR, bits 4-7 reserved; announcement type 0x00 General, 0x01 Targeted, 0x02-0xFF Reserved. Verified on 2026-09-23 against Zephyr v3.4.0's `tmap.h`, `gmap.h` and `audio.h`. If the current TMAP or GMAP edition defines more bits, the specification wins and the reserved mask shrinks.
- **RSI layout:** octets 0-2 hash, 3-5 prand, each 24-bit little-endian; prand's two most significant bits must be `01` (Zephyr `csip_set_member.c`, `generate_prand`).
- **Bad input never throws.** Every fixed field is checked with the broadcast patch's `le_audio_fits` before it is added. Overruns raise `bluetooth.le_audio.length_overrun`. Undecoded octets are shown with `le_audio_trailing_data`. Tests check `_ws.expert.message contains "Exception occurred"` is absent, as the broadcast tests do.
- **C style is Wireshark's:** 4-space indent, no tabs, declarations at the top of a block, `unsigned` offsets in `packet-bluetooth.c` (the RSI code lives in a function that uses `int` offsets; match it there).
- **Commit messages** follow `.gitmessage`: subject `<component>: <imperative summary>`, body wrapped at 72 columns, then `Assisted-by: Claude Code (Claude Opus 5.5)` and `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Re-read `.gitmessage` and `CONTRIBUTING.md` before the first commit in case the wording changed.
- **Nothing is posted anywhere.** No merge request, no push, no capture uploaded. The deliverable is a patch series on disk.
- **Session scratchpad** (`$S` below) is `C:\Users\Work\AppData\Local\Temp\claude\G--dev-projects-esp32c6-sniffer\6ebae47c-9929-43c2-a022-36794e0f6a03\scratchpad`, which Git Bash sees as `/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad`. This machine's locations live in two untracked files there: `$S/machine.sh` defines `NRF`, the throwaway build and capture directory outside both repositories, and `$S/machine.ps1` defines `$Tc` (toolchain), `$Ncs` (NCS v3.4.0 workspace), `$Nrf` and `$Ocd` (openocd). Commands below load one of them; the repository's privacy test forbids writing those paths into a tracked file.
- **Boards:** ESP32-C6 sniffer on COM3; XIAO nRF54L15 on COM4, currently running the nRF sniffer firmware, whose build is the directory `bcap` under `$NRF`. The local NCS v3.4.0 openocd script is patched to commit the last RRAM line; always flash the XIAO with `--verify`.

## Review Focus

- **ASCS metadata whose length runs past the service data.** The metadata decoder is shared, but ASCS reaches it by a new path. `Metadata_Length` 5 with three octets present must flag the overrun, show the three octets as trailing data, and not throw. Pinned by Task 2, Step 1 (`test_ascs_metadata_length_overruns`).
- **A TMAS payload of one octet.** The role is two octets. One octet must flag the overrun and show as trailing data, with no role field. Pinned by Task 3, Step 1 (`test_tmap_role_too_short`).
- **Octets after a fixed-size announcement.** A GMAS payload of two octets must show the role and then the extra octet as trailing data, not drop it. Pinned by Task 3, Step 1 (`test_gmap_shows_bytes_it_did_not_decode`).
- **Reserved role bits set.** A future TMAP edition may use bit 6. It must show as the reserved flag, with no warning and no exception. Pinned by Task 3, Step 1 (`test_tmap_reserved_role_bits`).
- **An RSI that is not six octets.** A five-octet RSI must keep today's single field, add no hash or prand, and raise `btcommon.eir_ad.invalid_length`. Pinned by Task 4, Step 1 (`test_rsi_with_the_wrong_length`).

---

### Task 1: Branch, baseline and the capture fixture

**Files:**
- Create (WSL): branch `le-audio-unicast` in `~/src/wireshark`
- Create: `~/src/wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng` (not committed until Task 2)
- Create (throwaway): `$S/xiao_tmap_build.ps1`, `$S/xiao_flash.ps1`, build directory `$NRF/btmap`, captures `$NRF/tmap1.pcapng`, `$NRF/tmap-all.pcapng`, `$NRF/bt-le-audio-tmap-peripheral.pcapng`

**Interfaces:**
- Consumes: the `le-audio-broadcast` branch (commits `9f7199f20c`, `c52e46268b`, `b507750c0c`) and its build in `~/src/wsbuild`.
- Produces: branch `le-audio-unicast`; the fixture `bt-le-audio-tmap-peripheral.pcapng` with exactly 10 LE Extended Advertising Reports from the sample, each carrying service data for `184e`, `1853`, `1855` and an RSI; the **observed values** (ASCS payload, CAS payload, TMAS payload) written into this task's Step 7 notes, which Tasks 2 and 3 use as their expected values.

- [ ] **Step 1: Create the branch and check the baseline**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git status --short | head -5 && git switch -c le-audio-unicast le-audio-broadcast && git log --oneline -4'
```

Expected: an empty status, then `Switched to a new branch 'le-audio-unicast'` and the three broadcast commits on top of `7caf6e0b96`. If the status is not empty, stop and report it; do not stash or discard anything.

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | tail -2 && pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: the build is up to date or finishes without errors, and all 16 `LeAudio` tests pass (the count on 2026-09-23).

- [ ] **Step 2: Write the build script for the sample**

Write `$S/xiao_tmap_build.ps1`:

```powershell
# Builds Zephyr tmap_peripheral (duo) for the XIAO nRF54L15. Throwaway.
. "$PSScriptRoot\machine.ps1"
$env:PATH = (@(".","mingw64/bin","bin","opt/bin","opt/bin/Scripts","opt/nanopb/generator-bin","nrfutil/bin","opt/zephyr-sdk/gnu/arm-zephyr-eabi/bin","opt/zephyr-sdk/gnu/riscv64-zephyr-elf/bin") | ForEach-Object { Join-Path $Tc $_ }) -join ";" | ForEach-Object { "$Ocd;$_;$env:PATH" }
$env:PYTHONPATH = (@("opt/bin","opt/bin/Lib","opt/bin/Lib/site-packages") | ForEach-Object { Join-Path $Tc $_ }) -join ";"
$env:NRFUTIL_HOME = Join-Path $Tc "nrfutil/home"
$env:ZEPHYR_TOOLCHAIN_VARIANT = "zephyr/gnu"
$env:ZEPHYR_SDK_INSTALL_DIR = Join-Path $Tc "opt/zephyr-sdk"
$env:ZEPHYR_BASE = Join-Path $Ncs "zephyr"
Set-Location $Ncs
west build --no-sysbuild -b xiao_nrf54l15/nrf54l15/cpuapp -d (Join-Path $Nrf "btmap") zephyr/samples/bluetooth/tmap_peripheral --pristine -- -DEXTRA_CONF_FILE=duo.conf 2>&1 | Select-String -Pattern "error|FLASH:|RAM:|warning: " | Select-Object -Last 12
```

And `$S/xiao_flash.ps1`, which flashes whichever build under `$Nrf` it is named:

```powershell
# Flashes one of the builds under $Nrf to the XIAO nRF54L15 and verifies it. Throwaway.
param([Parameter(Mandatory)] [string] $Build)
. "$PSScriptRoot\machine.ps1"
$env:PATH = (@(".","mingw64/bin","bin","opt/bin","opt/bin/Scripts","opt/nanopb/generator-bin","nrfutil/bin","opt/zephyr-sdk/gnu/arm-zephyr-eabi/bin","opt/zephyr-sdk/gnu/riscv64-zephyr-elf/bin") | ForEach-Object { Join-Path $Tc $_ }) -join ";" | ForEach-Object { "$Ocd;$_;$env:PATH" }
$env:PYTHONPATH = (@("opt/bin","opt/bin/Lib","opt/bin/Lib/site-packages") | ForEach-Object { Join-Path $Tc $_ }) -join ";"
$env:NRFUTIL_HOME = Join-Path $Tc "nrfutil/home"
$env:ZEPHYR_TOOLCHAIN_VARIANT = "zephyr/gnu"
$env:ZEPHYR_SDK_INSTALL_DIR = Join-Path $Tc "opt/zephyr-sdk"
$env:ZEPHYR_BASE = Join-Path $Ncs "zephyr"
Set-Location $Ncs
west flash -d (Join-Path $Nrf $Build) --runner openocd --verify 2>&1 | Select-String -Pattern "downloaded|verified|rror|diff|mismatch" | Select-Object -First 20
```

- [ ] **Step 3: Build and flash the sample**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w $S/xiao_tmap_build.ps1)" 2>&1 | tail -6
```

Expected: `FLASH:` and `RAM:` usage lines and no `error`. If the build fails (for example the sample does not fit, or a Kconfig choice is unsatisfied on this board), stop and report the error; do not patch the sample.

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w $S/xiao_flash.ps1)" -Build btmap
```

Expected: a `downloaded` line and a `verified` line, with no `mismatch`. A mismatch on the image's last line means the local openocd patch is gone; stop and report.

- [ ] **Step 4: Capture with the ESP32-C6**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && . $S/machine.sh && cd /g/dev/projects/esp32c6-sniffer && timeout 30 host/.venv/Scripts/python.exe extcap/esp32c6-sniffer.py --capture --extcap-interface esp32c6-ble@COM3 --fifo "$(cygpath -m $NRF)/tmap1.pcapng"; "/c/Program Files/Wireshark/tshark.exe" -r "$(cygpath -m $NRF)/tmap1.pcapng" -Y 'btcommon.eir_ad.entry.device_name == "TMAP Peripheral"' -T fields -e frame.number -e bthci_evt.bd_addr | head -5
```

Expected: several frame numbers with an address. If none, run the same 30 s capture again once (the sample advertises every 20-30 ms, so none at all means it did not boot); if still none, stop and report.

- [ ] **Step 5: Read the sample's announcement bytes**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && . $S/machine.sh && "/c/Program Files/Wireshark/tshark.exe" -r "$(cygpath -m $NRF)/tmap1.pcapng" -Y 'btcommon.eir_ad.entry.device_name == "TMAP Peripheral"' -c 1 -V | sed -n '/Advertising Data/,$p' | head -60
```

Expected, from the sample's source:

| UUID | Service data | Meaning |
|---|---|---|
| `0x1855` | `0a00` | TMAP role 0x000A: CT and UMR |
| `0x1853` | `01` | CAS, Targeted |
| `0x184e` | `011f001f0000` | ASCS, Targeted, sink 0x001F, source 0x001F, metadata length 0 |

plus a `Resolvable Set Identifier` of 6 octets, and `Device Name: TMAP Peripheral`.

- [ ] **Step 6: Check the address is private, then trim**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && . $S/machine.sh && cd $NRF && "/c/Program Files/Wireshark/tshark.exe" -r tmap1.pcapng -Y 'btcommon.eir_ad.entry.device_name == "TMAP Peripheral"' -T fields -e bthci_evt.bd_addr | sort -u
```

Expected: one or two addresses, each with a first octet of 0x40-0x7F (a resolvable private address; the sample sets `CONFIG_BT_PRIVACY`). If the first octet is 0xC0-0xFF (a static address, which would identify this board), stop and report instead of continuing.

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && . $S/machine.sh && cd $NRF && "/c/Program Files/Wireshark/tshark.exe" -r tmap1.pcapng -Y 'btcommon.eir_ad.entry.device_name == "TMAP Peripheral"' -w tmap-all.pcapng && "/c/Program Files/Wireshark/editcap.exe" -r tmap-all.pcapng bt-le-audio-tmap-peripheral.pcapng 1-10 && "/c/Program Files/Wireshark/capinfos.exe" -c -E bt-le-audio-tmap-peripheral.pcapng && "/c/Program Files/Wireshark/tshark.exe" -r bt-le-audio-tmap-peripheral.pcapng -Y 'frame.comment || !(btcommon.eir_ad.entry.device_name == "TMAP Peripheral")' -T fields -e frame.number
```

Expected: `capinfos` reports 10 packets, and the last command prints no frame numbers (no comments, no other device).

- [ ] **Step 7: Record the observed values**

Compare Step 5's output with the table. If every value matches, Tasks 2 and 3 use them as written. If any differs, the capture is right: edit the expected values in Task 2's `test_ascs_and_cas_from_a_real_device` and Task 3's `test_tmap_role_from_a_real_device` before running them, and correct the "Capture" section of the spec to match. Note the result in the task report.

- [ ] **Step 8: Put the fixture in the clone**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && . $S/machine.sh && W=$(wsl.exe -d Ubuntu-26.04 -- wslpath "$(cygpath -m $NRF)" | tr -d "\r") && wsl.exe -d Ubuntu-26.04 -- bash -lc "cp $W/bt-le-audio-tmap-peripheral.pcapng ~/src/wireshark/test/captures/ && ls -l ~/src/wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng"
```

Expected: the file listed, a few kilobytes at most.

- [ ] **Step 9: Put the sniffer firmware back on the XIAO**

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && powershell -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w $S/xiao_flash.ps1)" -Build bcap
```

Expected: `verified`, no `mismatch`. The XIAO answers on COM4 as the nRF sniffer again.

No commit in this task: the fixture is committed with the tests that read it, in Task 2.

---

### Task 2: Commit 1 — ASCS and CAS announcements

**Files:**
- Modify: `~/src/wireshark/epan/dissectors/packet-bluetooth.c` (the `btad_le_audio` block: declarations near line 1606-1720, dissectors after `dissect_btad_le_audio_public_broadcast` near line 2288, `proto_register_btad_le_audio`, `proto_reg_handoff_btad_le_audio`)
- Modify: `~/src/wireshark/test/suite_dissection.py` (class `TestDissectBluetoothLeAudio`, from line 2220)
- Add: `~/src/wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng` (from Task 1)

**Interfaces:**
- Consumes (broadcast patch, `packet-bluetooth.c`): `proto_btad_le_audio`; `ett_btad_le_audio`; `ett_btad_le_audio_contexts`; `le_audio_context_bits` (`int * const []`, 12 context flags plus reserved); `bool le_audio_fits(tvbuff_t *tvb, packet_info *pinfo, proto_item *culprit, unsigned offset, unsigned len)`; `bool dissect_le_audio_metadata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset)` (caller checks the length octet is present); `void le_audio_trailing_data(tvbuff_t *tvb, proto_tree *tree, unsigned offset)`. Test helpers `_hci_frame(cmd_text2pcap, result_file, base_env, name, hex_bytes) -> path` and `_frames(cmd_tshark, test_env, capture, display_filter) -> list[str]`.
- Produces: `le_audio_announcement_type_rvals` (`range_string[]`); dissectors `dissect_btad_le_audio_ascs`, `dissect_btad_le_audio_cas` registered as `"bluetooth.le_audio.ascs"`, `"bluetooth.le_audio.cas"` on UUIDs `"184e"`, `"1853"`; test helpers `_adv_frame(self, cmd_text2pcap, result_file, base_env, name, ad_hex) -> path` and `_verbose(cmd_tshark, test_env, capture) -> str`, which Tasks 3 and 4 use.

- [ ] **Step 1: Write the failing tests**

Append to class `TestDissectBluetoothLeAudio` in `test/suite_dissection.py`, after `test_public_broadcast_shows_bytes_it_did_not_decode`:

```python
    def _adv_frame(self, cmd_text2pcap, result_file, base_env, name, ad_hex):
        '''Writes one LE Extended Advertising Report (subevent 0x0D) carrying ad_hex as its advertising data.

        The report is connectable, extended and complete, from a random address; the lengths are computed here.
        '''
        ad = bytes.fromhex(ad_hex)
        report = bytes.fromhex('0100 01 aabbccddeeff 01 01 ff 7f c4 0000 00 000000000000') + bytes([len(ad)]) + ad
        params = bytes([0x0d, 0x01]) + report
        frame = bytes([0x04, 0x3e, len(params)]) + params
        return self._hci_frame(cmd_text2pcap, result_file, base_env, name, frame.hex())

    @staticmethod
    def _verbose(cmd_tshark, test_env, capture):
        '''The whole packet tree of a capture, as tshark -V prints it.'''
        return subprocess.check_output((cmd_tshark, '-r', capture, '-V'), encoding='utf-8', env=test_env)

    def test_ascs_and_cas_from_a_real_device(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-tmap-peripheral.pcapng')
        assert len(self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.ascs.announcement_type == 0x01'
                ' && bluetooth.le_audio.ascs.available_sink_contexts == 0x001f'
                ' && bluetooth.le_audio.ascs.available_source_contexts == 0x001f'
                ' && bluetooth.le_audio.metadata.length == 0'
                ' && bluetooth.le_audio.cas.announcement_type == 0x01')) == 10
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || bluetooth.le_audio.trailing_data'
                ' || _ws.expert.message contains "Exception occurred"') == []
        verbose = self._verbose(cmd_tshark, test_env, capture)
        assert 'Bluetooth LE Audio Announcements: ASCS, Targeted Announcement' in verbose
        assert 'Bluetooth LE Audio Announcements: CAS, Targeted Announcement' in verbose

    def test_ascs_with_metadata(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Streaming Audio Contexts: Media, in the announcement's metadata.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-ascs-metadata',
                '0d16 4e18 01 1f00 1f00 04 03020400')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.ascs.available_source_contexts == 0x001f'
                ' && bluetooth.le_audio.metadata.length == 4'
                ' && bluetooth.le_audio.metadata.streaming_audio_contexts == 0x0004'
                ' && bluetooth.le_audio.context.media == 1') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.expert.message contains "Exception occurred"') == []

    def test_ascs_truncated_after_sink_contexts(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # The source contexts and the metadata length are missing.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-ascs-short',
                '0616 4e18 01 1f00')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun'
                ' && bluetooth.le_audio.ascs.available_sink_contexts == 0x001f'
                ' && !bluetooth.le_audio.ascs.available_source_contexts') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.expert.message contains "Exception occurred"') == []

    def test_ascs_metadata_length_overruns(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Metadata_Length says five; three octets follow.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-ascs-metadata-overrun',
                '0c16 4e18 01 1f00 1f00 05 030204')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun'
                ' && bluetooth.le_audio.trailing_data == 03:02:04') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.expert.message contains "Exception occurred"') == []

    def test_reserved_announcement_type(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-cas-reserved',
                '0416 5318 02')
        verbose = self._verbose(cmd_tshark, test_env, capture)
        assert 'Announcement Type: Reserved (0x02)' in verbose
        assert 'CAS, Reserved Announcement' in verbose
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.expert.message contains "Exception occurred"') == []
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k "ascs or announcement_type" --disable-capture --disable-gui -q 2>&1 | tail -8'
```

Expected: 5 failed. tshark rejects the filters because `bluetooth.le_audio.ascs.*` and `bluetooth.le_audio.cas.*` do not exist (`CalledProcessError`), and the reserved-type test fails its first assertion.

- [ ] **Step 3: Declare the fields, the value names and the handles**

In `packet-bluetooth.c`, after `static int ett_btad_le_audio_pba_features;`:

```c
static int hf_btad_le_audio_ascs_announcement_type;
static int hf_btad_le_audio_ascs_available_sink_contexts;
static int hf_btad_le_audio_ascs_available_source_contexts;
static int hf_btad_le_audio_cas_announcement_type;
```

After `static dissector_handle_t btad_le_audio_public_broadcast;`:

```c
static dissector_handle_t btad_le_audio_ascs;
static dissector_handle_t btad_le_audio_cas;
```

Before `static int * const le_audio_context_bits[]` (so it sits with the other value tables):

```c
/* Announcement_Type, shared by the ASCS and CAS announcements. */
static const range_string le_audio_announcement_type_rvals[] = {
    { 0x00, 0x00, "General" },
    { 0x01, 0x01, "Targeted" },
    { 0x02, 0xFF, "Reserved" },
    { 0, 0, NULL }
};
```

- [ ] **Step 4: Write the two dissectors**

After `dissect_btad_le_audio_public_broadcast` and before `proto_register_btad_le_audio`:

```c
/* Announcement_Type, which names the announcement in the protocol item. */
static void
dissect_le_audio_announcement_type(tvbuff_t *tvb, proto_tree *tree, proto_item *main_item,
        int hf, unsigned offset)
{
    uint32_t type;

    proto_tree_add_item_ret_uint(tree, hf, tvb, offset, 1, ENC_NA, &type);
    proto_item_append_text(main_item, ", %s Announcement",
            rval_to_str_const(type, le_audio_announcement_type_rvals, "Reserved"));
}

/* The fields of an ASCS announcement, in order, stopping at the first that
 * does not fit.
 */
static void
dissect_le_audio_ascs_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_item *main_item, unsigned *offset)
{
    if (!le_audio_fits(tvb, pinfo, main_item, *offset, 1))
        return;
    dissect_le_audio_announcement_type(tvb, tree, main_item, hf_btad_le_audio_ascs_announcement_type, *offset);
    *offset += 1;

    if (!le_audio_fits(tvb, pinfo, main_item, *offset, 2))
        return;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_btad_le_audio_ascs_available_sink_contexts,
            ett_btad_le_audio_contexts, le_audio_context_bits, ENC_LITTLE_ENDIAN);
    *offset += 2;

    if (!le_audio_fits(tvb, pinfo, main_item, *offset, 2))
        return;
    proto_tree_add_bitmask(tree, tvb, *offset, hf_btad_le_audio_ascs_available_source_contexts,
            ett_btad_le_audio_contexts, le_audio_context_bits, ENC_LITTLE_ENDIAN);
    *offset += 2;

    if (!le_audio_fits(tvb, pinfo, main_item, *offset, 1))
        return;
    dissect_le_audio_metadata(tvb, pinfo, tree, offset);
}

static int
dissect_btad_le_audio_ascs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": ASCS");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    dissect_le_audio_ascs_fields(tvb, pinfo, main_tree, main_item, &offset);

    le_audio_trailing_data(tvb, main_tree, offset);

    return tvb_captured_length(tvb);
}

static int
dissect_btad_le_audio_cas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": CAS");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    if (le_audio_fits(tvb, pinfo, main_item, offset, 1)) {
        dissect_le_audio_announcement_type(tvb, main_tree, main_item, hf_btad_le_audio_cas_announcement_type, offset);
        offset += 1;
    }

    le_audio_trailing_data(tvb, main_tree, offset);

    return tvb_captured_length(tvb);
}
```

- [ ] **Step 5: Register the fields, rename the protocol, hand off the UUIDs**

In `proto_register_btad_le_audio`, append to the `hf[]` array after the `hf_btad_le_audio_pba_features_reserved` entry:

```c
        { &hf_btad_le_audio_ascs_announcement_type,
          { "Announcement Type", "bluetooth.le_audio.ascs.announcement_type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(le_audio_announcement_type_rvals), 0x0,
            "Whether the device is connectable by any client (General) or asks for one (Targeted)", HFILL }
        },
        { &hf_btad_le_audio_ascs_available_sink_contexts,
          { "Available Sink Contexts", "bluetooth.le_audio.ascs.available_sink_contexts",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_ascs_available_source_contexts,
          { "Available Source Contexts", "bluetooth.le_audio.ascs.available_source_contexts",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_cas_announcement_type,
          { "Announcement Type", "bluetooth.le_audio.cas.announcement_type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(le_audio_announcement_type_rvals), 0x0,
            NULL, HFILL }
        },
```

Change the protocol registration's first argument:

```c
    proto_btad_le_audio = proto_register_protocol("Bluetooth LE Audio Announcements",
            "LE Audio Announcement", "bluetooth.le_audio");
```

After the `btad_le_audio_public_broadcast = register_dissector(...)` statement:

```c
    btad_le_audio_ascs = register_dissector("bluetooth.le_audio.ascs",
            dissect_btad_le_audio_ascs, proto_btad_le_audio);
    btad_le_audio_cas = register_dissector("bluetooth.le_audio.cas",
            dissect_btad_le_audio_cas, proto_btad_le_audio);
```

In `proto_reg_handoff_btad_le_audio`, after the `"1856"` line:

```c
    dissector_add_string("btcommon.eir_ad.entry.uuid", "184e", btad_le_audio_ascs);
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1853", btad_le_audio_cas);
```

- [ ] **Step 6: Build and run the tests**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | grep -E "error|warning" | head -10; pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -4'
```

Expected: no compiler errors or warnings, and every `LeAudio` test passes (the 5 new ones plus the broadcast ones). If `test_ascs_and_cas_from_a_real_device` fails only on the item text, print it with `./run/tshark -r ../wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng -V -c 1 | grep "LE Audio"` and fix the code, not the test.

- [ ] **Step 7: Commit**

Re-read `.gitmessage` and the AI section of `CONTRIBUTING.md`. Then:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg-u1.txt <<"EOF"
Bluetooth: dissect ASCS and CAS announcements

An LE Audio device that accepts connections says so in its advertising,
in service data for the Audio Stream Control Service (0x184E) and the
Common Audio Service (0x1853): whether it wants any client or asks for
one, which audio contexts it can take as a sink and as a source right
now, and metadata. Both were shown as bytes.

Dissect them in the LE Audio announcement protocol, reusing its audio
context flags and metadata decoding, and name the announcement type in
the protocol item. Rename the protocol to "Bluetooth LE Audio
Announcements", since it no longer covers broadcasts only; its filter
name is unchanged.

The layouts follow the Basic Audio Profile 1.0.2 and the Common Audio
Profile 1.0.1. The capture is Zephyr's tmap_peripheral sample, taken
with an ESP32-C6 and trimmed to that device; its address is a
resolvable private address.

Assisted-by: Claude Code (Claude Opus 5.5)
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
cd ~/src/wireshark && git add epan/dissectors/packet-bluetooth.c test/suite_dissection.py test/captures/bt-le-audio-tmap-peripheral.pcapng && git commit -F /tmp/msg-u1.txt && git log --oneline -1'
```

Before committing, check the profile versions named in the message against the documents actually used; if they differ, correct the message.

---

### Task 3: Commit 2 — TMAP and GMAP roles

**Files:**
- Modify: `~/src/wireshark/epan/dissectors/packet-bluetooth.c` (same block as Task 2)
- Modify: `~/src/wireshark/test/suite_dissection.py` (class `TestDissectBluetoothLeAudio`)

**Interfaces:**
- Consumes: from the broadcast patch, `proto_btad_le_audio`, `ett_btad_le_audio`, `le_audio_fits`, `le_audio_trailing_data`; from Task 2, the test helpers `_adv_frame` and `_frames`, and the fixture `bt-le-audio-tmap-peripheral.pcapng`.
- Produces: dissectors `dissect_btad_le_audio_tmas`, `dissect_btad_le_audio_gmas` registered as `"bluetooth.le_audio.tmap"`, `"bluetooth.le_audio.gmap"` on UUIDs `"1855"`, `"1858"`; subtrees `ett_btad_le_audio_tmap_role`, `ett_btad_le_audio_gmap_role`.

- [ ] **Step 1: Write the failing tests**

Append to `TestDissectBluetoothLeAudio`:

```python
    def test_tmap_role_from_a_real_device(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-tmap-peripheral.pcapng')
        assert len(self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.tmap.role == 0x000a'
                ' && bluetooth.le_audio.tmap.role.ct == 1'
                ' && bluetooth.le_audio.tmap.role.umr == 1'
                ' && bluetooth.le_audio.tmap.role.cg == 0'
                ' && bluetooth.le_audio.tmap.role.ums == 0'
                ' && bluetooth.le_audio.tmap.role.bms == 0'
                ' && bluetooth.le_audio.tmap.role.bmr == 0')) == 10
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.expert.message contains "Exception occurred"') == []

    def test_gmap_role(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # No Zephyr sample advertises a GMAP role: Unicast Game Terminal.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-gmap',
                '0416 5818 02')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.gmap.role == 0x02'
                ' && bluetooth.le_audio.gmap.role.ugt == 1'
                ' && bluetooth.le_audio.gmap.role.ugg == 0'
                ' && bluetooth.le_audio.gmap.role.bgs == 0'
                ' && bluetooth.le_audio.gmap.role.bgr == 0') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || bluetooth.le_audio.trailing_data'
                ' || _ws.expert.message contains "Exception occurred"') == []

    def test_gmap_shows_bytes_it_did_not_decode(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-gmap-trailing',
                '0516 5818 02 aa')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.gmap.role == 0x02'
                ' && bluetooth.le_audio.trailing_data == aa') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.expert.message contains "Exception occurred"') == []

    def test_tmap_reserved_role_bits(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Bit 6, which TMAP 1.0 reserves.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-tmap-reserved',
                '0516 5518 4000')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.tmap.role == 0x0040'
                ' && bluetooth.le_audio.tmap.role.reserved == 1') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun || _ws.expert.message contains "Exception occurred"') == []

    def test_tmap_role_too_short(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # One octet where the role needs two.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-tmap-short',
                '0416 5518 0a')
        assert self._frames(cmd_tshark, test_env, capture,
                'bluetooth.le_audio.length_overrun'
                ' && bluetooth.le_audio.trailing_data == 0a'
                ' && !bluetooth.le_audio.tmap.role') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.expert.message contains "Exception occurred"') == []
```

If Task 1, Step 7 recorded a different TMAP role, use that value and its bits in `test_tmap_role_from_a_real_device`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k "tmap or gmap" --disable-capture --disable-gui -q 2>&1 | tail -8'
```

Expected: 5 failed, tshark rejecting `bluetooth.le_audio.tmap.*` and `bluetooth.le_audio.gmap.*` as unknown fields.

- [ ] **Step 3: Declare the fields, subtrees and handles**

After the four `hf_` declarations added in Task 2:

```c
static int hf_btad_le_audio_tmap_role;
static int hf_btad_le_audio_tmap_role_cg;
static int hf_btad_le_audio_tmap_role_ct;
static int hf_btad_le_audio_tmap_role_ums;
static int hf_btad_le_audio_tmap_role_umr;
static int hf_btad_le_audio_tmap_role_bms;
static int hf_btad_le_audio_tmap_role_bmr;
static int hf_btad_le_audio_tmap_role_reserved;
static int hf_btad_le_audio_gmap_role;
static int hf_btad_le_audio_gmap_role_ugg;
static int hf_btad_le_audio_gmap_role_ugt;
static int hf_btad_le_audio_gmap_role_bgs;
static int hf_btad_le_audio_gmap_role_bgr;
static int hf_btad_le_audio_gmap_role_reserved;

static int ett_btad_le_audio_tmap_role;
static int ett_btad_le_audio_gmap_role;
```

After `static dissector_handle_t btad_le_audio_cas;`:

```c
static dissector_handle_t btad_le_audio_tmas;
static dissector_handle_t btad_le_audio_gmas;
```

- [ ] **Step 4: Write the two dissectors**

After `dissect_btad_le_audio_cas`:

```c
static int
dissect_btad_le_audio_tmas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int * const roles[] = {
        &hf_btad_le_audio_tmap_role_cg,
        &hf_btad_le_audio_tmap_role_ct,
        &hf_btad_le_audio_tmap_role_ums,
        &hf_btad_le_audio_tmap_role_umr,
        &hf_btad_le_audio_tmap_role_bms,
        &hf_btad_le_audio_tmap_role_bmr,
        &hf_btad_le_audio_tmap_role_reserved,
        NULL
    };
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": TMAS");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    if (le_audio_fits(tvb, pinfo, main_item, offset, 2)) {
        proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_le_audio_tmap_role,
                ett_btad_le_audio_tmap_role, roles, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    le_audio_trailing_data(tvb, main_tree, offset);

    return tvb_captured_length(tvb);
}

static int
dissect_btad_le_audio_gmas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    static int * const roles[] = {
        &hf_btad_le_audio_gmap_role_ugg,
        &hf_btad_le_audio_gmap_role_ugt,
        &hf_btad_le_audio_gmap_role_bgs,
        &hf_btad_le_audio_gmap_role_bgr,
        &hf_btad_le_audio_gmap_role_reserved,
        NULL
    };
    proto_item *main_item;
    proto_tree *main_tree;
    unsigned offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_le_audio, tvb, 0, -1, ENC_NA);
    proto_item_append_text(main_item, ": GMAS");
    main_tree = proto_item_add_subtree(main_item, ett_btad_le_audio);

    if (le_audio_fits(tvb, pinfo, main_item, offset, 1)) {
        proto_tree_add_bitmask(main_tree, tvb, offset, hf_btad_le_audio_gmap_role,
                ett_btad_le_audio_gmap_role, roles, ENC_NA);
        offset += 1;
    }

    le_audio_trailing_data(tvb, main_tree, offset);

    return tvb_captured_length(tvb);
}
```

- [ ] **Step 5: Register and hand off**

Append to the `hf[]` array after the `hf_btad_le_audio_cas_announcement_type` entry:

```c
        { &hf_btad_le_audio_tmap_role,
          { "TMAP Role", "bluetooth.le_audio.tmap.role",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_cg,
          { "Call Gateway", "bluetooth.le_audio.tmap.role.cg",
            FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_ct,
          { "Call Terminal", "bluetooth.le_audio.tmap.role.ct",
            FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_ums,
          { "Unicast Media Sender", "bluetooth.le_audio.tmap.role.ums",
            FT_BOOLEAN, 16, NULL, 0x0004, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_umr,
          { "Unicast Media Receiver", "bluetooth.le_audio.tmap.role.umr",
            FT_BOOLEAN, 16, NULL, 0x0008, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_bms,
          { "Broadcast Media Sender", "bluetooth.le_audio.tmap.role.bms",
            FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_bmr,
          { "Broadcast Media Receiver", "bluetooth.le_audio.tmap.role.bmr",
            FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_btad_le_audio_tmap_role_reserved,
          { "Reserved", "bluetooth.le_audio.tmap.role.reserved",
            FT_BOOLEAN, 16, NULL, 0xFFC0, NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role,
          { "GMAP Role", "bluetooth.le_audio.gmap.role",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role_ugg,
          { "Unicast Game Gateway", "bluetooth.le_audio.gmap.role.ugg",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role_ugt,
          { "Unicast Game Terminal", "bluetooth.le_audio.gmap.role.ugt",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role_bgs,
          { "Broadcast Game Sender", "bluetooth.le_audio.gmap.role.bgs",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role_bgr,
          { "Broadcast Game Receiver", "bluetooth.le_audio.gmap.role.bgr",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_btad_le_audio_gmap_role_reserved,
          { "Reserved", "bluetooth.le_audio.gmap.role.reserved",
            FT_BOOLEAN, 8, NULL, 0xF0, NULL, HFILL }
        },
```

Append to the `ett[]` array, after `&ett_btad_le_audio_pba_features,`:

```c
        &ett_btad_le_audio_tmap_role,
        &ett_btad_le_audio_gmap_role,
```

After the `btad_le_audio_cas = register_dissector(...)` statement:

```c
    btad_le_audio_tmas = register_dissector("bluetooth.le_audio.tmap",
            dissect_btad_le_audio_tmas, proto_btad_le_audio);
    btad_le_audio_gmas = register_dissector("bluetooth.le_audio.gmap",
            dissect_btad_le_audio_gmas, proto_btad_le_audio);
```

In `proto_reg_handoff_btad_le_audio`, after the `"1853"` line:

```c
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1855", btad_le_audio_tmas);
    dissector_add_string("btcommon.eir_ad.entry.uuid", "1858", btad_le_audio_gmas);
```

Before building, check the current TMAP and GMAP editions for role bits beyond those above. If an edition defines more, add a field for each defined bit, shrink the reserved mask to match, and name the edition in the commit message.

- [ ] **Step 6: Build and run the tests**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | grep -E "error|warning" | head -10; pytest ../wireshark/test/suite_dissection.py -k LeAudio --disable-capture --disable-gui -q 2>&1 | tail -4'
```

Expected: no compiler errors or warnings; every `LeAudio` test passes.

- [ ] **Step 7: Commit**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg-u2.txt <<"EOF"
Bluetooth: dissect TMAP and GMAP roles

LE Audio devices advertise which roles they play in the Telephony and
Media Audio Profile, as service data for the Telephony and Media Audio
Service (0x1855), and in the Gaming Audio Profile, as service data for
the Gaming Audio Service (0x1858). Both were shown as bytes.

Dissect each as a bitmask of its roles, with the bits the profile does
not define shown as reserved, in the LE Audio announcement protocol.

The role bits follow the Telephony and Media Audio Profile 1.0 and the
Gaming Audio Profile 1.0.

Assisted-by: Claude Code (Claude Opus 5.5)
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
cd ~/src/wireshark && git add epan/dissectors/packet-bluetooth.c test/suite_dissection.py && git commit -F /tmp/msg-u2.txt && git log --oneline -2'
```

Correct the profile versions in the message if Step 5's check used later editions.

---

### Task 4: Commit 3 — split the Resolvable Set Identifier

**Files:**
- Modify: `~/src/wireshark/epan/dissectors/packet-bthci_cmd.c` (declarations near line 1458 and 1618-1625; `case 0x2e` near line 12102; `hf` registration near line 13160; `ett[]` and `ei[]` near line 13962-13974)
- Modify: `~/src/wireshark/test/suite_dissection.py` (class `TestDissectBluetoothLeAudio`)

**Interfaces:**
- Consumes: `hf_btcommon_eir_ad_rsi` (existing, `FT_BYTES`), `ei_eir_ad_invalid_length` (existing, `btcommon.eir_ad.invalid_length`), the local `sub_item` (`proto_item *`) of the advertising-data function; from Task 2, `_adv_frame` and `_frames`.
- Produces: `hf_btcommon_eir_ad_rsi_hash`, `hf_btcommon_eir_ad_rsi_prand`, `ett_eir_ad_rsi`, `ei_eir_ad_rsi_bad_prand`.

- [ ] **Step 1: Write the failing tests**

Append to `TestDissectBluetoothLeAudio`:

```python
    def test_rsi_from_a_real_device(self, cmd_tshark, capture_file, test_env):
        capture = capture_file('bt-le-audio-tmap-peripheral.pcapng')
        assert len(self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.rsi.hash && btcommon.eir_ad.entry.rsi.prand')) == 10
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.rsi.bad_prand || btcommon.eir_ad.invalid_length') == []

    def test_rsi_is_split(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # prand 0x665544: its top two bits are 01, as they must be.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-rsi',
                '072e 112233 445566')
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.rsi == 11:22:33:44:55:66'
                ' && btcommon.eir_ad.entry.rsi.hash == 0x332211'
                ' && btcommon.eir_ad.entry.rsi.prand == 0x665544') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.rsi.bad_prand || _ws.expert.message contains "Exception occurred"') == []

    def test_rsi_prand_marker_bits(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # prand 0xc65544: its top two bits are 11.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-rsi-bad-prand',
                '072e 112233 4455c6')
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.entry.rsi.bad_prand'
                ' && btcommon.eir_ad.entry.rsi.prand == 0xc65544') == ['1']

    def test_rsi_with_the_wrong_length(self, cmd_text2pcap, cmd_tshark, result_file, base_env, test_env):
        # Five octets where the RSI has six.
        capture = self._adv_frame(cmd_text2pcap, result_file, base_env, 'le-audio-rsi-short',
                '062e 112233 4455')
        assert self._frames(cmd_tshark, test_env, capture,
                'btcommon.eir_ad.invalid_length'
                ' && btcommon.eir_ad.entry.rsi == 11:22:33:44:55'
                ' && !btcommon.eir_ad.entry.rsi.hash') == ['1']
        assert self._frames(cmd_tshark, test_env, capture,
                '_ws.expert.message contains "Exception occurred"') == []
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py -k rsi --disable-capture --disable-gui -q 2>&1 | tail -8'
```

Expected: 4 failed, tshark rejecting `btcommon.eir_ad.entry.rsi.hash` and `.rsi.bad_prand` as unknown fields.

- [ ] **Step 3: Declare**

In `packet-bthci_cmd.c`, after `static int hf_btcommon_eir_ad_rsi;`:

```c
static int hf_btcommon_eir_ad_rsi_hash;
static int hf_btcommon_eir_ad_rsi_prand;
```

After `static int ett_eir_ad_biginfo_seedaa;`:

```c
static int ett_eir_ad_rsi;
```

After `static expert_field ei_eir_ad_invalid_length;`:

```c
static expert_field ei_eir_ad_rsi_bad_prand;
```

- [ ] **Step 4: Split the RSI**

Replace the existing case:

```c
        case 0x2e: /* Resolvable Set Identifier */
            proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_rsi, tvb, offset, length, ENC_NA);
            offset += length;

            break;
```

with:

```c
        case 0x2e: /* Resolvable Set Identifier */ {
            proto_item *prand_item;
            uint32_t    prand;

            sub_item = proto_tree_add_item(entry_tree, hf_btcommon_eir_ad_rsi, tvb, offset, length, ENC_NA);
            if (length == 6) {
                sub_tree = proto_item_add_subtree(sub_item, ett_eir_ad_rsi);
                proto_tree_add_item(sub_tree, hf_btcommon_eir_ad_rsi_hash, tvb, offset, 3, ENC_LITTLE_ENDIAN);
                prand_item = proto_tree_add_item_ret_uint(sub_tree, hf_btcommon_eir_ad_rsi_prand,
                        tvb, offset + 3, 3, ENC_LITTLE_ENDIAN, &prand);
                /* CSIS: the two most significant bits of prand are 0 then 1. */
                if ((prand >> 22) != 0x1)
                    expert_add_info(pinfo, prand_item, &ei_eir_ad_rsi_bad_prand);
            } else {
                expert_add_info(pinfo, sub_item, &ei_eir_ad_invalid_length);
            }
            offset += length;

            break;
        }
```

- [ ] **Step 5: Register**

After the `hf_btcommon_eir_ad_rsi` entry in the `hf[]` array:

```c
        { &hf_btcommon_eir_ad_rsi_hash,
          { "Hash", "btcommon.eir_ad.entry.rsi.hash",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btcommon_eir_ad_rsi_prand,
          { "prand", "btcommon.eir_ad.entry.rsi.prand",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            "The random part, from which the hash is computed with the set's key", HFILL }
        },
```

Change the end of the `ett[]` array from `&ett_eir_ad_biginfo_seedaa` to:

```c
        &ett_eir_ad_biginfo_seedaa,
        &ett_eir_ad_rsi
```

Append to the `ei[]` array after the `ei_eir_ad_invalid_length` entry:

```c
        { &ei_eir_ad_rsi_bad_prand,   { "btcommon.eir_ad.entry.rsi.bad_prand", PI_PROTOCOL, PI_WARN, "The two most significant bits of prand are not 0b01", EXPFILL }},
```

- [ ] **Step 6: Build and run the tests**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ninja tshark text2pcap 2>&1 | grep -E "error|warning" | head -10; pytest ../wireshark/test/suite_dissection.py -k "LeAudio or Bluetooth" --disable-capture --disable-gui -q 2>&1 | tail -4'
```

Expected: no compiler errors or warnings; all selected tests pass. The existing `btcommon.eir_ad.entry.rsi` filter still matches, which `test_rsi_is_split` checks.

- [ ] **Step 7: Commit**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cat > /tmp/msg-u3.txt <<"EOF"
Bluetooth: split the Resolvable Set Identifier

A member of a coordinated set, such as one of a pair of earbuds,
advertises a Resolvable Set Identifier: a 24-bit hash followed by the
24-bit prand it was computed from. It was shown as six bytes.

Show the hash and prand beneath the existing field, which keeps its
name so existing filters still match. Flag a prand whose two most
significant bits are not 0b01, which the Coordinated Set
Identification Service requires, and an identifier that is not six
octets long.

Resolving the identifier needs the set's key, which is exchanged over
an encrypted connection; that is not attempted.

Assisted-by: Claude Code (Claude Opus 5.5)
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
cd ~/src/wireshark && git add epan/dissectors/packet-bthci_cmd.c test/suite_dissection.py && git commit -F /tmp/msg-u3.txt && git log --oneline -3'
```

---

### Task 5: Upstream checks and the draft series

**Files:**
- Create: `~/src/wireshark/le-audio-unicast-patches/` (the `format-patch` output and `merge-request.md`, untracked)
- Create: copies of the same in `$S/le-audio-unicast-patches/`

**Interfaces:**
- Consumes: the three commits from Tasks 2-4.
- Produces: a draft series on top of `le-audio-broadcast`, for the user to read now. It is **not** the hand-over series; that is made in Task 6 after the rebase.

- [ ] **Step 1: Run upstream's static checks on the changed files**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && F="epan/dissectors/packet-bluetooth.c epan/dissectors/packet-bthci_cmd.c" && tools/checkAPIs.pl $F; tools/checkhf.pl $F; tools/checkfiltername.pl $F; python3 tools/check_typed_item_calls.py --file epan/dissectors/packet-bluetooth.c --file epan/dissectors/packet-bthci_cmd.c; python3 tools/check_spelling.py --file epan/dissectors/packet-bluetooth.c --file epan/dissectors/packet-bthci_cmd.c 2>&1 | tail -20'
```

Expected: no output that names a line added by the three commits. If the spelling checker needs the environment used for the broadcast patch, run it as `~/spellenv/bin/python tools/check_spelling.py ...`. Complaints about lines this branch did not touch are left alone. If unsure whether a complaint is new, run the same command in a worktree of the base (`git worktree add /tmp/wsbase le-audio-broadcast`, then `git worktree remove /tmp/wsbase`) and compare.

Fix anything that names a new line, rebuild, rerun the `LeAudio` tests, and amend the commit that introduced it with `git commit --fixup=<sha>` then `git rebase --autosquash le-audio-broadcast` (non-interactive: set `GIT_SEQUENCE_EDITOR=true`).

- [ ] **Step 2: Fuzz the new capture**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && ../wireshark/tools/fuzz-test.sh -b ./run -P 200 ../wireshark/test/captures/bt-le-audio-tmap-peripheral.pcapng 2>&1 | tail -10'
```

Expected: 200 passes, ending with no `Processing failed` line.

- [ ] **Step 3: Run the whole dissection suite**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wsbuild && pytest ../wireshark/test/suite_dissection.py --disable-capture --disable-gui -q 2>&1 | tail -3'
```

Expected: all pass. The `LeAudio` subset alone is now 30 tests: Task 1's 16 plus the 14 added here (5 + 5 + 4).

- [ ] **Step 4: Write the draft series and merge request description**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && rm -rf le-audio-unicast-patches && git format-patch -o le-audio-unicast-patches le-audio-broadcast..le-audio-unicast && ls le-audio-unicast-patches'
```

Expected: three `.patch` files.

Write `~/src/wireshark/le-audio-unicast-patches/merge-request.md`:

```markdown
Bluetooth: dissect LE Audio unicast announcements

Depends on !<broadcast MR number>, and is rebased onto master once that merges.

An LE Audio device that accepts connections announces itself in its
advertising: whether it wants a connection and which audio contexts it can
take (ASCS, 0x184E), its Common Audio Profile announcement (CAS, 0x1853),
and its TMAP (0x1855) and GMAP (0x1858) roles. Earbuds that form a pair also
advertise a Resolvable Set Identifier. Wireshark showed all of it as bytes.

- Commit 1 decodes the ASCS and CAS announcements in the LE Audio
  announcement protocol, reusing its audio context and metadata decoding,
  and renames the protocol to "Bluetooth LE Audio Announcements".
- Commit 2 decodes the TMAP and GMAP roles.
- Commit 3 splits the RSI into its hash and prand, under the existing field.

Tests: nine hand-built frames and one capture of Zephyr's tmap_peripheral
sample, taken with an ESP32-C6 and trimmed to that device. Its address is
a resolvable private address.

Assisted-by: Claude Code (Claude Opus 5.5)
```

Then copy the directory out:

```bash
S=/c/Users/Work/AppData/Local/Temp/claude/G--dev-projects-esp32c6-sniffer/6ebae47c-9929-43c2-a022-36794e0f6a03/scratchpad && wsl.exe -d Ubuntu-26.04 -- bash -lc "cp -r ~/src/wireshark/le-audio-unicast-patches \"\$(wslpath '$(cygpath -w $S)')\"/" && ls $S/le-audio-unicast-patches
```

Expected: three patches and `merge-request.md`.

- [ ] **Step 5: Report**

Report to the user: the three commit subjects, the test counts, the check and fuzz results, where the draft series is, and that it is a draft until the broadcast merge request merges.

---

### Task 6: After the broadcast merge request merges (deferred)

Run this only when the user says the broadcast merge request has merged, and give them its number and the merged `master`.

**Files:**
- Modify (WSL): branch `le-audio-unicast`, rebased
- Modify: `G:\dev\projects\esp32c6-sniffer\docs\using-wireshark.md` (only once this merge request exists)

**Interfaces:**
- Consumes: Tasks 2-5.
- Produces: the hand-over series, and one documentation line in this repository.

- [ ] **Step 1: Rebase onto master**

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git fetch origin && git log --oneline origin/master | grep -i "LE Audio\|Basic Audio\|periodic advertising" | head -5'
```

Expected: the broadcast commits, as merged. Then:

```bash
wsl.exe -d Ubuntu-26.04 -- bash -lc 'cd ~/src/wireshark && git rebase --onto origin/master le-audio-broadcast le-audio-unicast && git log --oneline -4'
```

If there are conflicts, it is because review changed the broadcast patch. Resolve them by following the merged names: for example, if `le_audio_fits` or `dissect_le_audio_metadata` were renamed, or the protocol already renamed, adapt this branch's calls to them. Do not reintroduce anything review removed.

- [ ] **Step 2: Rebuild and retest**

Repeat Task 5, Steps 1-3 against the rebased branch.

- [ ] **Step 3: Write the hand-over series**

Repeat Task 5, Step 4 with `origin/master..le-audio-unicast` in place of `le-audio-broadcast..le-audio-unicast`, and replace the "Depends on" line of `merge-request.md` with nothing. Copy it to `$S` as before and tell the user it is ready; opening the merge request is theirs to do.

- [ ] **Step 4: The documentation line (once the user has opened the merge request)**

In `docs/using-wireshark.md`, beside the broadcast patch's note, add a sentence naming the new filter fields (`bluetooth.le_audio.ascs.*`, `bluetooth.le_audio.cas.announcement_type`, `bluetooth.le_audio.tmap.role`, `bluetooth.le_audio.gmap.role`, `btcommon.eir_ad.entry.rsi.hash`) and linking the merge request the user gives. Commit it in this repository:

```bash
cd /g/dev/projects/esp32c6-sniffer && host/.venv/Scripts/python.exe -m pytest -q host/tests/test_no_private_data.py host/tests/test_no_stray_control_characters.py && git add docs/using-wireshark.md && git commit -m "docs: point at the Wireshark LE Audio unicast announcement patch" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
