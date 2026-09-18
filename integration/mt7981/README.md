# QEMU MT7981 board notes

This directory retains the MT7981 device-tree overlays used by the firmware
experiments. The maintained QEMU adapter is `qemu/hw/unifi/unifi-board.c`,
backed by the generic `board-ffi` ABI.

The generic device owns one opaque board instance, maps metadata-derived MMIO
windows, lends host DMA callbacks per call, exposes UART and network backends,
and returns IRQ/event batches from the Rust model.

The temporary QEMU 10.2.4 integration also registers a named `-M mt7981`
machine profile. It currently reuses the `virt` CPU/GIC/timer implementation
and adds the MT7981 UART/address compatibility layer; it is a stepping stone
toward a fully native MT7981 machine.

The Rust library owns the opaque board pointer; unsafe code is confined to the
FFI crate.

The Rust board model also accepts the MT7981 infrastructure clock, topckgen,
APMixedSys, and Ethernet reset/syscon address ranges. A QEMU instance covering
the SoC control window can therefore probe these registers while preserving
the same UART/watchdog state model.

Use `scripts/fetch.sh`, `scripts/build.sh`, and
`scripts/run.sh mt7981` to build and boot the OpenWrt or U6+ test artifacts.

## Synthetic board identity

The default EEPROM supplies a synthetic U6+ SBD record: vendor `0777`, system
`a642`, shortname `UAPL6`, and locally administered MACs beginning
`02:00:00:79:81:01`. These are emulation values, not factory credentials or
per-device calibration. Explicit flash images still replace the default.

The v2 format/version fields at `0x800c`/`0x800e` are big-endian, as in the
first C implementation (`00b85bb9`); the CRC word remains little-endian.
Vendor ID is at `0x8010`, **system ID at `0x8012`**. The firmware's
`ubnthal.ko` board table maps `a642` to `U6+`/`UAPL6`; `0777` alone does not
identify the model. The Rust tests check both fields and the CRC.

The record layout is confirmed against `EEPROM` partition dumps taken from a
live U6-Lite (`a612`) and UAP6MP (`a650`); `scripts/board-data.py` parses the
head record of both. Two corrections came out of that comparison:

- `0x8008` is a big-endian `u32` **record length**, and the CRC covers exactly
  that many bytes from `0x800c`. Hardware stores `0x65`, so the trailing `0x01`
  marker at `0x8070` is inside the checksummed range. The generator previously
  wrote `0x64` and omitted the marker, which `qemu/hw/unifi/unifi-machine.c`
  would have rejected as a stale synthetic record.
- Unwritten bytes are `0xff`, not zero: the partition is erased NOR.
- `0x801e`, `0x801f` and `0x8070` are **MAC pool sizes**, not opaque bytes.
  `mt7981_scan_eeprom` reads an Ethernet count at `0x801e` (clamped to 12), a
  Wi-Fi count at `0x801f` and a Bluetooth count at `0x8070`, then hands out
  consecutive addresses from the base MAC. The hardware values `1`, `2`, `1`
  reproduce the guest's `eth0`, `ra0`/`rai0` and `bt0` exactly. The old record
  wrote `2` Ethernet MACs and omitted the Bluetooth count.

The head record at `0x0000` carries eth0 and eth1 MACs, then board and vendor
IDs in the opposite order to the SBD record, then a big-endian `u32` BOM
revision whose low byte the HAL reports as `boardrevision`. eth1 is derived
from eth0 by setting the locally administered bit in the first octet; this
synthetic base already has that bit, so it is incremented instead, matching
`scripts/board-data.py`.

`ubnthal.ko`'s own `mt7981_scan_eeprom` corroborates the record fields: it
checks `UBNT` at `0x8000`, byte-swaps the length at `0x8008`, and runs
`cyg_crc32` over exactly `length` bytes from `0x800c` against the word at
`0x8004`. It accepts a length of `0x64` **or** `0x65`, which is why the old
short record booted despite not matching hardware.

Because these are counts rather than a fixed signature, `board-ffi`'s UDM-Pro
record writing `2` at `0x801e` is consistent with its two-MAC head record and
is **not** a defect; it needs no hardware dump to settle.

The manufacturing `TlvInfo` block at `0xd000` is reproduced, including its
checksum: the layout is ONIE's, but the `0xfe` CRC TLV stores the same
`legacy_crc32` as the SBD record, over the block up to but excluding that
TLV's own type and length bytes, big-endian. Both hardware blocks reproduce
under that rule and under neither ONIE's standard CRC-32 nor any other range
tried.

That block is **not** the source of `system.info`'s manufacturing fields, and
adding it does not change the guest's output. `systeminfo_dump` renders
`mfgweek` from a 32-bit Unix timestamp via `time64_to_tm`, with `manufid` and
`qrid` in neighbouring fields. Filling unwritten spans of the emulated image
with a marker byte and reading the guest's `system.info` back located those in
a **second record at `0xa000`**, which both hardware dumps carry with the same
layout:

| Offset | Field | U6-Lite | UAP6MP |
| --- | --- | --- | --- |
| `0xa002` | `manufid`, big-endian `u16` | `0002` | `0004` |
| `0xa018` | manufacturing time, big-endian `u32` | 2021-09-18 | 2022-08-06 |
| `0xa01e` / `0xa020` | system ID / vendor ID | `a612` / `0777` | `a650` / `0777` |
| `0xa022` / `0xa028` | eth0 / eth1 MAC | matches head | matches head |
| `0xa0b7` | BOM revision, big-endian `u32` | `0003050f` | `0003c326` |
| `0xa0bb` | `qrid`, NUL-terminated ASCII | `V7UFxu` | `X3FxZ6` |

Those timestamps reproduce the reported `mfgweek` values (`202138`, `202232`)
exactly. The generator now writes this record, so the guest reports
`manufid=0002`, `qrid=QEMU01` and `mfgweek=202401` instead of the erased
`ffff`, `000000` and `210607` -- 2106-02-07 being the 32-bit time overflow of
an erased `0xffffffff` timestamp. Its timestamp and the TlvInfo date are kept
in agreement, as hardware keeps them.

The HAL validates neither the `12 03` signature nor any checksum in this
record: filling the span with a marker byte made `manufid` read back as that
marker. Only the bytes both dumps agree on are written; the per-unit fields
and the high-entropy span from roughly `0xa044` to `0xa0b7` hold device
factory data that cannot be reconstructed and stay erased.

### Device key container

Both dumps carry a key container at `0xe004`: a `91NT` magic, a version byte
(`0x02`), a big-endian `u16` payload length, then an RFC 4253 style sequence
of `ssh-rsa`, `e`, `n`, `d`, `p` and `q` -- an RSA **private** key, 805
payload bytes for 2048 bits.

The generator writes a synthetic 2048-bit key in that container, matching the
hardware field lengths exactly. The key is generated for the emulator, is
committed in the open and identical on every build, and has no security
value; it must never be trusted or used to identify anything. No real
device's key is reproduced -- per-device factory keys stay on their devices.

Nothing observed consumes it: no rootfs binary references the container or an
`ssh-rsa` literal, and adding it leaves `system.info` byte-identical with no
SSH, dropbear or RSA activity in the boot log. It is written for byte
fidelity with hardware, not to enable behaviour.

Writing the record also switched the guest from `flashsize=` to `flashSize=`.
`ubnthal.ko` carries both format strings and a live U6-Lite emits the
capitalised one, so this is an independent sign that the record is now parsed
along the same path as real hardware.

The SPI backing covers the advertised 16 MiB W25Q128, including erased space
after the 64 KiB EEPROM partition. Controller transfers start on ACT, reset
lowers the interrupt, and clocked transfers complete independently of flash
opcode recognition. RDSR2 is supported as well as RDSR1. Tests cover reads
beyond EEPROM, status-register readback, and start/reset completion behavior.
These fixes do not implement the Wi-Fi MCU or supply a provisioned filesystem.
Normal `/init` boot now passes `cfgmtd -r`, reaches `procd: - init -`, and
offers `Please press Enter to activate this console.` This does not establish
SSH or Wi-Fi readiness.

### SPI-NOR lock regression

The blocked-task trace showed `cfgmtd` waiting in `spi_nor_lock_and_prep`.
Inspecting the mutex owner showed **the same cfgmtd task already held it**:
`ubnthal` acquires `ui_nor_lock`, then bit-bangs an SFDP identification read
through GPIO 29/26/27/28 (CS/clock/MOSI/MISO). The unimplemented GPIO input
returned zero. The vendor module's unrecognized-SFDP branch returned without
unlocking; its later MTD block read deadlocked on its own mutex.

`gpio_spi.rs` implements mode-0 reads of the synthetic SFDP revision header
and the 13-byte identification region at `0x8c`, including GPIO SET/CLR
aliases and chip-select restart. This is deliberately a minimal identification
model, not complete SFDP, real factory data, or radio calibration. The SFDP
identity remains synthetic even when an EEPROM image is supplied; factory
encrypted configuration compatibility is not promised. No guest kernel,
module, or init-script patch is used to bypass the lock.

The investigation also found sticky ACT bits replaying DMA during register
setup. ACT/RESUME/RST now self-clear, reset takes priority, and TX-only
transfers cannot write a stale RX address. Regression tests preserve a guard
region around the old DMA buffer during a subsequent larger transfer setup.

Verify normal firmware startup (not the diagnostic shell):

```sh
python3 smoke/mt7981-console.py --normal-startup --timeout 120
cargo test -p mt7981-machine
```

## Interactive console

`task u6plus` now attaches the terminal directly to UART0; it does not start
a stdio QEMU monitor. No Ctrl+A/C switching is needed. The standalone machine
maps QEMU's complete 16550 register bank at `0x11002000`, with register shift 2
and the vendor DT's SPI 123. This supplies register probing, RX callbacks,
FIFO state and IRQ delivery missing from the early-output-only placeholder.
The old adapter in `00b85bb9` had a receive callback, and its interactive
launcher used `-serial stdio -monitor none`; both contracts were lost during
the refactor.

For diagnosis before vendor init completes, run `task u6plus:console`. This
explicitly selects `rdinit=/bin/sh`, opens a local root shell, and does not
forward SSH. It does not bypass init in the normal `u6plus` task. In this
PID-1 shell, BusyBox's "job control turned off" warning is expected; `id` and
other commands still work. Use Ctrl+C on the host terminal to stop QEMU.

Run `python3 smoke/mt7981-console.py` to boot the vendor kernel and
verify typed commands are executed, not merely echoed. Normal firmware boot
still has separate board-identity/startup issues; a working diagnostic shell
does not establish normal login or SSH readiness.

## Ethernet regression checks

The Rust model owns TX/RX descriptor SRAM; host DMA is used only for packet
buffers in guest RAM. QDMA TX consumes the linked NETSYS_V2 descriptor chain
from DTX up to (but excluding) CTX. The adapter defers outgoing packets until
the borrowed Rust event batch has been consumed, so an immediate slirp reply
cannot invalidate that batch. SPI 197 carries TX completion and SPI 198 carries
PDMA RX completion, with independent masks and write-one-to-clear status.
PDMA RX padding is controlled by PDMA GLO_CFG, not QDMA GLO_CFG.

Run the firmware-independent ARP round-trip and IRQ tests against a built QEMU:

```sh
python3 smoke/mt7981-ethernet.py --qemu /tmp/qemu-build-10.2.4/qemu-system-aarch64
cargo test -p mt7981-machine -p board-ffi
```

The U6+ vendor kernel also passed an isolated three-packet ping to slirp's
`10.0.2.2` gateway with zero loss. That diagnostic boot used a minimal init
script and disabled the SPI node in a temporary DTB to avoid an independent
EEPROM/ubnthal boot crash. It does not establish full firmware boot, working
Wi-Fi, or TCP checksum/segmentation offload support. The default firmware
images and DTB were not modified.

## MMC completion regression checks

The Rust model drives MSDC0's level-triggered SPI 143 from `MSDC_INT &
MSDC_INTEN`. Command and DMA completion, mask changes, and write-one-to-clear
acknowledgement all recompute that level. Board reset clears controller state
and lowers the IRQ without erasing the card contents.

```sh
python3 smoke/mt7981-msdc.py --qemu /tmp/qemu-build-10.2.4/qemu-system-aarch64
cargo test -p mt7981-machine msdc
```

The firmware-independent tests cover command responses, completion while
masked, partial acknowledgement, and DMA write/read round trips through guest
RAM. Rust tests also cover board reset. Previously, status bits were set but
no IRQ event was emitted, so the vendor driver timed out on every request.
With IRQ delivery restored, the U6+ kernel enumerates `mmcblk0` instead. This
does not supply a populated eMMC image or establish full firmware boot.

## U6+ high-level MCU experiment

Current Rust-model verification (2026-09-11): TX DIDX reads now expose the
engine cursor for all five modeled WFDMA TX rings. Previously DDONE was written
but DIDX read zero, so the vendor firmware-download ring exhausted its slots.
The qtest suite checks DIDX on each completion, a 160-chunk download across ten
ring wraps, and no completion for an unreadable payload. The expanded MCU suite
now has 31 passing tests, including dual-processor startup, RX-header
setup, MAC/station/group, airtime, VoW-feature, channel/path/protection and
power-save flush configuration, batched MIB reads, and undersized RX-buffer
protection:

```sh
python3 smoke/mt7981-mcu.py --qemu /tmp/qemu-build-10.2.4/qemu-system-aarch64
```

The original firmware now reports matching FWDL CIDX/DIDX (`0x51`) and command
CIDX/DIDX (`0x10`), both with zero queued descriptors. The previous `FreeNum == 0`
errors are absent.

The subsequent startup-state regression is also corrected: FW_START option bit
2 selects WA and reports sync 7; WM-only startup reports 3. In the original
module, the stage-3 branch at text offset `0x24b800` selects expected sync 7
when the chip supports both processors. The older C implementation in commit
`00b85bb9` made the same distinction. The Rust port had discarded the option.
An incomplete WA download is still rejected without advancing the state.

MCU replies now advertise header plus payload length (not a fixed 12 bytes),
and boot responses retain their four-byte status payload. Calibration results
use extended event ID zero. RX-header command `0x47` again validates and stores
translation/blacklist configuration, cleared on board reset. This configuration
storage does not implement a wireless RX data path.

The original firmware now reaches sync 7, selects its EEPROM BIN, and proceeds
past those response checks without invalid-length errors or `0x47` timeouts.
The startup configuration handlers in `crates/mt7981-machine/src/wifi_mcu.rs`
were traced against the original driver opened in Binary Ninja
(`u6p_mt7981_wifi.ko.bndb`, ELF view, analysis base `0x400000`). These are
configuration-state models, not an implementation of firmware execution or
wireless scheduling/data transfer:

| Command | Original driver evidence (Binary Ninja address) | Modeled behavior / reply |
| --- | --- | --- |
| `0x46` | `MtCmdSetMacTxRx`, `0x640bc0` | Four-byte enable/band request; independent band state; generic eight-byte result, status zero on success. |
| `0x32` | `MtAsicDelWcidTabByFw`, `0x614fc8`; `CmdExtWtblUpdate`, `0x653bc0` | Operation 1 resets one 10-bit station index; operation 4 resets all. Eight-byte generic result. TLV updates and queries remain unsupported, without success replies. |
| `0x36` | `vow_set_sta`, `0x43f5d8`; `MtCmdSetVoWDRRCtrl`, `0x63cde8`; callback `0x62ee88` | Stores supported per-field/per-station configuration; full 20-byte reply with success **1 at byte 5**, not generic status zero. |
| `0x37` | `vow_set_group`, `0x43ff30`; `vow_fill_group_all`, `0x43fb58`; `MtCmdSetVoWGroupCtrl`, `0x63cfb8` | Single/bulk packed group records and quantum configuration; full 288-byte reply, success 1 at byte 5. Individual token-field updates remain unsupported and return failure. |
| `0x38` | `vow_set_feature_all`, `0x4404f8`; `MtCmdSetVoWFeatureCtrl`, `0x63d1e0`; callback `0x62f050` | 40-byte response with masked BSS enable, token-check and feature values. Refill-period selector controls three value bits. MT7981 extension bytes are retained as a packed request, not executed as scheduling policy. |
| `0x08` | `MtCmdChannelSwitch`, `0x634798`; `EventExtCmdResult`, `0x62d540` | Validates and stores a 76-byte channel request independently per DBDC band, including stream counts, switch reason, AP bandwidth/center and the 49-byte power table. Eight-byte generic result with extended event ID zero; invalid requests return nonzero status without replacing state. |
| `0x4a` | `vow_init_rx`, `0x442130`; `vow_set_backoff_time`, `0x4410c0`; `MtCmdSetVoWRxAirtimeCtrl`, `0x63d418`; callback `0x62f638` | Full 68-byte reply. Stores RX enable/features, ED offset, own-MAC/BSS WMM mappings, masked per-AC backoff and scalar timers. Reads and clears model counters, currently zero without a wireless receive path. |
| `0x4b` | `vow_set_at_estimator`, `0x441700`; `vow_set_at_estimator_group`, `0x441968`; `MtCmdSetVoWModuleCtrl`, `0x63d758`; callback `0x62dc30` | Full 100-byte reply. Stores estimator enable/period, masked per-group min/max ratios and band mappings. Bad-node operations remain unsupported. |
| `0x3e` | `MtCmdUpdateProtect`, `0x63f170`; producers `0x616ae8`/`0x616b70` | Validated 12-byte request: operation 1 stores RTS length/count thresholds, operation 2 stores protection flags/ER mask, independently per band. Eight-byte generic result. |
| `0x4e` | `MtCmdSetTxRxPath`, `0x6350c8` | Separate 76-byte path configuration per band. Byte 4 is an RX chain bitmask, not the channel command's stream count; power/SKU fields remain zero. Eight-byte generic result. |
| `0x0f` | `MtCmdPsStaFlushCtrl`, `0x6473c8` | Eight-byte WA request: per-station limit and total threshold (two LE u16s), enable byte, three reserved bytes. Stores policy, returns eight-byte generic result; does not run a station queue/flush engine. |
| `0x5a` | `MtCmdMultipleMibRegAccessRead`, `0x635d78`; callback `0x62d330` | Batched 16-byte band/ID/u64-counter records, extended event ID `0x5a`. Supports startup IDs `0x1ea`, `6`, `8`, `0x1eb`, `0`, `0x34`; idle counters are zero. Invalid/unknown requests receive no success event. |
| Extended `0x07` | `MtCmdExtPmStateCtrl`, `0x634500`; `AsicRadioOnOffCtrl`, `0x58b708` | 32-byte PM5 radio-power request, independently per band: state 1 = off, 2 = on. Eight-byte generic result. PM4 station power-save transitions remain unsupported. Distinct from boot CID `0x07`. |
| `0x25` | `CmdExtStaRecUpdate`, `0x6552e8`; insert/delete callbacks `0x650f08`/`0x651138` | Validates and stores basic, TX-processing, nested WTBL and HE records. New-record updates replace old state; disconnect removes the station and its WTBL. Full 16-byte result with WCID low at byte 9 and high at byte 13. |
| `0x26` | `CmdExtBssInfoUpdate`, `0x6563e0`; callback `0x64e9d8`; beacon builder `0x651578` | Stores supported BSS TLVs independently, including basic active state, channel, rate/sync, RA, AMSDU, color, HE, protection and beacon-template/offload configuration. Full 16-byte result with BSS at byte 8 and TLV count at byte 10. Does not transmit beacons. |
| `0x27` | `MtCmdEdcaParameterSet`, `0x63b158`; producers `0x617050`/`0x616e60`; WMM fields `0x4c8ee8` | Up to 24 eight-byte queue records after a four-byte header. Masked AIFS/CWmin/CWmax/TXOP updates preserve other fields/queues. Optional TXMODE is not a band index. Eight-byte generic result; no queue scheduling execution. |
| `0x2a` | `CmdExtDevInfoUpdate`, `0x654dc8`; callback `0x64e6e0` | Stores active state and own MAC independently per band/index. Full 16-byte result with own-MAC index at byte 8 and TLV count at byte 10. |

`wifi_mcu/records.rs` validates the complete batch before changing state.
Supported BSS tags are 0/1/2/8/9/10/11/12/13/14/15; station tags are 0/8/13/14.
The fixed 288-byte station WTBL container has its own count, matching 10-bit
station index, and zero padding. Its records share the authoritative WTBL
store with command `0x32` resets. BSS beacon tag 15 has variable-length nested
CSA/BCC/MBSSID/content/BTWT records; the model caps it at 4 KiB, checks lengths,
and retains the latest request without running an offload engine. Unknown
tags, duplicate tags, bad counts/lengths and unsupported variants get failure,
not a blanket success ACK. Physical firmware error-code meanings are not
inferred; rejected modeled requests use nonzero status 1.

`fixtures/mt7981-startup-records.txt` preserves the five commands'
original startup requests from the synthetic test board (no keys). Rust and
QEMU DMA tests replay them; additional tests cover station IDs 543/1023,
insert/delete/reset, partial updates, malformed nesting and short RX buffers.

`mac_config.rs` stores protection and power-save policy and handles read-only
MIB queries. MIB responses retain request order and duplicate IDs, return full
64-bit values, and include **20 trailing zero bytes**: the original producer
expects `16*N+20` payload bytes, and its callback calculates `(length-20)/16`
while reading records from payload offset zero. `AndesMTRxProcessEvent`
(`0x62ccf0`) checks this exact payload length and callback dispatch `0x625320`
passes it without further adjustment. Queries are bounded to 64 records;
normal startup batches contain six. RX capacity is checked before DMA writes.

The airtime handlers live in `crates/mt7981-machine/src/wifi_mcu/airtime.rs`.
Both commands use a 24-byte control header; callbacks log status words at
offsets 4 and 8. Supported replies retain zero in those words; physical-firmware
error codes have not been inferred. Invalid lengths, reserved bytes, indices,
and unsupported operations produce no success event and do not mutate state.
The older [MediaTek driver header](https://github.com/dt99/mt7615/blob/master/mt_wifi/include/mcu/mt_cmd.h)
was used only to cross-check field names: the original MT7981 binary is
authoritative, notably placing RX feature 3 at offset 26 rather than 25.

All configuration state clears on board reset. Malformed MAC/scheduler requests
are rejected without changing state. The transport test checks replies through
real QEMU guest-memory DMA, ring wrap/reclaim, and no write beyond a short RX
buffer. Rust tests also inspect stored configuration and reset behavior.

The original firmware now accepts MAC enable (`MtCmdSetMacTxRx: ret = 0`),
station-table reset, scheduler setup and airtime configuration instead of
repeatedly timing out on those commands. Verification on 2026-09-11 passed all
84 Rust tests, Clippy with warnings denied, and the 37 DMA-level MCU tests.
The normal-startup check reached `procd: - init -` and console activation
within its 120-second host deadline (about 38 seconds of guest time in
`/tmp/u6-console-alzw70ap.log`). The Wi-Fi interface-open probe returned
`qemu-wifi-probe: up-status=0`. There were no `FWCmdTimeout` messages,
device/BSS/station failure-status replies, or invalid response-length messages.
The separate diagnostic-shell test executed typed commands successfully
(`/tmp/u6-console-sg7xvjaa.log`).

To check the startup handlers against the original-driver initramfs
(requires its `qemu-wifi-probe` hook), run:

```sh
python3 smoke/mt7981-console.py --wifi-startup --timeout 120
```

This requires the path-configuration call, successful interface-open probe and
normal console milestone, and rejects `0x07`/`0x0f`/`0x25`/`0x26`/`0x27`/
`0x2a`/`0x3e`/`0x4e`/`0x5a` timeouts and device/BSS/station failure statuses.
The failure-status check matters: the driver can report interface-open success
even after rejecting its later beacon-template BSS update.

Channel, path and VoW-feature handlers are in
`crates/mt7981-machine/src/wifi_mcu/radio_config.rs`.
These previously fell through the unsupported-command dispatch: TX descriptors
completed, but no RX event was posted. VoW cannot use a generic eight-byte
acknowledgement because its driver callback copies all 40 response bytes.
Regression tests cover partial updates, independent bands, malformed requests,
board reset, response sequence/ring wrapping and undersized RX buffers.

This is **not working Wi-Fi**. The five extended commands above now accept
the observed startup requests, including the beacon-template update reached
after link-up. A separate teardown problem remains: `ctrl_fw_state_v2` requests
target stage 0 while the model still reports sync 7. Other PM variants, station
and BSS tags, and physical packet scheduling remain outside this implementation.
Console activation does not establish radio readiness, and the hwsim backend
is not connected to the vendor descriptor frontend yet.

Run `MT7981_MCU_TX_REPLY=1 task u6plus` with the original kernel and Wi-Fi
module to enable the experimental high-level MCU service model. This is not
a working radio and does not execute the uploaded firmware's MCU instructions.
It handles semaphore acquire/release, download target selection, raw scatter
DMA, patch finish, WM/WA startup state, erased-efuse reads, calibration-page
storage, and RX-header translation configuration storage. Unsupported commands
are logged and are not acknowledged as successful.

The original guest now uploads the patch and ten firmware regions, completes
both startup stages, reads efuse, selects its supplied default EEPROM BIN,
and uploads all four calibration pages. MAC initialization, reset-only WTBL,
scheduler and airtime configuration have the limited stateful implementations
listed above; the radio data path remains unimplemented.

The verified original guest maps Linux IRQ 79 to GIC INTID 245 (SPI 213).
No kernel IRQ patch is needed. The shim posts at TX1 CIDX `0x18024418`, not
the teardown reset at `0x18024100`. Its RX packet uses type 7 in the first
DMA word, actual length/LS0/DDONE in the descriptor, and EID 4 with the
request's sequence and semaphore status 2. The guest consumes R0 and sends
the next command with sequence 2.

TX0 carries raw firmware bytes without MCU headers; TX1 carries boot commands;
TX4 carries normal extended commands. Extended CID is at TX buffer `+0x29`,
not `+0x28`. Download regions are retained with SHA-256 diagnostics. No firmware
or kernel patch is needed. qtest regression coverage is in
`smoke/mt7981-mcu.py`; the QEMU integration is preserved in
`qemu/0001-unifi-machines-qemu-10.2.4.patch` (see `qemu/README.md`).

For UART capture use `MT7981_SERIAL_MODE=file`; the default log is
`/tmp/mt7981-serial.log`. Default `stdio` mode displays UART in the terminal.
