use std::fmt::Write as _;
use std::io::Write;

use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};

/// Size of the synthetic U6+ EEPROM image.
pub const EEPROM_IMAGE_SIZE: usize = 0x10000;
// JEDEC ef:40:18 advertises a 16 MiB W25Q128, not just its EEPROM partition.
pub(super) const SPI_NOR_SIZE: usize = 16 * 1024 * 1024;

/// Vendor ID the HAL checks as the record's magic.
pub(super) const UBIQUITI_VENDOR_ID: u16 = 0x0777;
/// `ubnthal`'s board table maps system ID 0xa642 to U6+ / UAPL6.
pub(super) const SYNTHETIC_SYSTEM_ID: u16 = 0xa642;
/// Synthetic eth0 MAC.  Locally administered, so it cannot collide with a
/// factory address; it is an emulation value, not a real serial number.
pub(super) const SYNTHETIC_ETH0_MAC: [u8; 6] = [0x02, 0, 0, 0x79, 0x81, 1];
/// Synthetic eth1 MAC, derived by the rule in `scripts/board-data.py`: the
/// first octet normally gains the locally administered bit, but this base
/// already has it, so the address is incremented instead.
pub(super) const SYNTHETIC_ETH1_MAC: [u8; 6] = [0x02, 0, 0, 0x79, 0x81, 2];
/// BOM revision, reported as `boardrevision` from its low byte.  Both APs
/// dumped from hardware carry `0x0003` in the high half (U6-Lite
/// `0x0003050f`, UAP6MP `0x0003c326`); the low half is per unit.
pub(super) const SYNTHETIC_BOM_REVISION: u32 = 0x0003_0001;
/// Ethernet, Wi-Fi and Bluetooth MAC pool sizes, at `0x801e`, `0x801f` and
/// `0x8070`.  The HAL allocates consecutive addresses from the base MAC in
/// that order, so these reproduce `eth0`, `ra0`/`rai0` and `bt0`.  Both
/// hardware records carry the same values; the Ethernet count is clamped to
/// 12 by `mt7981_scan_eeprom`.
pub(super) const ETHERNET_MAC_COUNT: u8 = 1;
pub(super) const WIFI_MAC_COUNT: u8 = 2;
pub(super) const BLUETOOTH_MAC_COUNT: u8 = 1;

/// Bytes covered by the SBD length field at `0x8008` and its CRC.
///
/// The length is a big-endian `u32` and the CRC spans exactly that many bytes
/// from `0x800c`, so the Bluetooth MAC count at `0x8070` is inside the range.
/// Both hardware dumps store `0x65`, and both CRCs reproduce with it.
pub(super) const SBD_RECORD_LENGTH: u32 = 0x65;

/// Offset of the second board record, the source of `system.info`'s
/// manufacturing fields.  Both hardware dumps agree on the layout, and
/// offsets below are relative to this base:
///
/// | Offset | Field |
/// | --- | --- |
/// | `0x00` | `12 03` signature |
/// | `0x02` | `manufid`, big-endian `u16` |
/// | `0x18` | manufacturing time, big-endian `u32` Unix seconds |
/// | `0x1e` / `0x20` | system ID / vendor ID, big-endian `u16` |
/// | `0x22` / `0x28` | eth0 / eth1 MAC |
/// | `0xb7` | BOM revision, big-endian `u32` |
/// | `0xbb` | `qrid`, six ASCII bytes and a NUL |
///
/// The HAL validates neither the signature nor any checksum here: filling the
/// span with a marker byte in the emulator made `manufid` read back as that
/// marker.  Writing only the fields both dumps agree on is therefore safe,
/// and the per-unit and high-entropy spans are left erased.
pub(super) const SECOND_RECORD_OFFSET: usize = 0xa000;
/// Manufacturer ID.  This field is a small enum where an arbitrary value has
/// no defined meaning, so the synthetic record borrows the U6-Lite's `0002`;
/// no U6+ record is available to read a real one from.
pub(super) const SYNTHETIC_MANUF_ID: u16 = 0x0002;
/// Manufacturing time, 2024-01-01T00:00:00Z.  This is the same date
/// `SYNTHETIC_MFG_DATE` spells for the `TlvInfo` block, matching hardware,
/// where one date is recorded in both places.  The HAL reports it as
/// `mfgweek=202401`.
pub(super) const SYNTHETIC_MFG_TIMESTAMP: u32 = 1_704_067_200;
/// QR identifier, six ASCII characters and a NUL.
pub(super) const SYNTHETIC_QR_ID: &[u8; 6] = b"QEMU01";

/// Length of the second record's written span.
pub(super) const SECOND_RECORD_LENGTH: usize = 0xcc;

/// Writes the second board record in place.
///
/// Only bytes both hardware dumps agree on are written.  The per-unit fields
/// at `0x08`, `0x10`, `0x30` and the high-entropy span from roughly `0x44` to
/// `0xb7` carry device-specific factory data that cannot be reconstructed, so
/// they stay erased.
pub(super) fn write_second_record(image: &mut [u8]) {
    let record = &mut image[SECOND_RECORD_OFFSET..SECOND_RECORD_OFFSET + SECOND_RECORD_LENGTH];

    record[0x00..0x02].copy_from_slice(&[0x12, 0x03]);
    record[0x02..0x04].copy_from_slice(&SYNTHETIC_MANUF_ID.to_be_bytes());
    record[0x04..0x08].copy_from_slice(&[0; 4]);
    // Both units carry 0x06 here, then three per-unit bytes.
    record[0x08] = 0x06;
    record[0x0c..0x10].copy_from_slice(&[0; 4]);
    record[0x10] = 0x06;
    record[0x14..0x18].copy_from_slice(&[0; 4]);
    record[0x18..0x1c].copy_from_slice(&SYNTHETIC_MFG_TIMESTAMP.to_be_bytes());
    record[0x1c..0x1e].copy_from_slice(&[0x00, 0x14]);
    record[0x1e..0x20].copy_from_slice(&SYNTHETIC_SYSTEM_ID.to_be_bytes());
    record[0x20..0x22].copy_from_slice(&UBIQUITI_VENDOR_ID.to_be_bytes());
    record[0x22..0x28].copy_from_slice(&SYNTHETIC_ETH0_MAC);
    record[0x28..0x2e].copy_from_slice(&SYNTHETIC_ETH1_MAC);
    record[0x2e..0x30].copy_from_slice(&[0x00, 0xc2]);
    record[0x32..0x34].copy_from_slice(&[0x10, 0xc2]);
    record[0xb7..0xbb].copy_from_slice(&SYNTHETIC_BOM_REVISION.to_be_bytes());
    record[0xbb..0xc1].copy_from_slice(SYNTHETIC_QR_ID);
    record[0xc1..0xc6].copy_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x00]);
    record[0xc7..0xcb].copy_from_slice(&[0x06, 0x01, 0x00, 0x05]);
}

/// Offset of the per-device key container, present on both hardware dumps.
///
/// The layout is a `91NT` magic, a version byte (`0x02`), a big-endian `u16`
/// payload length, then the payload: an RFC 4253 style sequence of
/// `ssh-rsa`, `e`, `n`, `d`, `p` and `q`, so the container holds an RSA
/// *private* key.  Real units carry 805 payload bytes for a 2048-bit key.
pub(super) const DEVICE_KEY_OFFSET: usize = 0xe004;
pub(super) const DEVICE_KEY_MAGIC: &[u8; 4] = b"91NT";
pub(super) const DEVICE_KEY_VERSION: u8 = 0x02;

/// A synthetic 2048-bit RSA private key in the container's payload encoding.
///
/// This key was generated for the emulator and has no security value: it is
/// committed in the open, identical on every build, and must never be
/// trusted or used to identify anything.  It exists so the region is
/// well-formed rather than erased, matching the shape of hardware records.
/// No real device's key is reproduced here; per-device factory keys stay on
/// their devices.
pub(super) const SYNTHETIC_DEVICE_KEY: &[u8] = include_bytes!("synthetic_device_key.bin");

/// Writes the device key container in place.
pub(super) fn write_device_key(image: &mut [u8]) {
    let length = u16::try_from(SYNTHETIC_DEVICE_KEY.len()).expect("key payload fits a u16");
    image[DEVICE_KEY_OFFSET..DEVICE_KEY_OFFSET + 4].copy_from_slice(DEVICE_KEY_MAGIC);
    image[DEVICE_KEY_OFFSET + 4] = DEVICE_KEY_VERSION;
    image[DEVICE_KEY_OFFSET + 5..DEVICE_KEY_OFFSET + 7].copy_from_slice(&length.to_be_bytes());
    let payload = DEVICE_KEY_OFFSET + 7;
    image[payload..payload + SYNTHETIC_DEVICE_KEY.len()].copy_from_slice(SYNTHETIC_DEVICE_KEY);
}

/// Offset of the ONIE-style `TlvInfo` block, as found in both hardware dumps.
pub(super) const TLV_INFO_OFFSET: usize = 0xd000;
/// Manufacture date, ASCII `YYYYMMDD`.  The HAL derives `mfgweek` from it as
/// `year * 100 + ceil(day_of_year / 7)`; both dumps agree (`20210918` ->
/// `202138`, `20220806` -> `202232`).
pub(super) const SYNTHETIC_MFG_DATE: &[u8; 8] = b"20240101";
/// Part number.  Real records end in the board revision (`113-00773-15` at
/// revision 15, `113-00963-38` at revision 38); this one carries the
/// synthetic revision above.
pub(super) const SYNTHETIC_PART_NUMBER: &[u8; 12] = b"113-00000-01";

/// Builds the manufacturing `TlvInfo` block both hardware dumps carry.
///
/// The layout is ONIE's, but the checksum is not.  The `0xfe` CRC TLV stores
/// `legacy_crc32` -- the same reflected, unseeded variant the SBD record uses
/// -- over the block up to but excluding that TLV's own type and length
/// bytes, big-endian.  Both hardware dumps reproduce with exactly that, and
/// with neither ONIE's standard CRC-32 nor any other range tried.
///
/// This block is **not** what `/proc/ubnthal/system.info` reports, and adding
/// it does not change the guest's output.  `systeminfo_dump` renders
/// `mfgweek` from a 32-bit Unix timestamp through `time64_to_tm`, with
/// `manufid` and `qrid` in neighbouring fields; a marker-fill experiment in
/// the emulator located their source in a **second record at `0xa000`**, not
/// here (see `SECOND_RECORD_OFFSET`).  The dates do correlate with the
/// reported `mfgweek` (`20210918` with `202138`, `20220806` with `202232`)
/// because both record the same manufacturing date, not because the HAL
/// reads this block.
///
/// Tag `0x03` is `0x01` on both units and its meaning is unknown.
pub(super) fn generate_tlv_info() -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, value) in [
        (0x01_u8, &SYNTHETIC_MFG_DATE[..]),
        (0x02, &SYNTHETIC_MFG_DATE[..]),
        (0x03, &[0x01][..]),
        (0x04, &SYNTHETIC_PART_NUMBER[..]),
    ] {
        body.push(tag);
        body.push(u8::try_from(value.len()).expect("TLV value length fits a byte"));
        body.extend_from_slice(value);
    }
    // The six-byte CRC TLV is counted in the declared length, but not in the
    // checksummed range.
    let total = u16::try_from(body.len() + 6).expect("TlvInfo block fits a u16");

    let mut block = Vec::with_capacity(11 + usize::from(total));
    block.extend_from_slice(b"TlvInfo\0");
    block.push(1);
    block.extend_from_slice(&total.to_be_bytes());
    block.extend_from_slice(&body);
    let crc = legacy_crc32(&block);
    block.extend_from_slice(&[0xfe, 4]);
    block.extend_from_slice(&crc.to_be_bytes());
    block
}

/// Builds the deterministic EEPROM record consumed by the U6+ `ubnthal` module.
///
/// The real board stores this record in the `EEPROM` SPI-NOR partition.  The
/// QEMU board has no physical flash image by default, so it must start with a
/// valid record rather than an all-zero NOR device; otherwise `ubnthal` fails
/// its scan and dependent modules such as `gpiodev` report unresolved symbols.
///
/// The layout follows `EEPROM` partition dumps taken from a live U6-Lite
/// (`a612`) and UAP6MP (`a650`); `scripts/board-data.py` documents the head
/// record and parses both.  The `TlvInfo` block at `0xd000` is reproduced;
/// the second board record at `0xa000` and the device key container at
/// `0xe004` are reproduced too.  The per-unit factory spans inside the
/// `0x9000` region are not, and cannot be.
#[must_use]
pub fn generate_eeprom() -> Vec<u8> {
    // NOR flash the factory never wrote reads back erased, and the vendor
    // parser sees 0xff there rather than zero.
    let mut image = vec![0xff; EEPROM_IMAGE_SIZE];

    // Head record: the two MACs, then board and vendor IDs in the opposite
    // order to the SBD record below, then the BOM revision.
    image[0x00..0x06].copy_from_slice(&SYNTHETIC_ETH0_MAC);
    image[0x06..0x0c].copy_from_slice(&SYNTHETIC_ETH1_MAC);
    image[0x0c..0x0e].copy_from_slice(&SYNTHETIC_SYSTEM_ID.to_be_bytes());
    image[0x0e..0x10].copy_from_slice(&UBIQUITI_VENDOR_ID.to_be_bytes());
    image[0x10..0x14].copy_from_slice(&SYNTHETIC_BOM_REVISION.to_be_bytes());

    // SBD record.
    image[0x8000..0x8004].copy_from_slice(b"UBNT");
    image[0x8008..0x800c].copy_from_slice(&SBD_RECORD_LENGTH.to_be_bytes());
    // SBD fields are big-endian; only the CRC below is native little-endian.
    image[0x800c..0x800e].copy_from_slice(&2_u16.to_be_bytes());
    image[0x800e..0x8010].copy_from_slice(&2_u16.to_be_bytes());
    image[0x8010..0x8012].copy_from_slice(&UBIQUITI_VENDOR_ID.to_be_bytes());
    image[0x8012..0x8014].copy_from_slice(&SYNTHETIC_SYSTEM_ID.to_be_bytes());
    image[0x8014..0x8018].copy_from_slice(&SYNTHETIC_BOM_REVISION.to_be_bytes());
    image[0x8018..0x801e].copy_from_slice(&SYNTHETIC_ETH0_MAC);
    // MAC pool sizes, not opaque bytes.  `mt7981_scan_eeprom` reads the
    // Ethernet count at 0x801e (clamped to 12), the Wi-Fi count at 0x801f,
    // and the Bluetooth count at 0x8070, then hands out consecutive
    // addresses from the base above.  One, two and one reproduce the U6+'s
    // eth0, ra0/rai0 and bt0, and match both hardware records.
    image[0x801e] = ETHERNET_MAC_COUNT;
    image[0x801f] = WIFI_MAC_COUNT;
    image[0x8020..0x8022].copy_from_slice(&[0, 0]);
    image[0x8070] = BLUETOOTH_MAC_COUNT;

    // Manufacturing fields the HAL actually reports.
    write_second_record(&mut image);

    // Manufacturing metadata block, for fidelity with hardware dumps; see
    // `generate_tlv_info` for why it does not reach `system.info`.
    let tlv_info = generate_tlv_info();
    image[TLV_INFO_OFFSET..TLV_INFO_OFFSET + tlv_info.len()].copy_from_slice(&tlv_info);

    // Synthetic device key, so the region is well-formed rather than erased.
    write_device_key(&mut image);

    let start = 0x800c;
    let end = start + SBD_RECORD_LENGTH as usize;
    let crc = legacy_crc32(&image[start..end]);
    image[0x8004..0x8008].copy_from_slice(&crc.to_le_bytes());
    image
}

/// Offset of the `u-boot-env` SPI-NOR partition, matching the device tree.
pub const UBOOT_ENV_OFFSET: usize = 0x1_0000;
/// Size of the `u-boot-env` SPI-NOR partition, matching `/etc/fw_env.config`.
pub const UBOOT_ENV_SIZE: usize = 0x8_0000;

/// The board model as the U-Boot environment spells it.
///
/// A live U6-Lite stores `device_model=U6-LITE`, upper-case where
/// `/etc/board.info` says `U6-Lite`.  `ubntbox` reads the variable back out of
/// `/var/run/fw_env`, which preinit fills with `fw_printenv`; with the
/// variable missing it renders a `ubnt::errors` token instead, which is how
/// `Error-A12` reached `/etc/version` and the early hostname.
pub(super) const SYNTHETIC_DEVICE_MODEL: &str = "U6-PLUS";

/// Builds the U-Boot environment block the board ships.
///
/// An erased SPI-NOR partition makes `fw_printenv` report `Warning: Bad CRC,
/// using default environment` and leaves `fw_setenv` writing over an
/// unrecognized block.  The layout is the non-redundant one named by the
/// firmware's `/etc/fw_env.config`: a leading CRC-32 over the remaining bytes,
/// then NUL-separated `key=value` entries closed by an empty one.
///
/// The variables and their order are a live U6-Lite's, with the addresses and
/// model changed to this board's.  `device_model` is the one the firmware
/// actually reads; the rest are carried so `fw_printenv` looks like hardware.
#[must_use]
pub fn generate_uboot_env() -> Vec<u8> {
    let mac = SYNTHETIC_ETH0_MAC
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let variables = [
        "baudrate=115200".to_owned(),
        "bootcmd=bootubnt".to_owned(),
        "bootdelay=2".to_owned(),
        format!("device_model={SYNTHETIC_DEVICE_MODEL}"),
        format!("ethaddr={mac}"),
        "fw_version=9.9.9".to_owned(),
        "ipaddr=192.168.1.20".to_owned(),
        "is_default=false".to_owned(),
        format!("macaddr={mac}"),
        "netmask=255.255.255.0".to_owned(),
        "serverip=192.168.1.19".to_owned(),
    ];

    let mut image = vec![0_u8; UBOOT_ENV_SIZE];
    let mut offset = 4;
    for variable in &variables {
        image[offset..offset + variable.len()].copy_from_slice(variable.as_bytes());
        // Each entry is NUL-terminated; the trailing NUL already present ends
        // the list.
        offset += variable.len() + 1;
    }
    let checksum = crc32(&image[4..]);
    image[0..4].copy_from_slice(&checksum.to_le_bytes());
    image
}

/// Magic at the head of a stored `UniFi` configuration record.
pub(super) const CFG_RECORD_MAGIC: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

/// Bytes of fixed header ahead of a record's compressed payload.
pub(super) const CFG_RECORD_HEADER_LEN: usize = 0x18;

/// Distance between the two record slots in a `cfg` partition.
///
/// The U6-Lite's 1 MiB `cfg` partition holds its second record exactly here,
/// and the guest only finds the second kind at this stride: seeded half a
/// partition apart instead, `cfgmtd` reports `Could not find cfg type: 1`.
pub(super) const CFG_RECORD_SLOT_STRIDE: u64 = 0x8_0000;

/// Record kind the factory writes into a `cfg` partition's first slot.
pub(super) const CFG_RECORD_KIND_FIRST: u32 = 2;

/// Record kind in the second slot, which `cfgmtd` looks for first.
pub(super) const CFG_RECORD_KIND_SECOND: u32 = 1;

/// Hostname the seeded configuration gives the board.
///
/// `sanitize_cfg` in the firmware's `usr/bin/unifi_util_funcs.sh` reads
/// `resolv.host.1.name` and `ubntbox` writes it to
/// `/proc/sys/kernel/hostname`.  Without a stored configuration that key is
/// absent and the guest falls back to a `ubnt::errors` token, coming up as
/// `Error-A12` in both the hostname and `/etc/version`.
pub const SYNTHETIC_HOSTNAME: &str = "U6Plus";

/// The board's default configuration, `usr/etc/default-a642.cfg` from the U6+
/// 6.7.54 firmware (`artifacts/firmware-u6plus-6.7.54-15663`), verbatim
/// including its `DEFAULTSSID` and `DEFAULTPASSWORD` placeholders.
pub(super) const VENDOR_DEFAULT_CFG: &str = include_str!("../data/default-a642.cfg");

/// The configuration text the seeded record carries.
///
/// A restored configuration has to stand on its own: the firmware's
/// `lib/preinit/99_21_ubnt_ubntconf` throws it away and copies the defaults
/// over it when it still says `mgmt.is_default=true`, which is why an
/// identity-only record left the guest on its `ubnt::errors` hostname.  So
/// this is the board's own default configuration, with the two substitutions
/// `do_ubntconf` performs applied, the default flag cleared, and the identity
/// keys the defaults never carry appended.
pub(super) fn synthetic_system_cfg() -> String {
    let serial = synthetic_serial_number();
    // `do_ubntconf` builds the default PSK from the serial's last six
    // characters followed by the QR id.
    let key = format!(
        "{}{}",
        &serial[serial.len() - 6..],
        String::from_utf8_lossy(SYNTHETIC_QR_ID)
    );

    let mut text = VENDOR_DEFAULT_CFG
        .replace("DEFAULTSSID", &serial)
        .replace("DEFAULTPASSWORD", &key)
        .replace("mgmt.is_default=true", "mgmt.is_default=false");
    write!(
        text,
        "\nresolv.status=enabled\n\
         resolv.host.1.name={SYNTHETIC_HOSTNAME}\n\
         resolv.nameserver.1.status=disabled\n\
         resolv.nameserver.2.status=disabled\n"
    )
    .expect("writing configuration to a String cannot fail");
    text
}

/// The serial number the HAL derives from the eth0 MAC, as the firmware's
/// scripts read it out of `/proc/ubnthal/system.info` and upper-case it.
pub(super) fn synthetic_serial_number() -> String {
    let mut serial = String::with_capacity(SYNTHETIC_ETH0_MAC.len() * 2);
    for octet in SYNTHETIC_ETH0_MAC {
        write!(serial, "{octet:02X}").expect("writing a serial number to a String cannot fail");
    }
    serial
}

/// Writes a zero-padded octal `ustar` field, NUL-terminated as the format
/// requires.
pub(super) fn tar_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    field[..digits].copy_from_slice(&text.as_bytes()[text.len() - digits..]);
    field[digits] = 0;
}

/// A `tar` archive holding the empty `persistent` directory.
///
/// `cfgmtd` restores `/etc/persistent` by unpacking this archive; on a board
/// with no stored record the directory never appears at all, and `login`
/// reports `can't change directory to '/etc/persistent'`.
pub(super) fn persistent_tar() -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..11].copy_from_slice(b"persistent/");
    tar_octal(&mut header[100..108], 0o755);
    tar_octal(&mut header[108..116], 0);
    tar_octal(&mut header[116..124], 0);
    tar_octal(&mut header[124..136], 0);
    tar_octal(&mut header[136..148], 0);
    header[156] = b'5';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    // The checksum is computed with its own field read as spaces.
    header[148..156].copy_from_slice(b"        ");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    tar_octal(&mut header[148..155], u64::from(checksum));
    header[155] = b' ';

    let mut archive = header.to_vec();
    // Two zero blocks close the archive.
    archive.extend_from_slice(&[0_u8; 1024]);
    archive
}

/// Builds one stored configuration record of the given kind.
///
/// The layout is taken from a live U6-Lite's `cfg` partition, which holds two
/// such records, one per slot:
///
/// | Offset | Field |
/// | --- | --- |
/// | `0x00` | magic `12 34 56 78` |
/// | `0x04` | big-endian u32 length of the zlib stream |
/// | `0x08` | big-endian standard CRC-32 over the configuration text |
/// | `0x0c` | big-endian u32 length of that text |
/// | `0x10` | little-endian u32 record kind, 1 or 2 |
/// | `0x18` | zlib stream: the text, then a gzipped `tar` of `/etc/persistent` |
///
/// Both of the dumped records carry the same text and CRC and differ only in
/// their kind and their archive, so the CRC covers the text alone.
#[must_use]
pub fn generate_cfg_record(kind: u32) -> Vec<u8> {
    let text = synthetic_system_cfg();
    let mut payload = text.clone().into_bytes();
    let mut archive = GzEncoder::new(Vec::new(), Compression::default());
    let _ = archive.write_all(&persistent_tar());
    payload.extend_from_slice(&archive.finish().unwrap_or_default());

    let mut deflated = ZlibEncoder::new(Vec::new(), Compression::default());
    let _ = deflated.write_all(&payload);
    let compressed = deflated.finish().unwrap_or_default();

    let mut record = vec![0_u8; CFG_RECORD_HEADER_LEN];
    record[0x00..0x04].copy_from_slice(&CFG_RECORD_MAGIC);
    record[0x04..0x08].copy_from_slice(
        &u32::try_from(compressed.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    record[0x08..0x0c].copy_from_slice(&crc32(text.as_bytes()).to_be_bytes());
    record[0x0c..0x10]
        .copy_from_slice(&u32::try_from(text.len()).unwrap_or(u32::MAX).to_be_bytes());
    record[0x10..0x14].copy_from_slice(&kind.to_le_bytes());
    record.extend_from_slice(&compressed);
    record
}

/// Addressable blocks on the emulated eMMC.  The CSD reported by the card
/// model advertises 1 GiB and the GPT keeps its backup header in the last
/// block, so the two must agree.
pub const EMMC_BLOCK_COUNT: usize = 2 * 1024 * 1024;

/// Partition names and block counts written into the default eMMC image.
///
/// The names and their order are the device's own, taken from
/// `usr/etc/mmc-table.txt` in the U6+ firmware.  That file records no sizes.
/// `Factory` is sized from evidence: `INDEX0_EEPROM_size=0x200000` in
/// `/etc/wireless/l1profile_mt7981.dat`, which the firmware's
/// `/etc/hotplug.d/firmware/11-mtk-wifi-e2p` handler compares against the
/// partition's size before copying it out as the radio calibration blob.  The
/// remaining block counts are chosen to be plausible for this 1 GiB card and
/// only need to give each name a block device.  `cfg` is the partition the
/// `UniFi` configuration tools open as `/dev/mmcblk0p9`.
pub(super) const EMMC_PARTITIONS: [(&str, u64); 10] = [
    ("bl2", 1024),
    ("u-boot-env", 1024),
    ("Factory", 4096),
    ("u-boot", 4096),
    ("EEPROM", 1024),
    ("kernel0", 65536),
    ("kernel1", 65536),
    ("bs", 2048),
    ("cfg", 32768),
    ("log", 32768),
];

pub(super) const GPT_ENTRY_COUNT_USIZE: usize = 128;
pub(super) const GPT_ENTRY_COUNT_U32: u32 = 128;
pub(super) const GPT_ENTRY_SIZE: usize = 128;
pub(super) const GPT_ENTRY_SIZE_U32: u32 = 128;
pub(super) const GPT_ENTRIES_LBA: u64 = 2;
pub(super) const GPT_ENTRY_BLOCKS: u64 = 32;
pub(super) const GPT_PRIMARY_BLOCKS: usize = 34;
pub(super) const GPT_ENTRIES_OFFSET: usize = 2 * GPT_BLOCK_SIZE;
pub(super) const GPT_FIRST_ALIGNED_LBA: u64 = 2048;
pub(super) const GPT_BLOCK_SIZE: usize = 512;
/// Mixed-endian encoding of the "Linux filesystem data" partition type GUID
/// `0FC63DAF-8483-4772-8E79-3D69D8477DE4`.
pub(super) const GPT_LINUX_TYPE_GUID: [u8; 16] = [
    0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
];

pub(super) fn gpt_partition_entries() -> Vec<u8> {
    let mut entries = vec![0_u8; GPT_ENTRY_COUNT_USIZE * GPT_ENTRY_SIZE];
    let mut lba = GPT_FIRST_ALIGNED_LBA;
    for (index, (name, blocks)) in EMMC_PARTITIONS.iter().enumerate() {
        let last = lba + blocks - 1;
        let entry = &mut entries[index * GPT_ENTRY_SIZE..(index + 1) * GPT_ENTRY_SIZE];
        entry[0..16].copy_from_slice(&GPT_LINUX_TYPE_GUID);
        // A deterministic per-partition unique GUID keeps images reproducible.
        entry[16..32].copy_from_slice(&GPT_LINUX_TYPE_GUID);
        entry[16] = u8::try_from(index + 1).unwrap_or(0xff);
        entry[32..40].copy_from_slice(&lba.to_le_bytes());
        entry[40..48].copy_from_slice(&last.to_le_bytes());
        for (position, unit) in name.encode_utf16().take(36).enumerate() {
            let offset = 56 + position * 2;
            entry[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        lba = last + 1;
    }
    entries
}

pub(super) fn gpt_header(current: u64, backup: u64, entries_lba: u64, entries_crc: u32) -> Vec<u8> {
    let block_count = EMMC_BLOCK_COUNT as u64;
    let mut header = vec![0_u8; GPT_BLOCK_SIZE];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
    header[12..16].copy_from_slice(&92_u32.to_le_bytes());
    header[24..32].copy_from_slice(&current.to_le_bytes());
    header[32..40].copy_from_slice(&backup.to_le_bytes());
    header[40..48].copy_from_slice(&(GPT_ENTRIES_LBA + GPT_ENTRY_BLOCKS).to_le_bytes());
    header[48..56].copy_from_slice(&(block_count - 2 - GPT_ENTRY_BLOCKS).to_le_bytes());
    // Deterministic disk GUID; only its stability matters to the guest.
    header[56..72].copy_from_slice(&GPT_LINUX_TYPE_GUID);
    header[56] = 0x06;
    header[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    header[80..84].copy_from_slice(&GPT_ENTRY_COUNT_U32.to_le_bytes());
    header[84..88].copy_from_slice(&GPT_ENTRY_SIZE_U32.to_le_bytes());
    header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let checksum = crc32(&header[..92]);
    header[16..20].copy_from_slice(&checksum.to_le_bytes());
    header
}

/// Builds the default eMMC contents as `(starting block, bytes)` regions: the
/// protective MBR with the primary GPT at the front of the card and the GPT
/// backup structures at its end.
///
/// Without them the emulated card is blank, no `/dev/mmcblk0pN` node appears,
/// and the `UniFi` configuration tools fail with
/// `Could not open MTD device /dev/mmcblk0p9`.
#[must_use]
pub fn generate_emmc_regions() -> Vec<(u64, Vec<u8>)> {
    let block_count = EMMC_BLOCK_COUNT as u64;
    let backup_lba = block_count - 1;
    let backup_entries_lba = backup_lba - GPT_ENTRY_BLOCKS;
    let entries = gpt_partition_entries();
    let entries_crc = crc32(&entries);

    let mut head = vec![0_u8; GPT_BLOCK_SIZE * GPT_PRIMARY_BLOCKS];
    // Protective MBR: one 0xee partition spanning the device.
    head[447..450].copy_from_slice(&[0x00, 0x02, 0x00]);
    head[450] = 0xee;
    head[451..454].copy_from_slice(&[0xff, 0xff, 0xff]);
    head[454..458].copy_from_slice(&1_u32.to_le_bytes());
    head[458..462].copy_from_slice(
        &u32::try_from(block_count - 1)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    head[510..512].copy_from_slice(&[0x55, 0xaa]);
    head[512..1024].copy_from_slice(&gpt_header(1, backup_lba, GPT_ENTRIES_LBA, entries_crc));
    let entries_offset = GPT_ENTRIES_OFFSET;
    head[entries_offset..entries_offset + entries.len()].copy_from_slice(&entries);

    let mut backup = entries;
    backup.extend_from_slice(&gpt_header(backup_lba, 1, backup_entries_lba, entries_crc));

    let mut regions = vec![(0, head), (backup_entries_lba, backup)];
    if let Some((start, blocks)) = emmc_partition("cfg") {
        // Two slots, `CFG_RECORD_SLOT_STRIDE` apart, the second holding the
        // kind `cfgmtd` looks for first.
        let stride = CFG_RECORD_SLOT_STRIDE / GPT_BLOCK_SIZE as u64;
        debug_assert!(stride * 2 <= blocks, "both slots fit the cfg partition");
        regions.push((start, generate_cfg_record(CFG_RECORD_KIND_FIRST)));
        regions.push((start + stride, generate_cfg_record(CFG_RECORD_KIND_SECOND)));
    }
    regions
}

/// Locates a partition in the default eMMC layout as `(starting block, blocks)`.
pub(super) fn emmc_partition(name: &str) -> Option<(u64, u64)> {
    let mut lba = GPT_FIRST_ALIGNED_LBA;
    for (partition, blocks) in EMMC_PARTITIONS {
        if partition == name {
            return Some((lba, blocks));
        }
        lba += blocks;
    }
    None
}

/// Standard CRC-32 (IEEE 802.3), as the GPT structures require.
pub(super) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}

pub(super) fn legacy_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    crc
}
