use std::fmt::Write as _;
use std::io::Write;

use flate2::Compression;
use flate2::write::{GzEncoder, ZlibEncoder};

/// Start of the `cfg` partition, `64448k` into the part in the vendor
/// `mtdparts` layout, which the guest sees as `mtd5`.
pub const CFG_PARTITION_OFFSET: u64 = 0x3ef_0000;
/// Distance between the partition's two record slots, from a live U6-Lite's
/// `cfg` dump. Two of them fill the 1 MiB partition exactly.
pub const CFG_RECORD_SLOT_STRIDE: u64 = 0x8_0000;
pub(super) const CFG_RECORD_MAGIC: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
pub(super) const CFG_RECORD_HEADER_LEN: usize = 0x18;
/// Kind held in the first slot.
pub(super) const CFG_RECORD_KIND_FIRST: u32 = 2;
/// Kind held in the second, the one `cfgmtd` asks for first: `init` runs
/// `cfgmtd -r` and only then retries with `-t 2`.
pub(super) const CFG_RECORD_KIND_SECOND: u32 = 1;

/// The board's default configuration, `usr/etc/default_bcm5334x.cfg` from the
/// US24PRO 7.5.15 firmware, verbatim.
pub(super) const VENDOR_DEFAULT_CFG: &str = include_str!("../data/default_bcm5334x.cfg");

/// Hostname the seeded configuration carries.
///
/// This controls the model name in the prompt. `Error-A12` is a separate
/// factory-authentication failure, not a missing-hostname fallback; see
/// `docs/us24pro/factory-auth.md`.
pub const CFG_HOSTNAME: &str = "USW-Pro-24-PoE";

/// The configuration text the seeded record carries.
///
/// Three changes to the vendor default. `mgmt.is_default=true` has to go:
/// `init` copies the defaults back over any restored configuration that still
/// says it, so a record carrying the flag is thrown away as soon as it is
/// read. `unifi.status` has to be there: `run_plugin` only starts a plugin
/// when `ubntconf` has written `/etc/sysinit/<name>.conf`, `ubntconf` writes
/// that one off `unifi.status`, and the vendor default has no such key --
/// which is why `mcad` never starts and `mca-ctrl -t discover` spins on a
/// `/tmp/.mcad` socket that never appears. The hostname is the third.
pub(super) fn cfg_text() -> String {
    let mut text = VENDOR_DEFAULT_CFG.replace("mgmt.is_default=true", "mgmt.is_default=false");
    write!(
        text,
        "\nunifi.status=enabled\n\
         resolv.status=enabled\n\
         resolv.host.1.name={CFG_HOSTNAME}\n"
    )
    .expect("writing configuration text to a String cannot fail");
    text
}

/// A `tar` archive holding the empty `persistent` directory, which `cfgmtd`
/// unpacks into `/etc/persistent`.
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
    header[148..156].copy_from_slice(&[b' '; 8]);
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    tar_octal(&mut header[148..155], u64::from(checksum));
    header[155] = b' ';

    let mut archive = header.to_vec();
    // Two zero blocks close the archive.
    archive.extend_from_slice(&[0_u8; 1024]);
    archive
}

/// Writes a zero-padded octal `ustar` field, NUL-terminated as the format
/// requires.
pub(super) fn tar_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    field[..digits].copy_from_slice(&text.as_bytes()[text.len() - digits..]);
    field[digits] = 0;
}

/// Builds one stored configuration record of the given kind.
///
/// The layout is the one a live U6-Lite's `cfg` partition carries, and
/// `cfgmtd` is the same binary on both:
///
/// | Offset | Field |
/// | --- | --- |
/// | `0x00` | magic `12 34 56 78` |
/// | `0x04` | big-endian u32 length of the zlib stream |
/// | `0x08` | big-endian standard CRC-32 over the configuration text |
/// | `0x0c` | big-endian u32 length of that text |
/// | `0x10` | little-endian u32 record kind, 1 or 2 |
/// | `0x18` | zlib stream: the text, then a gzipped `tar` of `persistent/` |
#[must_use]
pub fn cfg_record(kind: u32) -> Vec<u8> {
    let text = cfg_text();
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

/// Base of the `bcm-gmac0` register block.
///
/// Read out of the running guest rather than guessed: `/proc/iomem` shows
/// `18042000-18042bff : bcm-gmac0`, and `iproc_gmac_drv_probe` at
/// `0xc00192b0` takes the address from `platform_get_resource(pdev,

pub const BOARD_DATA_OFFSET: u64 = 0x3ff_0000;
/// Length `ubnthal` reads.
pub const BOARD_DATA_LEN: usize = 0x1000;
/// Ubiquiti vendor id; `scan_eeprom` rejects the record without it.
pub const VENDOR_ID_UBIQUITI: u16 = 0x0777;
/// `US24PRO`, read out of `ubnthal`'s own board table: `unifi_get_board`
/// walks records of `0x66d8` bytes from `0x155d8` comparing `+0x6454`, and
/// the record whose short name is `US24PRO` (long name `USW-Pro-24-PoE`)
/// carries this id.
pub const BOARD_ID_US24PRO: u16 = 0xeb36;

/// Builds the board-data record the vendor HAL expects.
///
/// Field offsets come from `bcm5334x_dump_boarddata`, which prints them as
/// `eth0.macaddr`, `eth1.macaddr`, `boardid`, `vendorid` and `bomrev`:
///
/// ```text
/// +0x00  6 B  eth0 MAC        +0x0c  u16 BE  boardid
/// +0x06  6 B  eth1 MAC        +0x0e  u16 BE  vendorid
///                             +0x10  u32 BE  bomrev
/// ```
///
/// The MACs use the locally administered `52:54:00` prefix, as
/// `build_udmpro_eeprom` does for the UDM Pro; only the board and vendor ids
/// are real values. Everything else is left at `0xff`, as erased flash.
#[must_use]
pub fn board_data() -> Vec<u8> {
    let mut record = vec![0xff; BOARD_DATA_LEN];
    record[0x00..0x06].copy_from_slice(&[0x52, 0x54, 0x00, 0x55, 0x53, 0x01]);
    record[0x06..0x0c].copy_from_slice(&[0x52, 0x54, 0x00, 0x55, 0x53, 0x02]);
    record[0x0c..0x0e].copy_from_slice(&BOARD_ID_US24PRO.to_be_bytes());
    record[0x0e..0x10].copy_from_slice(&VENDOR_ID_UBIQUITI.to_be_bytes());
    record[0x10..0x14].copy_from_slice(&1_u32.to_be_bytes());
    record
}

/// Offset of the u-boot environment block within the SPI-NOR.
///
/// `nvram_env_init` at `0xc001cb78` ioremaps physical `0xf0200000` for
/// [`NVRAM_ENV_LEN`] bytes; `0xf0000000` is where u-boot links and where the
/// flash is memory-mapped, so this is flash offset `0x200000`.
pub const NVRAM_ENV_OFFSET: u64 = 0x20_0000;
/// Length `nvram_env_init` maps and copies.
pub const NVRAM_ENV_LEN: usize = 0x1_0000;

/// Builds the u-boot environment block the kernel's NVRAM layer parses.
///
/// `nvram_env_init` copies [`NVRAM_ENV_LEN`] bytes out of the mapping and
/// starts parsing four bytes in, past u-boot's CRC32 header. From there it
/// walks NUL-terminated `name=value` strings, skipping leading tab, space and
/// `#`, splitting each on the first `=`, and stopping at an empty string or
/// the end of the copy. Entries land in a table of at most `0x200` pairs that
/// `nvram_get` (`0xc001cd44`) later searches.
///
/// The one variable the board actually needs is `ethaddr`: the GMAC probe at
/// `0xc00192b0` asks `sub_c001cd04` for unit 0's variable name — which is the
/// literal `"ethaddr"` — looks it up, and on failure prints
/// `et0: ethaddr not found, ignore it` and returns `-ENODEV`, leaving the
/// guest with no network interface. `eth1addr` follows u-boot's convention for
/// the second port and matches the board-data record's eth1 MAC.
///
/// The CRC32 is u-boot's: the standard reflected polynomial with an inverted
/// initial and final value, over everything after the header.
#[must_use]
pub fn nvram_env() -> Vec<u8> {
    let vars = ["ethaddr=52:54:00:55:53:01", "eth1addr=52:54:00:55:53:02"];
    let mut body = Vec::with_capacity(NVRAM_ENV_LEN - 4);
    for var in vars {
        body.extend_from_slice(var.as_bytes());
        body.push(0);
    }
    // The parser stops on an empty string, so the table ends with a second
    // NUL. u-boot pads the remainder of the block with zeroes.
    body.push(0);
    body.resize(NVRAM_ENV_LEN - 4, 0);

    let mut image = Vec::with_capacity(NVRAM_ENV_LEN);
    image.extend_from_slice(&crc32(&body).to_le_bytes());
    image.extend_from_slice(&body);
    image
}

pub(super) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}
