#![allow(unsafe_code)]
#![warn(missing_docs)]

//! The sole unsafe boundary for board models.

use board_core::dma::TransferStatus;
use board_core::{AccessWidth, Describe, Event, Machine, MachineContext, MmioError};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
mod alpine;
mod lcm;
mod net;
mod wifi;

/// Board kind understood by the ABI.
#[repr(u32)]
pub enum UnifiBoardKind {
    /// MT7981/U6+.
    Mt7981 = 1,
    /// UDM Pro/Alpine.
    UdmPro = 2,
    /// BCM5616x/iProc switch (US24PRO class).
    Bcm5616x = 3,
}
/// Host callbacks borrowed for one execution call.
#[repr(C)]
pub struct UnifiHost {
    /// Current virtual time.
    pub now_ns: u64,
    /// Optional DMA read callback.
    pub dma_read: Option<extern "C" fn(*mut std::ffi::c_void, u64, *mut u8, usize) -> u32>,
    /// Optional DMA write callback.
    pub dma_write: Option<extern "C" fn(*mut std::ffi::c_void, u64, *const u8, usize) -> u32>,
    /// Optional diagnostic logger.
    pub log: Option<extern "C" fn(*mut std::ffi::c_void, u32, *const u8, usize)>,
    /// Host-owned callback context.
    pub context: *mut std::ffi::c_void,
}
/// One cold-path memory window returned to a host.
#[repr(C)]
pub struct UnifiWindow {
    /// First physical address.
    pub base: u64,
    /// Window length in bytes.
    pub size: u64,
    /// Overlap priority.
    pub priority: u32,
    /// Stable model device identifier.
    pub device: u32,
}

/// Hardware layout shared by the Rust UDM Pro model and QEMU.
#[repr(C)]
pub struct UnifiUdmProLayout {
    /// Stable board identifier used by the UDM Pro userspace profile.
    pub board_id: *const std::ffi::c_char,
    /// Synthetic vendor identifier used when the factory EEPROM is blank.
    pub vendor_id: *const std::ffi::c_char,
    /// Synthetic system identifier used by UDM Pro board selection.
    pub system_id: *const std::ffi::c_char,
    /// Stable emulation serial number.
    pub serial_number: *const std::ffi::c_char,
    /// Human-readable model name.
    pub model: *const std::ffi::c_char,
    /// Primary Alpine UART address and interrupt.
    pub uart_base: u64,
    /// Primary Alpine UART interrupt.
    pub uart_irq: u32,
    /// Alpine UART1: the port the CSR8811 Bluetooth controller hangs off.
    pub bt_uart_base: u64,
    /// Alpine UART1 interrupt.
    pub bt_uart_irq: u32,
    /// Alpine DW SPI controller address and interrupt.
    pub spi_base: u64,
    /// Alpine DW SPI controller interrupt.
    pub spi_irq: u32,
    /// Primary SP805 watchdog address and interrupt.
    pub watchdog_base: u64,
    /// Primary SP805 watchdog interrupt.
    pub watchdog_irq: u32,
    /// Integrated Ethernet unit register bases.
    pub ethernet_bases: [u64; 4],
    /// PL061 GPIO register bases.
    pub gpio_bases: [u64; 6],
    /// Linux global GPIO offsets for each PL061 bank.
    pub gpio_base_indices: [u32; 6],
}

// These pointers refer only to immutable, process-lifetime C strings below;
// publishing the descriptor through a shared static cannot create a data race.
unsafe impl Sync for UnifiUdmProLayout {}

static UDM_PRO_LAYOUT: UnifiUdmProLayout = UnifiUdmProLayout {
    board_id: c"ea15".as_ptr(),
    vendor_id: c"0777".as_ptr(),
    system_id: c"ea15".as_ptr(),
    serial_number: c"020000000001".as_ptr(),
    model: c"UDM-Pro".as_ptr(),
    uart_base: 0xfd883000,
    uart_irq: 17,
    // The vendor DT declares uart1 at 0xfd884000 on SPI 18, and
    // /usr/sbin/hci-device-up drives the UDM Pro's `ea15` board through
    // /dev/ttyS1.  Linux enumerates the two nodes in address order, so this
    // has to be a real second 16550 for that name to land on the right port.
    bt_uart_base: 0xfd884000,
    bt_uart_irq: 18,
    spi_base: 0xfd882000,
    spi_irq: 23,
    watchdog_base: 0xfd88c000,
    watchdog_irq: 13,
    ethernet_bases: [0xfc000000, 0xfc100000, 0xfc200000, 0xfc300000],
    gpio_bases: [
        0xfd887000, 0xfd888000, 0xfd889000, 0xfd88a000, 0xfd88b000, 0xfd897000,
    ],
    gpio_base_indices: [0, 8, 16, 24, 32, 40],
};

const UDM_PRO_EEPROM_SIZE: usize = 0x10000;

/// The UDM Pro's entry in `ubnt-tools`' board table.
///
/// A different value retargets the model to another console, but only one the
/// firmware's own table already knows; an unlisted id misses the lookup and
/// drops the guest onto the generic `ARMv8` profile.
pub const UDM_PRO_SYSTEM_ID: u16 = 0xea15;

fn build_udmpro_eeprom(system_id: u16) -> Vec<u8> {
    // Match the erased NOR state used by the vendor parser.  In particular,
    // bytes outside the 0x65-byte legacy record are 0xff, not zero.
    let mut image = vec![0xff; UDM_PRO_EEPROM_SIZE];
    image[0..12].copy_from_slice(&[
        0x52, 0x54, 0x00, 0x4d, 0x50, 0x01, 0x52, 0x54, 0x00, 0x4d, 0x50, 0x02,
    ]);
    // `ubnt-tools` does not read the UBNT record at 0x8000 for this platform.
    // Its handler for MIDR 0x411fd073 (sub_40e120) takes the base of the 64 KiB
    // region and reads a legacy header there: a big-endian u16 system id at
    // 0x0c and vendor id at 0x0e, which it matches against a 13-entry board
    // table keyed on the bare system id -- 0xea15 is the UDM Pro.  Leaving
    // these bytes erased made every lookup miss and fall back to the generic
    // `ARMv8` profile, which in turn made unifi-core exit with
    // `Unsupported console model`.
    image[0x0c..0x0e].copy_from_slice(&system_id.to_be_bytes());
    image[0x0e..0x10].copy_from_slice(&0x0777_u16.to_be_bytes());
    // ubnt-tools reads this big-endian revision separately from the UBNT
    // record below. Erased bytes become hwrev=0xffffffff, which overflows
    // ULP's signed revision parser and prevents its host service starting.
    image[0x10..0x14].copy_from_slice(&10_u32.to_be_bytes());
    // The second identity record `ubnt-tools` reads before it will use the
    // version-5 UUID derivation; see docs/udm-pro/qemu-emulation.md.  With any
    // of these missing it falls back to an MD5/version-3 UUID, which the UniFi
    // Network application rejects outright with `Invalid uuid version - 3`.
    // Format 0x12 with a sub-version above 1 is the combination that also
    // enables the 6-character field at 0xa0bb.
    image[0xa000] = 0x12;
    image[0xa001] = 0x02;
    image[0xa020..0xa022].copy_from_slice(&0x0777_u16.to_be_bytes());
    // Read into board profile +0x9b, which `ubnt-tools id` prints as
    // board.serialno; keep it consistent with the MAC used everywhere else.
    image[0xa022..0xa028].copy_from_slice(&[0x52, 0x54, 0x00, 0x4d, 0x50, 0x01]);
    // Six ASCII characters.  The fallback path stamps the literal "000000"
    // here, and an all-0xff or all-zero read is rejected, so this is
    // deliberately a plausible synthetic value rather than either.
    image[0xa0bb..0xa0c1].copy_from_slice(b"QEMU01");
    image[0x8000..0x8004].copy_from_slice(b"UBNT");
    image[0x8008..0x800b].fill(0);
    image[0x800b] = 0x65;
    image[0x800c..0x800e].copy_from_slice(&2_u16.to_be_bytes());
    image[0x800e..0x8010].copy_from_slice(&2_u16.to_be_bytes());
    image[0x8010..0x8012].copy_from_slice(&0x0777_u16.to_be_bytes());
    image[0x8012..0x8014].copy_from_slice(&system_id.to_be_bytes());
    // UDM Pro's Alpine board table identifies this hardware as BOM 10.
    image[0x8014..0x8018].copy_from_slice(&10_u32.to_be_bytes());
    image[0x8018..0x801e].copy_from_slice(&[0x52, 0x54, 0x00, 0x4d, 0x50, 0x01]);
    image[0x801e..0x8020].copy_from_slice(&[2, 2]);
    image[0x8070] = 0x01;
    // The legacy record's length is 0x65 bytes and includes the marker at
    // 0x8070. The vendor stores the CRC as a little-endian u32.
    let crc = udmpro_legacy_crc32(&image[0x800c..0x8071]);
    image[0x8004..0x8008].copy_from_slice(&crc.to_le_bytes());
    image
}

fn udmpro_legacy_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    crc
}

/// Returns the deterministic UDM Pro factory EEPROM record.
#[must_use]
pub fn udmpro_eeprom() -> &'static [u8] {
    static EEPROM: OnceLock<Vec<u8>> = OnceLock::new();
    EEPROM
        .get_or_init(|| build_udmpro_eeprom(UDM_PRO_SYSTEM_ID))
        .as_slice()
}

/// Returns the UDM Pro factory EEPROM built for `system_id`.
///
/// The default id takes the cached image above. Any other is built once and
/// kept for the life of the process, so the returned slice stays valid for the
/// flash seeding and the comparison that decides whether to reseed.
#[must_use]
pub fn udmpro_eeprom_for(system_id: u16) -> &'static [u8] {
    if system_id == UDM_PRO_SYSTEM_ID {
        return udmpro_eeprom();
    }
    static RETARGETED: Mutex<BTreeMap<u16, &'static [u8]>> = Mutex::new(BTreeMap::new());
    let mut cache = RETARGETED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.entry(system_id).or_insert_with(|| {
        let image: &'static mut [u8] = Box::leak(build_udmpro_eeprom(system_id).into_boxed_slice());
        &*image
    })
}

/// Returns the deterministic UDM Pro EEPROM through the C ABI.
///
/// # Safety
///
/// `size` may be null or point to a writable `usize` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_udmpro_eeprom(size: *mut usize) -> *const u8 {
    let image = udmpro_eeprom();
    if !size.is_null() {
        // SAFETY: the caller owns the writable size pointer.
        unsafe { *size = image.len() };
    }
    image.as_ptr()
}

/// Returns the UDM Pro EEPROM for `system_id` through the C ABI.
///
/// Pass [`UDM_PRO_SYSTEM_ID`] for the stock console.
///
/// # Safety
///
/// `size` may be null or point to a writable `usize` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_udmpro_eeprom_for(system_id: u16, size: *mut usize) -> *const u8 {
    let image = udmpro_eeprom_for(system_id);
    if !size.is_null() {
        // SAFETY: the caller owns the writable size pointer.
        unsafe { *size = image.len() };
    }
    image.as_ptr()
}

/// Returns the stock UDM Pro system id through the C ABI.
#[unsafe(no_mangle)]
pub extern "C" fn unifi_udmpro_default_system_id() -> u16 {
    UDM_PRO_SYSTEM_ID
}

/// Returns the BCM5616x board-data record and its length.
///
/// The machine seeds it into the SPI-NOR image at
/// [`bcm5616x_machine::BOARD_DATA_OFFSET`], where the vendor HAL reads it.
///
/// # Safety
/// `size` may be null or point to a writable `usize` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_bcm5616x_board_data(size: *mut usize) -> *const u8 {
    static RECORD: OnceLock<Vec<u8>> = OnceLock::new();
    let record = RECORD.get_or_init(bcm5616x_machine::board_data);
    if !size.is_null() {
        // SAFETY: the caller owns the writable size pointer.
        unsafe { *size = record.len() };
    }
    record.as_ptr()
}

/// Returns the flash offset the board-data record is seeded at.
#[unsafe(no_mangle)]
pub extern "C" fn unifi_bcm5616x_board_data_offset() -> u64 {
    bcm5616x_machine::BOARD_DATA_OFFSET
}

/// Returns the BCM5616x u-boot environment block and its length.
///
/// The machine seeds it into the SPI-NOR image at
/// [`bcm5616x_machine::NVRAM_ENV_OFFSET`], which the kernel's NVRAM layer
/// ioremaps at physical `0xf0200000` to find `ethaddr`.
///
/// # Safety
/// `size` may be null or point to a writable `usize` for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_bcm5616x_nvram_env(size: *mut usize) -> *const u8 {
    static ENV: OnceLock<Vec<u8>> = OnceLock::new();
    let env = ENV.get_or_init(bcm5616x_machine::nvram_env);
    if !size.is_null() {
        // SAFETY: the caller owns the writable size pointer.
        unsafe { *size = env.len() };
    }
    env.as_ptr()
}

/// Returns the flash offset the u-boot environment is seeded at.
#[unsafe(no_mangle)]
pub extern "C" fn unifi_bcm5616x_nvram_env_offset() -> u64 {
    bcm5616x_machine::NVRAM_ENV_OFFSET
}

/// Returns the immutable UDM Pro hardware layout shared across the FFI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn unifi_udmpro_layout() -> *const UnifiUdmProLayout {
    &UDM_PRO_LAYOUT
}
/// ABI status.
#[repr(u32)]
pub enum UnifiStatus {
    /// Successful operation.
    Ok = 0,
    /// Address is unmapped.
    Unmapped = 1,
    /// Access width is unsupported.
    InvalidWidth = 2,
    /// Access address is misaligned.
    Misaligned = 3,
    /// Internal failure.
    BusError = 4,
}
/// Result filled by each execution call.
#[repr(C)]
pub struct UnifiExecutionResult {
    /// Operation status.
    pub status: UnifiStatus,
    /// Read value, if applicable.
    pub value: u64,
    /// Next timer deadline, or zero.
    pub next_deadline_ns: u64,
    /// Pointer to the event batch, valid until the next execution call.
    pub events: *const UnifiEvent,
    /// Number of events in the batch.
    pub event_count: usize,
}

/// One event returned from a board execution call.
#[repr(C)]
pub struct UnifiEvent {
    /// Event kind: 1 IRQ, 2 UART TX, 3 reset, 4 wire frame, 5 offload request,
    /// 6 front-panel JSON.
    pub kind: u32,
    /// IRQ line or UART port.
    pub line_or_port: u32,
    /// Event level, byte, or zero.
    pub value: u64,
    /// Optional pointer to event-owned payload bytes.
    pub payload: *const u8,
    /// Length of `payload` in bytes.
    pub payload_len: usize,
    /// Versioned normalized request for kind 5; default for other events.
    pub net_request: net_offload::Request,
}

#[derive(Serialize)]
struct CaptureHeader {
    #[serde(rename = "type")]
    record_type: &'static str,
    version: u32,
    board: &'static str,
    blobs: Vec<CaptureBlob>,
}

#[derive(Serialize, Clone)]
struct CaptureBlob {
    kind: u32,
    name: String,
    sha256: String,
}

#[derive(Serialize)]
struct CaptureInput<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    sequence: u64,
    now_ns: u64,
    kind: &'a str,
    capture_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    width: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u64>,
    expected_value: Option<u64>,
    expected_status: &'a str,
    events: Vec<CaptureEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'a [u8]>,
}

#[derive(Serialize)]
struct CaptureEvent {
    kind: u32,
    line_or_port: u32,
    value: u64,
    data: Vec<u8>,
}

#[derive(Serialize)]
struct CaptureDma<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    operation: &'static str,
    address: u64,
    data: &'a [u8],
    status: bool,
}

struct Capture {
    file: BufWriter<File>,
    blob_dir: PathBuf,
    board: &'static str,
    blobs: Vec<CaptureBlob>,
    header_written: bool,
    sequence: u64,
    failed: bool,
}

impl Capture {
    fn new(path: &std::ffi::OsStr, board: &'static str) -> Option<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .ok()?;
        let capture = Self {
            file: BufWriter::new(file),
            blob_dir: Path::new(path).with_extension("blobs"),
            board,
            blobs: Vec::new(),
            header_written: false,
            sequence: 0,
            failed: false,
        };
        Some(capture)
    }

    fn ensure_header(&mut self) {
        if self.header_written {
            return;
        }
        let header = CaptureHeader {
            record_type: "header",
            version: 1,
            board: self.board,
            blobs: self.blobs.clone(),
        };
        self.write(&header);
        self.header_written = !self.failed;
    }

    fn write<T: Serialize>(&mut self, value: &T) {
        if self.failed {
            return;
        }
        if serde_json::to_writer(&mut self.file, value).is_err()
            || self.file.write_all(b"\n").is_err()
            || self.file.flush().is_err()
        {
            self.failed = true;
        }
    }

    fn add_blob(&mut self, kind: u32, data: &[u8]) {
        if self.header_written {
            self.failed = true;
            return;
        }
        let digest = hex::encode(Sha256::digest(data));
        let name = format!("{digest}.bin");
        if std::fs::create_dir_all(&self.blob_dir)
            .and_then(|()| std::fs::write(self.blob_dir.join(&name), data))
            .is_err()
        {
            self.failed = true;
            return;
        }
        self.blobs.push(CaptureBlob {
            kind,
            name,
            sha256: digest,
        });
    }

    fn dma_read(&mut self, address: u64, data: &[u8], status: bool) {
        self.ensure_header();
        self.write(&CaptureDma {
            record_type: "dma",
            operation: "read",
            address,
            data,
            status,
        });
    }

    fn dma_write(&mut self, address: u64, data: &[u8], status: bool) {
        self.ensure_header();
        self.write(&CaptureDma {
            record_type: "dma",
            operation: "write",
            address,
            data,
            status,
        });
    }
}

/// Opaque board allocation owned by the FFI caller.
pub struct UnifiBoard {
    board: Board,
    eeprom: Vec<u8>,
    emmc: Vec<u8>,
    events: Vec<UnifiEvent>,
    event_payloads: Vec<Vec<u8>>,
    capture: Option<Capture>,
}
enum Board {
    Mt7981(Box<mt7981_machine::Mt7981Board>),
    UdmPro(Box<udmpro_machine::UdmProBoard>),
    Bcm5616x(Box<bcm5616x_machine::Bcm5616xBoard>),
}

struct HostDmaBus {
    read: Option<extern "C" fn(*mut std::ffi::c_void, u64, *mut u8, usize) -> u32>,
    write: Option<extern "C" fn(*mut std::ffi::c_void, u64, *const u8, usize) -> u32>,
    context: *mut std::ffi::c_void,
    capture: Option<*mut Capture>,
}

impl board_core::dma::DmaBus for HostDmaBus {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> TransferStatus {
        let status = self.read.is_some_and(|callback| {
            callback(self.context, address, buffer.as_mut_ptr(), buffer.len()) == 0
        });
        if let Some(capture) = self.capture {
            unsafe { (*capture).dma_read(address, buffer, status) };
        }
        if status {
            TransferStatus::Complete
        } else {
            TransferStatus::Failed
        }
    }
    fn write(&mut self, address: u64, buffer: &[u8]) -> TransferStatus {
        let status = self.write.is_some_and(|callback| {
            callback(self.context, address, buffer.as_ptr(), buffer.len()) == 0
        });
        if let Some(capture) = self.capture {
            unsafe { (*capture).dma_write(address, buffer, status) };
        }
        if status {
            TransferStatus::Complete
        } else {
            TransferStatus::Failed
        }
    }
}

fn status(error: MmioError) -> UnifiStatus {
    match error {
        MmioError::Unmapped => UnifiStatus::Unmapped,
        MmioError::InvalidWidth => UnifiStatus::InvalidWidth,
        MmioError::Misaligned => UnifiStatus::Misaligned,
        MmioError::BusError => UnifiStatus::BusError,
    }
}

fn status_name(result: &Result<u64, MmioError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(MmioError::Unmapped) => "unmapped",
        Err(MmioError::InvalidWidth | MmioError::Misaligned) => "invalid",
        Err(MmioError::BusError) => "bus_error",
    }
}

/// Allocates an opaque board instance. The returned pointer must be freed once.
///
/// # Safety
/// `config` may be null or point to a valid NUL-terminated string for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_new(
    kind: u32,
    _config: *const std::ffi::c_char,
) -> *mut UnifiBoard {
    let board = match kind {
        1 => Board::Mt7981(Box::new(mt7981_machine::Mt7981Board::new())),
        2 => Board::UdmPro(Box::new(udmpro_machine::UdmProBoard::new())),
        3 => Board::Bcm5616x(Box::new(bcm5616x_machine::Bcm5616xBoard::new())),
        _ => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(UnifiBoard {
        board,
        eeprom: Vec::new(),
        emmc: Vec::new(),
        events: Vec::new(),
        event_payloads: Vec::new(),
        capture: std::env::var_os("UNIFI_TRACE_FILE").and_then(|path| {
            Capture::new(
                &path,
                match kind {
                    k if k == UnifiBoardKind::Mt7981 as u32 => "mt7981",
                    k if k == UnifiBoardKind::Bcm5616x as u32 => "bcm5616x",
                    _ => "udm-pro",
                },
            )
        }),
    }))
}

/// Frees a board allocated by [`unifi_board_new`].
///
/// # Safety
/// `board` must be null or a pointer returned by [`unifi_board_new`] that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_free(board: *mut UnifiBoard) {
    if !board.is_null() {
        drop(unsafe { Box::from_raw(board) });
    }
}

/// Resets a board and clears work pending in the supplied execution context.
///
/// # Safety
/// `board` and `out` must be valid for the duration of the call when non-null; `host` must be null or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_reset(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    out: *mut UnifiExecutionResult,
) {
    unsafe {
        execute(
            board,
            host,
            out,
            "reset",
            None,
            None,
            None,
            |board, ctx| {
                match board {
                    Board::Mt7981(b) => Machine::reset(&mut **b, ctx),
                    Board::UdmPro(b) => Machine::reset(&mut **b, ctx),
                    Board::Bcm5616x(b) => Machine::reset(&mut **b, ctx),
                };
                Ok(0)
            },
            None,
        )
    }
}

/// Copies board window metadata into caller-owned storage and returns its count.
///
/// # Safety
/// `board` must be null or valid; when non-null, `out` must reference `cap` writable `UnifiWindow` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_windows(
    board: *const UnifiBoard,
    out: *mut UnifiWindow,
    cap: usize,
) -> usize {
    let Some(board) = (unsafe { board.as_ref() }) else {
        return 0;
    };
    let windows = match &board.board {
        Board::Mt7981(b) => Describe::windows(&**b),
        Board::UdmPro(b) => Describe::windows(&**b),
        Board::Bcm5616x(b) => Describe::windows(&**b),
    };
    if !out.is_null() {
        for (target, source) in (unsafe { std::slice::from_raw_parts_mut(out, cap) })
            .iter_mut()
            .zip(windows)
        {
            *target = UnifiWindow {
                base: source.base,
                size: source.size,
                priority: source.priority,
                device: source.device,
            };
        }
    }
    windows.len()
}

/// Copies cold-path interrupt-line metadata into caller-owned storage.
///
/// # Safety
/// `board` must be null or valid; when non-null, `out` must reference `cap`
/// writable values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_irq_lines(
    board: *const UnifiBoard,
    out: *mut u32,
    cap: usize,
) -> usize {
    let Some(board) = (unsafe { board.as_ref() }) else {
        return 0;
    };
    let lines = match &board.board {
        Board::Mt7981(machine) => Describe::irq_lines(&**machine),
        Board::UdmPro(machine) => Describe::irq_lines(&**machine),
        Board::Bcm5616x(machine) => Describe::irq_lines(&**machine),
    };
    if !out.is_null() {
        for (target, source) in (unsafe { std::slice::from_raw_parts_mut(out, cap) })
            .iter_mut()
            .zip(lines)
        {
            *target = *source;
        }
    }
    lines.len()
}

/// Marks every block of image `kind` (2 == eMMC) as pending, so a newly
/// created backing file receives the board's seeded contents.
///
/// # Safety
/// `board` must be null or a valid board pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_mark_image_dirty(board: *mut UnifiBoard, kind: u32) {
    let Some(board) = (unsafe { board.as_mut() }) else {
        return;
    };
    if let (Board::Mt7981(machine), 2) = (&mut board.board, kind) {
        machine.mark_emmc_dirty();
    }
}

/// Removes and reports guest writes to the eMMC that the host has not yet
/// persisted.
///
/// Each taken block is written as its block number into `blocks` and its 512
/// bytes into `data`. The return value is the number of blocks reported, which
/// is at most `cap`. Blocks are dropped from the board's pending set once
/// reported, so a caller that cannot store them loses them; pass `cap == 0` to
/// query without taking anything.
///
/// # Safety
/// `board` must be null or valid. When `cap` is non-zero, `blocks` must
/// reference `cap` writable `u64` values and `data` must reference
/// `cap * 512` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_take_dirty_blocks(
    board: *mut UnifiBoard,
    kind: u32,
    blocks: *mut u64,
    data: *mut u8,
    cap: usize,
) -> usize {
    let Some(board) = (unsafe { board.as_mut() }) else {
        return 0;
    };
    let Board::Mt7981(machine) = &mut board.board else {
        return 0;
    };
    if kind != 2 {
        return 0;
    }
    if cap == 0 {
        return usize::from(machine.emmc_is_dirty());
    }
    if blocks.is_null() || data.is_null() {
        return 0;
    }
    let taken = machine.take_dirty_emmc_blocks();
    let count = taken.len().min(cap);
    for (index, (block, contents)) in taken.into_iter().take(count).enumerate() {
        unsafe {
            blocks.add(index).write(block);
            std::ptr::copy_nonoverlapping(
                contents.as_ptr(),
                data.add(index * board_core::mmc::BLOCK_SIZE),
                board_core::mmc::BLOCK_SIZE,
            );
        }
    }
    count
}

/// Copies an EEPROM (`kind == 1`) or eMMC (`kind == 2`) image into board-owned storage.
///
/// # Safety
/// `board` must be valid. `data` must be null only when `len` is zero, otherwise it must reference
/// `len` readable bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_load_image(
    board: *mut UnifiBoard,
    kind: u32,
    data: *const u8,
    len: usize,
) -> UnifiStatus {
    let Some(board) = (unsafe { board.as_mut() }) else {
        return UnifiStatus::BusError;
    };
    if len != 0 && data.is_null() {
        return UnifiStatus::BusError;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    let status = match (&mut board.board, kind) {
        (Board::Bcm5616x(machine), 1) => match machine.load_eeprom_image(bytes) {
            Ok(()) => UnifiStatus::Ok,
            Err(_) => UnifiStatus::BusError,
        },
        (Board::Mt7981(machine), 1) => match machine.load_eeprom_image(bytes) {
            Ok(()) => {
                board.eeprom = bytes.to_vec();
                UnifiStatus::Ok
            }
            Err(_) => UnifiStatus::BusError,
        },
        (Board::Mt7981(machine), 2) => match machine.load_emmc_image(bytes) {
            Ok(()) => {
                board.emmc = bytes.to_vec();
                UnifiStatus::Ok
            }
            Err(_) => UnifiStatus::BusError,
        },
        (_, 1 | 2) => UnifiStatus::BusError,
        _ => UnifiStatus::BusError,
    };
    if matches!(status, UnifiStatus::Ok)
        && let Some(capture) = board.capture.as_mut()
    {
        capture.add_blob(kind, bytes);
    }
    status
}

/// Performs one width-aware MMIO read.
///
/// # Safety
/// `board` and `out` must be valid pointers and `host` must be null or valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_mmio_read(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    addr: u64,
    width: u8,
    out: *mut UnifiExecutionResult,
) {
    unsafe {
        execute(
            board,
            host,
            out,
            "mmio_read",
            Some(addr),
            Some(width),
            None,
            |board, ctx| {
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return Err(MmioError::InvalidWidth);
                }
                Ok(match board {
                    Board::Mt7981(b) if width == 4 => {
                        Machine::mmio_read(&mut **b, ctx, addr, AccessWidth::U32)?
                    }
                    Board::UdmPro(b) if width == 4 => {
                        Machine::mmio_read(&mut **b, ctx, addr, AccessWidth::U32)?
                    }
                    Board::Bcm5616x(b) if width == 4 => {
                        Machine::mmio_read(&mut **b, ctx, addr, AccessWidth::U32)?
                    }
                    // Match the historical C adapters for byte/halfword/
                    // doubleword register accesses: registers are 32-bit
                    // and the low word is returned.
                    Board::Mt7981(b) => u64::from(b.mmio_read(addr)),
                    Board::UdmPro(b) => u64::from(b.mmio_read(addr)),
                    Board::Bcm5616x(b) => u64::from(b.mmio_read(addr)),
                })
            },
            None,
        )
    }
}

/// Performs one width-aware MMIO write.
///
/// # Safety
/// `board` and `out` must be valid pointers and `host` must be null or valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_mmio_write(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    addr: u64,
    width: u8,
    value: u64,
    out: *mut UnifiExecutionResult,
) {
    unsafe {
        execute(
            board,
            host,
            out,
            "mmio_write",
            Some(addr),
            Some(width),
            Some(value),
            |board, ctx| {
                if !matches!(width, 1 | 2 | 4 | 8) {
                    return Err(MmioError::InvalidWidth);
                }
                match board {
                    Board::Mt7981(b) if width == 4 => {
                        Machine::mmio_write(&mut **b, ctx, addr, value, AccessWidth::U32)?;
                        Ok(0)
                    }
                    Board::UdmPro(b) if width == 4 => {
                        Machine::mmio_write(&mut **b, ctx, addr, value, AccessWidth::U32)?;
                        Ok(0)
                    }
                    Board::Bcm5616x(b) if width == 4 => {
                        Machine::mmio_write(&mut **b, ctx, addr, value, AccessWidth::U32)?;
                        Ok(0)
                    }
                    Board::Mt7981(b) => {
                        b.mmio_write(addr, u32::try_from(value).map_err(|_| MmioError::BusError)?);
                        Ok(0)
                    }
                    Board::UdmPro(b) => {
                        b.mmio_write(addr, u32::try_from(value).map_err(|_| MmioError::BusError)?);
                        Ok(0)
                    }
                    Board::Bcm5616x(b) => {
                        b.mmio_write(addr, u32::try_from(value).map_err(|_| MmioError::BusError)?);
                        Ok(0)
                    }
                }
            },
            None,
        )
    }
}

/// Delivers one byte to a board UART through the common execution wrapper.
///
/// # Safety
/// `board` and `out` must be valid pointers and `host` must be null or valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_uart_rx(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    port: u32,
    byte: u8,
    out: *mut UnifiExecutionResult,
) {
    unsafe {
        execute(
            board,
            host,
            out,
            "uart_rx",
            Some(u64::from(port)),
            Some(1),
            Some(u64::from(byte)),
            |board, _ctx| {
                match board {
                    Board::Mt7981(b) => b.uart0.push_rx(&[byte]),
                    Board::UdmPro(_) => {}
                    Board::Bcm5616x(b) => Machine::uart_rx(&mut **b, _ctx, port, byte),
                };
                Ok(0)
            },
            None,
        )
    }
}

/// Reports whether the board can consume an inbound Ethernet frame.
///
/// # Safety
/// `board` must be null or point to a live board allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_net_can_receive(board: *const UnifiBoard, port: u32) -> bool {
    let Some(board) = (unsafe { board.as_ref() }) else {
        return false;
    };
    match &board.board {
        Board::Mt7981(machine) => Machine::net_can_receive(&**machine, port),
        Board::UdmPro(machine) => Machine::net_can_receive(&**machine, port),
        Board::Bcm5616x(machine) => Machine::net_can_receive(&**machine, port),
    }
}

/// Delivers one inbound Ethernet frame through the common board boundary.
///
/// # Safety
/// `board` and `out` must be valid pointers; `data` must reference `length`
/// readable bytes; `host` must be null or valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_net_rx(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    port: u32,
    data: *const u8,
    length: usize,
    out: *mut UnifiExecutionResult,
) {
    if data.is_null() && length != 0 {
        return;
    }
    let frame = if length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, length) }
    };
    unsafe {
        execute(
            board,
            host,
            out,
            "net_rx",
            Some(u64::from(port)),
            None,
            Some(u64::try_from(length).unwrap_or(u64::MAX)),
            |board, ctx| {
                match board {
                    Board::Mt7981(b) => b.net_rx(ctx, port, frame),
                    Board::UdmPro(_) => {}
                    Board::Bcm5616x(b) => b.net_rx(ctx, port, frame),
                }
                Ok(0)
            },
            Some(frame),
        )
    }
}

/// Advances scheduled work and returns queued board outputs.
///
/// # Safety
/// `board` and `out` must be valid pointers and `host` must be null or valid for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_advance_to(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    out: *mut UnifiExecutionResult,
) {
    unsafe {
        execute(
            board,
            host,
            out,
            "advance",
            None,
            None,
            None,
            |_board, _ctx| Ok(0),
            None,
        )
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "ABI operation metadata is explicit at the boundary"
)]
unsafe fn execute<F>(
    board: *mut UnifiBoard,
    host: *const UnifiHost,
    out: *mut UnifiExecutionResult,
    kind: &str,
    address: Option<u64>,
    width: Option<u8>,
    value: Option<u64>,
    operation: F,
    data: Option<&[u8]>,
) where
    F: FnOnce(&mut Board, &mut MachineContext) -> Result<u64, MmioError>,
{
    let (Some(owner), Some(out)) = (unsafe { board.as_mut() }, unsafe { out.as_mut() }) else {
        return;
    };
    let host = unsafe { host.as_ref() };
    let now = host.map_or(0, |h| h.now_ns);
    let capture = owner
        .capture
        .as_mut()
        .map(|capture| capture as *mut Capture);
    let mut dma = HostDmaBus {
        read: host.and_then(|h| h.dma_read),
        write: host.and_then(|h| h.dma_write),
        context: host.map_or(std::ptr::null_mut(), |h| h.context),
        capture,
    };
    let (result, next_deadline_ns, events) = {
        let mut ctx = MachineContext::with_dma(now, &mut dma);
        let machine_deadline = match &mut owner.board {
            Board::Mt7981(machine) => {
                Machine::advance_to(&mut **machine, &mut ctx);
                Machine::next_deadline(&**machine)
            }
            Board::UdmPro(machine) => {
                Machine::advance_to(&mut **machine, &mut ctx);
                Machine::next_deadline(&**machine)
            }
            Board::Bcm5616x(machine) => {
                Machine::advance_to(&mut **machine, &mut ctx);
                Machine::next_deadline(&**machine)
            }
        };
        let result = operation(&mut owner.board, &mut ctx);
        // Convert board-queued UART bytes into the ordered output stream so
        // the host does not need a second drain FFI call after each write.
        loop {
            let byte = match &mut owner.board {
                Board::Mt7981(machine) => Machine::take_uart_tx(&mut **machine),
                Board::UdmPro(machine) => Machine::take_uart_tx(&mut **machine),
                Board::Bcm5616x(machine) => Machine::take_uart_tx(&mut **machine),
            };
            let Some(byte) = byte else { break };
            ctx.events.push(Event::UartTx { port: 0, byte });
        }
        let next_deadline_ns = match (ctx.next_deadline(), machine_deadline) {
            (Some(context_deadline), Some(machine_deadline)) => {
                context_deadline.min(machine_deadline)
            }
            (Some(deadline), None) | (None, Some(deadline)) => deadline,
            (None, None) => 0,
        };
        let events = ctx.events;
        (result, next_deadline_ns, events)
    };
    owner.events.clear();
    owner.event_payloads.clear();
    let mut payload_indices = Vec::with_capacity(events.len());
    owner
        .events
        .extend(events.into_iter().map(|event| match event {
            Event::IrqLevel { line, level } => {
                payload_indices.push(None);
                UnifiEvent {
                    kind: 1,
                    line_or_port: line,
                    value: u64::from(level),
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: net_offload::Request::default(),
                }
            }
            Event::UartTx { port, byte } => {
                payload_indices.push(None);
                UnifiEvent {
                    kind: 2,
                    line_or_port: port,
                    value: u64::from(byte),
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: net_offload::Request::default(),
                }
            }
            Event::NetTx { port, frame } => {
                let index = owner.event_payloads.len();
                owner.event_payloads.push(frame);
                payload_indices.push(Some(index));
                UnifiEvent {
                    kind: 4,
                    line_or_port: port,
                    value: 0,
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: net_offload::Request::default(),
                }
            }
            Event::NetTxOffload {
                port,
                queue,
                request,
                frame,
            } => {
                let index = owner.event_payloads.len();
                owner.event_payloads.push(frame);
                payload_indices.push(Some(index));
                UnifiEvent {
                    kind: 5,
                    line_or_port: port,
                    value: u64::from(queue),
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: request,
                }
            }
            Event::FrontPanel { payload } => {
                let index = owner.event_payloads.len();
                owner.event_payloads.push(payload);
                payload_indices.push(Some(index));
                UnifiEvent {
                    kind: 6,
                    line_or_port: 0,
                    value: 0,
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: net_offload::Request::default(),
                }
            }
            Event::ResetRequest => {
                payload_indices.push(None);
                UnifiEvent {
                    kind: 3,
                    line_or_port: 0,
                    value: 0,
                    payload: std::ptr::null(),
                    payload_len: 0,
                    net_request: net_offload::Request::default(),
                }
            }
        }));
    // Payload vectors may move while the event list is built, so take their
    // final addresses only after all pushes are complete.
    for (event, index) in owner.events.iter_mut().zip(payload_indices) {
        if let Some(index) = index {
            let payload = &owner.event_payloads[index];
            event.payload = payload.as_ptr();
            event.payload_len = payload.len();
        }
    }
    let capture_error = owner.capture.as_ref().is_some_and(|capture| capture.failed);
    if let Some(capture) = owner.capture.as_mut() {
        capture.ensure_header();
        let sequence = capture.sequence;
        capture.sequence = capture.sequence.saturating_add(1);
        capture.write(&CaptureInput {
            record_type: "input",
            sequence,
            now_ns: now,
            kind,
            capture_error,
            address,
            width,
            value,
            expected_value: result.as_ref().ok().copied(),
            expected_status: status_name(&result),
            events: owner
                .events
                .iter()
                .map(|event| CaptureEvent {
                    kind: event.kind,
                    line_or_port: event.line_or_port,
                    value: event.value,
                    data: if event.kind == 5 {
                        let mut data = event.net_request.encode().to_vec();
                        data.extend_from_slice(unsafe {
                            std::slice::from_raw_parts(event.payload, event.payload_len)
                        });
                        data
                    } else if event.kind == 4 {
                        unsafe { std::slice::from_raw_parts(event.payload, event.payload_len) }
                            .to_vec()
                    } else {
                        vec![]
                    },
                })
                .collect(),
            data,
        });
    }
    *out = UnifiExecutionResult {
        status: result
            .as_ref()
            .map_or_else(|e| status(*e), |_| UnifiStatus::Ok),
        value: result.unwrap_or(0),
        next_deadline_ns,
        events: owner.events.as_ptr(),
        event_count: owner.events.len(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn udmpro_identity_profile_is_stable() {
        let layout = unsafe { &*unifi_udmpro_layout() };
        let text = |ptr: *const std::ffi::c_char| unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(text(layout.board_id), "ea15");
        assert_eq!(text(layout.vendor_id), "0777");
        assert_eq!(text(layout.system_id), "ea15");
        assert_eq!(text(layout.serial_number), "020000000001");
        assert_eq!(text(layout.model), "UDM-Pro");
    }

    #[test]
    fn udmpro_eeprom_has_parser_record_and_crc() {
        let image = udmpro_eeprom();
        assert_eq!(&image[0..6], &[0x52, 0x54, 0x00, 0x4d, 0x50, 0x01]);
        assert_eq!(&image[0x10..0x14], &10_u32.to_be_bytes());
        assert_eq!(&image[0x10..0x14], &image[0x8014..0x8018]);
        assert_eq!(&image[0x8000..0x8004], b"UBNT");
        assert_eq!(image[0x800b], 0x65);
        assert_eq!(&image[0x8010..0x8012], &0x0777_u16.to_be_bytes());
        assert_eq!(&image[0x8012..0x8014], &0xea15_u16.to_be_bytes());
        assert_eq!(image[0x8070], 0x01);
        assert!(image[0x8071..0xa000].iter().all(|byte| *byte == 0xff));
        assert!(image[0xa0c1..].iter().all(|byte| *byte == 0xff));
        assert_eq!(
            &image[0x8004..0x8008],
            &udmpro_legacy_crc32(&image[0x800c..0x8071]).to_le_bytes()
        );
    }

    #[test]
    fn retargeting_rewrites_both_identity_sites_and_the_record_crc() {
        let stock = udmpro_eeprom();
        let other = udmpro_eeprom_for(0xea2a);
        assert_eq!(&other[0x0c..0x0e], &0xea2a_u16.to_be_bytes());
        assert_eq!(&other[0x8012..0x8014], &0xea2a_u16.to_be_bytes());
        // The record checksum covers 0x8012, so it must move with the id.
        assert_eq!(
            &other[0x8004..0x8008],
            &udmpro_legacy_crc32(&other[0x800c..0x8071]).to_le_bytes()
        );
        assert_ne!(&other[0x8004..0x8008], &stock[0x8004..0x8008]);
        // Nothing else moves: same length, same vendor id, same MACs.
        assert_eq!(other.len(), stock.len());
        assert_eq!(&other[0x00..0x0c], &stock[0x00..0x0c]);
        assert_eq!(&other[0x0e..0x0c + 8], &stock[0x0e..0x0c + 8]);
        assert_eq!(&other[0x8010..0x8012], &stock[0x8010..0x8012]);
        assert_eq!(&other[0xa000..], &stock[0xa000..]);
    }

    #[test]
    fn retargeting_is_cached_and_the_default_id_returns_the_stock_image() {
        assert!(std::ptr::eq(
            udmpro_eeprom_for(UDM_PRO_SYSTEM_ID).as_ptr(),
            udmpro_eeprom().as_ptr()
        ));
        assert!(std::ptr::eq(
            udmpro_eeprom_for(0xea63).as_ptr(),
            udmpro_eeprom_for(0xea63).as_ptr()
        ));
    }

    #[test]
    fn opaque_pointer_supports_multiple_independent_boards() {
        let host = UnifiHost {
            now_ns: 7,
            dma_read: None,
            dma_write: None,
            log: None,
            context: std::ptr::null_mut(),
        };
        let mut first = UnifiExecutionResult {
            status: UnifiStatus::BusError,
            value: 0,
            next_deadline_ns: 0,
            events: std::ptr::null(),
            event_count: 0,
        };
        let mut second = UnifiExecutionResult {
            status: UnifiStatus::BusError,
            value: 0,
            next_deadline_ns: 0,
            events: std::ptr::null(),
            event_count: 0,
        };
        let a = unsafe { unifi_board_new(UnifiBoardKind::Mt7981 as u32, std::ptr::null()) };
        let b = unsafe { unifi_board_new(UnifiBoardKind::UdmPro as u32, std::ptr::null()) };
        assert!(!a.is_null() && !b.is_null());
        unsafe {
            unifi_mmio_read(a, &host, mt7981_machine::CHIP_ID, 4, &mut first);
        }
        unsafe {
            unifi_mmio_read(b, &host, udmpro_machine::PBS_BASE + 0x15c, 2, &mut second);
        }
        assert_eq!(first.value, 0x7981);
        assert_eq!(second.status as u32, UnifiStatus::Ok as u32);
        assert_eq!(second.value, 0x0001_0000);
        unsafe {
            unifi_board_free(a);
            unifi_board_free(b);
        }
    }

    #[test]
    fn image_loading_copies_input_before_returning() {
        let board = unsafe { unifi_board_new(UnifiBoardKind::Mt7981 as u32, std::ptr::null()) };
        let mut image = [1, 2, 3];
        assert_eq!(
            unsafe { unifi_load_image(board, 1, image.as_ptr(), image.len()) as u32 },
            UnifiStatus::Ok as u32
        );
        image.fill(9);
        assert_eq!(
            unsafe { unifi_load_image(board, 2, std::ptr::null(), 0) as u32 },
            UnifiStatus::Ok as u32
        );
        assert_eq!(
            unsafe { unifi_load_image(board, 3, image.as_ptr(), image.len()) as u32 },
            UnifiStatus::BusError as u32
        );
        unsafe {
            unifi_board_free(board);
        }
    }

    #[test]
    fn mmio_uart_write_returns_output_event_in_same_call() {
        let host = UnifiHost {
            now_ns: 0,
            dma_read: None,
            dma_write: None,
            log: None,
            context: std::ptr::null_mut(),
        };
        let board = unsafe { unifi_board_new(UnifiBoardKind::UdmPro as u32, std::ptr::null()) };
        let mut result = UnifiExecutionResult {
            status: UnifiStatus::BusError,
            value: 0,
            events: std::ptr::null(),
            event_count: 0,
            next_deadline_ns: 0,
        };
        unsafe {
            unifi_mmio_write(board, &host, 0xfd88_3000, 4, u64::from(b'X'), &mut result);
            let events = std::slice::from_raw_parts(result.events, result.event_count);
            assert_eq!(result.status as u32, UnifiStatus::Ok as u32);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].kind, 2);
            assert_eq!(events[0].value, u64::from(b'X'));
            unifi_board_free(board);
        }
    }

    #[test]
    fn capture_header_references_hashed_image_blobs() {
        let root = std::env::temp_dir().join(format!(
            "unifi-ffi-capture-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("trace.jsonl");
        let mut capture = Capture::new(path.as_os_str(), "mt7981").unwrap();
        capture.add_blob(1, &[1, 2, 3]);
        capture.ensure_header();
        let header = std::fs::read_to_string(&path).unwrap();
        let digest = hex::encode(Sha256::digest([1, 2, 3]));
        assert!(header.contains("\"kind\":1"));
        assert!(header.contains(&digest));
        assert!(
            path.with_extension("blobs")
                .join(format!("{digest}.bin"))
                .exists()
        );
        std::fs::remove_dir_all(path.with_extension("blobs")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
