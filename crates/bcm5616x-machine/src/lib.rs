#![warn(missing_docs)]

//! Pure Rust register model for the board-local `BCM5616x` switch peripherals.
//!
//! The target is the US24PRO class of `UniFi` switches: a Broadcom iProc
//! (Northstar family) Cortex-A9 `SoC` running a vendor `Linux 3.6.5`. As with
//! [`udmpro-machine`], the Cortex-A9 `MPCore` block, memory regions, DMA and
//! interrupt delivery stay in the thin QEMU adapter; this crate owns stable
//! register semantics and board constants so they can be tested without QEMU.
//!
//! Every address below is read out of the vendor kernel rather than taken from
//! upstream Broadcom support, and the evidence is recorded in
//! `docs/us24pro/firmware-container.md`:
//!
//! - the static `map_desc` table gives `0x1800_0000`+2 MiB and
//!   `0x1900_0000`+1 MiB as the two peripheral windows;
//! - literal pools give the GIC CPU interface, GIC distributor, SCU and TWD,
//!   which place the A9 periphbase at `0x1902_0000`;
//! - further pools give the CRU and the two QSPI IDM bases;
//! - the uImage load address and the kernel's own link base fix `PHYS_OFFSET`.

use std::collections::{HashMap, VecDeque};

use board_core::dma::TransferStatus;
use board_core::spi_nor::SpiNor;
use board_core::{AccessWidth, Describe, Machine, MachineContext, MmioError, Window};
mod factory;
mod persist;
#[cfg(test)]
use persist::*;
mod regs;
#[cfg(test)]
use regs::*;
#[cfg(test)]
mod tests;
pub use persist::*;
pub use regs::*;
mod front_panel;
pub mod lcm;
/// IORESOURCE_MEM, 0)` and `ioremap`s [`GMAC_SIZE`] bytes of it.
pub const GMAC_BASE: u64 = 0x1804_2000;
/// Length the probe maps, and the length of the resource.
pub const GMAC_SIZE: u64 = 0xc00;
/// GIC interrupt the GMAC is wired to, from the probe's IRQ resource and
/// confirmed by `/proc/interrupts` (`113: ... GIC eth0`).
pub const GMAC_IRQ: u32 = 113;

// Register offsets within the GMAC core.  This is Broadcom's common "et"
// GMAC layout — the same one Linux's own bgmac driver models — and the
// vendor driver here uses it unchanged.
/// Interrupt status; the driver acknowledges by writing the bits back.
const GMAC_INT_STATUS: u64 = GMAC_BASE + 0x020;
/// Interrupt mask.
const GMAC_INT_MASK: u64 = GMAC_BASE + 0x024;
/// PHY access: bit 30 starts a transfer and the hardware clears it when the
/// transfer completes.  The MDIO the switch ports hang off is the separate
/// `CMICd` bus, so nothing answers here.
const GMAC_PHY_ACCESS: u64 = GMAC_BASE + 0x180;
/// Start/busy bit in [`GMAC_PHY_ACCESS`].
const GMAC_PHY_ACCESS_START: u32 = 1 << 30;
/// Unimac command configuration; bit 13 is a self-clearing software reset.
const GMAC_CMDCFG: u64 = GMAC_BASE + 0x808;
/// Software reset bit in [`GMAC_CMDCFG`].
const GMAC_CMDCFG_SR: u32 = 1 << 13;
/// Promiscuous mode bit in [`GMAC_CMDCFG`].
const GMAC_CMDCFG_PROM: u32 = 1 << 4;
/// Unimac station address, high four octets.
const GMAC_MACADDR_HIGH: u64 = GMAC_BASE + 0x80c;
/// Unimac station address, low two octets, right-aligned in the word: the
/// driver writes `0x52540055` then `0x00005301` for `52:54:00:55:53:01`.
const GMAC_MACADDR_LOW: u64 = GMAC_BASE + 0x810;

// The two DMA channels.  This core uses Broadcom's 32-bit engine, not the
// 64-bit one: a trace of the vendor driver bringing eth0 up shows the ring
// base written at +0x04 and the posted pointer at +0x08 stepping by eight
// bytes per frame, which is `dma32regs_t` {control, addr, ptr, status} over
// `dma32dd_t` {ctrl, addr}.
/// Transmit channel registers.
const GMAC_DMA_TX: u64 = GMAC_BASE + 0x200;
/// Receive channel registers.
const GMAC_DMA_RX: u64 = GMAC_BASE + 0x220;
/// Channel enable, and for the receive channel the frame offset.
const DMA_CTRL: u64 = 0x00;
/// Descriptor ring base address; the ring is 4 KiB aligned.
const DMA_ADDR: u64 = 0x04;
/// Last descriptor posted, as a byte offset into the ring.
const DMA_PTR: u64 = 0x08;
/// Current descriptor and channel state.
const DMA_STATUS: u64 = 0x0c;
/// Channel enable bit, in both directions.
const DMA_CTRL_ENABLE: u32 = 1 << 0;
/// Receive frame offset: how far into each buffer the frame is written.
///
/// The driver programs 30 here, which the trace shows as a receive control
/// of `0xc0c3d`.
const DMA_RX_CTRL_OFFSET: u32 = 0xfe;
/// Shift of [`DMA_RX_CTRL_OFFSET`].
const DMA_RX_CTRL_OFFSET_SHIFT: u32 = 1;
/// Descriptor offsets are 12 bits wide, so a ring holds at most 512 of them.
const DMA_PTR_MASK: u32 = 0xfff;
/// Channel state field in `status`; the driver waits for these to settle.
const DMA_STATE_ACTIVE: u32 = 0x1000_0000;
/// Bytes per `dma32dd_t`: the control word and the buffer address.
const DMA_DESCRIPTOR_BYTES: u32 = 8;
/// Most descriptors one pump will walk, so a malformed ring cannot spin.
const DMA_MAX_DESCRIPTORS: u32 = 512;
/// Buffer byte count, in a descriptor's control word.
const DMA_CTRL_LENGTH: u32 = 0x1fff;
/// End of descriptor table: the ring wraps after this entry.
const DMA_CTRL_EOT: u32 = 1 << 28;
/// End of frame.
const DMA_CTRL_EOF: u32 = 1 << 30;
/// Start of frame.
const DMA_CTRL_SOF: u32 = 1 << 31;
/// Receive interrupt, in [`GMAC_INT_STATUS`].
///
/// The driver's own mask, `0x0f01fc00`, covers the error bits, this one, and
/// one transmit bit per queue from bit 24 up.
const GMAC_INT_RX: u32 = 1 << 16;
/// Transmit interrupt for queue 0.
const GMAC_INT_TX: u32 = 1 << 24;
/// Longest frame the model will move in either direction.
const GMAC_MAX_FRAME: usize = 2048;
/// Length of the frame check sequence the receive engine delivers.
const ETHERNET_FCS_LEN: usize = 4;

/// Offset of the board-data record within the 64 MiB SPI-NOR, i.e. physical
/// `0x1fff0000` through the `0x1c000000` window. `bcm5334x_scan_eeprom` in
/// `ubnthal.ko` reads 4 KiB from there.
/// DRAM base; the kernel links at `0xc000_8000` and loads at `0x6100_8000`.
pub const DRAM_BASE: u64 = 0x6100_0000;
/// DRAM size the vendor command line grants the kernel (`mem=128M`).
pub const DRAM_SIZE: u64 = 128 << 20;
/// Entry point of the u-boot standalone application (`ubntaddr`).
pub const STANDALONE_APP_ENTRY: u64 = 0x6703_00a0;
/// uImage load and entry address for `kernel0`.
pub const KERNEL_LOAD_ADDR: u64 = 0x6100_8000;

// regshift 2: 8250 register `n` sits at byte offset `n << 2`.
const UART_THR: u64 = 0x00;
const UART_RBR: u64 = 0x00;
const UART_LSR: u64 = 0x05 << 2;
const UART_LSR_THRE: u32 = 1 << 5;
const UART_LSR_TEMT: u64 = 1 << 6;
const UART_LSR_DR: u32 = 1 << 0;

const DEVICE_CHIPCOMMON: u32 = 1;
const DEVICE_UART0: u32 = 2;
const DEVICE_CRU: u32 = 3;
const DEVICE_QSPI: u32 = 4;
const DEVICE_QSPI_IDM: u32 = 8;
const DEVICE_CRU_REGS: u32 = 5;
const DEVICE_DMU_REGS: u32 = 6;
const DEVICE_CMICD: u32 = 7;
const DEVICE_GMAC: u32 = 9;
const DEVICE_EROM: u32 = 10;
const DEVICE_GPIO: u32 = 11;

// Reset values chosen to satisfy the formulas above rather than read off
// hardware: pdiv 1 and ndiv 80 give a 2 GHz GENPLL from the 25 MHz reference,
// and mdiv 20 divides that to the 100 MHz the vendor's own code falls back to
// when `clk_get("iproc_slow", "c_clk125")` fails. Replace them with measured
// values if a real board is ever read out.
const GENPLL_CTRL: u64 = GENPLL_BASE + 0x04;
const GENPLL_CHAN_DIV: u64 = GENPLL_BASE + 0x08;
const GENPLL_STATUS: u64 = GENPLL_BASE + 0x18;
const GENPLL_CTRL_RESET: u32 = (1 << 10) | 0x50;
const GENPLL_CHAN_DIV_RESET: u32 = 5 << 8;
const GENPLL_STATUS_LOCKED: u32 = 1;
// Vendor USB probe 0xc0017e08 tests strap bit 17 before mapping the HCD.
const USB_HOST_STRAP: u64 = DMU_REGS_BASE + 0xca4;
const USB_PHY_PLL_CTRL: u64 = DMU_REGS_BASE + 0xc44;
const USB_PHY_PLL_STATUS: u64 = DMU_REGS_BASE + 0xc58;
const CHIPID_BCM5616X: u32 = 0xb160;
// US24PRO (system ID eb36) selects SDK board b6160009, which requires
// BCM56166. ChipCommon still identifies the BCM5616x family as b160.
const SWITCH_DEVICE_BCM56166: u32 = 0xb166;
const CHIPID_TYPE_AI: u32 = 1 << 28;

mod cmic;
mod cmic_dma;
mod cmic_sbus;
mod gpio;
mod i2c;
mod mdio;
mod poe;
mod smbus;

const BOARD_IRQS: [u32; 5] = [QSPI_IRQ, GMAC_IRQ, gpio::IRQ, smbus::IRQ, cmic::IRQ];

// MSPI transfer control. Writing SPCR2 with SPE starts the queued transfer;
// the model completes it immediately, latches MSPI done and raises the shared
// QSPI interrupt. Reads of RXRAM return 0xff to match the blank flash the
// machine maps at 0xf0000000.
const MSPI_SPCR2: u64 = MSPI_BASE + 0x18;
const MSPI_SPCR2_SPE: u32 = 1 << 6;
const MSPI_STATUS: u64 = MSPI_BASE + 0x20;
const MSPI_STATUS_SPIF: u32 = 1;
const MSPI_RXRAM: u64 = MSPI_BASE + 0xc0;
const MSPI_RXRAM_END: u64 = MSPI_BASE + 0x140;
// The queue is 16 slots; TXRAM and RXRAM stride 8 bytes per slot, as in
// `spi-bcm-qspi.c`. `iproc_qspi_flash_read` at 0xc001641c drives it with a
// plain SPI-NOR command stream: 0xb7, then 0x03 plus a big-endian address,
// then 0xe9.
const MSPI_SLOTS: usize = 16;
// Each queue slot occupies two 32-bit words, one byte per word. With CDRAM
// bit 6 (BITSE) set the driver packs two bytes per slot, into both words; with
// it clear only the first word is used. The fill loop in the pump at
// 0xc0015db4 writes `txram[(2*slot + 0x10) << 2]` and, for the two-byte case,
// `[(2*slot + 0x11) << 2]`, and reads RXRAM back the same way.
const MSPI_WORDS: usize = MSPI_SLOTS * 2;
const MSPI_CDRAM_BITSE: u8 = 0x40;
const MSPI_TXRAM: u64 = MSPI_BASE + 0x40;
const MSPI_TXRAM_END: u64 = MSPI_BASE + 0xc0;
const MSPI_NEWQP: u64 = MSPI_BASE + 0x10;
const MSPI_ENDQP: u64 = MSPI_BASE + 0x14;
const MSPI_CDRAM: u64 = MSPI_BASE + 0x140;
const MSPI_CDRAM_END: u64 = MSPI_BASE + 0x180;
// `switchdrvr` reaches the same MSPI through a nearly identical layout in the
// CMIC block. The SDK register table shifts NEWQP, ENDQP, SPCR2, STATUS and
// RXRAM relative to the iProc window, so this is not a uniform address alias.
const CMIC_MSPI_BASE: u64 = CMIC_BLOCK_BASE + 0x1500;
const CMIC_MSPI_END: u64 = CMIC_MSPI_BASE + 0x180;

fn cmic_mspi_address(addr: u64) -> u64 {
    let offset = addr - CMIC_MSPI_BASE;
    MSPI_BASE
        + match offset {
            0x04 => 0,
            0x14 => 0x10,
            0x18 => 0x14,
            0x20 => 0x18,
            0x24 => 0x20,
            0xc4..0x140 => offset - 4,
            _ => offset,
        }
}
// CDRAM bit 7 keeps chip-select asserted past the slot, so one SPI command
// spans several queued transfers: the driver sends 0x9f in one, then clocks
// dummy bytes in the next to collect the reply.
const MSPI_CDRAM_CONT: u8 = 0x80;
/// Capacity of the fitted part, an MX66L51235F named in the u-boot strings.
pub const FLASH_SIZE: usize = 64 << 20;
/// Macronix MX66L51235F JEDEC identity.
pub const FLASH_JEDEC_ID: [u8; 3] = [0xc2, 0x20, 0x1a];
const BSPI_BUSY_STATUS: u64 = BSPI_BASE + 0x0c;
// Seven sources; `mspi_done` is index 5, the same position it holds in the
// upstream table (four link-read sources, session done, mspi_done,
// mspi_halted).
const QSPI_INTR_COUNT: u64 = 7;
const QSPI_INTR_LR_FULLNESS: u64 = QSPI_INTR_BASE;
const QSPI_INTR_LR_SESSION_DONE: u64 = QSPI_INTR_BASE + 3 * 4;
const QSPI_INTR_MSPI_DONE: u64 = QSPI_INTR_BASE + 5 * 4;

// Link reads -- the bulk path, and the only one that serves an MTD read.
// `bcm_qspi_bspi_flash_read` at 0xc0015748 programs a session with the low
// 24 bits of the address, having first written the top byte to the upper
// address register, and splits a transfer that would cross a 16 MiB
// boundary into two sessions. It then clears all seven interrupt sources,
// unmasks them and writes the start bit.
const BSPI_FLASH_UPPER_ADDR: u64 = BSPI_BASE + 0x38;
const BSPI_RAF_START_ADDR: u64 = BSPI_RAF_BASE;
const BSPI_RAF_NUM_WORDS: u64 = BSPI_RAF_BASE + 0x04;
const BSPI_RAF_CTRL: u64 = BSPI_RAF_BASE + 0x08;
const BSPI_RAF_FULLNESS: u64 = BSPI_RAF_BASE + 0x0c;
const BSPI_RAF_STATUS: u64 = BSPI_RAF_BASE + 0x14;
const BSPI_RAF_READ_DATA: u64 = BSPI_RAF_BASE + 0x18;
const BSPI_RAF_CTRL_START: u32 = 1 << 0;
const BSPI_RAF_CTRL_CLEAR: u32 = 1 << 1;
// The drain loop in the interrupt handler at 0xc0015ac0 reads words until
// this bit says the FIFO is empty.
const BSPI_RAF_STATUS_FIFO_EMPTY: u32 = 1 << 1;

/// Board state for the board-local `BCM5616x` registers.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these booleans model independent hardware latches and signal levels"
)]
pub struct Bcm5616xBoard {
    gpio: gpio::Gpio,
    smbus: smbus::Smbus,
    cmic_i2cm: smbus::Smbus,
    cmic: cmic::Cmic,
    uart_tx: Vec<u8>,
    uart_rx: Vec<u8>,
    registers: HashMap<u64, u32>,
    front_panel: front_panel::FrontPanel,
    mspi_done: bool,
    /// Words a link-read session has fetched and the driver has not drained.
    raf_fifo: VecDeque<u32>,
    /// Link-read interrupt sources this model has raised.
    raf_fullness: bool,
    raf_done: bool,
    irq_asserted: bool,
    mspi_tx: [u8; MSPI_WORDS],
    mspi_rx: [u8; MSPI_WORDS],
    mspi_newqp: usize,
    mspi_endqp: usize,
    flash_4byte_address: bool,
    mspi_cdram: [u8; MSPI_SLOTS],
    spi: Option<SpiCommand>,
    flash: Option<Box<SpiNor>>,
    /// Next transmit descriptor the engine has not consumed.
    gmac_tx_index: u32,
    /// Next receive descriptor the engine will fill.
    gmac_rx_index: u32,
    /// Level currently driven on [`GMAC_IRQ`].
    gmac_irq_asserted: bool,
}

/// One chip-select session on the SPI bus.
#[derive(Debug, Clone, Copy)]
struct SpiCommand {
    opcode: u8,
    address: usize,
    address_bytes: usize,
    address_seen: usize,
    data_index: usize,
}

// UART0 sits at 0x18020000, outside the ChipcommonA block at 0x18000000, so
// no window here overlaps another.
const BCM5616X_WINDOWS: [Window; 12] = [
    Window {
        base: smbus::BASE,
        size: 0x1000,
        priority: 0,
        device: 12,
    },
    Window {
        base: CHIPCOMMON_BASE,
        size: 0x1000,
        priority: 0,
        device: DEVICE_CHIPCOMMON,
    },
    Window {
        base: UART0_BASE,
        size: 0x1000,
        priority: 0,
        device: DEVICE_UART0,
    },
    Window {
        base: CRU_BASE,
        size: 0x1000,
        priority: 0,
        device: DEVICE_CRU,
    },
    Window {
        base: 0x1800_a000,
        size: 0x1000,
        priority: 0,
        device: DEVICE_GPIO,
    },
    Window {
        base: QSPI_BASE,
        size: 0x400,
        priority: 0,
        device: DEVICE_QSPI,
    },
    Window {
        base: QSPI_IDM_BASE & !0xf,
        size: 0x10,
        priority: 0,
        device: DEVICE_QSPI_IDM,
    },
    Window {
        base: CRU_REGS_BASE,
        size: 0x1000,
        priority: 0,
        device: DEVICE_CRU_REGS,
    },
    Window {
        base: DMU_REGS_BASE,
        size: 0x1000,
        priority: 0,
        device: DEVICE_DMU_REGS,
    },
    Window {
        base: GMAC_BASE,
        size: GMAC_SIZE,
        priority: 0,
        device: DEVICE_GMAC,
    },
    Window {
        base: CMIC_BLOCK_BASE,
        size: CMIC_BLOCK_SIZE,
        priority: 0,
        device: DEVICE_CMICD,
    },
    // The BDE maps 4 KiB from EROMPTR, so the whole slot has to answer even
    // though the table stops after five words.
    Window {
        base: EROM_BASE,
        size: EROM_SIZE,
        priority: 0,
        device: DEVICE_EROM,
    },
];

impl Bcm5616xBoard {
    /// Creates a board in its reset state, with the board-data record seeded
    /// into the SPI-NOR the MSPI controller talks to.
    ///
    /// # Panics
    ///
    /// Panics if a fixed factory, configuration, or environment image no
    /// longer fits the modelled flash layout.
    #[must_use]
    pub fn new() -> Self {
        let mut flash = SpiNor::new(FLASH_SIZE, FLASH_JEDEC_ID);
        let record = factory::eeprom();
        let offset = usize::try_from(BOARD_DATA_OFFSET).unwrap_or(0);
        // `program` models the real part: it refuses writes unless the chip
        // has been write-enabled first.
        flash.write_enable();
        flash
            .program(offset, &record)
            .expect("the board-data record must fit the modelled flash");
        // `program` clears the write-enable latch, as the real part does.
        // Two slots, the second holding the kind `cfgmtd` asks for first.
        for (slot, kind) in [
            (0, CFG_RECORD_KIND_FIRST),
            (CFG_RECORD_SLOT_STRIDE, CFG_RECORD_KIND_SECOND),
        ] {
            flash.write_enable();
            let offset = usize::try_from(CFG_PARTITION_OFFSET + slot).unwrap_or(0);
            flash
                .program(offset, &cfg_record(kind))
                .expect("a configuration record must fit its slot");
        }
        flash.write_enable();
        let env = nvram_env();
        let env_offset = usize::try_from(NVRAM_ENV_OFFSET).unwrap_or(0);
        flash
            .program(env_offset, &env)
            .expect("the u-boot environment must fit the modelled flash");
        flash.write_disable();
        Self {
            flash: Some(Box::new(flash)),
            cmic_i2cm: smbus::Smbus::cmic(),
            // Match reset(): an unwritten receive word reads as an erased byte.
            mspi_rx: [0xff; MSPI_WORDS],
            ..Self::default()
        }
    }

    /// Loads diagnostic authentication data for the fixed synthetic identity.
    ///
    /// The host file is copied into volatile model storage, never written back.
    /// Only IV, encrypted digest, and signature bytes may differ from the seed.
    ///
    /// # Errors
    /// Rejects a wrong-sized image, changed identity, or unavailable flash.
    pub fn load_eeprom_image(&mut self, image: &[u8]) -> Result<(), &'static str> {
        let seed = factory::eeprom();
        if image.len() != seed.len() {
            return Err("expected a 64 KiB synthetic EEPROM");
        }
        if image.iter().zip(&seed).enumerate().any(|(offset, (a, b))| {
            !(0xbd40..0xbd48).contains(&offset) && !(0xbdc0..0xc000).contains(&offset) && a != b
        }) {
            return Err("EEPROM identity must match the model's synthetic identity");
        }
        let flash = self.flash.as_mut().ok_or("flash is unavailable")?;
        let offset = usize::try_from(BOARD_DATA_OFFSET).map_err(|_| "invalid EEPROM offset")?;
        let mut current = vec![0; seed.len()];
        flash
            .read(board_core::spi_nor::command::READ, offset, &mut current)
            .map_err(|_| "EEPROM read failed")?;
        if current != seed {
            return Err("EEPROM loading requires a fresh model");
        }
        flash.write_enable();
        let result = flash
            .program(offset, image)
            .map_err(|_| "EEPROM load failed");
        flash.write_disable();
        result
    }

    /// Returns true when the address belongs to the boot console.
    const fn is_uart(addr: u64) -> bool {
        addr >= UART0_BASE && addr - UART0_BASE < 0x1000
    }

    /// Runs the queued MSPI transfer against the SPI-NOR.
    ///
    /// Each slot exchanges one byte. The command is carried by the bytes the
    /// guest writes into TXRAM, and chip-select persists while CDRAM bit 7 is
    /// set, so a command started in one transfer is answered in the next.
    fn mspi_run_queue(&mut self) {
        let first = self.mspi_newqp.min(MSPI_SLOTS - 1);
        let last = self.mspi_endqp.min(MSPI_SLOTS - 1);
        if last < first {
            return;
        }
        for slot in first..=last {
            let control = self.mspi_cdram[slot];
            let words = if control & MSPI_CDRAM_BITSE == 0 {
                1
            } else {
                2
            };
            for word in 0..words {
                let tx = self.mspi_tx[slot * 2 + word];
                let rx = self.spi_exchange(tx);
                // Received bytes are right-aligned in the slot: a single byte
                // lands in the second word, which is why the driver reads one
                // back from RXRAM + (slot << 3) + 4, while two bytes fill both
                // words in order.
                self.mspi_rx[slot * 2 + (2 - words) + word] = rx;
            }
            if control & MSPI_CDRAM_CONT == 0 {
                self.spi_deselect();
            }
        }
    }

    /// Exchanges one byte with the modelled flash.
    fn spi_exchange(&mut self, tx: u8) -> u8 {
        let Some(command) = self.spi.as_mut() else {
            let address_bytes = match tx {
                0x5a => 3,
                0x03 => {
                    if self.flash_4byte_address {
                        4
                    } else {
                        3
                    }
                }
                _ => 0,
            };
            self.spi = Some(SpiCommand {
                opcode: tx,
                address: 0,
                address_bytes,
                address_seen: 0,
                data_index: 0,
            });
            return 0xff;
        };
        if command.address_seen < command.address_bytes {
            command.address = command.address << 8 | usize::from(tx);
            command.address_seen += 1;
            return 0xff;
        }
        let opcode = command.opcode;
        let index = command.data_index;
        let address = command.address;
        command.data_index += 1;
        let Some(flash) = self.flash.as_deref() else {
            return 0xff;
        };
        let mut byte = [0xffu8; 1];
        match opcode {
            // SFDP uses three address bytes and one dummy byte regardless
            // of the normal flash read address mode. BDE reads its UUID here.
            0x5a => {
                return if index == 0 {
                    0xff
                } else {
                    factory::sfdp_byte((address + index - 1) & 0x00ff_ffff)
                };
            }
            0x9f => {
                let id = flash.jedec_id();
                return id.get(index).copied().unwrap_or(0xff);
            }
            // Read status register. The driver polls this after every
            // address-mode switch and waits for the write-in-progress bit to
            // clear. An unhandled opcode answers 0xff, whose low bit reads as
            // "busy", so the poll never ends: the wait becomes a 30-second
            // block-layer timeout and the MTD read fails with -EIO.
            0x05 => {
                if flash.read(opcode, 0, &mut byte).is_ok() {
                    return byte[0];
                }
            }
            0x03 => {
                // ubnthal passes the physical address inside the 0x1c000000
                // window rather than a flash offset, so the command carries
                // 0x1fff0000 for a record 0x3ff0000 into the part. A real
                // SPI-NOR ignores address bits above its capacity; wrap the
                // same way instead of failing the read.
                let address = (address + index) & (FLASH_SIZE - 1);
                if flash.read(opcode, address, &mut byte).is_ok() {
                    return byte[0];
                }
            }
            _ => {}
        }
        0xff
    }

    /// Runs one link-read session: fetches what it asks for and reports both
    /// the watermark and the completion, which is what the handler's
    /// `fullness || session done` test looks for.
    fn raf_start(&mut self) {
        let upper = self.reg(BSPI_FLASH_UPPER_ADDR) & 0xff00_0000;
        let start = self.reg(BSPI_RAF_START_ADDR) & 0x00ff_ffff;
        let words = usize::try_from(self.reg(BSPI_RAF_NUM_WORDS)).unwrap_or(0);
        let words = words.min(FLASH_SIZE / 4);
        let address = usize::try_from(upper | start).unwrap_or(0);
        // A session that runs off the end of the part reads as erased, the
        // same as any other read of blank flash.
        let mut bytes = vec![0xff_u8; words * 4];
        if let Some(flash) = self.flash.as_deref() {
            // The controller clocks a fast read, per the command byte the
            // driver leaves in `BSPI_CMD_AND_MODE_BYTE`.
            let _ = flash.read(0x0b, address, &mut bytes);
        }
        // The handler stores each word straight into a `u32` buffer and
        // shifts the tail out a byte at a time from the bottom, so the first
        // byte off the part is the low byte of the word.
        self.raf_fifo = bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        self.raf_fullness = true;
        self.raf_done = true;
    }

    /// Ends the current chip-select session, applying the address-mode
    /// commands the driver brackets its reads with.
    fn spi_deselect(&mut self) {
        if let Some(command) = self.spi.take() {
            match command.opcode {
                0xb7 => self.flash_4byte_address = true,
                0xe9 => self.flash_4byte_address = false,
                _ => {}
            }
        }
    }

    /// Reads one board register.
    #[must_use]
    pub fn mmio_read(&mut self, addr: u64) -> u32 {
        if let Some(offset) = addr.checked_sub(CMIC_BLOCK_BASE)
            && offset < smbus::REGISTER_SPACE_SIZE
        {
            return self.cmic_i2cm.read(offset);
        }
        if let Some(offset) = addr.checked_sub(CMIC_BLOCK_BASE)
            && let Some(value) = self.cmic.read(offset)
        {
            return value;
        }
        let addr = if (CMIC_MSPI_BASE..CMIC_MSPI_END).contains(&addr) {
            cmic_mspi_address(addr)
        } else {
            addr
        };
        if (smbus::BASE..smbus::BASE + 0x1000).contains(&addr) {
            return self.smbus.read(addr - smbus::BASE);
        }
        if let Some(offset) = addr.checked_sub(gpio::BASE)
            && let Some(value) = self.gpio.read(offset)
        {
            return value;
        }
        if Self::is_uart(addr) {
            return self.uart_read(addr - UART0_BASE);
        }
        // Modelled registers take precedence over anything the guest has
        // written: the driver clears MSPI status during init, and a stored
        // zero must not shadow the completion this model reports.
        match addr {
            GENPLL_CTRL => GENPLL_CTRL_RESET,
            GENPLL_CHAN_DIV => GENPLL_CHAN_DIV_RESET,
            GENPLL_STATUS => GENPLL_STATUS_LOCKED,
            USB_HOST_STRAP => 1 << 17,
            USB_PHY_PLL_STATUS => {
                // 0xc0017c04 asserts reset (bit 26), releases it, then
                // enables the PLL (bits 24/25) before polling lock bit 1.
                u32::from(self.reg(USB_PHY_PLL_CTRL) & (7 << 24) == (3 << 24)) << 1
            }
            CHIPCOMMON_CHIPID => CHIPID_BCM5616X | CHIPID_TYPE_AI,
            CHIPCOMMON_EROM_PTR => EROM_BASE_U32,
            CMIC_DEVICE_ID => SWITCH_DEVICE_BCM56166,
            MSPI_STATUS => {
                if self.mspi_done {
                    MSPI_STATUS_SPIF
                } else {
                    0
                }
            }
            BSPI_BUSY_STATUS => 0,
            // The hardware clears the start bit once the MDIO transfer
            // finishes; leaving it set spins the driver forever.
            GMAC_PHY_ACCESS => {
                self.registers.get(&addr).copied().unwrap_or(0) & !GMAC_PHY_ACCESS_START
            }
            // The reset is self-clearing, so the driver's wait for it to drop
            // completes on the first read.
            GMAC_CMDCFG => self.registers.get(&addr).copied().unwrap_or(0) & !GMAC_CMDCFG_SR,
            QSPI_INTR_MSPI_DONE => u32::from(self.mspi_done),
            QSPI_INTR_LR_FULLNESS => u32::from(self.raf_fullness),
            QSPI_INTR_LR_SESSION_DONE => u32::from(self.raf_done),
            // Session busy never reads back set: the model fetches the whole
            // session before it acknowledges the start.
            BSPI_RAF_STATUS => {
                if self.raf_fifo.is_empty() {
                    BSPI_RAF_STATUS_FIFO_EMPTY
                } else {
                    0
                }
            }
            BSPI_RAF_READ_DATA => self.raf_fifo.pop_front().unwrap_or(u32::MAX),
            // Every other source reads as idle. The handler ORs bit 0 of all
            // seven into one word and treats aborted, impatient or overread
            // as a failed session, so a source that reads back the 1 the
            // clear loop wrote to it fails every transfer.
            addr if (QSPI_INTR_BASE..QSPI_INTR_BASE + QSPI_INTR_COUNT * 4).contains(&addr) => 0,
            BSPI_RAF_FULLNESS => u32::try_from(self.raf_fifo.len()).unwrap_or(u32::MAX),
            // Past the end of the table the slot reads as zero, which the
            // BDE never sees: the descriptor it wants ends the walk.
            addr if (EROM_BASE..EROM_BASE + EROM_SIZE).contains(&addr) => {
                let word = usize::try_from((addr - EROM_BASE) / 4).unwrap_or(usize::MAX);
                EROM_TABLE.get(word).copied().unwrap_or(0)
            }
            addr if (MSPI_RXRAM..MSPI_RXRAM_END).contains(&addr) => {
                let word = usize::try_from((addr - MSPI_RXRAM) / 4).unwrap_or(0);
                u32::from(self.mspi_rx[word.min(MSPI_WORDS - 1)])
            }
            addr => self.registers.get(&addr).copied().unwrap_or(0),
        }
    }

    /// Writes one board register.
    pub fn mmio_write(&mut self, addr: u64, value: u32) {
        if let Some(offset) = addr.checked_sub(CMIC_BLOCK_BASE)
            && offset < smbus::REGISTER_SPACE_SIZE
        {
            self.cmic_i2cm.write(offset, value);
            return;
        }
        if let Some(offset) = addr.checked_sub(CMIC_BLOCK_BASE)
            && self.cmic.write(offset, value)
        {
            return;
        }
        let addr = if (CMIC_MSPI_BASE..CMIC_MSPI_END).contains(&addr) {
            cmic_mspi_address(addr)
        } else {
            addr
        };
        if (smbus::BASE..smbus::BASE + 0x1000).contains(&addr) {
            self.smbus.write(addr - smbus::BASE, value);
            return;
        }
        if let Some(offset) = addr.checked_sub(gpio::BASE)
            && self.gpio.write(offset, value)
        {
            return;
        }
        if Self::is_uart(addr) {
            self.uart_write(addr - UART0_BASE, value);
            return;
        }
        match addr {
            // Writing a bit back acknowledges it, as everywhere in this core.
            GMAC_INT_STATUS => {
                let pending = self.registers.get(&addr).copied().unwrap_or(0);
                self.registers.insert(addr, pending & !value);
                return;
            }
            MSPI_NEWQP => self.mspi_newqp = value as usize & (MSPI_SLOTS - 1),
            MSPI_ENDQP => self.mspi_endqp = value as usize & (MSPI_SLOTS - 1),
            addr if (MSPI_TXRAM..MSPI_TXRAM_END).contains(&addr) => {
                let word = usize::try_from((addr - MSPI_TXRAM) / 4).unwrap_or(0);
                self.mspi_tx[word.min(MSPI_WORDS - 1)] = value.to_le_bytes()[0];
            }
            addr if (MSPI_CDRAM..MSPI_CDRAM_END).contains(&addr) => {
                let slot = usize::try_from((addr - MSPI_CDRAM) / 4).unwrap_or(0);
                self.mspi_cdram[slot.min(MSPI_SLOTS - 1)] = value.to_le_bytes()[0];
            }
            MSPI_SPCR2 if value & MSPI_SPCR2_SPE != 0 => {
                self.mspi_run_queue();
                self.mspi_done = true;
            }
            BSPI_RAF_CTRL if value & BSPI_RAF_CTRL_START != 0 => self.raf_start(),
            BSPI_RAF_CTRL if value & BSPI_RAF_CTRL_CLEAR != 0 => self.raf_fifo.clear(),
            // The status register acknowledges the transfer, and so does the
            // per-source clear loop at 0xc00156f4, which writes 1 to each
            // source named in its mask.
            MSPI_STATUS | QSPI_INTR_MSPI_DONE => self.mspi_done = false,
            QSPI_INTR_LR_FULLNESS => self.raf_fullness = false,
            QSPI_INTR_LR_SESSION_DONE => self.raf_done = false,
            addr if (QSPI_INTR_BASE..QSPI_INTR_BASE + QSPI_INTR_COUNT * 4).contains(&addr) => {}
            _ => {}
        }
        self.registers.insert(addr, value);
    }

    fn gpio_update_irq(&mut self, ctx: &mut MachineContext<'_>) {
        if let Some(level) = self.gpio.irq_change() {
            ctx.events.push(board_core::Event::IrqLevel {
                line: gpio::IRQ,
                level,
            });
        }
    }

    /// Sets GPIOG external input levels; bits 4 through 15 are implemented.
    pub fn set_gpio_inputs(&mut self, ctx: &mut MachineContext<'_>, levels: u32) {
        self.gpio.set_input(levels);
        self.gpio_update_irq(ctx);
    }

    /// Reads one modelled register's stored value.
    fn reg(&self, addr: u64) -> u32 {
        self.registers.get(&addr).copied().unwrap_or(0)
    }

    /// Reads guest memory through the host bus borrowed for this call.
    fn dma_read(ctx: &mut MachineContext<'_>, address: u64, buffer: &mut [u8]) -> bool {
        match ctx.dma.as_deref_mut() {
            Some(bus) => bus.read(address, buffer) == TransferStatus::Complete,
            None => false,
        }
    }

    /// Writes guest memory through the host bus borrowed for this call.
    fn dma_write(ctx: &mut MachineContext<'_>, address: u64, buffer: &[u8]) -> bool {
        match ctx.dma.as_deref_mut() {
            Some(bus) => bus.write(address, buffer) == TransferStatus::Complete,
            None => false,
        }
    }

    /// Reads descriptor `index` of the ring based at `base`.
    ///
    /// `dma32dd_t` is two little-endian words: a control word carrying the
    /// frame flags and the buffer byte count, then the buffer address.
    fn dma_descriptor(ctx: &mut MachineContext<'_>, base: u64, index: u32) -> Option<(u32, u64)> {
        let address = base + u64::from(index * DMA_DESCRIPTOR_BYTES);
        let mut raw = [0u8; 8];
        if !Self::dma_read(ctx, address, &mut raw) {
            return None;
        }
        let control = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let buffer = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        Some((control, u64::from(buffer)))
    }

    /// Converts a posted `ptr` register into a descriptor index.
    ///
    /// The 32-bit engine posts a plain byte offset into the ring, which is
    /// why the trace shows 0x08, 0x10, 0x18 as successive frames go out.
    fn dma_index(ptr: u32) -> u32 {
        (ptr & DMA_PTR_MASK) / DMA_DESCRIPTOR_BYTES
    }

    /// Records the engine's position in `status`, the way the driver reads it.
    fn dma_set_current(&mut self, channel: u64, index: u32) {
        let offset = (index * DMA_DESCRIPTOR_BYTES) & DMA_PTR_MASK;
        self.registers
            .insert(channel + DMA_STATUS, DMA_STATE_ACTIVE | offset);
    }

    /// Walks the transmit ring up to the posted pointer, emitting each frame.
    ///
    /// A frame runs from a descriptor carrying `SOF` to one carrying `EOF`;
    /// the driver's fast path puts both on a single descriptor, but chained
    /// frames are assembled the same way.
    fn gmac_tx_pump(&mut self, ctx: &mut MachineContext<'_>) {
        if self.reg(GMAC_DMA_TX + DMA_CTRL) & DMA_CTRL_ENABLE == 0 {
            return;
        }
        let base = u64::from(self.reg(GMAC_DMA_TX + DMA_ADDR));
        let target = Self::dma_index(self.reg(GMAC_DMA_TX + DMA_PTR));
        let mut index = self.gmac_tx_index;
        let mut frame: Vec<u8> = Vec::new();
        let mut sent = false;
        for _ in 0..DMA_MAX_DESCRIPTORS {
            if index == target {
                break;
            }
            let Some((control, buffer)) = Self::dma_descriptor(ctx, base, index) else {
                break;
            };
            if control & DMA_CTRL_SOF != 0 {
                frame.clear();
            }
            let length = usize::try_from(control & DMA_CTRL_LENGTH).unwrap_or(0);
            if length > 0 && frame.len() + length <= GMAC_MAX_FRAME {
                let mut payload = vec![0u8; length];
                if Self::dma_read(ctx, buffer, &mut payload) {
                    frame.extend_from_slice(&payload);
                }
            }
            if control & DMA_CTRL_EOF != 0 && !frame.is_empty() {
                ctx.events.push(board_core::Event::NetTx {
                    port: 0,
                    frame: std::mem::take(&mut frame),
                });
                sent = true;
            }
            index = if control & DMA_CTRL_EOT != 0 {
                0
            } else {
                index + 1
            };
        }
        self.gmac_tx_index = index;
        self.dma_set_current(GMAC_DMA_TX, index);
        if sent {
            let status = self.reg(GMAC_INT_STATUS) | GMAC_INT_TX;
            self.registers.insert(GMAC_INT_STATUS, status);
        }
    }

    /// Delivers one received frame into the next posted receive descriptor.
    ///
    /// The engine writes a four-byte header at the start of the buffer --
    /// little-endian length, then flags -- and the frame itself at the offset
    /// the driver programmed into the receive control register.
    fn gmac_rx_deliver(&mut self, ctx: &mut MachineContext<'_>, frame: &[u8]) -> bool {
        let control = self.reg(GMAC_DMA_RX + DMA_CTRL);
        if control & DMA_CTRL_ENABLE == 0 || frame.len() > GMAC_MAX_FRAME {
            return false;
        }
        if !self.gmac_accepts(frame) {
            return false;
        }
        let base = u64::from(self.reg(GMAC_DMA_RX + DMA_ADDR));
        let posted = Self::dma_index(self.reg(GMAC_DMA_RX + DMA_PTR));
        let index = self.gmac_rx_index;
        if index == posted {
            return false;
        }
        let Some((descriptor, buffer)) = Self::dma_descriptor(ctx, base, index) else {
            return false;
        };
        let offset = u64::from((control & DMA_RX_CTRL_OFFSET) >> DMA_RX_CTRL_OFFSET_SHIFT);
        let capacity = usize::try_from(descriptor & DMA_CTRL_LENGTH).unwrap_or(0);
        // Real hardware delivers the frame check sequence and counts it in the
        // header length; the driver strips it again. The host bus hands us
        // frames without one, so the model appends four bytes of its own.
        // Getting this wrong is quiet: ARP still works, because the four bytes
        // come out of its padding, while ICMP loses payload and fails its
        // checksum.
        let delivered = frame.len() + ETHERNET_FCS_LEN;
        if usize::try_from(offset).unwrap_or(0) + delivered > capacity {
            return false;
        }
        let mut header = [0u8; 4];
        let length = u16::try_from(delivered).unwrap_or(u16::MAX);
        header[0..2].copy_from_slice(&length.to_le_bytes());
        let mut payload = Vec::with_capacity(delivered);
        payload.extend_from_slice(frame);
        payload.extend_from_slice(&[0; ETHERNET_FCS_LEN]);
        if !Self::dma_write(ctx, buffer, &header)
            || !Self::dma_write(ctx, buffer + offset, &payload)
        {
            return false;
        }
        self.gmac_rx_index = if descriptor & DMA_CTRL_EOT != 0 {
            0
        } else {
            index + 1
        };
        self.dma_set_current(GMAC_DMA_RX, self.gmac_rx_index);
        let status = self.reg(GMAC_INT_STATUS) | GMAC_INT_RX;
        self.registers.insert(GMAC_INT_STATUS, status);
        true
    }

    /// Drives [`GMAC_IRQ`] from the masked interrupt status.
    fn gmac_update_irq(&mut self, ctx: &mut MachineContext<'_>) {
        let pending = self.reg(GMAC_INT_STATUS) & self.reg(GMAC_INT_MASK) != 0;
        if pending == self.gmac_irq_asserted {
            return;
        }
        self.gmac_irq_asserted = pending;
        ctx.events.push(board_core::Event::IrqLevel {
            line: GMAC_IRQ,
            level: pending,
        });
    }

    /// Returns the station address the driver programmed into the Unimac.
    fn gmac_station_address(&self) -> [u8; 6] {
        let high = self.reg(GMAC_MACADDR_HIGH).to_be_bytes();
        let low = self.reg(GMAC_MACADDR_LOW).to_be_bytes();
        [high[0], high[1], high[2], high[3], low[2], low[3]]
    }

    /// Decides whether the MAC would have accepted this frame.
    ///
    /// The host bus can hand us traffic addressed elsewhere, which real
    /// hardware drops before it reaches a descriptor. Broadcast and multicast
    /// pass, as does anything while the driver has set promiscuous mode.
    fn gmac_accepts(&self, frame: &[u8]) -> bool {
        let Some(destination) = frame.get(0..6) else {
            return false;
        };
        self.reg(GMAC_CMDCFG) & GMAC_CMDCFG_PROM != 0
            || destination[0] & 1 != 0
            || destination == self.gmac_station_address()
    }

    /// Returns a pending interrupt level change, if the last access produced
    /// one. The line is shared by every QSPI source.
    fn take_irq_change(&mut self) -> Option<bool> {
        let level = self.mspi_done || self.raf_fullness || self.raf_done;
        if level == self.irq_asserted {
            return None;
        }
        self.irq_asserted = level;
        Some(self.irq_asserted)
    }

    fn uart_read(&mut self, offset: u64) -> u32 {
        match offset {
            UART_RBR if !self.uart_rx.is_empty() => u32::from(self.uart_rx.remove(0)),
            UART_LSR => {
                let mut lsr = UART_LSR_THRE | u32::try_from(UART_LSR_TEMT).unwrap_or(0);
                if !self.uart_rx.is_empty() {
                    lsr |= UART_LSR_DR;
                }
                lsr
            }
            _ => self
                .registers
                .get(&(UART0_BASE + offset))
                .copied()
                .unwrap_or(0),
        }
    }

    fn uart_write(&mut self, offset: u64, value: u32) {
        if offset == UART_THR {
            self.uart_tx.push(value.to_le_bytes()[0]);
            return;
        }
        self.registers.insert(UART0_BASE + offset, value);
    }

    /// Takes one byte queued for the host-facing console.
    pub fn take_uart_tx_byte(&mut self) -> Option<u8> {
        if self.uart_tx.is_empty() {
            None
        } else {
            Some(self.uart_tx.remove(0))
        }
    }

    /// Drains every byte queued for the host-facing console.
    pub fn take_uart_tx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.uart_tx)
    }
}

impl Describe for Bcm5616xBoard {
    fn windows(&self) -> &[Window] {
        &BCM5616X_WINDOWS
    }
    fn irq_lines(&self) -> &[u32] {
        &BOARD_IRQS
    }
}

impl Machine for Bcm5616xBoard {
    fn reset(&mut self, ctx: &mut MachineContext<'_>) {
        self.gpio = gpio::Gpio::default();
        self.smbus = smbus::Smbus::default();
        self.cmic_i2cm = smbus::Smbus::cmic();
        self.cmic = cmic::Cmic::default();
        for &line in &BOARD_IRQS {
            ctx.events
                .push(board_core::Event::IrqLevel { line, level: false });
        }
        self.registers.clear();
        self.front_panel = front_panel::FrontPanel::default();
        self.uart_tx.clear();
        self.uart_rx.clear();
        self.mspi_done = false;
        self.raf_fifo.clear();
        self.raf_fullness = false;
        self.raf_done = false;
        self.irq_asserted = false;
        self.mspi_tx = [0; MSPI_WORDS];
        self.mspi_rx = [0xff; MSPI_WORDS];
        self.mspi_newqp = 0;
        self.mspi_endqp = 0;
        self.flash_4byte_address = false;
        self.mspi_cdram = [0; MSPI_SLOTS];
        self.spi = None;
        self.gmac_tx_index = 0;
        self.gmac_rx_index = 0;
        self.gmac_irq_asserted = false;
    }
    fn mmio_read(
        &mut self,
        _ctx: &mut MachineContext<'_>,
        addr: u64,
        width: AccessWidth,
    ) -> Result<u64, MmioError> {
        check_access(addr, width)?;
        Ok(u64::from(Self::mmio_read(self, addr)))
    }
    fn mmio_write(
        &mut self,
        ctx: &mut MachineContext<'_>,
        addr: u64,
        value: u64,
        width: AccessWidth,
    ) -> Result<(), MmioError> {
        check_access(addr, width)?;
        Self::mmio_write(
            self,
            addr,
            u32::try_from(value).map_err(|_| MmioError::BusError)?,
        );
        if let Some(payload) = self.front_panel.write(addr, value) {
            ctx.events.push(board_core::Event::FrontPanel { payload });
        }
        // Posting a descriptor or enabling the channel is what starts a
        // transmit; the engine has no other trigger.
        if addr == GMAC_DMA_TX + DMA_PTR || addr == GMAC_DMA_TX + DMA_CTRL {
            self.gmac_tx_pump(ctx);
        }
        if (CMIC_BLOCK_BASE..CMIC_BLOCK_BASE + CMIC_BLOCK_SIZE).contains(&addr) {
            self.cmic.pump(ctx);
        }
        self.gmac_update_irq(ctx);
        self.gpio_update_irq(ctx);
        if let Some(level) = self.smbus.irq_change() {
            ctx.events.push(board_core::Event::IrqLevel {
                line: smbus::IRQ,
                level,
            });
        }
        if let Some(level) = self.cmic.irq_change() {
            ctx.events.push(board_core::Event::IrqLevel {
                line: cmic::IRQ,
                level,
            });
        }
        if let Some(level) = self.take_irq_change() {
            ctx.events.push(board_core::Event::IrqLevel {
                line: QSPI_IRQ,
                level,
            });
        }
        Ok(())
    }
    fn advance_to(&mut self, _ctx: &mut MachineContext<'_>) {}
    fn next_deadline(&self) -> Option<board_core::VirtualTime> {
        None
    }
    fn uart_rx(&mut self, _ctx: &mut MachineContext<'_>, port: u32, byte: u8) {
        if port == 0 {
            self.uart_rx.push(byte);
        }
    }
    fn take_uart_tx(&mut self) -> Option<u8> {
        self.take_uart_tx_byte()
    }
    fn net_rx(&mut self, ctx: &mut MachineContext<'_>, port: u32, frame: &[u8]) {
        if port == cmic_dma::PORT {
            self.cmic.receive(ctx, frame);
            if let Some(level) = self.cmic.irq_change() {
                ctx.events.push(board_core::Event::IrqLevel {
                    line: cmic::IRQ,
                    level,
                });
            }
            return;
        }
        if port != 0 {
            return;
        }
        if self.gmac_rx_deliver(ctx, frame) {
            self.gmac_update_irq(ctx);
        }
    }
}

// The UART is byte-addressable; every other modelled block is 32-bit only.
fn check_access(addr: u64, width: AccessWidth) -> Result<(), MmioError> {
    if Bcm5616xBoard::is_uart(addr) {
        return match width {
            AccessWidth::U8 | AccessWidth::U32 => Ok(()),
            _ => Err(MmioError::InvalidWidth),
        };
    }
    if width != AccessWidth::U32 {
        return Err(MmioError::InvalidWidth);
    }
    if addr.is_multiple_of(u64::from(width.bytes())) {
        Ok(())
    } else {
        Err(MmioError::Misaligned)
    }
}
