#![warn(missing_docs)]

//! A small, deterministic MT7981 board model.
//!
//! This crate deliberately contains no QEMU-specific `unsafe` code.  It models
//! the register behavior needed by the U6+ Linux image and exposes a narrow
//! MMIO interface that a future QEMU FFI shim can call.  QEMU object creation,
//! memory regions, and IRQ wiring remain integration work in the QEMU source
//! tree.

use std::collections::{HashMap, VecDeque};
mod ethernet_offload;
mod images;
#[cfg(test)]
use images::*;
mod regs;
#[cfg(test)]
mod tests;
mod uart;
mod watchdog;
pub use images::*;
pub use regs::*;
pub use uart::Uart;
pub use watchdog::Watchdog;
mod gpio_spi;
mod wfdma_reset;
mod wifi;
mod wifi_frame;
mod wifi_mcu;
pub use wifi::{WifiFrame, WifiRxInfo, WifiStationStats};

use board_core::{
    AccessWidth, Describe, Machine, MachineContext, MmioError, Window,
    mmc::{Command as MmcCommand, MmcCard},
    spi_nor::SpiNor,
};

/// Board reset state exposed by the modeled reset controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetState {
    /// The board is running.
    Running,
    /// A watchdog or explicit reset request has been observed.
    Requested,
}

/// Direction of an MMIO access recorded in the unknown-access trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioDirection {
    /// A guest read.
    Read,
    /// A guest write.
    Write,
}

/// One unknown MMIO access retained for boot-trace driven modelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioAccess {
    /// Physical address accessed by the guest.
    pub address: u64,
    /// Access width in bytes.
    pub width: u8,
    /// Access direction.
    pub direction: MmioDirection,
    /// Value read or written.
    pub value: u32,
}

/// A minimal 16550-compatible UART state model.
#[derive(Debug)]
/// The modeled U6+ MT7981 board.
pub struct Mt7981Board {
    /// Guest RAM size in bytes.
    pub ram_size: u64,
    /// UART0 state.
    pub uart0: Uart,
    /// Watchdog state.
    pub watchdog: Watchdog,
    reset: ResetState,
    control_regs: HashMap<u64, u32>,
    conninfra_spi_addr: u32,
    conninfra_spi_data: u32,
    mdio_page: u16,
    mdio_regs: HashMap<(u32, u32), u16>,
    msdc_regs: HashMap<u64, u32>,
    msdc_resp: [u32; 4],
    mmc: MmcCard,
    msdc_cmd: u32,
    msdc_arg: u32,
    msdc_blk_num: u32,
    msdc_dma_sa: u32,
    spi_nor: SpiNor,
    gpio_spi: gpio_spi::GpioSpi,
    spi_cfg1: u32,
    spi_tx_src: u64,
    spi_rx_dst: u64,
    unknown_mmio: VecDeque<MmioAccess>,
    wfdma_tx_base: [u32; 5],
    wfdma_tx_count: [u32; 5],
    wfdma_tx_didx: [u32; 5],
    wfdma_rx_base: u32,
    wfdma_rx_count: u32,
    wfdma_rx_didx: u32,
    eth_rx_index: u32,
    eth_tx_frame: Vec<u8>,
    eth_tx_offload: ethernet_offload::Offload,
    host_offload: bool,
    firmware_download: Vec<u8>,
    firmware_download_length: u32,
    firmware_patch_complete: bool,
    firmware_patch_semaphore: bool,
    wfsys_fw_sync: u32,
    wifi_rx_translation: [u8; 8],
    wifi_rx_blacklist: HashMap<u8, [u8; 4]>,
    wifi_startup: wifi_mcu::StartupConfig,
    wifi: wifi::Wireless,
}

const MT7981_WINDOWS: [Window; 6] = [
    Window {
        base: 0x0800_0000,
        // Legacy mt7981-mmio exposed the complete vendor SoC aperture here.
        // Keep the broad compatibility window so clock/reset accesses that
        // sit outside the primary peripheral blocks are still acknowledged.
        size: 0x0400_0000,
        priority: 0,
        device: 0,
    },
    Window {
        base: 0x1000_0000,
        // This was the old fallback adapter's exact span.
        size: 0x0860_0000,
        priority: 1,
        device: 4,
    },
    Window {
        base: 0x1800_0000,
        size: 0x0080_0000,
        priority: 2,
        device: 5,
    },
    Window {
        base: UART0_BASE,
        size: DEVICE_WINDOW_SIZE,
        priority: 3,
        device: 1,
    },
    Window {
        base: MSDC0_BASE,
        size: DEVICE_WINDOW_SIZE,
        priority: 3,
        device: 2,
    },
    Window {
        base: ETH_MAC_BASE,
        size: ETH_MAC_WINDOW_SIZE,
        priority: 2,
        device: 3,
    },
];
const IRQ_LINES: [u32; 7] = [74, 142, 143, 196, 197, 198, 199];

impl Describe for Mt7981Board {
    fn windows(&self) -> &[Window] {
        &MT7981_WINDOWS
    }
    fn irq_lines(&self) -> &[u32] {
        &IRQ_LINES
    }
}

impl Machine for Mt7981Board {
    fn reset(&mut self, ctx: &mut MachineContext<'_>) {
        self.reset = ResetState::Running;
        self.wfdma_tx_base = [0; 5];
        self.wfdma_tx_count = [0; 5];
        self.wfdma_tx_didx = [0; 5];
        self.wfdma_rx_base = 0;
        self.wfdma_rx_count = 0;
        self.wfdma_rx_didx = 0;
        self.control_regs
            .retain(|address, _| !(0x1802_4500..0x1802_4560).contains(address));
        self.control_regs.insert(WFDMA0_INT_SOURCE, 0);
        self.control_regs.remove(&WFDMA0_INT_MASK);
        self.update_wifi_irq(ctx);
        self.eth_rx_index = 0;
        self.eth_tx_frame.clear();
        self.firmware_download.clear();
        self.firmware_download_length = 0;
        self.firmware_patch_complete = false;
        self.firmware_patch_semaphore = false;
        self.msdc_cmd = 0;
        self.msdc_arg = 0;
        self.msdc_blk_num = 0;
        self.msdc_dma_sa = 0;
        self.msdc_regs.clear();
        self.msdc_resp = [0; 4];
        self.update_msdc_irq(ctx);
        self.spi_cfg1 = 0;
        self.gpio_spi = gpio_spi::GpioSpi::default();
        self.spi_tx_src = 0;
        self.spi_rx_dst = 0;
        self.wfsys_fw_sync = 1;
        self.wifi_rx_translation = [0; 8];
        self.wifi_rx_blacklist.clear();
        self.wifi_startup = wifi_mcu::StartupConfig::default();
        self.wifi = wifi::Wireless::default();
    }
    fn mmio_read(
        &mut self,
        _ctx: &mut MachineContext<'_>,
        addr: u64,
        width: AccessWidth,
    ) -> Result<u64, MmioError> {
        if width != AccessWidth::U32 || !addr.is_multiple_of(u64::from(width.bytes())) {
            return Err(if width == AccessWidth::U32 {
                MmioError::Misaligned
            } else {
                MmioError::InvalidWidth
            });
        }
        Ok(u64::from(Self::mmio_read(self, addr)))
    }
    fn mmio_write(
        &mut self,
        ctx: &mut MachineContext<'_>,
        addr: u64,
        value: u64,
        width: AccessWidth,
    ) -> Result<(), MmioError> {
        if width != AccessWidth::U32 || !addr.is_multiple_of(u64::from(width.bytes())) {
            return Err(if width == AccessWidth::U32 {
                MmioError::Misaligned
            } else {
                MmioError::InvalidWidth
            });
        }
        let value32 = u32::try_from(value).map_err(|_| MmioError::BusError)?;
        Self::mmio_write(self, addr, value32);
        if addr == MSDC0_BASE + MSDC_INT || addr == MSDC0_BASE + MSDC_INTEN {
            self.update_msdc_irq(ctx);
        }
        if matches!(
            addr,
            ETH_PDMA_INT_STATUS | ETH_QDMA_INT_STATUS | ETH_PDMA_INT_MASK | ETH_QDMA_INT_MASK
        ) {
            self.update_eth_irq(ctx);
        }
        if matches!(addr, WFDMA0_INT_SOURCE | WFDMA0_INT_MASK | WFDMA0_RESET) {
            self.update_wifi_irq(ctx);
        }
        if addr == SPI0_BASE + SPI_CFG1 {
            self.spi_cfg1 = value32;
        } else if addr == SPI0_BASE + SPI_TX_SRC {
            self.spi_tx_src = u64::from(value32);
        } else if addr == SPI0_BASE + SPI_RX_DST {
            self.spi_rx_dst = u64::from(value32);
        } else if addr == SPI0_BASE + SPI_CMD {
            if value32 & 4 != 0 {
                ctx.events.push(board_core::Event::IrqLevel {
                    line: IRQ_LINES[1],
                    level: false,
                });
            } else if value32 & 3 != 0 {
                self.spi_complete(ctx);
            }
        } else if addr == ETH_MAC_BASE + 0x4700 {
            self.qdma_kick(ctx, value32);
        } else if addr == ETH_QDMA_DTX_PTR {
            self.eth_tx_frame.clear();
        } else if addr == ETH_MAC_BASE + ETH_PDMA_RST_IDX && value32 & (1 << 16) != 0 {
            self.eth_rx_index = 0;
        } else if addr == MSDC0_BASE + MSDC_SDC_CMD {
            self.msdc_cmd = value32;
            let opcode = value32 & 0x3f;
            if MSDC_SDIO_OPCODES.contains(&opcode) {
                // The U6+ has a soldered eMMC and no SDIO function, so the
                // SDIO probe commands must time out the way they do on the
                // board.  Answering them with a zero response instead made
                // the MMC core report "no support for card's volts" and
                // "error -22 whilst initialising SDIO card".
                self.msdc_timeout(ctx);
            } else {
                let response = match opcode {
                    1 => self.mmc.command(MmcCommand::SendOpCond, &[]),
                    2 => self.mmc.command(MmcCommand::AllSendCid, &[]),
                    3 => self.mmc.command(MmcCommand::SetRelativeAddress, &[]),
                    9 => self.mmc.command(MmcCommand::SendCsd, &[]),
                    13 => self.mmc.command(MmcCommand::SendStatus, &[]),
                    _ => Ok(board_core::mmc::Response {
                        words: [0; 4],
                        data: Vec::new(),
                    }),
                };
                self.msdc_complete(ctx, response.map_or([0; 4], |result| result.words), false);
            }
        } else if addr == MSDC0_BASE + MSDC_SDC_ARG {
            self.msdc_arg = value32;
        } else if addr == MSDC0_BASE + MSDC_BLK_NUM {
            self.msdc_blk_num = value32;
        } else if addr == MSDC0_BASE + MSDC_DMA_SA {
            self.msdc_dma_sa = value32;
        } else if addr == MSDC0_BASE + MSDC_DMA_CTRL && value32 & MSDC_DMA_START != 0 {
            self.msdc_dma(ctx);
        } else if (0x1802_4400..=0x1802_4440).contains(&addr)
            && (addr - 0x1802_4400).is_multiple_of(0x10)
        {
            let ring = ((addr - 0x1802_4400) / 0x10) as usize;
            if ring < self.wfdma_tx_base.len() {
                self.wfdma_tx_base[ring] = value32;
            }
        } else if (0x1802_4404..=0x1802_4444).contains(&addr)
            && (addr - 0x1802_4404).is_multiple_of(0x10)
        {
            let ring = ((addr - 0x1802_4404) / 0x10) as usize;
            if ring < self.wfdma_tx_count.len() {
                self.wfdma_tx_count[ring] = value32;
            }
        } else if (0x1802_4408..=0x1802_4448).contains(&addr)
            && (addr - 0x1802_4408).is_multiple_of(0x10)
        {
            let ring = ((addr - 0x1802_4408) / 0x10) as usize;
            if ring < self.wfdma_tx_didx.len() {
                self.wfdma_kick(ctx, ring, value32);
            }
        } else if addr == WFDMA0_RX0_BASE {
            self.wfdma_rx_base = value32;
        } else if addr == WFDMA0_RX0_CNT {
            self.wfdma_rx_count = value32;
        } else if addr == WFDMA0_RX0_CIDX {
            self.control_regs.insert(addr, value32);
        }
        Ok(())
    }
    fn advance_to(&mut self, _ctx: &mut MachineContext<'_>) {}
    fn next_deadline(&self) -> Option<board_core::VirtualTime> {
        None
    }
    fn uart_rx(&mut self, _ctx: &mut MachineContext<'_>, _port: u32, byte: u8) {
        self.uart0.push_rx(&[byte]);
    }
    fn take_uart_tx(&mut self) -> Option<u8> {
        self.uart0.take_tx_byte()
    }
    fn net_can_receive(&self, _port: u32) -> bool {
        if self
            .control_regs
            .get(&ETH_PDMA_GLO_CFG)
            .copied()
            .unwrap_or(0)
            & ETH_PDMA_RX_DMA_EN
            == 0
        {
            return false;
        }
        (0..2048).any(|offset| {
            let index = (self.eth_rx_index + offset) % 2048;
            let descriptor = ETH_RX_DESC_BASE + u64::from(index) * 16;
            let control = self
                .control_regs
                .get(&(descriptor + 4))
                .copied()
                .unwrap_or(0);
            self.control_regs.get(&descriptor).copied().unwrap_or(0) != 0
                && control & 0x8000_0000 == 0
                && (control >> 16) & 0x3fff >= 14
        })
    }
    fn net_rx(&mut self, ctx: &mut MachineContext<'_>, _port: u32, frame: &[u8]) {
        if frame.len() < 14 {
            return;
        }
        if self.mmio_read(ETH_PDMA_GLO_CFG) & ETH_PDMA_RX_DMA_EN == 0 {
            // The receive engine is configured but not running, so the ring's
            // buffer pointers are stale: the driver has either not armed them
            // yet or has already freed them.  Writing a frame into one
            // corrupts whatever the guest has since placed at that address,
            // which a bridged interface reaches within seconds because it
            // sees the segment's broadcast traffic from the moment the tap
            // joins the bridge.
            return;
        }
        let length = frame.len().min(1536);
        for _ in 0..2048 {
            let descriptor = ETH_RX_DESC_BASE + u64::from(self.eth_rx_index) * 16;
            let buffer = self.mmio_read(descriptor);
            let control = self.mmio_read(descriptor + 4);
            if buffer != 0 && control & 0x8000_0000 == 0 {
                // RX ring 0 belongs to PDMA. QDMA's alignment setting is
                // independent (the U6+ kernel enables it only for QDMA).
                let offset = if self.mmio_read(ETH_PDMA_GLO_CFG) & (1 << 31) != 0 {
                    2
                } else {
                    0
                };
                if !Self::dma_write(ctx, u64::from(buffer) + offset, &frame[..length]) {
                    return;
                }
                let status = 0x8000_0000 | u32::try_from(length).unwrap_or(0) << 16;
                self.mmio_write(descriptor + 4, status);
                self.mmio_write(descriptor + 8, 0);
                // The U6+ DT enables mac@1 (GMAC2); source ports are one-based.
                self.mmio_write(descriptor + 12, 2 << 19);
                let mirror = descriptor + 0x10000;
                self.mmio_write(mirror + 4, status);
                self.mmio_write(mirror + 8, 0);
                self.mmio_write(mirror + 12, 2 << 19);
                self.raise_eth_interrupt(true);
                self.update_eth_irq(ctx);
                self.eth_rx_index = (self.eth_rx_index + 1) % 2048;
                return;
            }
            self.eth_rx_index = (self.eth_rx_index + 1) % 2048;
        }
    }
}

impl Mt7981Board {
    /// Creates a board with the default 512 MiB guest RAM used by the harness.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ram(512 * 1024 * 1024)
    }

    /// Creates a board with a caller-selected RAM size.
    #[must_use]
    pub fn with_ram(ram_size: u64) -> Self {
        Self {
            ram_size,
            uart0: Uart::default(),
            watchdog: Watchdog::default(),
            reset: ResetState::Running,
            control_regs: HashMap::new(),
            conninfra_spi_addr: 0,
            conninfra_spi_data: 0,
            mdio_page: 0,
            mdio_regs: HashMap::from([
                ((0, PHY_REG_BMCR), PHY_BMCR_AUTONEG_ENABLE),
                (
                    (0, PHY_REG_BMSR),
                    PHY_BMSR_CAPABILITIES | PHY_BMSR_LINK_STATUS | PHY_BMSR_AUTONEG_COMPLETE,
                ),
                ((0, PHY_REG_PHYID1), PHY_ID1_MT7981),
                ((0, PHY_REG_PHYID2), PHY_ID2_MT7981),
                ((0, PHY_REG_ANAR), PHY_ANAR_10_100),
                ((0, PHY_REG_ANLPAR), PHY_ANAR_10_100 | (1 << 14)),
                ((0, PHY_REG_GBCR), PHY_GBCR_1000_FULL),
                ((0, PHY_REG_GBSR), PHY_GBSR_1000_FULL),
                ((0, PHY_REG_ESTATUS), PHY_ESTATUS_1000_FULL),
            ]),
            msdc_regs: HashMap::new(),
            msdc_resp: [0; 4],
            mmc: {
                let mut mmc = MmcCard::new(EMMC_BLOCK_COUNT);
                for (block, bytes) in generate_emmc_regions() {
                    let _ = mmc.write_blocks(block, &bytes);
                }
                mmc
            },
            msdc_cmd: 0,
            msdc_arg: 0,
            msdc_blk_num: 0,
            msdc_dma_sa: 0,
            spi_nor: {
                let mut spi_nor = SpiNor::new(SPI_NOR_SIZE, [0xef, 0x40, 0x18]);
                // Keep the default launcher self-contained. An explicitly
                // supplied image still replaces this deterministic record.
                let mut image = generate_eeprom();
                image.resize(UBOOT_ENV_OFFSET, 0xff);
                image.extend_from_slice(&generate_uboot_env());
                let _ = spi_nor.load_image(&image);
                spi_nor
            },
            spi_cfg1: 0,
            gpio_spi: gpio_spi::GpioSpi::default(),
            spi_tx_src: 0,
            spi_rx_dst: 0,
            unknown_mmio: VecDeque::new(),
            wfdma_tx_base: [0; 5],
            wfdma_tx_count: [0; 5],
            wfdma_tx_didx: [0; 5],
            wfdma_rx_base: 0,
            wfdma_rx_count: 0,
            wfdma_rx_didx: 0,
            eth_rx_index: 0,
            eth_tx_frame: Vec::new(),
            eth_tx_offload: ethernet_offload::Offload::default(),
            host_offload: false,
            firmware_download: Vec::new(),
            firmware_download_length: 0,
            firmware_patch_complete: false,
            firmware_patch_semaphore: false,
            wfsys_fw_sync: 1,
            wifi_rx_translation: [0; 8],
            wifi_rx_blacklist: HashMap::new(),
            wifi_startup: wifi_mcu::StartupConfig::default(),
            wifi: wifi::Wireless::default(),
        }
    }

    /// Executes an identity/status MMC command in the Rust card model.
    ///
    /// # Errors
    /// Returns the MMC model error when `opcode` is not one of the supported identity/status commands.
    pub fn msdc_command(&mut self, opcode: u32) -> Result<[u32; 4], board_core::mmc::Error> {
        let command = match opcode {
            1 => MmcCommand::SendOpCond,
            2 => MmcCommand::AllSendCid,
            3 => MmcCommand::SetRelativeAddress,
            9 => MmcCommand::SendCsd,
            13 => MmcCommand::SendStatus,
            _ => return Err(board_core::mmc::Error::Unsupported),
        };
        Ok(self.mmc.command(command, &[])?.words)
    }

    /// Loads the board's EEPROM/SPI-NOR image.
    ///
    /// # Errors
    /// Returns an error when the image is larger than the modeled flash.
    pub fn load_eeprom_image(&mut self, image: &[u8]) -> Result<(), board_core::spi_nor::Error> {
        if image.len() == EEPROM_IMAGE_SIZE {
            // A partition-sized factory image must retain the neighboring
            // U-Boot environment. Larger inputs remain full flash imports.
            self.spi_nor.load_region(0, image)
        } else {
            self.spi_nor.load_image(image)
        }
    }

    /// Loads the board's eMMC backing image.
    ///
    /// # Errors
    /// Returns an error when the image is larger than the modeled card.
    pub fn load_emmc_image(&mut self, image: &[u8]) -> Result<(), board_core::mmc::Error> {
        self.mmc.load_image(image)
    }

    /// Marks the whole eMMC as needing to be persisted, so a freshly created
    /// backing image receives the seeded partition table.
    pub fn mark_emmc_dirty(&mut self) {
        self.mmc.mark_all_dirty();
    }

    /// Returns whether the guest has written eMMC blocks not yet taken.
    #[must_use]
    pub fn emmc_is_dirty(&self) -> bool {
        self.mmc.is_dirty()
    }

    /// Removes and returns eMMC blocks the guest has written since the last
    /// call, so the host can persist them into a backing image.
    pub fn take_dirty_emmc_blocks(&mut self) -> Vec<(u64, [u8; board_core::mmc::BLOCK_SIZE])> {
        self.mmc.take_dirty()
    }

    fn dma_read(ctx: &mut MachineContext<'_>, address: u64, length: usize) -> Option<Vec<u8>> {
        let mut data = vec![0; length];
        let bus = ctx.dma.as_mut()?;
        if bus.read(address, &mut data) == board_core::dma::TransferStatus::Complete {
            Some(data)
        } else {
            None
        }
    }

    fn dma_write(ctx: &mut MachineContext<'_>, address: u64, data: &[u8]) -> bool {
        ctx.dma.as_mut().is_some_and(|bus| {
            bus.write(address, data) == board_core::dma::TransferStatus::Complete
        })
    }

    fn msdc_dma(&mut self, ctx: &mut MachineContext<'_>) {
        let blocks = usize::try_from(self.msdc_blk_num).unwrap_or(0);
        if self.msdc_dma_sa == 0 || blocks == 0 {
            return;
        }
        let total = blocks.saturating_mul(512);
        let Some(gpd) = Self::dma_read(ctx, u64::from(self.msdc_dma_sa) + 8, 4) else {
            return;
        };
        let mut bd = Self::word(&gpd, 0).unwrap_or(0);
        let mut descriptors = Vec::new();
        let mut remaining = total;
        for _ in 0..4096 {
            if bd == 0 || remaining == 0 {
                break;
            }
            let Some(raw) = Self::dma_read(ctx, u64::from(bd), 16) else {
                return;
            };
            let info = Self::word(&raw, 0).unwrap_or(0);
            let next = Self::word(&raw, 4).unwrap_or(0);
            let buffer = Self::word(&raw, 8).unwrap_or(0);
            let length = usize::try_from(Self::word(&raw, 12).unwrap_or(0) & 0x00ff_ffff)
                .unwrap_or(0)
                .min(remaining);
            if length != 0 {
                descriptors.push((buffer, length));
                remaining -= length;
            }
            if info & 1 != 0 {
                break;
            }
            bd = next;
        }
        if remaining != 0 {
            return;
        }
        let write = self.msdc_cmd & MSDC_DMA_WRITE != 0;
        let mut payload = Vec::with_capacity(total);
        if write {
            for (buffer, length) in &descriptors {
                let Some(bytes) = Self::dma_read(ctx, u64::from(*buffer), *length) else {
                    return;
                };
                payload.extend_from_slice(&bytes);
            }
        }
        let block = self.mmc.block_address(self.msdc_arg);
        let command = if write {
            MmcCommand::Write { block, blocks }
        } else {
            MmcCommand::Read { block, blocks }
        };
        let Ok(response) = self.mmc.command(command, &payload) else {
            return;
        };
        if !write {
            let mut offset = 0;
            for (buffer, length) in descriptors {
                let end = offset + length;
                if !Self::dma_write(ctx, u64::from(buffer), &response.data[offset..end]) {
                    return;
                }
                offset = end;
            }
        }
        self.msdc_complete(ctx, response.words, true);
    }

    fn spi_complete(&mut self, ctx: &mut MachineContext<'_>) {
        let length = usize::try_from((self.spi_cfg1 >> 16) & 0xffff)
            .unwrap_or(0)
            .saturating_add(1)
            .min(0x10000);
        let Some(command) = Self::dma_read(ctx, self.spi_tx_src, 16) else {
            return;
        };
        let opcode = command[0];
        let mut response = vec![0; length];
        let mut write_response = false;
        let result = match opcode {
            board_core::spi_nor::command::READ_ID => {
                let read_length = response.len().min(3);
                if response.len() < 3 {
                    Err(board_core::spi_nor::Error::OutOfRange)
                } else {
                    write_response = true;
                    self.spi_nor.read(opcode, 0, &mut response[..read_length])
                }
            }
            board_core::spi_nor::command::READ
            | board_core::spi_nor::command::FAST_READ
            | board_core::spi_nor::command::QUAD_READ
                if command.len() >= 4 =>
            {
                write_response = true;
                let address =
                    usize::try_from(u32::from_be_bytes([0, command[1], command[2], command[3]]))
                        .unwrap_or(0);
                self.spi_nor.read(opcode, address, &mut response)
            }
            board_core::spi_nor::command::READ_STATUS => {
                write_response = true;
                self.spi_nor.read(opcode, 0, &mut response[..1])
            }
            0x35 => {
                // RDSR2 is used by the vendor SPI-NOR protection path.
                write_response = true;
                response[0] = self.spi_nor.status2();
                Ok(())
            }
            board_core::spi_nor::command::WRITE_ENABLE => {
                write_response = true;
                self.spi_nor.write_enable();
                Ok(())
            }
            board_core::spi_nor::command::WRITE_DISABLE => {
                write_response = true;
                self.spi_nor.write_disable();
                Ok(())
            }
            board_core::spi_nor::command::WRITE_STATUS if command.len() > 1 => {
                write_response = true;
                self.spi_nor.write_status(command[1])
            }
            board_core::spi_nor::command::WRITE_STATUS2 if command.len() > 1 => {
                write_response = true;
                self.spi_nor.write_status2(command[1])
            }
            _ => Ok(()),
        };
        if result.is_ok() && write_response && self.mmio_read(SPI0_BASE + SPI_CMD) & (1 << 10) != 0
        {
            let _ = Self::dma_write(ctx, self.spi_rx_dst, &response);
        }
        // SPI has no command acknowledgement: finishing the clocked transfer
        // is independent of whether the flash recognizes the opcode.
        ctx.events.push(board_core::Event::IrqLevel {
            line: IRQ_LINES[1],
            level: true,
        });
    }

    /// Select host packet preparation without changing guest hardware state.
    pub fn set_host_offload(&mut self, enabled: bool) {
        self.host_offload = enabled;
    }

    fn qdma_kick(&mut self, ctx: &mut MachineContext<'_>, producer: u32) {
        // CTX points AFTER the submitted chain. Consume from DTX, using the
        // NETSYS_V2 TX length (bits 8..23), not the unrelated RX SRAM bank.
        let mut descriptor = u64::from(self.mmio_read(ETH_QDMA_DTX_PTR));
        for _ in 0..2048 {
            if descriptor == u64::from(producer)
                || !(ETH_TX_DESC_BASE..ETH_RX_DESC_BASE).contains(&descriptor)
                || !descriptor.is_multiple_of(32)
            {
                break;
            }
            let buffer = self.mmio_read(descriptor);
            let next = self.mmio_read(descriptor + 4);
            let control = self.mmio_read(descriptor + 8);
            let length = ((control >> 8) & 0xffff) as usize;
            if control & (1 << 31) != 0
                || buffer == 0
                || length == 0
                || self.eth_tx_frame.len() + length > 65535
            {
                break;
            }
            let Some(fragment) = Self::dma_read(ctx, u64::from(buffer), length) else {
                break;
            };
            if self.eth_tx_frame.is_empty() {
                self.eth_tx_offload = ethernet_offload::Offload {
                    control: self.mmio_read(descriptor + 16),
                    vlan: self.mmio_read(descriptor + 20),
                };
            }
            self.eth_tx_frame.extend_from_slice(&fragment);
            if control & (1 << 30) != 0 {
                let frame = std::mem::take(&mut self.eth_tx_frame);
                if self.host_offload {
                    ctx.events.push(board_core::Event::NetTxOffload {
                        port: 0,
                        queue: 0,
                        request: self.eth_tx_offload.request(&frame),
                        frame,
                    });
                } else {
                    for frame in self.eth_tx_offload.frames(frame) {
                        ctx.events.push(board_core::Event::NetTx { port: 0, frame });
                    }
                }
            }
            self.mmio_write(descriptor + 8, control | (1 << 31));
            self.mmio_write(
                ETH_QDMA_DRX_PTR,
                u32::try_from(descriptor).expect("validated TX SRAM address fits in 32 bits"),
            );
            self.mmio_write(ETH_QDMA_DTX_PTR, next);
            self.raise_eth_interrupt(false);
            self.update_eth_irq(ctx);
            descriptor = u64::from(next);
        }
    }

    fn update_eth_irq(&mut self, ctx: &mut MachineContext<'_>) {
        let pdma = self.mmio_read(ETH_PDMA_INT_STATUS) & self.mmio_read(ETH_PDMA_INT_MASK);
        let qdma = self.mmio_read(ETH_QDMA_INT_STATUS) & self.mmio_read(ETH_QDMA_INT_MASK);
        let tx = qdma & ETH_INT_TX_DONE != 0;
        let rx = pdma & ETH_INT_RX_DONE != 0;
        // The vendor driver uses separate TX and RX NAPI handlers. RX must
        // never keep the TX IRQ asserted after the driver masks TX completion.
        // No FE error/status interrupt is modeled on the fourth line.
        for (line, level) in ETH_IRQ_LINES.into_iter().zip([tx || rx, tx, rx, false]) {
            ctx.events.push(board_core::Event::IrqLevel { line, level });
        }
    }

    fn word(data: &[u8], offset: usize) -> Option<u32> {
        data.get(offset..offset + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_le_bytes)
    }

    fn wfdma_post_event(
        &mut self,
        ctx: &mut MachineContext<'_>,
        sequence: u8,
        eid: u8,
        response_ext: u8,
        payload: &[u8],
    ) {
        let count = self.wfdma_rx_count.min(4096);
        if self.wfdma_rx_base == 0 || count == 0 {
            return;
        }
        let index = self.wfdma_rx_didx % count;
        let descriptor = u64::from(self.wfdma_rx_base) + u64::from(index) * 16;
        let Some(desc) = Self::dma_read(ctx, descriptor, 8) else {
            return;
        };
        let Some(buffer) = Self::word(&desc, 0) else {
            return;
        };
        let Some(control) = Self::word(&desc, 4) else {
            return;
        };
        let header_length = if eid == 0xed { 12 } else { 8 };
        let packet_length = 24 + header_length + payload.len();
        if buffer == 0
            || control & 0x8000_0000 != 0
            || usize::try_from((control >> 16) & 0x3fff).unwrap_or(0) < packet_length
        {
            return;
        }
        let mut packet = vec![0; packet_length];
        packet[0..4].copy_from_slice(
            &(0x3800_0000u32 | u32::try_from(packet_length).unwrap_or(0)).to_le_bytes(),
        );
        let event_length = u32::try_from(header_length + payload.len()).unwrap_or(0);
        packet[0x18..0x1c].copy_from_slice(&(0xe000_0000u32 | event_length).to_le_bytes());
        packet[0x1c] = eid;
        packet[0x1d] = sequence;
        if eid == 0xed {
            packet[0x20] = response_ext;
        }
        packet[24 + header_length..].copy_from_slice(payload);
        if !Self::dma_write(ctx, u64::from(buffer), &packet) {
            return;
        }
        let done =
            (control & 0xffff) | 0xc000_0000 | (u32::try_from(packet_length).unwrap_or(0) << 16);
        if !Self::dma_write(ctx, descriptor + 4, &done.to_le_bytes()) {
            return;
        }
        self.wfdma_rx_didx = (index + 1) % count;
        self.raise_wifi_interrupt();
        self.control_regs
            .insert(WFDMA0_RX0_DIDX, self.wfdma_rx_didx);
        self.update_wifi_irq(ctx);
    }

    #[expect(
        clippy::too_many_lines,
        reason = "descriptor command dispatch mirrors hardware"
    )]
    fn wfdma_kick(&mut self, ctx: &mut MachineContext<'_>, ring: usize, target: u32) {
        if matches!(ring, 2 | 3) {
            self.wifi_kick(ctx, ring, target);
            return;
        }
        let count = self.wfdma_tx_count[ring].min(4096);
        let base = self.wfdma_tx_base[ring];
        if base == 0 || count == 0 {
            return;
        }
        let target = target % count;
        while self.wfdma_tx_didx[ring] != target {
            let index = self.wfdma_tx_didx[ring];
            let descriptor = u64::from(base) + u64::from(index) * 16;
            let Some(desc) = Self::dma_read(ctx, descriptor, 8) else {
                break;
            };
            let Some(buffer) = Self::word(&desc, 0) else {
                break;
            };
            let Some(control) = Self::word(&desc, 4) else {
                break;
            };
            let length = ((control >> 16) & 0x3fff) as usize;
            let data_offset = if ring == 0 { 0 } else { 0x40 };
            if buffer == 0 || control & 0x8000_0000 != 0 || length < data_offset {
                break;
            }
            let Some(packet) = Self::dma_read(ctx, u64::from(buffer), length) else {
                break;
            };
            let mut reply = true;
            let mut eid = 1;
            let mut status = 0;
            let mut response_ext = 0;
            let mut response = vec![0; 4];
            let mut sequence = 0;
            let cid = if ring == 0 {
                0xee
            } else {
                let Some(header) = Self::word(&packet, 0x24) else {
                    break;
                };
                sequence = (header >> 24) as u8;
                (header & 0xff) as u8
            };
            if cid == 0xee {
                reply = false;
                let payload = &packet[data_offset..];
                if self.firmware_download.len() + payload.len()
                    > self.firmware_download_length as usize
                {
                    status = 1;
                } else {
                    self.firmware_download.extend_from_slice(payload);
                }
            } else {
                match cid {
                    0x10 => {
                        let Some(argument) = Self::word(&packet, data_offset) else {
                            break;
                        };
                        eid = 4;
                        if argument == 1 {
                            self.firmware_patch_semaphore = true;
                            status = if self.firmware_patch_complete { 1 } else { 2 };
                        } else if argument == 0 {
                            self.firmware_patch_semaphore = false;
                            status = 3;
                        }
                    }
                    0x01 | 0x05 => {
                        let Some(address) = Self::word(&packet, data_offset) else {
                            break;
                        };
                        let Some(download_length) = Self::word(&packet, data_offset + 4) else {
                            break;
                        };
                        status = u8::from(
                            download_length == 0
                                || download_length > 8 * 1024 * 1024
                                || (cid == 5 && !self.firmware_patch_semaphore),
                        );
                        if status == 0 {
                            self.firmware_download.clear();
                            self.firmware_download_length = download_length;
                            let _ = address;
                        }
                    }
                    0x07 => {
                        status = u8::from(
                            self.firmware_download.len() != self.firmware_download_length as usize,
                        );
                        self.firmware_patch_complete = status == 0;
                    }
                    0x02 => {
                        let Some(option) = Self::word(&packet, data_offset) else {
                            break;
                        };
                        let Some(_entry) = Self::word(&packet, data_offset + 4) else {
                            break;
                        };
                        status = u8::from(
                            !self.firmware_patch_complete
                                || self.firmware_download.len()
                                    != self.firmware_download_length as usize,
                        );
                        if status == 0 {
                            // FW_START option bit 2 selects WA. The vendor's
                            // dual-processor stage-3 check requires sync 7,
                            // whereas starting WM alone reports sync 3.
                            self.wfsys_fw_sync = if option & 4 != 0 { 7 } else { 3 };
                        }
                    }
                    0x04 | 0xef => {
                        // Restart-download request.  `MtCmdRestartDLReq` sends
                        // the unified command 0x04 with a one-word payload of
                        // 1 on this chip and the legacy 0xef elsewhere; the
                        // vendor teardown path (`ctrl_fw_state_v2` with target
                        // stage 0) issues it and then polls the sync CR for a
                        // value of 1 or less, which the ROM reports once it is
                        // ready to accept a fresh patch and firmware download.
                        // Without this the driver spins for its full 1501 ms
                        // timeout and fails to re-initialize the radio.
                        let argument = Self::word(&packet, data_offset);
                        if cid == 0xef || argument == Some(1) {
                            reply = cid == 0xef;
                            self.firmware_download.clear();
                            self.firmware_download_length = 0;
                            self.firmware_patch_complete = false;
                            self.firmware_patch_semaphore = false;
                            self.wfsys_fw_sync = 1;
                        } else {
                            reply = false;
                        }
                    }
                    0xed => {
                        eid = 0xed;
                        reply = false;
                        if let Some(header) = Self::word(&packet, 0x28) {
                            response_ext = u8::try_from((header >> 8) & 0xff).unwrap_or(0);
                            match response_ext {
                                1 if length >= 0x58 => {
                                    let efuse = vec![0xff; 16];
                                    if let Some(address) = Self::word(&packet, data_offset) {
                                        response = address.to_le_bytes().to_vec();
                                        response.extend_from_slice(&[0; 4]);
                                        response.extend_from_slice(&efuse);
                                        reply = true;
                                    }
                                }
                                0x21 if length >= 0x44 => {
                                    let Some(config) = Self::word(&packet, data_offset) else {
                                        break;
                                    };
                                    let bytes = usize::try_from(config >> 16).unwrap_or(0);
                                    let page = (config >> 10) & 7;
                                    let last = (config >> 13) & 7;
                                    status = u8::from(
                                        (config & 0x3ff) != 0x101
                                            || page > last
                                            || bytes == 0
                                            || bytes > 1024
                                            || length != 0x44 + bytes,
                                    );
                                    response = vec![0x21, 0, 0, 0, status, 0, 0, 0];
                                    response_ext = 0; // Extended command result event.
                                    reply = true;
                                }
                                0x47 if length == 0x48 => {
                                    let config = &packet[data_offset..];
                                    if config[0] == 0 {
                                        self.wifi_rx_translation.copy_from_slice(config);
                                    } else if config[0] == 1 && config[1] == 1 {
                                        self.wifi_rx_blacklist.insert(
                                            config[4],
                                            [config[4], config[5], config[6], config[7]],
                                        );
                                    } else {
                                        status = 1;
                                    }
                                    response = vec![0x47, 0, 0, 0, status, 0, 0, 0];
                                    response_ext = 0;
                                    reply = true;
                                }
                                _ => {
                                    if let Some((event, payload)) = self
                                        .wifi_startup
                                        .command(response_ext, &packet[data_offset..])
                                    {
                                        response_ext = event;
                                        response = payload;
                                        reply = true;
                                    }
                                }
                            }
                        }
                    }
                    _ => reply = false,
                }
            }
            let done = control | 0x8000_0000;
            if !Self::dma_write(ctx, descriptor + 4, &done.to_le_bytes()) {
                break;
            }
            self.wfdma_tx_didx[ring] = (index + 1) % count;
            if reply && sequence != 0 {
                if eid != 0xed {
                    response[0] = status;
                }
                self.wfdma_post_event(ctx, sequence, eid, response_ext, &response);
            }
        }
    }

    fn wfdma_read(&self, address: u64) -> Option<u32> {
        // The driver reclaims TX slots by polling DIDX, not just DDONE.
        // Read the engine's cursor rather than the generic register shadow.
        if (0x1802_440c..=0x1802_444c).contains(&address)
            && (address - 0x1802_440c).is_multiple_of(0x10)
        {
            let ring = ((address - 0x1802_440c) / 0x10) as usize;
            return Some(self.wfdma_tx_didx[ring]);
        }
        match address {
            WFDMA0_RESET => Some(self.control_regs.get(&address).copied().unwrap_or(0x30)),
            WFDMA0_GLO_CFG => Some(self.control_regs.get(&address).copied().unwrap_or(0)),
            WFDMA0_INT_SOURCE | WFDMA0_MCU_CMD_SOURCE => {
                Some(self.control_regs.get(&address).copied().unwrap_or(0))
            }
            WFDMA0_INT_MASK => Some(self.control_regs.get(&address).copied().unwrap_or(u32::MAX)),
            WFDMA0_RX0_BASE..=WFDMA0_RX0_END if (address - WFDMA0_RX0_BASE).is_multiple_of(4) => {
                Some(self.control_regs.get(&address).copied().unwrap_or(0))
            }
            _ => None,
        }
    }
    /// Reads a 32-bit little-endian MMIO register.
    #[expect(
        clippy::too_many_lines,
        reason = "MMIO decode is kept in one ordered table"
    )]
    pub fn mmio_read(&mut self, address: u64) -> u32 {
        if let Some(value) = self.gpio_spi.read(address) {
            return value;
        }
        if address == CHIP_ID {
            return 0x7981;
        }
        if address == WBSYS_PCI_INTERRUPT_LINE {
            return WBSYS_PCI_INTERRUPT_LINE_VALUE;
        }
        if address == WBSYS_PCI_INTERRUPT_LINE + 1 {
            return (WBSYS_PCI_INTERRUPT_LINE_VALUE >> 8) & 0xff;
        }
        if address == CONNINFRA_RGU_BASE + CONNINFRA_IP_VERSION
            || address == CONNINFRA_SOC_BASE + CONNINFRA_IP_VERSION
        {
            // wbsys exposes a MediaTek PCI function at the base of the
            // connectivity window. The lower and upper halfwords are the
            // vendor/device IDs observed by the U6+ driver.
            return WBSYS_PCI_ID;
        }
        if address == CONNINFRA_CFG_BASE || address == CONNINFRA_SOC_BASE + 0x1000 {
            // conninfra polls this revision before enabling the connectivity
            // domains; the value is documented by the vendor driver log.
            return 0x0209_0000;
        }
        if address == WFSYS_RGU_STATUS
            || address == WFSYS_RGU_STATUS + WFSYS_BAND_STRIDE
            || address == CONN_HOST_CSR_WFSYS_STATUS
        {
            // WFSYS reset deassertion is complete in the synthetic device.
            return 0x4000_0000;
        }
        if address == WFSYS_BUS_STATUS || address == WFSYS_BUS_STATUS + WFSYS_BAND_STRIDE {
            // Report all three bus-sleep-protection acknowledgements.
            return 0xa200_0000;
        }
        if address == WFSYS_VERSION || address == WFSYS_VERSION + WFSYS_BAND_STRIDE {
            // The vendor driver accepts any version above 0x0205ffff.
            return 0x0206_0000;
        }
        if address == WFSYS_SLPPROT_STATUS || address == WFSYS_MCU_SLPPROT_STATUS {
            // The U6+ WFSYS bus is already awake in the synthetic board. The
            // driver tests these status registers for clear protection bits.
            return 0;
        }
        if address == WFSYS_CFG_VERSION {
            return 0x0206_0000;
        }
        if address == WFSYS_CFG_ON_ROM_INDEX {
            // The WFSYS ROM leaves this index at 0x1d1e once the MCU has
            // completed its reset path and is ready for host initialization.
            return 0x1d1e;
        }
        if address == WFSYS_MCU_BUS_READY {
            // The vendor driver writes the MCU bus enable/reset value here
            // and polls for the corresponding ready state before downloading
            // the radio firmware.
            return 0x8800_0000;
        }
        if address == WFSYS_FW_SYNC {
            // The callback masks this register to three bits and compares it
            // before starting the patch download.  The synthetic WFSYS has no
            // MCU image to advance that state, so expose the stage-1 value at
            // reset rather than waiting for a kick that occurs later.
            return self.wfsys_fw_sync;
        }
        if let Some(value) = self.wfdma_read(address) {
            return value;
        }
        if address == CONNINFRA_SPI_BASE || address == CONNINFRA_SPI_BASE + WFSYS_BAND_STRIDE {
            return 1;
        }
        if address == CONNINFRA_SPI_STATUS || address == CONNINFRA_SPI_STATUS + WFSYS_BAND_STRIDE {
            return match self.conninfra_spi_addr & 0x0fff {
                // WFSYS RGU reset status exposes bit 30.  The ADIE EFUSE2
                // status register uses bit 29 for a valid result and bit 30
                // for the kick/busy state; provide a completed readback.
                0x02c => 0x4000_0000,
                0x148 => 0x2000_0000,
                _ => self.conninfra_spi_data,
            };
        }
        if (CONNINFRA_SEMAPHORE_BASE..CONNINFRA_SEMAPHORE_BASE + 0x80).contains(&address)
            || (CONNINFRA_RGU_BASE + 0x2000..CONNINFRA_RGU_BASE + 0x2080).contains(&address)
            || (CONNINFRA_SOC_BASE + 0x5000..CONNINFRA_SOC_BASE + 0x5080).contains(&address)
            || (CONNINFRA_RGU_BASE + 0x5000..CONNINFRA_RGU_BASE + 0x5080).contains(&address)
            || (CONNINFRA_SOC_BASE + 0x70000..CONNINFRA_SOC_BASE + 0x70080).contains(&address)
            || (CONNINFRA_RGU_BASE + 0x70000..CONNINFRA_RGU_BASE + 0x70080).contains(&address)
            || (CONNINFRA_RGU_BASE + 0x70000 + 0x2000..CONNINFRA_RGU_BASE + 0x70000 + 0x2080)
                .contains(&address)
        {
            // The vendor driver polls one bit in each semaphore status word.
            // Return the acquired bit for deterministic single-owner emulation.
            return 1;
        }
        if let Some(value) = Self::efuse_read(address) {
            return value;
        }
        if address == ETH_MAC_BASE + ETH_MAC_PIAC {
            return self.control_regs.get(&address).copied().unwrap_or(0);
        }
        if address == ETH_MAC_BASE + ETH_MAC_XGMAC_STS
            || address == ETH_MAC_BASE + ETH_MAC_XGMAC_STS_ALT
        {
            // GMAC1 is attached through the GMII path on the U6+ board.
            return 1;
        }
        if address == ETH_MAC_BASE + ETH_MAC_MSR0 || address == ETH_MAC_BASE + ETH_MAC_MSR1 {
            // 1000 Mb/s, full duplex, link up. This mirrors the PHY result
            // and prevents the MAC side from immediately dropping carrier.
            return (1 << 3) | (1 << 1) | 1;
        }
        if (MSDC0_BASE..MSDC0_BASE + CONTROL_WINDOW_SIZE).contains(&address) {
            let offset = address - MSDC0_BASE;
            if (MSDC_SDC_RESP0..=MSDC_SDC_RESP3).contains(&offset) {
                return self.msdc_resp[((offset - MSDC_SDC_RESP0) / 4) as usize];
            }
            if offset == MSDC_CFG {
                return self.msdc_regs.get(&offset).copied().unwrap_or(0) | MSDC_CFG_CKSTB;
            }
            return self.msdc_regs.get(&offset).copied().unwrap_or(0);
        }
        if address == ETH_PDMA_INT_STATUS || address == ETH_QDMA_INT_STATUS {
            return self.control_regs.get(&address).copied().unwrap_or(0);
        }
        if address == SPI0_BASE + SPI_STATUS0 || address == SPI0_BASE + SPI_STATUS {
            return 1;
        }
        if let Some(offset) = address.checked_sub(UART0_BASE)
            && offset < DEVICE_WINDOW_SIZE
        {
            return self.uart0.read(offset);
        }
        if let Some(offset) = address.checked_sub(WATCHDOG_BASE)
            && offset < DEVICE_WINDOW_SIZE
        {
            return self.watchdog.read(offset);
        }
        if address == SPI0_BASE + SPI_CMD || Self::is_control_register(address) {
            let value = self.control_regs.get(&address).copied().unwrap_or(0);
            if address == MSDC0_BASE + MSDC_CFG {
                return value | MSDC_CFG_CKSTB;
            }
            if address == SPI0_BASE + SPI_CMD {
                // The controller keeps both completion interrupt enables set
                // after SPI initialization. Linux subsequently reads this
                // register before asserting ACT, so expose the hardware bits
                // in the readback used by that read-modify-write sequence.
                return value | SPI_CMD_FINISH_IE | SPI_CMD_PAUSE_IE;
            }
            return value;
        }
        let value = 0;
        self.record_unknown(address, MmioDirection::Read, value);
        value
    }

    /// Writes a 32-bit little-endian MMIO register.
    #[expect(
        clippy::too_many_lines,
        reason = "the address dispatch mirrors the device register map"
    )]
    pub fn mmio_write(&mut self, address: u64, value: u32) {
        if self.gpio_spi.write(address, value) {
            return;
        }
        if address == ETH_MAC_BASE + ETH_MAC_PIAC {
            self.write_mdio(value);
            return;
        }
        if address == MSDC0_BASE + MSDC_INT {
            let pending = self.msdc_regs.get(&MSDC_INT).copied().unwrap_or(0);
            self.msdc_regs.insert(MSDC_INT, pending & !value);
            return;
        }
        if address == ETH_PDMA_INT_STATUS || address == ETH_QDMA_INT_STATUS {
            let pending = self.control_regs.get(&address).copied().unwrap_or(0);
            self.control_regs.insert(address, pending & !value);
            return;
        }
        if address == CONNINFRA_SPI_ADDR || address == CONNINFRA_SPI_ADDR + WFSYS_BAND_STRIDE {
            self.conninfra_spi_addr = value;
            return;
        }
        if address == CONNINFRA_SPI_DATA || address == CONNINFRA_SPI_DATA + WFSYS_BAND_STRIDE {
            self.conninfra_spi_data = value;
            return;
        }
        if address == WFDMA0_INT_SOURCE {
            // The interrupt source register is write-one-to-clear.
            let pending = self.control_regs.get(&address).copied().unwrap_or(0);
            self.control_regs.insert(address, pending & !value);
            return;
        }
        if address == WFDMA0_RESET {
            // Logic reset is active-low; release bits are ordinary readback,
            // unlike the per-ring self-clearing pointer-reset strobes.
            if value & (1 << 4) == 0 {
                self.reset_wfdma_tx_pointers(u32::MAX);
                self.reset_wfdma_rx_pointers(u32::MAX);
                self.control_regs.insert(WFDMA0_INT_SOURCE, 0);
                self.control_regs.insert(WFDMA0_MCU_CMD_SOURCE, 0);
            }
            self.control_regs.insert(address, value);
            return;
        }
        if address == WFDMA0_RST_DTX_PTR || address == WFDMA0_RST_DRX_PTR {
            if address == WFDMA0_RST_DTX_PTR {
                self.reset_wfdma_tx_pointers(value);
            } else {
                self.reset_wfdma_rx_pointers(value);
            }
            self.control_regs.insert(address, 0);
            return;
        }
        if (WFDMA0_RX0_BASE..=WFDMA0_RX0_END).contains(&address)
            && (address - WFDMA0_RX0_BASE).is_multiple_of(4)
        {
            // These are ordinary ring configuration/index registers.  In
            // particular, DIDX is written by the emulated device and read by
            // the vendor ISR to discover newly completed RX descriptors.
            self.control_regs.insert(address, value);
            return;
        }
        if let Some(offset) = address.checked_sub(UART0_BASE)
            && offset < DEVICE_WINDOW_SIZE
        {
            self.uart0.write(offset, value);
            return;
        }
        if let Some(offset) = address.checked_sub(WATCHDOG_BASE)
            && offset < DEVICE_WINDOW_SIZE
            && self.watchdog.write(offset, value)
        {
            if offset == WATCHDOG_RESTART && self.watchdog.mode != 0 {
                self.reset = ResetState::Requested;
            }
            return;
        }
        if address == SPI0_BASE + SPI_CMD || Self::is_control_register(address) {
            if (MSDC0_BASE..MSDC0_BASE + CONTROL_WINDOW_SIZE).contains(&address) {
                let offset = address - MSDC0_BASE;
                let stored = if offset == MSDC_CFG {
                    value & !MSDC_CFG_RST & !MSDC_CFG_CKSTB
                } else if offset == MSDC_FIFOCS {
                    value & !MSDC_FIFOCS_CLR
                } else {
                    value
                };
                self.msdc_regs.insert(offset, stored);
                return;
            }
            let value = if address == MSDC0_BASE + MSDC_CFG {
                value & !MSDC_CFG_RST & !MSDC_CFG_CKSTB
            } else if address == MSDC0_BASE + MSDC_FIFOCS {
                value & !MSDC_FIFOCS_CLR
            } else if address == SPI0_BASE + SPI_CMD {
                // ACT/RESUME/RST are strobes, not persistent configuration.
                // Keeping ACT set replays transfers during driver RMW setup,
                // before the new DMA addresses are installed, corrupting RAM.
                (value & !7) | SPI_CMD_FINISH_IE | SPI_CMD_PAUSE_IE
            } else if address == ETH_MAC_BASE + ETH_PDMA_RST_IDX
                || address == ETH_MAC_BASE + ETH_QDMA_RST_IDX
                || address == ETH_MAC_BASE + ETH_DMA_INT_STATUS
            {
                // DMA index reset and interrupt status writes self-clear (or
                // are write-one-to-clear) on the hardware.
                0
            } else {
                value
            };
            self.control_regs.insert(address, value);
            return;
        }
        self.record_unknown(address, MmioDirection::Write, value);
    }

    fn update_msdc_irq(&self, ctx: &mut MachineContext<'_>) {
        let pending = self.msdc_regs.get(&MSDC_INT).copied().unwrap_or(0);
        let enabled = self.msdc_regs.get(&MSDC_INTEN).copied().unwrap_or(0);
        // Keep the level asserted until every enabled pending cause is cleared.
        ctx.events.push(board_core::Event::IrqLevel {
            line: MSDC_IRQ,
            level: pending & enabled != 0,
        });
    }

    fn msdc_timeout(&mut self, ctx: &mut MachineContext<'_>) {
        self.msdc_resp = [0; 4];
        let pending = self.msdc_regs.get(&MSDC_INT).copied().unwrap_or(0);
        self.msdc_regs.insert(MSDC_INT, pending | MSDC_INT_CMDTMO);
        self.update_msdc_irq(ctx);
    }

    fn msdc_complete(&mut self, ctx: &mut MachineContext<'_>, response: [u32; 4], data_done: bool) {
        self.msdc_resp = response;
        let mut pending = self.msdc_regs.get(&MSDC_INT).copied().unwrap_or(0);
        pending |= MSDC_INT_CMDRDY;
        if data_done {
            pending |= MSDC_INT_XFER_COMPL | MSDC_INT_DXFER_DONE;
            self.msdc_regs.insert(MSDC_DMA_CFG, 0);
            self.msdc_regs.insert(MSDC_DMA_CTRL, 0);
        }
        self.msdc_regs.insert(MSDC_INT, pending);
        self.update_msdc_irq(ctx);
    }

    /// Raises the synthetic MCU RX-done interrupt until the guest clears it.
    pub fn raise_wifi_interrupt(&mut self) {
        // The vendor event is delivered through the first MCU RX ring. Bit 0
        // is HOST_RX_DONE_INT_STS0; bits 1..3 are the other RX queues.
        *self.control_regs.entry(WFDMA0_INT_SOURCE).or_default() |= WFDMA0_RX_DONE_WM;
    }

    fn update_wifi_irq(&self, ctx: &mut MachineContext<'_>) {
        let pending = self
            .control_regs
            .get(&WFDMA0_INT_SOURCE)
            .copied()
            .unwrap_or(0);
        let mask = self
            .control_regs
            .get(&WFDMA0_INT_MASK)
            .copied()
            .unwrap_or(u32::MAX);
        ctx.events.push(board_core::Event::IrqLevel {
            line: WIFI_IRQ_LINE,
            level: pending & mask != 0,
        });
    }

    /// Raises a frame-engine interrupt until the guest acknowledges its bit.
    pub fn raise_eth_interrupt(&mut self, receive: bool) {
        let address = if receive {
            ETH_PDMA_INT_STATUS
        } else {
            ETH_QDMA_INT_STATUS
        };
        let pending = self.control_regs.get(&address).copied().unwrap_or(0);
        let interrupt = if receive {
            ETH_INT_RX_DONE
        } else {
            ETH_INT_TX_DONE
        };
        self.control_regs.insert(address, pending | interrupt);
        if receive {
            let pending = self
                .control_regs
                .get(&ETH_QDMA_INT_STATUS)
                .copied()
                .unwrap_or(0);
            self.control_regs
                .insert(ETH_QDMA_INT_STATUS, pending | ETH_INT_RX_DONE);
        }
    }

    fn is_control_register(address: u64) -> bool {
        (INFRACFG_AO_BASE..INFRACFG_AO_BASE + INFRACFG_AO_SIZE).contains(&address)
            || (INFRACFG_BASE..INFRACFG_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (TOPCKGEN_BASE..TOPCKGEN_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (APMIXEDSYS_BASE..APMIXEDSYS_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (ETHSYS_BASE..ETHSYS_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (ETH_MAC_BASE..ETH_MAC_BASE + ETH_MAC_WINDOW_SIZE).contains(&address)
            || (CONNINFRA_RGU_BASE..CONNINFRA_RGU_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (CONNINFRA_SPI_BASE..CONNINFRA_SPI_BASE + CONTROL_WINDOW_SIZE).contains(&address)
            || (CONNINFRA_RGU_BASE + 0x5000..CONNINFRA_RGU_BASE + 0x6000).contains(&address)
            || (WFSYS_MMIO_BASE..WFSYS_MMIO_BASE + WFSYS_MMIO_SIZE).contains(&address)
            || (MSDC0_BASE..MSDC0_BASE + CONTROL_WINDOW_SIZE).contains(&address)
    }

    fn efuse_read(address: u64) -> Option<u32> {
        let offset = address.checked_sub(EFUSE_BASE)?;
        if offset == EFUSE_EEPROM_TYPE {
            // The U6+ image contains the iPA/iLNA board-data blob. The
            // vendor selector chooses that filename when this efuse word is
            // 0x000c.
            return Some(0x000c);
        }
        if (EFUSE_CELL_SOC_CALIB_START..EFUSE_CELL_SOC_CALIB_START + 0x0c).contains(&offset) {
            return u32::try_from(offset - EFUSE_CELL_SOC_CALIB_START + 1).ok();
        }
        if (EFUSE_CELL_PHY_CALIB_START..EFUSE_CELL_PHY_CALIB_START + EFUSE_CELL_PHY_CALIB_LEN)
            .contains(&offset)
        {
            return u32::try_from(offset - EFUSE_CELL_PHY_CALIB_START + 1).ok();
        }
        None
    }

    fn write_mdio(&mut self, value: u32) {
        let phy = (value >> ETH_MAC_PIAC_PHY_SHIFT) & 0x1f;
        let register = (value >> ETH_MAC_PIAC_REG_SHIFT) & 0x1f;
        let command = (value >> ETH_MAC_PIAC_CMD_SHIFT) & 0x3;
        let data = (value & ETH_MAC_PIAC_DATA_MASK) as u16;

        if command == ETH_MDIO_READ {
            let result = if register == 0x1f {
                self.mdio_page
            } else if self.mdio_page == 1 && register == 0x14 {
                // MTK PHY page 1, AUX_CTRL_AND_STATUS: LP_DETECTED is set
                // when the synthetic peer has completed autonegotiation.
                0x0040
            } else {
                self.mdio_regs.get(&(phy, register)).copied().unwrap_or(0)
            };
            self.control_regs
                .insert(ETH_MAC_BASE + ETH_MAC_PIAC, u32::from(result));
        } else {
            if register == 0x1f {
                self.mdio_page = data;
            } else if self.mdio_page == 0 {
                // Negotiation completes synchronously in this PHY model.
                // Leaving ANRESTART set makes genphy_update_link force link
                // down even though BMSR reports autonegotiation complete.
                let data = if register == PHY_REG_BMCR {
                    data & !PHY_BMCR_RESTART_AUTONEG
                } else {
                    data
                };
                self.mdio_regs.insert((phy, register), data);
            }
            self.control_regs
                .insert(ETH_MAC_BASE + ETH_MAC_PIAC, u32::from(data));
        }

        // MAC_PIAC's PHY access start bit self-clears when the indirect
        // transaction completes. Keeping it clear makes Linux's polling
        // loop observe completion on the first read.
        debug_assert_ne!(value & ETH_MAC_PIAC_START, 0);
    }

    /// Returns the current board reset state.
    #[must_use]
    pub const fn reset_state(&self) -> ResetState {
        self.reset
    }

    /// Returns and clears the oldest unknown MMIO access, if one is queued.
    pub fn take_unknown_mmio(&mut self) -> Option<MmioAccess> {
        self.unknown_mmio.pop_front()
    }

    fn record_unknown(&mut self, address: u64, direction: MmioDirection, value: u32) {
        if self.unknown_mmio.len() == UNKNOWN_MMIO_TRACE_LIMIT {
            self.unknown_mmio.pop_front();
        }
        self.unknown_mmio.push_back(MmioAccess {
            address,
            width: 4,
            direction,
            value,
        });
    }
}

impl Default for Mt7981Board {
    fn default() -> Self {
        Self::new()
    }
}
