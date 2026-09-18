/// MT7981 physical address of the first vendor UART used by the U6+ DTB.
pub const UART0_BASE: u64 = 0x1100_2000;
/// MT7981 chip identification register queried by proprietary board support.
pub const CHIP_ID: u64 = 0x0800_0000;
/// MT7981 watchdog base address found in the U6+ device tree.
pub const WATCHDOG_BASE: u64 = 0x1001_c000;
/// MT7981 always-on infrastructure clock/reset controller base.
pub const INFRACFG_AO_BASE: u64 = 0x1000_1000;
/// MT7981 infrastructure clock controller base.
pub const INFRACFG_BASE: u64 = 0x1000_1068;
/// MT7981 top-level clock generator base.
pub const TOPCKGEN_BASE: u64 = 0x1001_b000;
/// MT7981 analog PLL clock controller base.
pub const APMIXEDSYS_BASE: u64 = 0x1001_e000;
/// MT7981 Ethernet clock/reset syscon base.
pub const ETHSYS_BASE: u64 = 0x1500_0000;
/// MT7981 Ethernet MAC/MDIO register block base.
pub const ETH_MAC_BASE: u64 = 0x1510_0000;
/// Size of the Ethernet MAC/MDIO register block.
pub const ETH_MAC_WINDOW_SIZE: u64 = 0x80000;
/// MT7981 efuse controller base used for PHY and USB calibration cells.
pub const EFUSE_BASE: u64 = 0x11f2_0000;
/// MT7981 connectivity-infrastructure reset/status block base.
pub const CONNINFRA_RGU_BASE: u64 = 0x1800_0000;
/// MT7981 connectivity-infrastructure configuration block base.
pub const CONNINFRA_CFG_BASE: u64 = 0x1800_1000;
/// MT7981 connectivity semaphore status block base.
pub const CONNINFRA_SEMAPHORE_BASE: u64 = 0x1807_2000;
/// MT7981 connectivity semaphore release block base.
pub const CONNINFRA_SEMAPHORE_RELEASE_BASE: u64 = 0x1807_2200;
pub(super) const CONNINFRA_SOC_BASE: u64 = 0x1000_0000;
pub(super) const WFSYS_RGU_STATUS: u64 = 0x1800_e2cc;
pub(super) const CONN_HOST_CSR_WFSYS_STATUS: u64 = 0x1806_02cc;
pub(super) const WFSYS_BUS_STATUS: u64 = 0x1800_7b0c;
pub(super) const WFSYS_VERSION: u64 = 0x1800_4f10;
pub(super) const WFSYS_SLPPROT_BASE: u64 = 0x184c_0000;
pub(super) const WFSYS_SLPPROT_STATUS: u64 = WFSYS_SLPPROT_BASE + 0x544;
pub(super) const WFSYS_MCU_SLPPROT_STATUS: u64 = WFSYS_SLPPROT_BASE + 0x300c;
pub(super) const WFSYS_CFG_BASE: u64 = 0x184b_0000;
pub(super) const WFSYS_CFG_VERSION: u64 = WFSYS_CFG_BASE + 0x10;
pub(super) const WFSYS_CFG_ON_ROM_INDEX: u64 = 0x184c_1604;
pub(super) const WFSYS_MMIO_BASE: u64 = CONNINFRA_RGU_BASE;
pub(super) const WFSYS_MMIO_SIZE: u64 = 0x0100_0000;
pub(super) const WFSYS_MCU_BUS_READY: u64 = 0x1840_01b8;
// mt7981_ctrl_rxv_group (used as the chip-ops FW-sync callback in this
// vendor build) reads this WBSYS register and returns its low three bits.
pub(super) const WFSYS_FW_SYNC: u64 = 0x1806_00f0;
// MT7981 uses the MT7986 WFDMA register layout inside the WBSYS aperture.
pub(super) const WFDMA0_INT_SOURCE: u64 = 0x1802_4200;
pub(super) const WFDMA0_INT_MASK: u64 = 0x1802_4204;
pub(super) const WFDMA0_RESET: u64 = 0x1802_4100;
pub(super) const WFDMA0_MCU_CMD_SOURCE: u64 = 0x1802_41f0;
pub(super) const WFDMA0_RX_DONE_WM: u32 = 1 << 0;
pub(super) const WIFI_IRQ_LINE: u32 = 213;
pub(super) const WFDMA0_GLO_CFG: u64 = 0x1802_4208;
pub(super) const WFDMA0_RST_DTX_PTR: u64 = 0x1802_420c;
pub(super) const WFDMA0_RST_DRX_PTR: u64 = 0x1802_4210;
// RX0 (WM2H) ring registers.  The vendor driver uses this ring for MCU
// events and reads the hardware-produced DIDX after HOST_RX_DONE_INT_STS0.
pub(super) const WFDMA0_RX0_BASE: u64 = 0x1802_4500;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const WFDMA0_RX0_CNT: u64 = WFDMA0_RX0_BASE + 0x04;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const WFDMA0_RX0_CIDX: u64 = WFDMA0_RX0_BASE + 0x08;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const WFDMA0_RX0_DIDX: u64 = WFDMA0_RX0_BASE + 0x0c;
pub(super) const WFDMA0_RX0_END: u64 = WFDMA0_RX0_BASE + 0x10;
pub(super) const CONNINFRA_SPI_BASE: u64 = 0x1800_4000;
pub(super) const CONNINFRA_SPI_ADDR: u64 = CONNINFRA_SPI_BASE + 0x50;
pub(super) const CONNINFRA_SPI_DATA: u64 = CONNINFRA_SPI_BASE + 0x54;
pub(super) const CONNINFRA_SPI_STATUS: u64 = CONNINFRA_SPI_BASE + 0x58;
pub(super) const WFSYS_BAND_STRIDE: u64 = 0x0008_0000;
/// MT7981 eMMC/SD controller base used by the U6+ boot firmware.
pub const MSDC0_BASE: u64 = 0x1123_0000;
/// Size of each modeled peripheral register window.
pub const DEVICE_WINDOW_SIZE: u64 = 0x1000;
/// Maximum number of unknown MMIO accesses retained per board.
pub const UNKNOWN_MMIO_TRACE_LIMIT: usize = 256;

pub(super) const INFRACFG_AO_SIZE: u64 = 0x68;
pub(super) const CONTROL_WINDOW_SIZE: u64 = 0x1000;
pub(super) const MSDC_CFG: u64 = 0x00;
pub(super) const MSDC_CFG_CKSTB: u32 = 1 << 7;
pub(super) const MSDC_CFG_RST: u32 = 1 << 2;
pub(super) const MSDC_FIFOCS: u64 = 0x14;
pub(super) const MSDC_FIFOCS_CLR: u32 = 1 << 31;
pub(super) const MSDC_INT: u64 = 0x0c;
pub(super) const MSDC_INTEN: u64 = 0x10;
pub(super) const MSDC_IRQ: u32 = 143;
/// SDIO-only opcodes: `IO_SEND_OP_COND`, `IO_RW_DIRECT` and `IO_RW_EXTENDED`.
pub(super) const MSDC_SDIO_OPCODES: [u32; 3] = [5, 52, 53];
pub(super) const MSDC_SDC_RESP0: u64 = 0x40;
pub(super) const MSDC_SDC_RESP3: u64 = 0x4c;
pub(super) const MSDC_DMA_CTRL: u64 = 0x98;
pub(super) const MSDC_DMA_CFG: u64 = 0x9c;
pub(super) const MSDC_SDC_CMD: u64 = 0x34;
pub(super) const MSDC_SDC_ARG: u64 = 0x38;
pub(super) const MSDC_BLK_NUM: u64 = 0x50;
pub(super) const MSDC_DMA_SA: u64 = 0x90;
pub(super) const MSDC_DMA_START: u32 = 1;
pub(super) const MSDC_DMA_WRITE: u32 = 1 << 13;
pub(super) const MSDC_INT_CMDRDY: u32 = 1 << 8;
pub(super) const MSDC_INT_CMDTMO: u32 = 1 << 9;
pub(super) const MSDC_INT_XFER_COMPL: u32 = 1 << 12;
pub(super) const MSDC_INT_DXFER_DONE: u32 = 1 << 13;
pub(super) const SPI0_BASE: u64 = 0x1100_9000;
pub(super) const SPI_CMD: u64 = 0x18;
pub(super) const SPI_STATUS0: u64 = 0x1c;
pub(super) const SPI_STATUS: u64 = 0x20;
pub(super) const SPI_CFG1: u64 = 0x04;
pub(super) const SPI_TX_SRC: u64 = 0x08;
pub(super) const SPI_RX_DST: u64 = 0x0c;
pub(super) const SPI_CMD_FINISH_IE: u32 = 1 << 16;
pub(super) const SPI_CMD_PAUSE_IE: u32 = 1 << 17;
pub(super) const ETH_MAC_PIAC: u64 = 0x10004;
pub(super) const ETH_MAC_XGMAC_STS: u64 = 0x1000c;
pub(super) const ETH_MAC_XGMAC_STS_ALT: u64 = 0x1001c;
pub(super) const ETH_MAC_MSR0: u64 = 0x10108;
pub(super) const ETH_MAC_MSR1: u64 = 0x10208;
pub(super) const ETH_MAC_PIAC_START: u32 = 1 << 31;
pub(super) const ETH_MAC_PIAC_REG_SHIFT: u32 = 25;
pub(super) const ETH_MAC_PIAC_PHY_SHIFT: u32 = 20;
pub(super) const ETH_MAC_PIAC_CMD_SHIFT: u32 = 18;
pub(super) const ETH_MAC_PIAC_DATA_MASK: u32 = 0xffff;
pub(super) const ETH_MDIO_READ: u32 = 0b10;
pub(super) const PHY_REG_BMCR: u32 = 0;
pub(super) const PHY_REG_BMSR: u32 = 1;
pub(super) const PHY_REG_PHYID1: u32 = 2;
pub(super) const PHY_REG_PHYID2: u32 = 3;
pub(super) const PHY_REG_ANAR: u32 = 4;
pub(super) const PHY_REG_ANLPAR: u32 = 5;
pub(super) const PHY_REG_GBCR: u32 = 9;
pub(super) const PHY_REG_GBSR: u32 = 10;
pub(super) const PHY_REG_ESTATUS: u32 = 15;
pub(super) const PHY_ID1_MT7981: u16 = 0x03a2;
pub(super) const PHY_ID2_MT7981: u16 = 0x9461;
pub(super) const PHY_BMCR_AUTONEG_ENABLE: u16 = 1 << 12;
pub(super) const PHY_BMCR_RESTART_AUTONEG: u16 = 1 << 9;
pub(super) const PHY_BMSR_LINK_STATUS: u16 = 1 << 2;
pub(super) const PHY_BMSR_AUTONEG_COMPLETE: u16 = 1 << 5;
// 10/100 modes, extended status, and autonegotiation capability. Linux
// only probes the gigabit capabilities in ESTATUS when bit 8 is set.
pub(super) const PHY_BMSR_CAPABILITIES: u16 = 0x7800 | (1 << 8) | (1 << 3) | 1;
pub(super) const PHY_ANAR_10_100: u16 = 0x01e1;
pub(super) const PHY_GBCR_1000_FULL: u16 = 1 << 9;
pub(super) const PHY_GBSR_1000_FULL: u16 = (1 << 13) | (1 << 12) | (1 << 11);
pub(super) const PHY_ESTATUS_1000_FULL: u16 = 1 << 13;
// Descriptor SRAM is owned by this model. Only packet buffers in guest RAM
// cross the host DMA interface (re-entering our MMIO window is not safe).
pub(super) const ETH_PDMA_RST_IDX: u64 = 0x4208;
pub(super) const ETH_QDMA_RST_IDX: u64 = 0x4608;
pub(super) const ETH_PDMA_INT_STATUS: u64 = ETH_MAC_BASE + 0x4220;
pub(super) const ETH_DMA_INT_STATUS: u64 = 0x4618;
pub(super) const ETH_QDMA_INT_STATUS: u64 = ETH_MAC_BASE + ETH_DMA_INT_STATUS;
pub(super) const ETH_PDMA_INT_MASK: u64 = ETH_MAC_BASE + 0x4228;
pub(super) const ETH_QDMA_INT_MASK: u64 = ETH_MAC_BASE + 0x461c;
pub(super) const ETH_QDMA_DRX_PTR: u64 = ETH_MAC_BASE + 0x4714;
pub(super) const ETH_QDMA_DTX_PTR: u64 = ETH_MAC_BASE + 0x4704;
pub(super) const ETH_PDMA_GLO_CFG: u64 = ETH_MAC_BASE + 0x4204;
/// `MTK_RX_DMA_EN`.  The driver writes its burst/NDP configuration into
/// `PDMA_GLO_CFG` long before it arms the receive ring, and only then sets
/// this bit.
pub(super) const ETH_PDMA_RX_DMA_EN: u32 = 1 << 2;
pub(super) const ETH_TX_DESC_BASE: u64 = 0x1515_0000;
pub(super) const ETH_RX_DESC_BASE: u64 = 0x1516_0000;
pub(super) const ETH_IRQ_LINES: [u32; 4] = [196, 197, 198, 199];
pub(super) const ETH_INT_RX_DONE: u32 = 1 << 30;
pub(super) const ETH_INT_TX_DONE: u32 = 1 << 28;
pub(super) const EFUSE_CELL_SOC_CALIB_START: u64 = 0x274;
pub(super) const EFUSE_EEPROM_TYPE: u64 = 0x270;
pub(super) const EFUSE_CELL_PHY_CALIB_START: u64 = 0x8dc;
pub(super) const EFUSE_CELL_PHY_CALIB_LEN: u64 = 0x10;
pub(super) const CONNINFRA_IP_VERSION: u64 = 0x00;
pub(super) const WBSYS_PCI_ID: u32 = 0x7981_14c3;
// The vendor mt_rbus host bridge does not install a generic OF map_irq
// callback. Its device nevertheless carries the legacy PCI interrupt line
// used by the proprietary driver when it requests the WFDMA ISR.
pub(super) const WBSYS_PCI_INTERRUPT_LINE: u64 = CONNINFRA_RGU_BASE + 0x3c;
// PCI config dword 0x3c contains the legacy line in byte 0 and INTA in byte
// 1. The vendor 5.4 GIC domain exposes DT SPI 213 as Linux IRQ 91 (the same
// translation that makes Ethernet SPI 196 appear as IRQ 74).
pub(super) const WBSYS_PCI_INTERRUPT_LINE_VALUE: u32 = 0x0001_005b;

pub(super) const UART_RBR_THR_DLL: u64 = 0x00;
pub(super) const UART_IER_DLH: u64 = 0x04;
pub(super) const UART_IIR_FCR: u64 = 0x08;
pub(super) const UART_LCR: u64 = 0x0c;
pub(super) const UART_LSR: u64 = 0x14;
pub(super) const UART_LSR_DATA_READY: u32 = 1 << 0;
pub(super) const UART_LSR_THR_EMPTY: u32 = 1 << 5;
pub(super) const UART_LSR_TRANSMITTER_EMPTY: u32 = 1 << 6;

pub(super) const WATCHDOG_MODE: u64 = 0x00;
pub(super) const WATCHDOG_LENGTH: u64 = 0x04;
pub(super) const WATCHDOG_RESTART: u64 = 0x08;
pub(super) const WATCHDOG_STATUS: u64 = 0x0c;
