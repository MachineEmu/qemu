use super::*;

// CMICd MIIM. A write to the control register completes immediately, and the
// transfer it starts reaches the one PHY this board models on the external
// ring — see `mdio`. Every other address reports 0xffff, so `mdiobus_scan`
// registers that PHY alone rather than one per address, and `mdiobus_register`
// succeeds instead of hanging on a status bit that never sets.
#[cfg(test)]
const CMICD_MIIM_PARAM: u64 = CMICD_BASE + 0x80;
#[cfg(test)]
const CMICD_MIIM_ADDRESS: u64 = CMICD_BASE + 0x88;
#[cfg(test)]
const CMICD_MIIM_CTRL: u64 = CMICD_BASE + 0x8c;
#[cfg(test)]
const CMICD_MIIM_STATUS: u64 = CMICD_BASE + 0x90;
#[cfg(test)]
const CMICD_MIIM_READ_DATA: u64 = CMICD_BASE + 0x84;

use board_core::AddressMap;

#[test]
fn the_window_map_resolves_every_modelled_block() {
    let board = Bcm5616xBoard::new();
    let map = AddressMap::new(board.windows().to_vec()).expect("windows must not conflict");
    assert_eq!(map.lookup(UART0_BASE).map(|w| w.device), Some(DEVICE_UART0));
    assert_eq!(
        map.lookup(CHIPCOMMON_BASE).map(|w| w.device),
        Some(DEVICE_CHIPCOMMON)
    );
    assert_eq!(map.lookup(CRU_BASE).map(|w| w.device), Some(DEVICE_CRU));
    assert_eq!(
        map.lookup(CRU_REGS_BASE + 0xe00).map(|w| w.device),
        Some(DEVICE_CRU_REGS)
    );
    assert_eq!(map.lookup(PERIPH_BASE + PERIPH_SIZE), None);
}

/// A flat block of guest memory for the descriptor engines to walk.
struct FakeMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl FakeMemory {
    fn new(base: u64, size: usize) -> Self {
        Self {
            base,
            bytes: vec![0; size],
        }
    }
    fn put(&mut self, address: u64, data: &[u8]) {
        let start = usize::try_from(address - self.base).unwrap();
        self.bytes[start..start + data.len()].copy_from_slice(data);
    }
    fn get(&self, address: u64, length: usize) -> &[u8] {
        let start = usize::try_from(address - self.base).unwrap();
        &self.bytes[start..start + length]
    }
    /// Writes a `dma32dd_t` at `index` of the ring based at `self.base`.
    fn descriptor(&mut self, index: u32, control: u32, buffer: u64) {
        let address = self.base + u64::from(index * DMA_DESCRIPTOR_BYTES);
        let mut raw = [0u8; 8];
        raw[0..4].copy_from_slice(&control.to_le_bytes());
        raw[4..8].copy_from_slice(
            &u32::try_from(buffer)
                .expect("test DMA buffers use 32-bit guest addresses")
                .to_le_bytes(),
        );
        self.put(address, &raw);
    }
}

impl board_core::dma::DmaBus for FakeMemory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> TransferStatus {
        let Ok(start) = usize::try_from(address.wrapping_sub(self.base)) else {
            return TransferStatus::Failed;
        };
        if start + buffer.len() > self.bytes.len() {
            return TransferStatus::Failed;
        }
        buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
        TransferStatus::Complete
    }
    fn write(&mut self, address: u64, buffer: &[u8]) -> TransferStatus {
        let Ok(start) = usize::try_from(address.wrapping_sub(self.base)) else {
            return TransferStatus::Failed;
        };
        if start + buffer.len() > self.bytes.len() {
            return TransferStatus::Failed;
        }
        self.bytes[start..start + buffer.len()].copy_from_slice(buffer);
        TransferStatus::Complete
    }
}

const RING_BASE: u64 = 0x6200_0000;
const STATION: [u8; 6] = [0x52, 0x54, 0x00, 0x55, 0x53, 0x01];

/// Programs the station address the way the Unimac carries it: the first
/// four octets in the high word, the last two left-aligned in the low one.
fn set_station(board: &mut Bcm5616xBoard) {
    board.registers.insert(
        GMAC_MACADDR_HIGH,
        u32::from_be_bytes([STATION[0], STATION[1], STATION[2], STATION[3]]),
    );
    board.registers.insert(
        GMAC_MACADDR_LOW,
        u32::from(u16::from_be_bytes([STATION[4], STATION[5]])),
    );
}

#[test]
fn a_posted_transmit_descriptor_becomes_a_frame() {
    let mut board = Bcm5616xBoard::new();
    let mut memory = FakeMemory::new(RING_BASE, 0x4000);
    let payload: Vec<u8> = (0..60u8).collect();
    let buffer = RING_BASE + 0x2000;
    memory.put(buffer, &payload);
    memory.descriptor(
        0,
        DMA_CTRL_SOF | DMA_CTRL_EOF | u32::try_from(payload.len()).unwrap(),
        buffer,
    );

    let mut ctx = MachineContext::with_dma(0, &mut memory);
    board.registers.insert(
        GMAC_DMA_TX + DMA_ADDR,
        u32::try_from(RING_BASE).expect("test ring uses a 32-bit guest address"),
    );
    board.registers.insert(GMAC_INT_MASK, GMAC_INT_TX);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        GMAC_DMA_TX + DMA_CTRL,
        u64::from(DMA_CTRL_ENABLE),
        AccessWidth::U32,
    )
    .unwrap();
    // Posting the offset of descriptor 1 means "descriptor 0 is ready".
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        GMAC_DMA_TX + DMA_PTR,
        u64::from(DMA_DESCRIPTOR_BYTES),
        AccessWidth::U32,
    )
    .unwrap();

    let frames: Vec<&Vec<u8>> = ctx
        .events
        .iter()
        .filter_map(|event| match event {
            board_core::Event::NetTx { port: 0, frame } => Some(frame),
            _ => None,
        })
        .collect();
    assert_eq!(frames, vec![&payload]);
    assert_ne!(board.reg(GMAC_INT_STATUS) & GMAC_INT_TX, 0);
    // The masked interrupt must reach the GIC line the probe took.
    assert!(ctx.events.iter().any(|event| matches!(
        event,
        board_core::Event::IrqLevel {
            line: GMAC_IRQ,
            level: true
        }
    )));
}

#[test]
fn a_received_frame_lands_at_the_programmed_offset() {
    let mut board = Bcm5616xBoard::new();
    set_station(&mut board);
    let mut memory = FakeMemory::new(RING_BASE, 0x4000);
    let buffer = RING_BASE + 0x2000;
    memory.descriptor(0, 0x600, buffer);

    // The driver programs the frame offset into the receive control
    // register; the model must honour it rather than assume one.
    let offset = 30u32;
    board.registers.insert(
        GMAC_DMA_RX + DMA_CTRL,
        DMA_CTRL_ENABLE | (offset << DMA_RX_CTRL_OFFSET_SHIFT),
    );
    board.registers.insert(
        GMAC_DMA_RX + DMA_ADDR,
        u32::try_from(RING_BASE).expect("test ring uses a 32-bit guest address"),
    );
    board
        .registers
        .insert(GMAC_DMA_RX + DMA_PTR, DMA_DESCRIPTOR_BYTES);
    board.registers.insert(GMAC_INT_MASK, GMAC_INT_RX);

    let mut frame = Vec::from(STATION);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend(std::iter::repeat_n(0xa5, 46));

    let mut ctx = MachineContext::with_dma(0, &mut memory);
    Machine::net_rx(&mut board, &mut ctx, 0, &frame);

    assert_ne!(board.reg(GMAC_INT_STATUS) & GMAC_INT_RX, 0);
    assert!(ctx.events.iter().any(|event| matches!(
        event,
        board_core::Event::IrqLevel {
            line: GMAC_IRQ,
            level: true
        }
    )));
    // The header length counts the frame check sequence the engine
    // appends, which is what the driver expects to strip.
    let length = u16::from_le_bytes(memory.get(buffer, 2).try_into().unwrap());
    assert_eq!(usize::from(length), frame.len() + ETHERNET_FCS_LEN);
    assert_eq!(
        memory.get(buffer + u64::from(offset), frame.len()),
        &frame[..]
    );
}

#[test]
fn frames_addressed_elsewhere_are_dropped() {
    let mut board = Bcm5616xBoard::new();
    set_station(&mut board);
    let mut memory = FakeMemory::new(RING_BASE, 0x4000);
    memory.descriptor(0, 0x600, RING_BASE + 0x2000);
    board
        .registers
        .insert(GMAC_DMA_RX + DMA_CTRL, DMA_CTRL_ENABLE | (30 << 1));
    board.registers.insert(
        GMAC_DMA_RX + DMA_ADDR,
        u32::try_from(RING_BASE).expect("test ring uses a 32-bit guest address"),
    );
    board
        .registers
        .insert(GMAC_DMA_RX + DMA_PTR, DMA_DESCRIPTOR_BYTES);

    let mut frame = vec![0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    frame.extend(std::iter::repeat_n(0, 54));
    let mut ctx = MachineContext::with_dma(0, &mut memory);
    Machine::net_rx(&mut board, &mut ctx, 0, &frame);
    assert_eq!(board.reg(GMAC_INT_STATUS) & GMAC_INT_RX, 0);

    // Broadcast still reaches the ring.
    frame[0] = 0xff;
    Machine::net_rx(&mut board, &mut ctx, 0, &frame);
    assert_ne!(board.reg(GMAC_INT_STATUS) & GMAC_INT_RX, 0);
}

#[test]
fn a_receive_ring_with_nothing_posted_drops_the_frame() {
    let mut board = Bcm5616xBoard::new();
    set_station(&mut board);
    let mut memory = FakeMemory::new(RING_BASE, 0x4000);
    board
        .registers
        .insert(GMAC_DMA_RX + DMA_CTRL, DMA_CTRL_ENABLE | (30 << 1));
    board.registers.insert(
        GMAC_DMA_RX + DMA_ADDR,
        u32::try_from(RING_BASE).expect("test ring uses a 32-bit guest address"),
    );
    // ptr still at the ring base: the driver has posted no descriptor.
    board.registers.insert(GMAC_DMA_RX + DMA_PTR, 0);

    let mut frame = Vec::from(STATION);
    frame.extend(std::iter::repeat_n(0, 54));
    let mut ctx = MachineContext::with_dma(0, &mut memory);
    Machine::net_rx(&mut board, &mut ctx, 0, &frame);
    assert_eq!(board.reg(GMAC_INT_STATUS) & GMAC_INT_RX, 0);
    assert!(ctx.events.is_empty());
}

#[test]
fn the_gmac_block_is_mapped_where_the_probe_maps_it() {
    let board = Bcm5616xBoard::new();
    let map = AddressMap::new(board.windows().to_vec()).expect("windows must not conflict");
    assert_eq!(map.lookup(GMAC_BASE).map(|w| w.device), Some(DEVICE_GMAC));
    assert_eq!(
        map.lookup(GMAC_BASE + GMAC_SIZE - 4).map(|w| w.device),
        Some(DEVICE_GMAC)
    );
    // The probe maps exactly 0xc00 bytes; nothing follows it.
    assert_eq!(map.lookup(GMAC_BASE + GMAC_SIZE), None);
    assert!(board.irq_lines().contains(&GMAC_IRQ));
}

#[test]
fn gmac_self_clearing_bits_do_not_spin_the_driver() {
    let mut board = Bcm5616xBoard::new();
    board.mmio_write(GMAC_PHY_ACCESS, GMAC_PHY_ACCESS_START | 0x1234);
    let access = board.mmio_read(GMAC_PHY_ACCESS);
    assert_eq!(access & GMAC_PHY_ACCESS_START, 0);
    assert_eq!(access & 0xffff, 0x1234);

    board.mmio_write(GMAC_CMDCFG, GMAC_CMDCFG_SR | 1);
    assert_eq!(board.mmio_read(GMAC_CMDCFG), 1);
}

#[test]
fn writing_gmac_interrupt_status_acknowledges_those_bits() {
    let mut board = Bcm5616xBoard::new();
    board.registers.insert(GMAC_INT_STATUS, 0b1011);
    board.mmio_write(GMAC_INT_STATUS, 0b0010);
    assert_eq!(board.mmio_read(GMAC_INT_STATUS), 0b1001);
    // The mask is an ordinary read/write register.
    board.mmio_write(GMAC_INT_MASK, 0xdead);
    assert_eq!(board.mmio_read(GMAC_INT_MASK), 0xdead);
}

#[test]
fn the_uboot_environment_carries_an_ethaddr_the_parser_can_reach() {
    let image = nvram_env();
    assert_eq!(image.len(), NVRAM_ENV_LEN);
    // nvram_env_init parses from +4, past u-boot's CRC32 header.
    let body = &image[4..];
    assert_eq!(
        u32::from_le_bytes([image[0], image[1], image[2], image[3]]),
        crc32(body),
        "u-boot checksums everything after the header"
    );
    let names: Vec<&str> = body
        .split(|byte| *byte == 0)
        .take_while(|entry| !entry.is_empty())
        .map(|entry| std::str::from_utf8(entry).expect("ASCII"))
        .collect();
    assert_eq!(
        names,
        ["ethaddr=52:54:00:55:53:01", "eth1addr=52:54:00:55:53:02"]
    );
    // The MACs must match the board-data record the HAL reports, or the
    // interface and /proc/ubnthal disagree about the same port.
    let record = board_data();
    assert_eq!(record[0x00..0x06], [0x52, 0x54, 0x00, 0x55, 0x53, 0x01]);
    assert_eq!(record[0x06..0x0c], [0x52, 0x54, 0x00, 0x55, 0x53, 0x02]);
}

#[test]
fn the_environment_is_readable_through_the_modelled_flash() {
    let mut board = Bcm5616xBoard::new();
    let flash = board.flash.as_mut().expect("the board models a SPI-NOR");
    let mut buffer = vec![0u8; 32];
    flash
        .read(
            board_core::spi_nor::command::READ,
            usize::try_from(NVRAM_ENV_OFFSET).unwrap(),
            &mut buffer,
        )
        .expect("the environment lies inside the modelled part");
    assert!(buffer.starts_with(&nvram_env()[..32]));
}

#[test]
fn diagnostic_eeprom_load_preserves_identity_and_rejects_reload() {
    let mut board = Bcm5616xBoard::new();
    let mut image = factory::eeprom();
    image[0xbd40..0xbd48].copy_from_slice(b"US24LAB!");
    image[0xbdc0..0xc000].fill(0x5a);
    board.load_eeprom_image(&image).unwrap();
    let mut actual = vec![0; image.len()];
    board
        .flash
        .as_ref()
        .unwrap()
        .read(
            board_core::spi_nor::command::READ,
            usize::try_from(BOARD_DATA_OFFSET).unwrap(),
            &mut actual,
        )
        .unwrap();
    assert_eq!(actual, image);
    assert!(board.load_eeprom_image(&image).is_err());
}

#[test]
fn diagnostic_eeprom_rejects_wrong_size_or_changed_identity_without_writing() {
    let mut board = Bcm5616xBoard::new();
    assert!(board.load_eeprom_image(&[]).is_err());
    let mut image = factory::eeprom();
    image[0xa033] ^= 1;
    assert!(board.load_eeprom_image(&image).is_err());
    assert!(board.load_eeprom_image(&factory::eeprom()).is_ok());
}

#[test]
fn board_data_lands_where_the_vendor_hal_reads_it() {
    let record = board_data();
    assert_eq!(record.len(), BOARD_DATA_LEN);
    // scan_eeprom tests the big-endian halfword at +0x0e against 0x777.
    assert_eq!(
        u16::from_be_bytes([record[0x0e], record[0x0f]]),
        VENDOR_ID_UBIQUITI
    );
    assert_eq!(
        u16::from_be_bytes([record[0x0c], record[0x0d]]),
        BOARD_ID_US24PRO
    );
    assert_eq!(record[0x00..0x06], [0x52, 0x54, 0x00, 0x55, 0x53, 0x01]);
    assert_eq!(record[0x06..0x0c], [0x52, 0x54, 0x00, 0x55, 0x53, 0x02]);
    assert!(
        record[0x14..].iter().all(|b| *b == 0xff),
        "the rest of the sector stays erased"
    );
}

#[test]
fn genpll_reset_values_yield_the_vendor_console_clock() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(
        board.mmio_read(GENPLL_STATUS) & 1,
        1,
        "PLL must report lock"
    );
    let ctrl = board.mmio_read(GENPLL_CTRL);
    let pll = (25_000_000 / ((ctrl >> 10) & 0xf)) * (ctrl & 0x3ff);
    assert_eq!(pll, 2_000_000_000, "GENPLL runs at 2 GHz");
    let mdiv = (board.mmio_read(GENPLL_CHAN_DIV) >> 8) << 2;
    assert_eq!(
        pll / mdiv,
        100_000_000,
        "c_clk125 is the 100 MHz console clock"
    );
}

#[test]
fn mspi_transfer_completes_and_raises_then_clears_the_interrupt() {
    let mut ctx = MachineContext::new(0);
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(MSPI_STATUS) & MSPI_STATUS_SPIF, 0);

    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSPI_SPCR2,
        u64::from(MSPI_SPCR2_SPE),
        AccessWidth::U32,
    )
    .expect("starting a transfer must be accepted");
    assert!(matches!(
        ctx.events.last(),
        Some(board_core::Event::IrqLevel {
            line: QSPI_IRQ,
            level: true
        })
    ));
    assert_eq!(
        board.mmio_read(MSPI_STATUS) & MSPI_STATUS_SPIF,
        MSPI_STATUS_SPIF
    );
    assert_eq!(board.mmio_read(QSPI_INTR_MSPI_DONE), 1);
    assert_eq!(
        board.mmio_read(MSPI_RXRAM),
        0xff,
        "an unread slot holds an erased byte"
    );

    ctx.events.clear();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        QSPI_INTR_MSPI_DONE,
        1,
        AccessWidth::U32,
    )
    .expect("acknowledging must be accepted");
    assert!(matches!(
        ctx.events.last(),
        Some(board_core::Event::IrqLevel {
            line: QSPI_IRQ,
            level: false
        })
    ));
    assert_eq!(board.mmio_read(MSPI_STATUS) & MSPI_STATUS_SPIF, 0);
}

// Drives one queued transfer the way the driver does: bytes into TXRAM,
// a control byte per slot, queue bounds, then the start bit.
fn mspi_transfer(board: &mut Bcm5616xBoard, tx: &[u8], keep_selected: bool) -> Vec<u8> {
    for (slot, byte) in tx.iter().enumerate() {
        let slot = slot as u64;
        board.mmio_write(MSPI_TXRAM + slot * 8, u32::from(*byte));
        let last = usize::try_from(slot).unwrap_or(0) == tx.len() - 1;
        let control = if last && !keep_selected { 0x0e } else { 0x8e };
        board.mmio_write(MSPI_CDRAM + slot * 4, control);
    }
    board.mmio_write(MSPI_NEWQP, 0);
    board.mmio_write(
        MSPI_ENDQP,
        u32::try_from(tx.len() - 1).expect("MSPI test transfers fit the queue"),
    );
    board.mmio_write(MSPI_SPCR2, MSPI_SPCR2_SPE);
    (0..tx.len() as u64)
        .map(|slot| board.mmio_read(MSPI_RXRAM + slot * 8 + 4).to_le_bytes()[0])
        .collect()
}

#[test]
fn an_mspi_read_command_returns_the_seeded_board_data() {
    let mut board = Bcm5616xBoard::new();
    // iproc_qspi_flash_read enters 4-byte addressing, sends READ plus the
    // address, then clocks dummy bytes to collect the data.
    mspi_transfer(&mut board, &[0xb7], false);
    let address = BOARD_DATA_OFFSET;
    let address_bytes = address.to_be_bytes();
    mspi_transfer(
        &mut board,
        &[
            0x03,
            address_bytes[4],
            address_bytes[5],
            address_bytes[6],
            address_bytes[7],
        ],
        true,
    );
    let read = mspi_transfer(&mut board, &[0xff; 6], false);
    assert_eq!(
        read,
        vec![0x52, 0x54, 0x00, 0x55, 0x53, 0x01],
        "the record opens with eth0's MAC"
    );
}

/// Runs a link read the way `bcm_qspi_bspi_flash_read` does, then drains
/// it the way the interrupt handler does.
fn bspi_link_read(board: &mut Bcm5616xBoard, address: u64, bytes: usize) -> Vec<u8> {
    board.mmio_write(BSPI_FLASH_UPPER_ADDR, (address & 0xff00_0000) as u32);
    board.mmio_write(BSPI_RAF_START_ADDR, (address & 0x00ff_ffff) as u32);
    board.mmio_write(
        BSPI_RAF_NUM_WORDS,
        u32::try_from(bytes.div_ceil(4)).expect("test link reads fit the RAF word count"),
    );
    board.mmio_write(BSPI_RAF_CTRL, BSPI_RAF_CTRL_START);
    let mut out = Vec::new();
    while board.mmio_read(BSPI_RAF_STATUS) & BSPI_RAF_STATUS_FIFO_EMPTY == 0 {
        out.extend_from_slice(&board.mmio_read(BSPI_RAF_READ_DATA).to_le_bytes());
    }
    out.truncate(bytes);
    out
}

#[test]
fn a_link_read_reaches_past_the_first_16_mib() {
    let mut board = Bcm5616xBoard::new();
    // The EEPROM partition, which no 24-bit session address can name on
    // its own; the driver puts the top byte in the upper address
    // register and programs the rest.
    let read = bspi_link_read(&mut board, BOARD_DATA_OFFSET, 6);
    assert_eq!(
        read,
        vec![0x52, 0x54, 0x00, 0x55, 0x53, 0x01],
        "the record opens with eth0's MAC"
    );
}

#[test]
fn a_link_read_reports_and_then_clears_its_interrupt() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(QSPI_INTR_LR_SESSION_DONE), 0);
    let _ = bspi_link_read(&mut board, BOARD_DATA_OFFSET, 8);
    assert_eq!(
        board.mmio_read(QSPI_INTR_LR_SESSION_DONE),
        1,
        "the handler waits for fullness or session done"
    );
    assert_eq!(board.mmio_read(QSPI_INTR_LR_FULLNESS), 1);
    // The clear loop writes 1 to each source its mask names.
    board.mmio_write(QSPI_INTR_LR_SESSION_DONE, 1);
    board.mmio_write(QSPI_INTR_LR_FULLNESS, 1);
    assert_eq!(board.mmio_read(QSPI_INTR_LR_SESSION_DONE), 0);
    assert_eq!(board.mmio_read(QSPI_INTR_LR_FULLNESS), 0);
}

#[test]
fn the_seeded_configuration_starts_the_management_agent() {
    let text = cfg_text();
    assert!(
        text.contains("unifi.status=enabled"),
        "without it ubntconf writes no /etc/sysinit/unifi.conf and mcad never runs"
    );
    assert!(
        !text.contains("mgmt.is_default=true"),
        "init copies the defaults back over a record that still says this"
    );
    assert!(text.contains(&format!("resolv.host.1.name={CFG_HOSTNAME}")));
}

#[test]
fn both_record_slots_are_readable_from_the_cfg_partition() {
    let mut board = Bcm5616xBoard::new();
    for (slot, kind) in [
        (0, CFG_RECORD_KIND_FIRST),
        (CFG_RECORD_SLOT_STRIDE, CFG_RECORD_KIND_SECOND),
    ] {
        let head = bspi_link_read(&mut board, CFG_PARTITION_OFFSET + slot, 0x14);
        assert_eq!(&head[..4], &[0x12, 0x34, 0x56, 0x78], "record magic");
        assert_eq!(
            u32::from_le_bytes([head[0x10], head[0x11], head[0x12], head[0x13]]),
            kind
        );
        let text = cfg_text();
        assert_eq!(
            u32::from_be_bytes([head[0x0c], head[0x0d], head[0x0e], head[0x0f]]),
            u32::try_from(text.len()).unwrap(),
            "the text length the record declares"
        );
        assert_eq!(
            u32::from_be_bytes([head[0x08], head[0x09], head[0x0a], head[0x0b]]),
            crc32(text.as_bytes()),
            "a wrong CRC makes cfgmtd reject the record"
        );
    }
}

#[test]
fn the_cfg_slots_fit_the_partition() {
    // mtd5 is 1 MiB, and the second slot has to end inside it.
    const { assert!(CFG_RECORD_SLOT_STRIDE * 2 <= 0x10_0000) };
    assert!(
        cfg_record(CFG_RECORD_KIND_FIRST).len()
            < usize::try_from(CFG_RECORD_SLOT_STRIDE)
                .expect("configuration slot stride fits usize")
    );
}

#[test]
fn status_polls_report_the_part_idle() {
    let mut board = Bcm5616xBoard::new();
    // `0xb7` and `0xe9` bracket every read, and the driver polls status
    // afterwards, spinning until write-in-progress clears.
    mspi_transfer(&mut board, &[0xb7], false);
    let status = mspi_transfer(&mut board, &[0x05, 0xff], false);
    assert_eq!(
        status[1] & 1,
        0,
        "a busy part stalls the read until the block layer gives up"
    );
}

#[test]
fn a_read_above_the_part_capacity_wraps() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0xb7], false);
    // The address ubnthal actually sends: physical, in the 0x1c000000
    // window, which is past the end of a 64 MiB chip.
    let address = 0x1fff_0000u64;
    let address_bytes = address.to_be_bytes();
    assert!(usize::try_from(address).unwrap_or(0) > FLASH_SIZE);
    mspi_transfer(
        &mut board,
        &[
            0x03,
            address_bytes[4],
            address_bytes[5],
            address_bytes[6],
            address_bytes[7],
        ],
        true,
    );
    let read = mspi_transfer(&mut board, &[0xff; 6], false);
    assert_eq!(
        read,
        vec![0x52, 0x54, 0x00, 0x55, 0x53, 0x01],
        "the wrapped address lands on the board-data record"
    );
}

#[test]
fn an_mspi_read_id_command_identifies_the_part() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0x9f], true);
    let id = mspi_transfer(&mut board, &[0xff; 3], false);
    assert_eq!(id, FLASH_JEDEC_ID.to_vec());
}

#[test]
fn bde_sfdp_reads_skip_dummy_byte_and_preserve_chip_select() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0x5a, 0, 0, 4, 0], true);
    assert_eq!(mspi_transfer(&mut board, &[0xff; 3], false), [0, 1, 1]);
    mspi_transfer(&mut board, &[0x5a, 0, 0, 0x8c, 0], true);
    let mut uuid = mspi_transfer(&mut board, &[0xff; 6], true);
    uuid.extend(mspi_transfer(&mut board, &[0xff; 7], false));
    assert_eq!(uuid, factory::FLASH_UUID);
}

#[test]
fn sfdp_address_width_does_not_change_with_flash_address_mode() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0xb7], false);
    mspi_transfer(&mut board, &[0x5a, 0, 0, 4], true);
    assert_eq!(
        mspi_transfer(&mut board, &[0xff; 4], false),
        [0xff, 0, 1, 1]
    );
}

#[test]
fn sfdp_unimplemented_addresses_read_erased_and_new_command_resets_cursor() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0x5a, 0, 0, 0x98, 0], true);
    assert_eq!(mspi_transfer(&mut board, &[0xff; 2], false), [b'1', 0xff]);
    mspi_transfer(&mut board, &[0x9f], true);
    assert_eq!(mspi_transfer(&mut board, &[0xff; 3], false), FLASH_JEDEC_ID);
}

#[test]
fn secondary_factory_record_is_readable_through_mspi() {
    let mut board = Bcm5616xBoard::new();
    mspi_transfer(&mut board, &[0xb7], false);
    mspi_transfer(&mut board, &[0x03, 0x03, 0xff, 0xa0, 0x00], true);
    assert_eq!(mspi_transfer(&mut board, &[0xff; 2], false), [0x0e, 0]);
}

#[test]
fn bspi_reports_idle_so_mspi_mode_is_entered() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(BSPI_BUSY_STATUS) & 1, 0);
}

/// Drives one clause 22 read the way `cmicd_miim_op` at `0xc0014de0`
/// does: parameter, then address, then the read start bit.
fn miim_read(board: &mut Bcm5616xBoard, param: u32, register: u32) -> u32 {
    board.mmio_write(CMICD_MIIM_PARAM, param);
    board.mmio_write(CMICD_MIIM_ADDRESS, register);
    board.mmio_write(CMICD_MIIM_CTRL, 2);
    assert_eq!(
        board.mmio_read(CMICD_MIIM_STATUS) & 1,
        1,
        "op must complete"
    );
    let data = board.mmio_read(CMICD_MIIM_READ_DATA);
    board.mmio_write(CMICD_MIIM_CTRL, 0);
    data
}

/// Ring select plus PHY address, as `mdiobus_scan` was observed to
/// issue them: ring 2 is the bus id 1 device at `0xc14a62c8`.
fn miim_param(ring: u32, phy: u32) -> u32 {
    (ring << 22) | (phy << 16)
}

#[test]
fn cmicd_miim_completes_and_answers_for_the_et_phy() {
    let mut board = Bcm5616xBoard::new();
    // `chipattach` falls back to `unit + 1` for `et0`, and `phy5461_init`
    // identifies the part from registers 2 and 3.
    assert_eq!(miim_read(&mut board, miim_param(2, 1), 2), 0x0020);
    assert_eq!(miim_read(&mut board, miim_param(2, 1), 3), 0x60c1);
    // Link up and autonegotiation complete, so `phy5461_link_get` does
    // not spin, and so `iproc_mii_read` finds a bus id 1 device at all.
    assert_eq!(miim_read(&mut board, miim_param(2, 1), 1) & 0x24, 0x24);
}

#[test]
fn cmicd_miim_reports_no_phy_anywhere_else() {
    let mut board = Bcm5616xBoard::new();
    for phy in (0..32).filter(|phy| *phy != 1) {
        assert_eq!(
            miim_read(&mut board, miim_param(2, phy), 2),
            0xffff,
            "address {phy} must read as an empty bus"
        );
    }
    // The other ring the scan walks carries nothing at all.
    for phy in 0..32 {
        assert_eq!(miim_read(&mut board, miim_param(1, phy), 2), 0xffff);
    }
}

#[test]
fn cmicd_miim_writes_reach_the_phy() {
    let mut board = Bcm5616xBoard::new();
    // `phy5461_ge_init` at `0xc00248ac` writes 0x1340; the restart bit is
    // self-clearing, the rest sticks.
    board.mmio_write(CMICD_MIIM_PARAM, miim_param(2, 1) | 0x1340);
    board.mmio_write(CMICD_MIIM_ADDRESS, 0);
    board.mmio_write(CMICD_MIIM_CTRL, 1);
    board.mmio_write(CMICD_MIIM_CTRL, 0);
    assert_eq!(miim_read(&mut board, miim_param(2, 1), 0), 0x1140);
}

#[test]
fn chip_identification_matches_the_kernel_dispatch() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(CHIPCOMMON_CHIPID) & 0xffff, 0xb160);
    // The HAL accepts BCM56166 within the BCM5616x family.
    assert_eq!(
        board.mmio_read(CMIC_DEVICE_ID) & 0xfff0,
        board.mmio_read(CHIPCOMMON_CHIPID) & 0xfff0
    );
}

#[test]
fn us24pro_switch_identity_matches_the_sdk_board_table() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(CMIC_DEVICE_ID), 0xb166);
}

#[test]
fn cmic_i2cm_master_command_completes_for_a_board_peripheral() {
    const ENABLE: u32 = 1 << 30;
    const START_BUSY: u32 = 1 << 31;
    const I2C_BLOCK_WRITE: u32 = 7 << 9;

    let mut board = Bcm5616xBoard::new();
    board.mmio_write(CMIC_BLOCK_BASE, ENABLE);
    board.mmio_write(CMIC_BLOCK_BASE + 0x40, 0x42);
    board.mmio_write(CMIC_BLOCK_BASE + 0x30, START_BUSY | I2C_BLOCK_WRITE);

    assert_eq!(
        board.mmio_read(CMIC_BLOCK_BASE + 0x30),
        I2C_BLOCK_WRITE,
        "CMIC must own and clear MASTER_START_BUSY_COMMAND"
    );
}

#[test]
fn cmic_i2cm_completion_status_is_write_one_to_clear() {
    const ENABLE: u32 = 1 << 30;
    const START_BUSY: u32 = 1 << 31;
    const DONE: u32 = 1 << 28;

    let mut board = Bcm5616xBoard::new();
    board.mmio_write(CMIC_BLOCK_BASE, ENABLE);
    board.mmio_write(CMIC_BLOCK_BASE + 0x30, START_BUSY);
    assert_eq!(board.mmio_read(CMIC_BLOCK_BASE + 0x3c), DONE);

    board.mmio_write(CMIC_BLOCK_BASE + 0x3c, DONE);
    assert_eq!(board.mmio_read(CMIC_BLOCK_BASE + 0x3c), 0);
}

#[test]
fn cmic_mspi_alias_completes_the_sdk_transfer() {
    let mut board = Bcm5616xBoard::new();
    board.mmio_write(CMIC_MSPI_BASE + 0x14, 0);
    board.mmio_write(CMIC_MSPI_BASE + 0x18, 0);
    board.mmio_write(CMIC_MSPI_BASE + 0x40, 0x9f);
    board.mmio_write(CMIC_MSPI_BASE + 0x140, 0);
    board.mmio_write(CMIC_MSPI_BASE + 0x20, MSPI_SPCR2_SPE);

    assert_eq!(board.mmio_read(CMIC_MSPI_BASE + 0x24), MSPI_STATUS_SPIF);
}

#[test]
fn factory_cpu_mirror_matches_the_bde_hardware_read() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(
        &factory::eeprom()[0xa0b3..0xa0b7],
        &board.mmio_read(CMIC_DEVICE_ID).to_be_bytes()
    );
}

/// Walks the EROM the way `_init` in `linux-kernel-bde.ko` does, so the
/// table is checked against the decoder that has to accept it rather
/// than against itself.
fn bde_erom_walk(board: &mut Bcm5616xBoard) -> Option<(u32, u32)> {
    let mut cursor = u64::from(board.mmio_read(CHIPCOMMON_EROM_PTR));
    let mut in_cmicd = false;
    let mut first_core_word = true;
    let mut start = 0_u32;
    // The BDE maps one page and reads no further.
    for _ in 0..(EROM_SIZE / 4) {
        let word = board.mmio_read(cursor);
        cursor += 4;
        match word & 7 {
            5 => {
                let size_type = (word >> 4) & 3;
                assert_eq!(word & 8, 0, "a 64-bit address is rejected outright");
                assert_eq!(size_type, 3, "any other size type caps the block at 16 KiB");
                if in_cmicd {
                    start = word & 0xffff_f000;
                }
                let size = board.mmio_read(cursor);
                cursor += 4;
                assert_eq!(size & 8, 0, "no second size word");
                if in_cmicd {
                    return Some((start, start.wrapping_sub(1) + (size & 0xffff_f000)));
                }
            }
            1 => {
                if first_core_word && (word >> 8) & 0xfff == EROM_CORE_CMICD {
                    in_cmicd = true;
                }
                first_core_word = !first_core_word;
            }
            _ if word & 0xf == 0xf => return None,
            _ => {}
        }
    }
    panic!("the walk ran off the end of the mapped page");
}

#[test]
fn the_erom_points_the_bde_at_the_modelled_cmic_block() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(
        board.mmio_read(CHIPCOMMON_EROM_PTR),
        EROM_BASE_U32,
        "a zero pointer sends the BDE to ioremap(0)"
    );
    assert_eq!(
        bde_erom_walk(&mut board),
        Some((
            CMIC_BLOCK_BASE_U32,
            CMIC_BLOCK_BASE_U32 + CMIC_BLOCK_SIZE_U32 - 1
        ))
    );
}

#[test]
fn the_erom_slot_answers_past_the_end_of_the_table() {
    let mut board = Bcm5616xBoard::new();
    // The BDE maps the whole page; every address in it must decode.
    assert_eq!(board.mmio_read(EROM_BASE + EROM_SIZE - 4), 0);
    assert_eq!(
        BCM5616X_WINDOWS
            .iter()
            .find(|w| w.device == DEVICE_EROM)
            .map(|w| w.size),
        Some(EROM_SIZE)
    );
}

#[test]
fn console_writes_are_owned_by_the_board_model() {
    let mut board = Bcm5616xBoard::new();
    for byte in b"ok" {
        board.mmio_write(UART0_BASE + UART_THR, u32::from(*byte));
    }
    assert_eq!(board.take_uart_tx(), b"ok".to_vec());
}

#[test]
fn line_status_reports_an_empty_transmitter() {
    let mut board = Bcm5616xBoard::new();
    let lsr = board.mmio_read(UART0_BASE + UART_LSR);
    assert_eq!(lsr & UART_LSR_THRE, UART_LSR_THRE);
    assert_eq!(lsr & UART_LSR_DR, 0, "no input is queued after reset");
}

#[test]
fn queued_input_raises_data_ready_and_is_read_once() {
    let mut ctx = MachineContext::new(0);
    let mut board = Bcm5616xBoard::new();
    board.uart_rx(&mut ctx, 0, b'z');
    assert_eq!(board.mmio_read(UART0_BASE + UART_LSR) & UART_LSR_DR, 1);
    assert_eq!(board.mmio_read(UART0_BASE + UART_RBR), u32::from(b'z'));
    assert_eq!(board.mmio_read(UART0_BASE + UART_LSR) & UART_LSR_DR, 0);
}

#[test]
fn non_console_blocks_reject_narrow_access() {
    let mut ctx = MachineContext::new(0);
    let mut board = Bcm5616xBoard::new();
    assert_eq!(
        Machine::mmio_read(&mut board, &mut ctx, CRU_BASE, AccessWidth::U8),
        Err(MmioError::InvalidWidth)
    );
    assert_eq!(
        Machine::mmio_read(&mut board, &mut ctx, CRU_BASE + 2, AccessWidth::U32),
        Err(MmioError::Misaligned)
    );
}

#[test]
fn reset_clears_console_and_register_state() {
    let mut ctx = MachineContext::new(0);
    let mut board = Bcm5616xBoard::new();
    board.mmio_write(CRU_BASE + 4, 0xa5a5_a5a5);
    board.mmio_write(UART0_BASE + UART_THR, u32::from(b'x'));
    board.reset(&mut ctx);
    assert_eq!(board.mmio_read(CRU_BASE + 4), 0);
    assert_eq!(board.take_uart_tx(), Vec::<u8>::new());
}

#[test]
fn cmic_id_is_in_the_second_64k_page() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(0x0321_0224), 0xb166);
    assert_eq!(board.mmio_read(0x0320_0224), 0);
}

#[test]
fn usb_host_strap_is_present_and_read_only() {
    let mut board = Bcm5616xBoard::new();
    board.mmio_write(USB_HOST_STRAP, 0);
    assert_eq!(board.mmio_read(0x1800_fca4) & (1 << 17), 1 << 17);
}

#[test]
fn usb_phy_lock_tracks_reset_and_enable() {
    let mut board = Bcm5616xBoard::new();
    assert_eq!(board.mmio_read(USB_PHY_PLL_STATUS), 0);
    board.mmio_write(USB_PHY_PLL_CTRL, 7 << 24);
    assert_eq!(board.mmio_read(USB_PHY_PLL_STATUS), 0);
    board.mmio_write(USB_PHY_PLL_CTRL, 3 << 24);
    assert_eq!(board.mmio_read(USB_PHY_PLL_STATUS), 2);
    board.mmio_write(USB_PHY_PLL_CTRL, 0);
    assert_eq!(board.mmio_read(USB_PHY_PLL_STATUS), 0);
}

#[test]
fn new_interrupts_reach_the_machine_event_boundary() {
    let mut board = Bcm5616xBoard::new();
    let mut ctx = MachineContext::new(0);
    for (addr, value) in [
        (0x1800_a00c, 1 << 14),
        (0x1800_a018, 1 << 14),
        (0x1800_8000, 1 << 30),
        (0x1800_8038, 1 << 28),
        (0x1800_8030, 1 << 31),
        (0x0323_3428, 1 << 7),
        (0x0323_308c, 2),
    ] {
        Machine::mmio_write(&mut board, &mut ctx, addr, value, AccessWidth::U32).unwrap();
    }
    board.set_gpio_inputs(&mut ctx, 0xfff0 & !(1 << 14));
    for line in [96, 97, 184] {
        assert!(
            ctx.events
                .contains(&board_core::Event::IrqLevel { line, level: true })
        );
    }
    ctx.events.clear();
    board.reset(&mut ctx);
    for line in [96, 97, 184] {
        assert!(
            ctx.events
                .contains(&board_core::Event::IrqLevel { line, level: false })
        );
    }
}
