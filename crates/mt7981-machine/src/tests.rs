use super::*;

#[test]
fn eeprom_partition_import_preserves_existing_uboot_environment() {
    let mut board = Mt7981Board::new();
    let mut before = vec![0; UBOOT_ENV_SIZE];
    board
        .spi_nor
        .read(0x03, UBOOT_ENV_OFFSET, &mut before)
        .unwrap();
    assert_eq!(before, generate_uboot_env());
    // Preserve current bytes, including changes after the initial seed.
    board
        .spi_nor
        .load_region(UBOOT_ENV_OFFSET + 16, b"changed")
        .unwrap();
    board
        .spi_nor
        .read(0x03, UBOOT_ENV_OFFSET, &mut before)
        .unwrap();
    board
        .load_eeprom_image(&vec![0x5a; EEPROM_IMAGE_SIZE])
        .unwrap();
    let mut after = vec![0; UBOOT_ENV_SIZE];
    board
        .spi_nor
        .read(0x03, UBOOT_ENV_OFFSET, &mut after)
        .unwrap();
    assert_eq!(after, before);
    let mut first = [0; 4];
    board.spi_nor.read(0x03, 0, &mut first).unwrap();
    assert_eq!(first, [0x5a; 4]);
}

#[test]
fn generated_eeprom_uses_v2_header_offsets() {
    let image = generate_eeprom();

    // Head record, as parsed by `scripts/board-data.py`.
    assert_eq!(&image[0x00..0x06], &SYNTHETIC_ETH0_MAC);
    assert_eq!(&image[0x06..0x0c], &SYNTHETIC_ETH1_MAC);
    assert_eq!(&image[0x0c..0x0e], &SYNTHETIC_SYSTEM_ID.to_be_bytes());
    assert_eq!(&image[0x0e..0x10], &UBIQUITI_VENDOR_ID.to_be_bytes());
    assert_eq!(&image[0x10..0x14], &SYNTHETIC_BOM_REVISION.to_be_bytes());

    // SBD record.
    assert_eq!(&image[0x8000..0x8004], b"UBNT");
    assert_eq!(&image[0x800c..0x8010], &[0, 2, 0, 2]);
    assert_eq!(
        u16::from_be_bytes(image[0x800c..0x800e].try_into().unwrap()),
        2
    );
    assert_eq!(
        u16::from_be_bytes(image[0x800e..0x8010].try_into().unwrap()),
        2
    );
    assert_eq!(&image[0x8010..0x8012], &[7, 0x77]);
    assert_eq!(&image[0x8012..0x8014], &[0xa6, 0x42]);
    assert_eq!(
        &image[0x8014..0x8018],
        &SYNTHETIC_BOM_REVISION.to_be_bytes()
    );
    assert_eq!(&image[0x8018..0x801e], &SYNTHETIC_ETH0_MAC);
    assert_eq!(&image[0x801e..0x8022], &[1, 2, 0, 0]);
    assert_eq!(image[0x8070], 0x01);
}

/// The length at `0x8008` drives the CRC range, and the marker at
/// `0x8070` falls inside it.  Live U6-Lite and UAP6MP records both store
/// `0x65` and reproduce their stored CRC over exactly those bytes.
#[test]
fn generated_eeprom_crc_covers_the_declared_record_length() {
    let image = generate_eeprom();

    let length = u32::from_be_bytes(image[0x8008..0x800c].try_into().unwrap());
    assert_eq!(length, 0x65);
    let end = 0x800c + length as usize;
    assert!((0x8070..end).contains(&0x8070));
    assert_eq!(
        u32::from_le_bytes(image[0x8004..0x8008].try_into().unwrap()),
        legacy_crc32(&image[0x800c..end])
    );
}

/// Unwritten NOR reads back erased, not zeroed.
#[test]
fn generated_eeprom_leaves_unwritten_flash_erased() {
    let image = generate_eeprom();

    assert!(image[0x14..0x8000].iter().all(|byte| *byte == 0xff));
    assert!(image[0x8022..0x8070].iter().all(|byte| *byte == 0xff));
    assert!(
        image[0x8071..SECOND_RECORD_OFFSET]
            .iter()
            .all(|byte| *byte == 0xff)
    );
    let second_end = SECOND_RECORD_OFFSET + SECOND_RECORD_LENGTH;
    assert!(
        image[second_end..TLV_INFO_OFFSET]
            .iter()
            .all(|byte| *byte == 0xff)
    );
    // The per-unit and high-entropy spans inside the record stay erased.
    assert!(
        image[SECOND_RECORD_OFFSET + 0x44..SECOND_RECORD_OFFSET + 0xb7]
            .iter()
            .all(|byte| *byte == 0xff)
    );
    let tlv_end = TLV_INFO_OFFSET + generate_tlv_info().len();
    assert!(
        image[tlv_end..DEVICE_KEY_OFFSET]
            .iter()
            .all(|byte| *byte == 0xff)
    );
    let key_end = DEVICE_KEY_OFFSET + 7 + SYNTHETIC_DEVICE_KEY.len();
    assert!(image[key_end..].iter().all(|byte| *byte == 0xff));
}

/// The container's shape is taken from two hardware dumps: `91NT`, a
/// version byte, a big-endian `u16` length, then `ssh-rsa`, `e`, `n`,
/// `d`, `p`, `q`.  The synthetic key matches their field lengths.
#[test]
fn generated_device_key_uses_the_hardware_container() {
    let image = generate_eeprom();

    assert_eq!(
        &image[DEVICE_KEY_OFFSET..DEVICE_KEY_OFFSET + 4],
        DEVICE_KEY_MAGIC
    );
    assert_eq!(image[DEVICE_KEY_OFFSET + 4], DEVICE_KEY_VERSION);
    let length = usize::from(u16::from_be_bytes(
        image[DEVICE_KEY_OFFSET + 5..DEVICE_KEY_OFFSET + 7]
            .try_into()
            .unwrap(),
    ));
    assert_eq!(length, SYNTHETIC_DEVICE_KEY.len());
    assert_eq!(length, 805, "hardware carries 805 bytes for a 2048-bit key");

    let payload = &image[DEVICE_KEY_OFFSET + 7..DEVICE_KEY_OFFSET + 7 + length];
    let mut lengths = Vec::new();
    let mut offset = 0;
    while offset + 4 <= payload.len() {
        let field = usize::try_from(u32::from_be_bytes(
            payload[offset..offset + 4].try_into().unwrap(),
        ))
        .unwrap();
        lengths.push(field);
        offset += 4 + field;
    }
    assert_eq!(offset, payload.len(), "fields exactly fill the payload");
    assert_eq!(&payload[4..11], b"ssh-rsa");
    assert_eq!(lengths, vec![7, 3, 257, 256, 129, 129]);
}

/// Field placement is taken from two hardware dumps, which agree on every
/// offset asserted here.  `mfgweek` is rendered from the timestamp, so it
/// must denote the same date the `TlvInfo` block spells.
#[test]
fn generated_second_record_matches_the_hardware_layout() {
    let image = generate_eeprom();
    let record = &image[SECOND_RECORD_OFFSET..];

    assert_eq!(&record[0x00..0x02], &[0x12, 0x03]);
    assert_eq!(&record[0x02..0x04], &SYNTHETIC_MANUF_ID.to_be_bytes());
    assert_eq!(&record[0x18..0x1c], &SYNTHETIC_MFG_TIMESTAMP.to_be_bytes());
    assert_eq!(&record[0x1c..0x1e], &[0x00, 0x14]);
    assert_eq!(&record[0x1e..0x20], &SYNTHETIC_SYSTEM_ID.to_be_bytes());
    assert_eq!(&record[0x20..0x22], &UBIQUITI_VENDOR_ID.to_be_bytes());
    assert_eq!(&record[0x22..0x28], &SYNTHETIC_ETH0_MAC);
    assert_eq!(&record[0x28..0x2e], &SYNTHETIC_ETH1_MAC);
    assert_eq!(&record[0xb7..0xbb], &SYNTHETIC_BOM_REVISION.to_be_bytes());
    assert_eq!(&record[0xbb..0xc1], SYNTHETIC_QR_ID);
    assert_eq!(record[0xc1], 0, "qrid is NUL-terminated");

    // The record and the TlvInfo block must agree on the build date, as
    // hardware does; 2024-01-01 is 1704067200.
    assert_eq!(SYNTHETIC_MFG_DATE, b"20240101");
    assert_eq!(SYNTHETIC_MFG_TIMESTAMP, 1_704_067_200);
}

/// The `0xfe` TLV carries `legacy_crc32` over the block up to but
/// excluding its own type and length bytes, stored big-endian.  Both the
/// U6-Lite and UAP6MP blocks reproduce under exactly that rule.
#[test]
fn generated_tlv_info_matches_the_hardware_block_shape() {
    let image = generate_eeprom();
    let block = &image[TLV_INFO_OFFSET..];

    assert_eq!(&block[..8], b"TlvInfo\0");
    assert_eq!(block[8], 1);
    let total = usize::from(u16::from_be_bytes(block[9..11].try_into().unwrap()));
    assert_eq!(total, 43, "both hardware blocks declare 43 bytes");

    let mut tags = Vec::new();
    let mut offset = 11;
    while offset < 11 + total {
        let tag = block[offset];
        let length = usize::from(block[offset + 1]);
        tags.push((tag, length));
        offset += 2 + length;
    }
    assert_eq!(offset, 11 + total, "TLVs exactly fill the declared length");
    assert_eq!(
        tags,
        vec![(0x01, 8), (0x02, 8), (0x03, 1), (0x04, 12), (0xfe, 4)]
    );

    let crc_tlv = 11 + total - 6;
    assert_eq!(
        u32::from_be_bytes(block[crc_tlv + 2..crc_tlv + 6].try_into().unwrap()),
        legacy_crc32(&block[..crc_tlv])
    );
}

/// A live U6-Lite's environment is the model: NUL-separated `key=value`
/// entries behind a CRC-32, with `device_model` among them.  Without that
/// variable `ubntbox` writes a `ubnt::errors` token into `/etc/version`.
#[test]
fn generated_uboot_env_carries_the_device_model() {
    let image = generate_uboot_env();

    assert_eq!(image.len(), UBOOT_ENV_SIZE);
    assert_eq!(
        u32::from_le_bytes(image[0..4].try_into().unwrap()),
        crc32(&image[4..]),
        "fw_printenv checks the leading CRC"
    );

    let variables: Vec<&str> = image[4..]
        .split(|byte| *byte == 0)
        .take_while(|entry| !entry.is_empty())
        .map(|entry| std::str::from_utf8(entry).expect("entries are UTF-8"))
        .collect();
    assert!(variables.contains(&"device_model=U6-PLUS"));
    assert!(variables.contains(&"bootcmd=bootubnt"));
    assert!(
        variables.contains(&"ethaddr=02:00:00:79:81:01"),
        "the MAC matches the EEPROM head record"
    );
    for variable in &variables {
        assert!(variable.contains('='), "{variable} is a key=value entry");
    }
}

/// Header fields and payload shape are taken from a live U6-Lite's `cfg`
/// partition: a big-endian compressed length, a standard CRC-32 over the
/// configuration text alone, that text's length, and a little-endian kind.
#[test]
fn generated_cfg_record_matches_the_hardware_layout() {
    use std::io::Read;

    let record = generate_cfg_record(CFG_RECORD_KIND_SECOND);

    assert_eq!(&record[0x00..0x04], &CFG_RECORD_MAGIC);
    let compressed = u32::from_be_bytes(record[0x04..0x08].try_into().unwrap()) as usize;
    assert_eq!(compressed, record.len() - CFG_RECORD_HEADER_LEN);
    let text_length = u32::from_be_bytes(record[0x0c..0x10].try_into().unwrap()) as usize;
    assert_eq!(
        u32::from_le_bytes(record[0x10..0x14].try_into().unwrap()),
        CFG_RECORD_KIND_SECOND
    );
    assert_eq!(&record[0x14..0x18], &[0, 0, 0, 0]);

    let mut payload = Vec::new();
    flate2::read::ZlibDecoder::new(&record[CFG_RECORD_HEADER_LEN..])
        .read_to_end(&mut payload)
        .expect("the payload is a zlib stream");

    let text = std::str::from_utf8(&payload[..text_length]).expect("the text is UTF-8");
    assert_eq!(text, synthetic_system_cfg());
    // The restored configuration has to survive preinit, which replaces
    // any configuration still flagged as the default.
    assert!(text.contains("mgmt.is_default=false"));
    assert!(!text.contains("mgmt.is_default=true"));
    // Both placeholders the firmware substitutes are resolved.
    assert!(!text.contains("DEFAULTSSID") && !text.contains("DEFAULTPASSWORD"));
    assert!(text.contains(&format!("aaa.1.ssid={}", synthetic_serial_number())));
    assert!(text.contains("aaa.1.wpa.psk=798101QEMU01"));
    // The vendor sections the guest needs are carried through.
    for key in [
        "users.status=enabled",
        "aaa.status=enabled",
        "radio.status=enabled",
    ] {
        assert!(text.contains(key), "the default configuration keeps {key}");
    }
    assert_eq!(
        u32::from_be_bytes(record[0x08..0x0c].try_into().unwrap()),
        crc32(text.as_bytes()),
        "the CRC covers the text alone, as both hardware records show"
    );
    assert!(text.contains(&format!("resolv.host.1.name={SYNTHETIC_HOSTNAME}")));

    // The text is followed by the gzipped `persistent` archive.
    assert_eq!(&payload[text_length..text_length + 2], &[0x1f, 0x8b]);
}

/// Both slots of the `cfg` partition carry a record, as hardware does, and
/// they land inside that partition rather than over a neighbor.
#[test]
fn emmc_regions_seed_both_cfg_slots() {
    let (start, blocks) = emmc_partition("cfg").expect("the layout has a cfg partition");
    let regions = generate_emmc_regions();

    let stride = CFG_RECORD_SLOT_STRIDE / GPT_BLOCK_SIZE as u64;
    let stride_bytes =
        usize::try_from(stride).expect("cfg record stride fits usize") * GPT_BLOCK_SIZE;
    for (slot, kind) in [
        (start, CFG_RECORD_KIND_FIRST),
        (start + stride, CFG_RECORD_KIND_SECOND),
    ] {
        let (_, bytes) = regions
            .iter()
            .find(|(block, _)| *block == slot)
            .expect("both slots are seeded");
        assert_eq!(&bytes[0x00..0x04], &CFG_RECORD_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap()),
            kind
        );
        assert!(
            bytes.len() <= stride_bytes && stride * 2 <= blocks,
            "a record fits its slot"
        );
    }
}

#[test]
fn uart_reports_empty_transmitter() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mmio_read(UART0_BASE + UART_LSR), 0x60);
}

#[test]
fn uart_round_trips_guest_output_and_input() {
    let mut board = Mt7981Board::new();
    board.uart0.push_rx(b"ok");
    assert_eq!(board.mmio_read(UART0_BASE + UART_LSR) & 1, 1);
    assert_eq!(board.mmio_read(UART0_BASE), u32::from(b'o'));
    board.mmio_write(UART0_BASE, u32::from(b'!'));
    assert_eq!(board.uart0.take_tx(), vec![b'!']);
}

#[test]
fn enabled_watchdog_restart_requests_reset() {
    let mut board = Mt7981Board::new();
    board.mmio_write(WATCHDOG_BASE + WATCHDOG_MODE, 1);
    board.mmio_write(WATCHDOG_BASE + WATCHDOG_RESTART, 0x1971);
    assert_eq!(board.reset_state(), ResetState::Requested);
}

#[test]
fn unmapped_mmio_is_read_as_zero() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mmio_read(0xffff_0000), 0);
    assert_eq!(
        board.take_unknown_mmio(),
        Some(MmioAccess {
            address: 0xffff_0000,
            width: 4,
            direction: MmioDirection::Read,
            value: 0,
        })
    );
}

#[test]
fn clock_and_reset_control_registers_round_trip() {
    let mut board = Mt7981Board::new();
    let clock = TOPCKGEN_BASE + 0x20;
    let reset = ETHSYS_BASE + 0x34;

    board.mmio_write(clock, 0x40);
    board.mmio_write(reset, 0x1);

    assert_eq!(board.mmio_read(clock), 0x40);
    assert_eq!(board.mmio_read(reset), 0x1);
}

#[test]
fn chip_id_reports_mt7981() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mmio_read(CHIP_ID), 0x7981);
}

#[test]
fn wbsys_pci_interrupt_line_reports_dt_spi() {
    let mut board = Mt7981Board::new();
    assert_eq!(
        board.mmio_read(WBSYS_PCI_INTERRUPT_LINE),
        WBSYS_PCI_INTERRUPT_LINE_VALUE
    );
}

#[test]
fn conninfra_reports_mt7981_ip_version() {
    let mut board = Mt7981Board::new();
    assert_eq!(
        board.mmio_read(CONNINFRA_RGU_BASE + CONNINFRA_IP_VERSION),
        WBSYS_PCI_ID
    );
    assert_eq!(board.mmio_read(CONNINFRA_CFG_BASE), 0x0209_0000);
    assert_eq!(board.mmio_read(CONNINFRA_SEMAPHORE_BASE), 1);
    assert_eq!(board.mmio_read(0x1000_5000), 1);
    assert_eq!(board.mmio_read(CONNINFRA_SEMAPHORE_BASE + 0x2c), 1);
    assert_eq!(board.mmio_read(CONNINFRA_RGU_BASE + 0x5000 + 0x70), 1);
}

#[test]
fn conninfra_internal_spi_reports_wfsys_ready() {
    let mut board = Mt7981Board::new();

    board.mmio_write(CONNINFRA_SPI_ADDR, 0xb02c);
    assert_eq!(board.mmio_read(CONNINFRA_SPI_STATUS), 0x4000_0000);
    board.mmio_write(CONNINFRA_SPI_ADDR, 0xb148);
    assert_eq!(board.mmio_read(CONNINFRA_SPI_STATUS), 0x2000_0000);

    assert_eq!(
        board.mmio_read(WFSYS_RGU_STATUS + WFSYS_BAND_STRIDE),
        0x4000_0000
    );
    assert_eq!(
        board.mmio_read(WFSYS_VERSION + WFSYS_BAND_STRIDE),
        0x0206_0000
    );
    assert_eq!(board.mmio_read(WFSYS_SLPPROT_STATUS), 0);
    assert_eq!(board.mmio_read(WFSYS_MCU_SLPPROT_STATUS), 0);
    assert_eq!(board.mmio_read(WFSYS_CFG_VERSION), 0x0206_0000);
    assert_eq!(board.mmio_read(WFSYS_CFG_ON_ROM_INDEX), 0x1d1e);
    assert_eq!(board.mmio_read(CONN_HOST_CSR_WFSYS_STATUS), 0x4000_0000);
}

#[test]
fn wfsys_register_banks_round_trip_guest_configuration() {
    let mut board = Mt7981Board::new();
    let register = 0x1800_3000;

    board.mmio_write(register, 0x203e_0000);

    assert_eq!(board.mmio_read(register), 0x203e_0000);
    assert!(board.take_unknown_mmio().is_none());
}

#[test]
fn wfdma_interrupt_source_is_write_one_to_clear() {
    let mut board = Mt7981Board::new();

    assert_eq!(board.mmio_read(WFDMA0_INT_MASK), u32::MAX);
    board.raise_wifi_interrupt();
    assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), WFDMA0_RX_DONE_WM);
    board.mmio_write(WFDMA0_INT_SOURCE, WFDMA0_RX_DONE_WM);
    assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), 0);
}

#[test]
fn board_reset_clears_wifi_startup_configuration() {
    let mut board = Mt7981Board::new();
    board.wifi_startup.command(0x46, &[1, 0, 0, 0]);
    board.wifi_startup.command(0x36, &[0; 20]);
    let mut airtime = [0; 68];
    airtime[0] = 1;
    airtime[2] = 1;
    airtime[24] = 1;
    assert!(board.wifi_startup.command(0x4a, &airtime).is_some());
    let mut features = [0; 40];
    features[0] = 1;
    features[20] = 1;
    assert!(board.wifi_startup.command(0x38, &features).is_some());
    let mut channel = [0; 76];
    channel[..7].copy_from_slice(&[6, 8, 1, 2, 2, 0, 0]);
    assert_eq!(
        board.wifi_startup.command(0x08, &channel),
        Some((0, vec![8, 0, 0, 0, 0, 0, 0, 0]))
    );
    for (cid, payload) in [
        (0x4e, channel.as_slice()),
        (0x3e, &[1, 1, 0, 0, 0xff, 0xff, 0, 0, 32, 0, 0, 0]),
        (0x3e, &[2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0x1f]),
        (0x0f, &[32, 0, 0xff, 0xff, 1, 0, 0, 0]),
    ] {
        assert_eq!(
            board.wifi_startup.command(cid, payload),
            Some((0, vec![cid, 0, 0, 0, 0, 0, 0, 0]))
        );
    }
    let mut power = [0; 32];
    power[..2].copy_from_slice(&[5, 2]);
    assert_eq!(board.wifi_startup.command(0x07, &power).unwrap().1[4], 0);
    assert_eq!(
        board
            .wifi_startup
            .command(0x27, &[1, 0, 1, 1, 1, 15, 3, 4, 6, 0, 94, 0])
            .unwrap()
            .1[4],
        0
    );
    for (cid, payload) in [
        (
            0x2a,
            &[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 12, 0, 1, 0, 2, 0, 0, 0, 0, 1][..],
        ),
        (0x26, &[0, 0, 1, 0, 1, 0, 0, 0, 12, 0, 8, 0, 0, 26, 0, 0]),
        (
            0x25,
            &[
                0, 31, 1, 0, 1, 14, 2, 0, 0, 0, 20, 0, 0, 0, 0, 0, 2, 0, 0, 0, 255, 255, 255, 255,
                255, 255, 3, 0,
            ],
        ),
    ] {
        let (event, reply) = board.wifi_startup.command(cid, payload).unwrap();
        assert_eq!(event, 0);
        assert_eq!(reply.len(), 16);
        assert_eq!(reply[4], 0);
    }
    assert_ne!(board.wifi_startup, wifi_mcu::StartupConfig::default());
    board.reset(&mut MachineContext::new(0));
    assert_eq!(board.wifi_startup, wifi_mcu::StartupConfig::default());
}

#[test]
fn wifi_rx_configuration_is_stored_and_cleared_on_board_reset() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    board.wfdma_tx_base[4] = 0x1000;
    board.wfdma_tx_count[4] = 2;
    let translation = [0, 1, 1, 0, 0, 0, 0, 0];
    let blacklist = [1, 1, 0, 0, 3, 0, 0x88, 0x8e];
    for (index, config) in [translation, blacklist].into_iter().enumerate() {
        let descriptor = 0x1000 + 16 * index;
        bus.bytes[descriptor..descriptor + 4].copy_from_slice(&0x2000_u32.to_le_bytes());
        bus.bytes[descriptor + 4..descriptor + 8]
            .copy_from_slice(&((0x48_u32 << 16) | (1 << 30)).to_le_bytes());
        bus.bytes[0x2024..0x2028].copy_from_slice(&0x0100_00ed_u32.to_le_bytes());
        bus.bytes[0x2028..0x202c].copy_from_slice(&0x4700_u32.to_le_bytes());
        bus.bytes[0x2040..0x2048].copy_from_slice(&config);
        let mut ctx = MachineContext::with_dma(0, &mut bus);
        board.wfdma_kick(&mut ctx, 4, u32::try_from((index + 1) % 2).unwrap());
    }
    assert_eq!(board.wifi_rx_translation, translation);
    assert_eq!(board.wifi_rx_blacklist.get(&3), Some(&[3, 0, 0x88, 0x8e]));
    board.reset(&mut MachineContext::new(0));
    assert_eq!(board.wifi_rx_translation, [0; 8]);
    assert!(board.wifi_rx_blacklist.is_empty());
}

#[test]
fn restart_download_request_returns_the_mcu_to_the_patch_ready_stage() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    board.wfdma_tx_base[4] = 0x1000;
    board.wfdma_tx_count[4] = 2;
    board.wfsys_fw_sync = 7;
    board.firmware_download = vec![0xaa; 8];
    board.firmware_download_length = 8;
    board.firmware_patch_complete = true;
    board.firmware_patch_semaphore = true;
    bus.bytes[0x1000..0x1004].copy_from_slice(&0x2000_u32.to_le_bytes());
    bus.bytes[0x1004..0x1008].copy_from_slice(&((0x44_u32 << 16) | (1 << 30)).to_le_bytes());
    bus.bytes[0x2024..0x2028].copy_from_slice(&0x0000_0004_u32.to_le_bytes());
    bus.bytes[0x2040..0x2044].copy_from_slice(&1_u32.to_le_bytes());

    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.wfdma_kick(&mut ctx, 4, 1);

    assert_eq!(board.mmio_read(WFSYS_FW_SYNC), 1);
    assert!(board.firmware_download.is_empty());
    assert_eq!(board.firmware_download_length, 0);
    assert!(!board.firmware_patch_complete);
    assert!(!board.firmware_patch_semaphore);
}

#[test]
fn wfdma_irq_tracks_mask_acknowledgement_and_reset() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);
    board.raise_wifi_interrupt();
    for (address, value, level) in [
        (WFDMA0_INT_MASK, 0, false),
        (WFDMA0_INT_MASK, 1, true),
        (WFDMA0_INT_SOURCE, 2, true),
        (WFDMA0_INT_SOURCE, 1, false),
    ] {
        ctx.events.clear();
        Machine::mmio_write(&mut board, &mut ctx, address, value, AccessWidth::U32).unwrap();
        assert!(ctx.events.contains(&board_core::Event::IrqLevel {
            line: WIFI_IRQ_LINE,
            level,
        }));
    }
    board.raise_wifi_interrupt();
    ctx.events.clear();
    board.reset(&mut ctx);
    assert!(ctx.events.contains(&board_core::Event::IrqLevel {
        line: WIFI_IRQ_LINE,
        level: false,
    }));
    assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), 0);
}

#[test]
fn wfdma_event_publishes_descriptor_before_interrupt() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    bus.bytes[0x1000..0x1004].copy_from_slice(&0x2000_u32.to_le_bytes());
    bus.bytes[0x1004..0x1008].copy_from_slice(&(256_u32 << 16).to_le_bytes());
    board.wfdma_rx_base = 0x1000;
    board.wfdma_rx_count = 16;
    board.control_regs.insert(WFDMA0_INT_SOURCE, 2);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.wfdma_post_event(&mut ctx, 1, 4, 0, &[2]);
    assert!(ctx.events.contains(&board_core::Event::IrqLevel {
        line: WIFI_IRQ_LINE,
        level: true,
    }));
    assert_eq!(board.wfdma_rx_didx, 1);
    assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), 3);
    assert_ne!(bus.bytes[0x1007] & 0x80, 0);
}

#[test]
fn patch_semaphore_completes_after_reinitializing_nonzero_dma_indices() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    board.wfdma_tx_base[1] = 0x1800;
    board.wfdma_tx_count[1] = 32;
    board.wfdma_tx_didx[1] = 16;
    board.wfdma_rx_base = 0x1000;
    board.wfdma_rx_count = 32;
    board.wfdma_rx_didx = 17;
    bus.bytes[0x1800..0x1804].copy_from_slice(&0x3000u32.to_le_bytes());
    bus.bytes[0x1804..0x1808].copy_from_slice(&(0x44u32 << 16).to_le_bytes());
    bus.bytes[0x3024..0x3028].copy_from_slice(&0x0100_0010u32.to_le_bytes());
    bus.bytes[0x3040..0x3044].copy_from_slice(&1u32.to_le_bytes());
    bus.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
    bus.bytes[0x1004..0x1008].copy_from_slice(&(256u32 << 16).to_le_bytes());
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.wfdma_kick(&mut ctx, 1, 1);
    assert!(!board.firmware_patch_semaphore);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        WFDMA0_RST_DTX_PTR,
        1 << 17,
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        WFDMA0_RST_DRX_PTR,
        1,
        AccessWidth::U32,
    )
    .unwrap();
    board.wfdma_kick(&mut ctx, 1, 1);
    assert!(board.firmware_patch_semaphore);
    assert_eq!(board.wfdma_tx_didx[1], 1);
    assert_eq!(board.wfdma_rx_didx, 1);
    assert!(ctx.events.contains(&board_core::Event::IrqLevel {
        line: WIFI_IRQ_LINE,
        level: true
    }));
    assert_eq!(bus.bytes[0x201c], 4);
    assert_eq!(bus.bytes[0x201d], 1);
    assert_eq!(bus.bytes[0x2020], 2);
}

#[test]
fn wfdma_global_control_and_pointer_resets_are_safe() {
    let mut board = Mt7981Board::new();

    board.mmio_write(WFDMA0_GLO_CFG, 0x0000_0045);
    assert_eq!(board.mmio_read(WFDMA0_GLO_CFG), 0x0000_0045);
    board.mmio_write(WFDMA0_RST_DTX_PTR, u32::MAX);
    board.mmio_write(WFDMA0_RST_DRX_PTR, u32::MAX);
    assert_eq!(board.mmio_read(WFDMA0_RST_DTX_PTR), 0);
    assert_eq!(board.mmio_read(WFDMA0_RST_DRX_PTR), 0);

    board.mmio_write(WFDMA0_RX0_BASE, 0x4e4f_4000);
    board.mmio_write(WFDMA0_RX0_CNT, 0x200);
    board.mmio_write(WFDMA0_RX0_CIDX, 0x1ff);
    board.mmio_write(WFDMA0_RX0_DIDX, 1);
    assert_eq!(board.mmio_read(WFDMA0_RX0_BASE), 0x4e4f_4000);
    assert_eq!(board.mmio_read(WFDMA0_RX0_CNT), 0x200);
    assert_eq!(board.mmio_read(WFDMA0_RX0_CIDX), 0x1ff);
    assert_eq!(board.mmio_read(WFDMA0_RX0_DIDX), 1);
}

#[test]
fn wfsys_mcu_bus_reports_ready_after_enable() {
    let mut board = Mt7981Board::new();

    board.mmio_write(WFSYS_MCU_BUS_READY, 0x8800_0000);

    assert_eq!(board.mmio_read(WFSYS_MCU_BUS_READY), 0x8800_0000);
}

#[test]
fn wfsys_firmware_sync_reports_initial_stage() {
    let mut board = Mt7981Board::new();

    assert_eq!(board.mmio_read(WFSYS_FW_SYNC), 1);
}

#[test]
fn spi_command_readback_keeps_completion_interrupts_enabled() {
    let mut board = Mt7981Board::new();
    board.mmio_write(SPI0_BASE + SPI_CMD, 1);

    let command = board.mmio_read(SPI0_BASE + SPI_CMD);
    assert_eq!(command & 7, 0);
    assert_eq!(
        command & (SPI_CMD_FINISH_IE | SPI_CMD_PAUSE_IE),
        SPI_CMD_FINISH_IE | SPI_CMD_PAUSE_IE
    );
}

#[test]
fn spi_reads_beyond_eeprom_complete_with_erased_flash() {
    let mut board = Mt7981Board::new();
    for address in [UBOOT_ENV_OFFSET + UBOOT_ENV_SIZE, SPI_NOR_SIZE - 16] {
        let mut bus = EthernetDma { bytes: vec![0; 64] };
        bus.bytes[0] = board_core::spi_nor::command::READ;
        bus.bytes[1..4].copy_from_slice(&u32::try_from(address).unwrap().to_be_bytes()[1..]);
        board.spi_tx_src = 0;
        board.spi_rx_dst = 32;
        board.spi_cfg1 = 15 << 16;
        board.mmio_write(SPI0_BASE + SPI_CMD, 1 << 10);
        let mut ctx = MachineContext::with_dma(0, &mut bus);
        board.spi_complete(&mut ctx);
        assert_eq!(
            ctx.events,
            vec![board_core::Event::IrqLevel {
                line: IRQ_LINES[1],
                level: true,
            }]
        );
        assert_eq!(&bus.bytes[32..48], &[0xff; 16]);
    }
}

#[test]
fn spi_status2_read_completes_with_stored_register() {
    let mut board = Mt7981Board::new();
    board.spi_nor.write_enable();
    board.spi_nor.write_status2(2).unwrap();
    let mut bus = EthernetDma { bytes: vec![0; 64] };
    bus.bytes[0] = 0x35;
    board.spi_rx_dst = 32;
    board.mmio_write(SPI0_BASE + SPI_CMD, 1 << 10);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.spi_complete(&mut ctx);
    assert_eq!(
        ctx.events,
        vec![board_core::Event::IrqLevel {
            line: IRQ_LINES[1],
            level: true,
        }]
    );
    assert_eq!(bus.bytes[32], 2);
}

#[test]
fn spi_only_starts_on_activate_and_reset_lowers_irq() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma { bytes: vec![0; 64] };
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        SPI0_BASE + SPI_CMD,
        u64::from(SPI_CMD_FINISH_IE),
        AccessWidth::U32,
    )
    .unwrap();
    assert!(ctx.events.is_empty());
    // Even an unrecognized flash opcode completes the bus transfer.
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        SPI0_BASE + SPI_CMD,
        1,
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        SPI0_BASE + SPI_CMD,
        4,
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events,
        vec![
            board_core::Event::IrqLevel {
                line: IRQ_LINES[1],
                level: true
            },
            board_core::Event::IrqLevel {
                line: IRQ_LINES[1],
                level: false
            },
        ]
    );
}

#[test]
fn spi_dma_setup_does_not_replay_previous_transfer_into_old_buffer() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0xcc; 0x20000],
    };
    // Read past the seeded EEPROM and u-boot-env partitions.
    bus.bytes[..4].copy_from_slice(&[0x03, 0x09, 0, 0]);
    board.spi_rx_dst = 128;
    board.spi_cfg1 = 63 << 16;
    {
        let mut ctx = MachineContext::with_dma(0, &mut bus);
        Machine::mmio_write(
            &mut board,
            &mut ctx,
            SPI0_BASE + SPI_CMD,
            (1 << 10) | (1 << 11) | 1,
            AccessWidth::U32,
        )
        .unwrap();
    }
    assert_eq!(&bus.bytes[128..192], &[0xff; 64]);
    // The driver installs the next length before updating the DMA address.
    // A read-modify-write of CMD must not replay ACT into the old buffer.
    board.spi_cfg1 = 0xfffb_0000;
    let config = board.mmio_read(SPI0_BASE + SPI_CMD);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        SPI0_BASE + SPI_CMD,
        u64::from(config),
        AccessWidth::U32,
    )
    .unwrap();
    assert!(ctx.events.is_empty());
    assert!(bus.bytes[192..].iter().all(|byte| *byte == 0xcc));
}

#[test]
fn spi_tx_only_command_does_not_write_stale_rx_dma_address() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0xcc; 64],
    };
    bus.bytes[0] = board_core::spi_nor::command::WRITE_ENABLE;
    board.spi_rx_dst = 32;
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        SPI0_BASE + SPI_CMD,
        (1 << 11) | 1,
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(&bus.bytes[32..], &[0xcc; 32]);
}

#[test]
fn mdio_reads_mt7981_phy_identity_and_link() {
    let mut board = Mt7981Board::new();
    let piac = ETH_MAC_BASE + ETH_MAC_PIAC;

    board.mmio_write(
        piac,
        ETH_MAC_PIAC_START
            | (PHY_REG_PHYID1 << ETH_MAC_PIAC_REG_SHIFT)
            | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT)
            | (1 << 16),
    );
    assert_eq!(
        board.mmio_read(piac) & ETH_MAC_PIAC_DATA_MASK,
        u32::from(PHY_ID1_MT7981)
    );

    board.mmio_write(
        piac,
        ETH_MAC_PIAC_START
            | (PHY_REG_PHYID2 << ETH_MAC_PIAC_REG_SHIFT)
            | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT)
            | (1 << 16),
    );
    assert_eq!(
        board.mmio_read(piac) & ETH_MAC_PIAC_DATA_MASK,
        u32::from(PHY_ID2_MT7981)
    );

    board.mmio_write(
        piac,
        ETH_MAC_PIAC_START
            | (PHY_REG_BMSR << ETH_MAC_PIAC_REG_SHIFT)
            | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT)
            | (1 << 16),
    );
    assert_eq!(
        board.mmio_read(piac) & ETH_MAC_PIAC_DATA_MASK,
        u32::from(PHY_BMSR_CAPABILITIES | PHY_BMSR_LINK_STATUS | PHY_BMSR_AUTONEG_COMPLETE,)
    );
}

#[test]
fn mdio_page_one_reports_link_partner_detection() {
    let mut board = Mt7981Board::new();
    let piac = ETH_MAC_BASE + ETH_MAC_PIAC;
    board.mmio_write(
        piac,
        ETH_MAC_PIAC_START | (0x1f << ETH_MAC_PIAC_REG_SHIFT) | 1,
    );
    board.mmio_write(
        piac,
        ETH_MAC_PIAC_START
            | (0x14 << ETH_MAC_PIAC_REG_SHIFT)
            | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT),
    );
    assert_eq!(board.mmio_read(piac) & ETH_MAC_PIAC_DATA_MASK, 0x0040);
}

#[test]
fn ethernet_mac_status_reports_gigabit_full_duplex_for_both_ports() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mmio_read(ETH_MAC_BASE + ETH_MAC_MSR0), 0xb);
    assert_eq!(board.mmio_read(ETH_MAC_BASE + ETH_MAC_MSR1), 0xb);
    assert_eq!(board.mmio_read(ETH_MAC_BASE + ETH_MAC_XGMAC_STS_ALT), 1);
}

#[test]
fn mdio_exposes_gigabit_capabilities_and_link_partner() {
    let mut board = Mt7981Board::new();
    let piac = ETH_MAC_BASE + ETH_MAC_PIAC;
    // Follow the capability and common-mode checks performed by genphy.
    for (register, mask, expected) in [
        (1, 0x0108, 0x0108),
        (15, 0x3000, 0x2000),
        (9, 0x0300, 0x0200),
        (10, 0x3c00, 0x3800),
        (5, 0x41e1, 0x41e1),
    ] {
        board.mmio_write(
            piac,
            ETH_MAC_PIAC_START
                | (register << ETH_MAC_PIAC_REG_SHIFT)
                | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT)
                | (1 << 16),
        );
        assert_eq!(
            board.mmio_read(piac) & mask,
            expected,
            "MII register {register}"
        );
    }
}

#[test]
fn mdio_autoneg_restart_self_clears_without_disabling_negotiation() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mdio_regs[&(0, PHY_REG_BMCR)], PHY_BMCR_AUTONEG_ENABLE);
    board.write_mdio(
        ETH_MAC_PIAC_START
            | (1 << ETH_MAC_PIAC_CMD_SHIFT)
            | (1 << 16)
            | u32::from(PHY_BMCR_AUTONEG_ENABLE | PHY_BMCR_RESTART_AUTONEG),
    );
    board.write_mdio(ETH_MAC_PIAC_START | (ETH_MDIO_READ << ETH_MAC_PIAC_CMD_SHIFT) | (1 << 16));
    assert_eq!(
        board.mmio_read(ETH_MAC_BASE + ETH_MAC_PIAC),
        u32::from(PHY_BMCR_AUTONEG_ENABLE)
    );
}

#[test]
fn ethernet_dma_status_and_reset_are_safe() {
    let mut board = Mt7981Board::new();
    let dma_status = ETH_MAC_BASE + ETH_DMA_INT_STATUS;
    let dma_mask = ETH_MAC_BASE + 0x461c;
    let pdma_reset = ETH_MAC_BASE + ETH_PDMA_RST_IDX;
    let qdma_reset = ETH_MAC_BASE + ETH_QDMA_RST_IDX;

    assert_eq!(board.mmio_read(dma_status), 0);
    board.raise_eth_interrupt(true);
    assert_eq!(board.mmio_read(ETH_PDMA_INT_STATUS), ETH_INT_RX_DONE);
    assert_eq!(board.mmio_read(dma_status), ETH_INT_RX_DONE);
    board.mmio_write(ETH_PDMA_INT_STATUS, ETH_INT_RX_DONE);
    board.mmio_write(dma_status, ETH_INT_RX_DONE);
    assert_eq!(board.mmio_read(dma_status), 0);
    board.raise_eth_interrupt(false);
    assert_eq!(board.mmio_read(dma_status), ETH_INT_TX_DONE);
    board.mmio_write(dma_status, ETH_INT_TX_DONE);
    assert_eq!(board.mmio_read(dma_status), 0);
    board.mmio_write(dma_mask, 0xffff_ffff);
    assert_eq!(board.mmio_read(dma_mask), 0xffff_ffff);
    board.mmio_write(dma_status, 0xffff_ffff);
    board.mmio_write(pdma_reset, 0xffff_ffff);
    board.mmio_write(qdma_reset, 0xffff_ffff);
    assert_eq!(board.mmio_read(dma_status), 0);
    assert_eq!(board.mmio_read(pdma_reset), 0);
    assert_eq!(board.mmio_read(qdma_reset), 0);
}

struct EthernetDma {
    bytes: Vec<u8>,
}
impl board_core::dma::DmaBus for EthernetDma {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> board_core::dma::TransferStatus {
        assert!(address < ETH_MAC_BASE, "device SRAM must not use host DMA");
        let start = usize::try_from(address).unwrap();
        let Some(source) = self.bytes.get(start..start + buffer.len()) else {
            return board_core::dma::TransferStatus::Failed;
        };
        buffer.copy_from_slice(source);
        board_core::dma::TransferStatus::Complete
    }
    fn write(&mut self, address: u64, buffer: &[u8]) -> board_core::dma::TransferStatus {
        assert!(address < ETH_MAC_BASE, "device SRAM must not use host DMA");
        let start = usize::try_from(address).unwrap();
        let Some(target) = self.bytes.get_mut(start..start + buffer.len()) else {
            return board_core::dma::TransferStatus::Failed;
        };
        target.copy_from_slice(buffer);
        board_core::dma::TransferStatus::Complete
    }
}

#[test]
fn qdma_tx_emits_frame_and_completion_irq() {
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    bus.bytes[0x3000 + 12..0x3000 + 14].copy_from_slice(&[0x08, 0x06]);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    let mut board = Mt7981Board::new();
    board.mmio_write(ETH_TX_DESC_BASE, 0x3000);
    board.mmio_write(ETH_TX_DESC_BASE + 4, 0x1515_0020);
    board.mmio_write(ETH_TX_DESC_BASE + 8, (1 << 30) | (42 << 8));
    board.mmio_write(ETH_QDMA_DTX_PTR, 0x1515_0000);
    board.mmio_write(ETH_QDMA_INT_MASK, ETH_INT_TX_DONE);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        ETH_MAC_BASE + 0x4700,
        ETH_TX_DESC_BASE + 32,
        AccessWidth::U32,
    )
    .unwrap();
    assert!(ctx.events.iter().any(|event| {
        matches!(event, board_core::Event::NetTx { port: 0, frame }
                if frame.len() == 42 && frame[12..14] == [0x08, 0x06])
    }));
    for (line, level) in ETH_IRQ_LINES.into_iter().zip([true, true, false, false]) {
        assert!(
            ctx.events
                .contains(&board_core::Event::IrqLevel { line, level })
        );
    }
    assert_eq!(board.mmio_read(ETH_QDMA_DRX_PTR), 0x1515_0000);
    assert_eq!(board.mmio_read(ETH_QDMA_DTX_PTR), 0x1515_0020);
    assert_eq!(board.mmio_read(ETH_TX_DESC_BASE + 8), 0xc000_2a00);
    assert_eq!(board.mmio_read(ETH_TX_DESC_BASE + 4), 0x1515_0020);
}

#[test]
fn ethernet_rx_is_dropped_while_the_receive_engine_is_stopped() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    board.mmio_write(ETH_RX_DESC_BASE, 0x3000);
    board.mmio_write(ETH_RX_DESC_BASE + 4, 1536 << 16);
    // The driver's burst/NDP configuration, written before it arms the
    // ring.  A frame arriving now must not reach the stale buffer.
    board.mmio_write(ETH_PDMA_GLO_CFG, 0x1c00);

    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::net_rx(&mut board, &mut ctx, 0, &[0x5a; 60]);

    assert_eq!(board.mmio_read(ETH_RX_DESC_BASE + 4), 1536 << 16);
    assert!(ctx.events.is_empty());
    drop(ctx);
    assert!(bus.bytes[0x3000..0x303c].iter().all(|byte| *byte == 0));
}

#[test]
fn ethernet_rx_updates_local_descriptors_and_guest_payload() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    assert!(!Machine::net_can_receive(&board, 0));
    board.mmio_write(ETH_RX_DESC_BASE, 0x3000);
    assert!(!Machine::net_can_receive(&board, 0));
    board.mmio_write(ETH_RX_DESC_BASE + 4, 1536 << 16);
    board.mmio_write(ETH_PDMA_INT_MASK, ETH_INT_RX_DONE);
    // QDMA alignment must not add padding to PDMA's receive buffers.
    board.mmio_write(ETH_MAC_BASE + 0x4604, 0x8000_0005);
    // The receive engine only writes into the ring once the driver runs it.
    board.mmio_write(ETH_PDMA_GLO_CFG, 0x1c00 | ETH_PDMA_RX_DMA_EN);
    assert!(Machine::net_can_receive(&board, 0));
    let frame = [0x5a; 60];
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::net_rx(&mut board, &mut ctx, 0, &frame);
    assert!(!Machine::net_can_receive(&board, 0));
    for offset in [0, 0x10000] {
        assert_eq!(board.mmio_read(ETH_RX_DESC_BASE + offset + 4), 0x803c_0000);
        assert_eq!(board.mmio_read(ETH_RX_DESC_BASE + offset + 12), 2 << 19);
    }
    for (line, level) in ETH_IRQ_LINES.into_iter().zip([true, false, true, false]) {
        assert!(
            ctx.events
                .contains(&board_core::Event::IrqLevel { line, level })
        );
    }
    drop(ctx);
    assert_eq!(&bus.bytes[0x3000..0x303c], &frame);
}

#[test]
fn ethernet_irqs_follow_masks_and_write_one_to_clear() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);
    board.raise_eth_interrupt(false);
    for (address, value, level) in [
        (ETH_QDMA_INT_MASK, 0, false),
        (ETH_QDMA_INT_MASK, ETH_INT_TX_DONE, true),
        (ETH_QDMA_INT_STATUS, ETH_INT_TX_DONE, false),
    ] {
        ctx.events.clear();
        Machine::mmio_write(
            &mut board,
            &mut ctx,
            address,
            u64::from(value),
            AccessWidth::U32,
        )
        .unwrap();
        assert_eq!(
            ctx.events,
            ETH_IRQ_LINES.map(|line| board_core::Event::IrqLevel {
                line,
                level: level && (line == 196 || line == 197),
            })
        );
    }
}

#[test]
fn qdma_scatter_gather_preserves_partial_frame_until_last_fragment() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    bus.bytes[0x3000..0x3003].copy_from_slice(b"abc");
    bus.bytes[0x3100..0x3103].copy_from_slice(b"def");
    for (offset, buffer, control) in [(0, 0x3000, 3 << 8), (32, 0x3100, (1 << 30) | (3 << 8))] {
        board.mmio_write(ETH_TX_DESC_BASE + offset, buffer);
        board.mmio_write(
            ETH_TX_DESC_BASE + offset + 4,
            u32::try_from(ETH_TX_DESC_BASE + offset + 32).unwrap(),
        );
        board.mmio_write(ETH_TX_DESC_BASE + offset + 8, control);
    }
    board.mmio_write(ETH_QDMA_DTX_PTR, u32::try_from(ETH_TX_DESC_BASE).unwrap());
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.qdma_kick(&mut ctx, u32::try_from(ETH_TX_DESC_BASE + 32).unwrap());
    assert!(
        !ctx.events
            .iter()
            .any(|event| matches!(event, board_core::Event::NetTx { .. }))
    );
    board.qdma_kick(&mut ctx, u32::try_from(ETH_TX_DESC_BASE + 64).unwrap());
    let frames: Vec<_> = ctx
        .events
        .iter()
        .filter_map(|event| match event {
            board_core::Event::NetTx { frame, .. } => Some(frame.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(frames, [b"abcdef".as_slice()]);
    assert_eq!(
        board.mmio_read(ETH_QDMA_DRX_PTR),
        u32::try_from(ETH_TX_DESC_BASE + 32).unwrap()
    );
}

#[test]
fn qdma_offload_metadata_survives_separate_doorbells() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma {
        bytes: vec![0; 0x4000],
    };
    bus.bytes[0x3000..0x3008].copy_from_slice(b"abcdefgh");
    bus.bytes[0x3100..0x3108].copy_from_slice(b"ijklmnop");
    for (offset, buffer, control) in [(0, 0x3000, 8 << 8), (32, 0x3100, (1 << 30) | (8 << 8))] {
        board.mmio_write(ETH_TX_DESC_BASE + offset, buffer);
        board.mmio_write(
            ETH_TX_DESC_BASE + offset + 4,
            u32::try_from(ETH_TX_DESC_BASE + offset + 32).unwrap(),
        );
        board.mmio_write(ETH_TX_DESC_BASE + offset + 8, control);
    }
    board.mmio_write(ETH_TX_DESC_BASE + 20, 0x1007b);
    board.mmio_write(ETH_QDMA_DTX_PTR, u32::try_from(ETH_TX_DESC_BASE).unwrap());
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.qdma_kick(&mut ctx, u32::try_from(ETH_TX_DESC_BASE + 32).unwrap());
    assert!(
        !ctx.events
            .iter()
            .any(|event| matches!(event, board_core::Event::NetTx { .. }))
    );
    board.qdma_kick(&mut ctx, u32::try_from(ETH_TX_DESC_BASE + 64).unwrap());
    let frames: Vec<_> = ctx
        .events
        .iter()
        .filter_map(|event| match event {
            board_core::Event::NetTx { frame, .. } => Some(frame.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(frames, [b"abcdefghijkl\x81\x00\x00\x7bmnop".as_slice()]);
    assert_eq!(
        board.mmio_read(ETH_QDMA_DRX_PTR),
        u32::try_from(ETH_TX_DESC_BASE + 32).unwrap()
    );
}

#[test]
fn failed_ethernet_dma_does_not_complete_descriptors() {
    let mut board = Mt7981Board::new();
    let mut bus = EthernetDma { bytes: Vec::new() };
    board.mmio_write(ETH_TX_DESC_BASE, 0x3000);
    board.mmio_write(
        ETH_TX_DESC_BASE + 4,
        u32::try_from(ETH_TX_DESC_BASE + 32).unwrap(),
    );
    board.mmio_write(ETH_TX_DESC_BASE + 8, (1 << 30) | (42 << 8));
    board.mmio_write(ETH_QDMA_DTX_PTR, u32::try_from(ETH_TX_DESC_BASE).unwrap());
    board.mmio_write(ETH_RX_DESC_BASE, 0x3000);
    board.mmio_write(ETH_RX_DESC_BASE + 4, 1536 << 16);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    board.qdma_kick(&mut ctx, u32::try_from(ETH_TX_DESC_BASE + 32).unwrap());
    Machine::net_rx(&mut board, &mut ctx, 0, &[0; 60]);
    assert!(ctx.events.is_empty());
    assert_eq!(
        board.mmio_read(ETH_QDMA_DTX_PTR),
        u32::try_from(ETH_TX_DESC_BASE).unwrap()
    );
    assert_eq!(board.mmio_read(ETH_TX_DESC_BASE + 8), (1 << 30) | (42 << 8));
    assert_eq!(board.mmio_read(ETH_RX_DESC_BASE + 4), 1536 << 16);
}

#[test]
fn ethernet_rx_pending_does_not_hold_masked_tx_irq_high() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);
    board.raise_eth_interrupt(false);
    board.raise_eth_interrupt(true);
    board.mmio_write(ETH_QDMA_INT_MASK, ETH_INT_TX_DONE);
    board.mmio_write(ETH_PDMA_INT_MASK, ETH_INT_RX_DONE);
    Machine::mmio_write(&mut board, &mut ctx, ETH_QDMA_INT_MASK, 0, AccessWidth::U32).unwrap();
    assert_eq!(
        ctx.events,
        ETH_IRQ_LINES
            .into_iter()
            .zip([true, false, true, false])
            .map(|(line, level)| board_core::Event::IrqLevel { line, level })
            .collect::<Vec<_>>()
    );
}

#[test]
fn efuse_calibration_cells_are_nonzero_and_byte_addressable() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.mmio_read(EFUSE_BASE + EFUSE_EEPROM_TYPE), 0x000c);
    for offset in EFUSE_CELL_PHY_CALIB_START..EFUSE_CELL_PHY_CALIB_START + 0x10 {
        assert_ne!(board.mmio_read(EFUSE_BASE + offset), 0);
    }
}

#[test]
fn msdc_command_irq_tracks_mask_and_acknowledgement() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_CMD,
        0x181,
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_INT), MSDC_INT_CMDRDY);
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: false
        })
    );

    // Enabling an already pending completion must assert the level too.
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INTEN,
        u64::from(MSDC_INT_CMDRDY),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INTEN,
        0,
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: false
        })
    );
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_INT), MSDC_INT_CMDRDY);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INTEN,
        u64::from(MSDC_INT_CMDRDY),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INT,
        u64::from(MSDC_INT_XFER_COMPL),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INT,
        u64::from(MSDC_INT_CMDRDY),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: false
        })
    );
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_INT), 0);
}

#[test]
fn msdc_board_reset_clears_pending_irq_and_registers() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);
    board.mmio_write(MSDC0_BASE + MSDC_INTEN, MSDC_INT_CMDRDY);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_CMD,
        0x181,
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    Machine::reset(&mut board, &mut ctx);
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: false
        })
    );
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_INT), 0);
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_INTEN), 0);
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_SDC_RESP0), 0);
}

#[test]
fn msdc_clock_status_reports_stable_after_ungate() {
    let mut board = Mt7981Board::new();
    board.mmio_write(MSDC0_BASE + MSDC_CFG, 0x1);
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_CFG), 0x81);
    board.mmio_write(MSDC0_BASE + MSDC_CFG, MSDC_CFG_RST);
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_CFG), MSDC_CFG_CKSTB);
}

#[test]
fn default_emmc_image_exposes_the_firmware_partition_table() {
    let mut board = Mt7981Board::new();

    // Linux reads the GPT header from block 1 using a byte-offset
    // argument, and its backup header from the final block.
    assert_eq!(board.mmc.block_address(512), 1);
    let last = (EMMC_BLOCK_COUNT - 1) as u64;
    assert_eq!(
        board.mmc.block_address(u32::try_from(last * 512).unwrap()),
        last
    );
    for block in [1, last] {
        let header = board
            .mmc
            .command(board_core::mmc::Command::Read { block, blocks: 1 }, &[])
            .unwrap()
            .data;
        assert_eq!(&header[0..8], b"EFI PART");
    }

    let entries = board
        .mmc
        .command(
            board_core::mmc::Command::Read {
                block: GPT_ENTRIES_LBA,
                blocks: 32,
            },
            &[],
        )
        .unwrap()
        .data;
    for (index, (name, _)) in EMMC_PARTITIONS.iter().enumerate() {
        let entry = &entries[index * GPT_ENTRY_SIZE..(index + 1) * GPT_ENTRY_SIZE];
        let decoded: String = entry[56..128]
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .take_while(|unit| *unit != 0)
            .filter_map(|unit| char::from_u32(u32::from(unit)))
            .collect();
        assert_eq!(&decoded, name);
    }
}

#[test]
fn sdio_probe_commands_report_a_command_timeout() {
    let mut board = Mt7981Board::new();
    let mut ctx = MachineContext::new(0);

    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_CMD,
        5,
        AccessWidth::U32,
    )
    .unwrap();

    let pending = board.mmio_read(MSDC0_BASE + MSDC_INT);
    assert_eq!(pending & MSDC_INT_CMDTMO, MSDC_INT_CMDTMO);
    assert_eq!(pending & MSDC_INT_CMDRDY, 0);
    assert_eq!(board.mmio_read(MSDC0_BASE + MSDC_SDC_RESP0), 0);
}

#[test]
fn rust_mmc_model_matches_legacy_identity_responses() {
    let mut board = Mt7981Board::new();
    assert_eq!(board.msdc_command(1).unwrap()[0], 0x80ff_8080);
    assert_eq!(board.msdc_command(2).unwrap()[3], 0x4d54_4b55);
    assert_eq!(board.msdc_command(9).unwrap()[1], 0xc007_bf80);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "DMA fixture covers a full BD lifecycle"
)]
fn msdc_bd_chain_round_trips_through_host_dma() {
    struct MemoryDma {
        bytes: Vec<u8>,
    }
    impl board_core::dma::DmaBus for MemoryDma {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> board_core::dma::TransferStatus {
            let Some(start) = usize::try_from(address).ok() else {
                return board_core::dma::TransferStatus::Failed;
            };
            let Some(end) = start.checked_add(buffer.len()) else {
                return board_core::dma::TransferStatus::Failed;
            };
            let Some(source) = self.bytes.get(start..end) else {
                return board_core::dma::TransferStatus::Failed;
            };
            buffer.copy_from_slice(source);
            board_core::dma::TransferStatus::Complete
        }
        fn write(&mut self, address: u64, buffer: &[u8]) -> board_core::dma::TransferStatus {
            let Some(start) = usize::try_from(address).ok() else {
                return board_core::dma::TransferStatus::Failed;
            };
            let Some(end) = start.checked_add(buffer.len()) else {
                return board_core::dma::TransferStatus::Failed;
            };
            let Some(target) = self.bytes.get_mut(start..end) else {
                return board_core::dma::TransferStatus::Failed;
            };
            target.copy_from_slice(buffer);
            board_core::dma::TransferStatus::Complete
        }
    }

    let mut bus = MemoryDma {
        bytes: vec![0; 0x4000],
    };
    bus.bytes[0x1008..0x100c].copy_from_slice(&0x2000u32.to_le_bytes());
    bus.bytes[0x2000..0x2004].copy_from_slice(&1u32.to_le_bytes());
    bus.bytes[0x2008..0x200c].copy_from_slice(&0x3000u32.to_le_bytes());
    bus.bytes[0x200c..0x2010].copy_from_slice(&512u32.to_le_bytes());
    bus.bytes[0x3000..0x3200].fill(0x5a);

    let mut board = Mt7981Board::new();
    board.mmio_write(MSDC0_BASE + MSDC_INTEN, MSDC_INT_XFER_COMPL);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_ARG,
        0,
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_BLK_NUM,
        1,
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_DMA_SA,
        0x1000,
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_CMD,
        u64::from(0x18 | (1 << 11) | MSDC_DMA_WRITE),
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_DMA_CTRL,
        u64::from(MSDC_DMA_START),
        AccessWidth::U32,
    )
    .unwrap();
    assert_ne!(
        board.mmio_read(MSDC0_BASE + MSDC_INT) & MSDC_INT_DXFER_DONE,
        0
    );
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_INT,
        u64::from(u32::MAX),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: false
        })
    );
    drop(ctx);
    bus.bytes[0x3000..0x3200].fill(0);
    let mut ctx = MachineContext::with_dma(0, &mut bus);
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_SDC_CMD,
        u64::from(0x11u32 | (1 << 11)),
        AccessWidth::U32,
    )
    .unwrap();
    Machine::mmio_write(
        &mut board,
        &mut ctx,
        MSDC0_BASE + MSDC_DMA_CTRL,
        u64::from(MSDC_DMA_START),
        AccessWidth::U32,
    )
    .unwrap();
    assert_eq!(
        ctx.events.pop(),
        Some(board_core::Event::IrqLevel {
            line: 143,
            level: true
        })
    );
    assert!(bus.bytes[0x3000..0x3200].iter().all(|byte| *byte == 0x5a));
}
