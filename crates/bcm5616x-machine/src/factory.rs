//! Synthetic factory identity and the flash identity bytes queried by BDE.
//!
//! This is not a vendor-signed EEPROM. The signature slot stays erased; see
//! `docs/us24pro/factory-auth.md` for the remaining stock-firmware boot gate.

use super::{BOARD_DATA_LEN, FLASH_JEDEC_ID, SWITCH_DEVICE_BCM56166, board_data};

pub(super) const EEPROM_LEN: usize = 0x10000;
// The stock BDE selects the 35F layout from SFDP[4..7], then reads 13 bytes
// at SFDP[0x8c]. Keep the factory mirror and that read on one identity.
const FLASH_UUID_LEN: u8 = 13;
pub(super) const FLASH_UUID: [u8; FLASH_UUID_LEN as usize] = *b"US24EMU000001";

pub(super) fn eeprom() -> Vec<u8> {
    let mut image = vec![0xff; EEPROM_LEN];
    image[..BOARD_DATA_LEN].copy_from_slice(&board_data());
    image[0xa000] = 0x0e;
    image[0xa001] = 0; // Non-v1 BCM5616x record: BOM revision is at 0xa1b7.
    image.copy_within(0x0c..0x10, 0xa01e);
    image.copy_within(0x00..0x06, 0xa022);
    image[0xa02e..0xa032].copy_from_slice(&[
        0,
        FLASH_JEDEC_ID[0],
        FLASH_JEDEC_ID[1],
        FLASH_JEDEC_ID[2],
    ]);
    image[0xa032] = FLASH_UUID_LEN;
    image[0xa033..0xa033 + FLASH_UUID.len()].copy_from_slice(&FLASH_UUID);
    image[0xa0b3..0xa0b7].copy_from_slice(&SWITCH_DEVICE_BCM56166.to_be_bytes());
    image.copy_within(0x20..0x120, 0xa0b7);
    image.copy_within(0x10..0x14, 0xa1b7);
    image
}

/// Identity-only SFDP subset, not a complete flash parameter table.
pub(super) fn sfdp_byte(address: usize) -> u8 {
    match address {
        0..=3 => b"SFDP"[address],
        4..=6 => [0, 1, 1][address - 4],
        0x8c..=0x98 => FLASH_UUID[address - 0x8c],
        _ => 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_preserves_the_original_hal_record() {
        assert_eq!(&eeprom()[..BOARD_DATA_LEN], board_data());
    }

    #[test]
    fn secondary_record_mirrors_the_hal_identity() {
        let image = eeprom();
        for (source, target, size) in [
            (0x0c, 0xa01e, 4),
            (0, 0xa022, 6),
            (0x20, 0xa0b7, 0x100),
            (0x10, 0xa1b7, 4),
        ] {
            assert_eq!(&image[target..target + size], &image[source..source + size]);
        }
    }

    #[test]
    fn factory_uuid_matches_the_bde_sfdp_layout() {
        let image = eeprom();
        assert_eq!(image[0xa032], 13);
        for i in 0..13 {
            assert_eq!(image[0xa033 + i], sfdp_byte(0x8c + i));
        }
    }

    #[test]
    fn signature_is_explicitly_absent() {
        assert!(eeprom()[0xbe00..0xc000].iter().all(|&byte| byte == 0xff));
    }
}
