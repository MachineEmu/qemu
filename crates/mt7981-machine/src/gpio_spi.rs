//! GPIO-mode flash reads used by ubnthal while it holds `ui_nor_lock`.

const CS: u32 = 1 << 29;
const CLK: u32 = 1 << 26;
const MOSI: u32 = 1 << 27;
const MISO: u32 = 1 << 28;
pub(super) const BASE: u64 = 0x11d0_0000;

#[derive(Debug)]
pub(super) struct GpioSpi {
    output: u32,
    command: u32,
    opcode: u8,
    clocks: u32,
    miso: bool,
}

impl Default for GpioSpi {
    fn default() -> Self {
        Self {
            output: CS,
            command: 0,
            opcode: 0,
            clocks: 0,
            miso: true,
        }
    }
}

impl GpioSpi {
    pub(super) fn read(&self, address: u64) -> Option<u32> {
        match address.checked_sub(BASE)? {
            0x100 => Some(self.output),
            // SET/CLR are write-only aliases, not independent output latches.
            0x104 | 0x108 => Some(0),
            0x200 => Some((self.output & !MISO) | if self.miso { MISO } else { 0 }),
            _ => None,
        }
    }

    pub(super) fn write(&mut self, address: u64, value: u32) -> bool {
        let previous = self.output;
        self.output = match address.checked_sub(BASE) {
            Some(0x100) => value,
            Some(0x104) => previous | value,
            Some(0x108) => previous & !value,
            _ => return false,
        };
        if self.output & CS != 0 || previous & CS != 0 {
            self.command = 0;
            self.opcode = 0;
            self.clocks = 0;
            self.miso = true;
        }
        if self.output & CS == 0 && previous & CLK == 0 && self.output & CLK != 0 {
            if self.clocks < 8 {
                self.command = (self.command << 1) | u32::from(self.output & MOSI != 0);
                if self.clocks == 7 {
                    self.opcode = self.command.to_le_bytes()[0];
                }
            } else if self.opcode == 0x9f {
                // JEDEC ID follows the opcode immediately, without address
                // or dummy clocks. Match the controller's W25Q128 identity.
                let bit = self.clocks - 8;
                let byte = [0xef, 0x40, 0x18]
                    .get((bit / 8) as usize)
                    .copied()
                    .unwrap_or(0xff);
                self.miso = byte & (0x80 >> (bit % 8)) != 0;
            } else if self.clocks < 32 {
                self.command = (self.command << 1) | u32::from(self.output & MOSI != 0);
            } else if self.clocks >= 40 {
                // Mode 0: command + 24-bit address + eight dummy clocks.
                let bit = self.clocks - 40;
                let address = (self.command & 0x00ff_ffff).wrapping_add(bit / 8);
                let byte = if self.command >> 24 == 0x5a {
                    sfdp_byte(address)
                } else {
                    0xff
                };
                self.miso = byte & (0x80 >> (bit % 8)) != 0;
            }
            self.clocks = self.clocks.saturating_add(1);
        }
        true
    }
}

fn sfdp_byte(address: u32) -> u8 {
    // Synthetic SFDP revision 1.0 identification and a synthetic device ID.
    // ubnthal reads bytes 4..7, then its 13-byte ID region at 0x8c. An
    // unrecognized revision triggers a vendor error path that leaks the NOR
    // mutex. This is not a factory identity or a complete SFDP parameter table.
    match address {
        0..=7 => b"SFDP\x00\x01\x01\xff"[address as usize],
        0x8c..=0x98 => b"QEMU-U6PLUS-01"[(address - 0x8c) as usize],
        _ => 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer(spi: &mut GpioSpi, byte: u8) -> u8 {
        let mut response = 0;
        for shift in (0..8).rev() {
            spi.write(
                BASE + if byte & (1 << shift) != 0 {
                    0x104
                } else {
                    0x108
                },
                MOSI,
            );
            spi.write(BASE + 0x104, CLK);
            response = (response << 1) | u8::from(spi.read(BASE + 0x200).unwrap() & MISO != 0);
            spi.write(BASE + 0x108, CLK);
        }
        response
    }

    #[test]
    fn bitbang_reads_header_and_restarts_at_requested_address() {
        let mut spi = GpioSpi::default();
        for address in [4, 0x8c] {
            spi.write(BASE + 0x108, CS);
            for byte in [0x5a, 0, 0, address, 0] {
                transfer(&mut spi, byte);
            }
            let bytes: Vec<_> = (0..4).map(|_| transfer(&mut spi, 0xff)).collect();
            let expected: &[u8] = if address == 4 {
                &[0, 1, 1, 0xff]
            } else {
                b"QEMU"
            };
            assert_eq!(bytes, expected);
            spi.write(BASE + 0x104, CS);
        }
    }

    #[test]
    fn bitbang_jedec_id_has_no_address_or_dummy_cycles() {
        let mut spi = GpioSpi::default();
        for _ in 0..2 {
            spi.write(BASE + 0x108, CS);
            transfer(&mut spi, 0x9f);
            let bytes: Vec<_> = (0..4).map(|_| transfer(&mut spi, 0)).collect();
            assert_eq!(bytes, [0xef, 0x40, 0x18, 0xff]);
            spi.write(BASE + 0x104, CS);
        }
        spi.write(BASE + 0x108, CS);
        for byte in [0x5a, 0, 0, 0x8c, 0] {
            transfer(&mut spi, byte);
        }
        let serial: Vec<_> = (0..13).map(|_| transfer(&mut spi, 0xff)).collect();
        assert_eq!(serial, b"QEMU-U6PLUS-0");
    }

    #[test]
    fn gpio_alias_reads_do_not_repeat_previous_pin_changes() {
        let mut spi = GpioSpi::default();
        spi.write(BASE + 0x104, CLK);
        assert_eq!(spi.read(BASE + 0x104), Some(0));
        spi.write(BASE + 0x108, CLK);
        assert_eq!(spi.read(BASE + 0x108), Some(0));
        assert_eq!(spi.read(BASE + 0x100), Some(CS));
    }
}
