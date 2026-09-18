//! iProc/CMIC I2C master controller, the board's `PoE` management MCU at
//! address 0x20 and the rest of the bus in [`super::i2c`].
//! Register layout: vendor functions 0xc0025454 / 0xc0024f78; NACK encoding
//! agrees with Linux drivers/i2c/busses/i2c-bcm-iproc.c.
//!
//! Protocol numbers come from the controller's command register and were
//! confirmed against a traced boot: 0 quick, 1 send byte, 2 receive byte,
//! 3 write byte data, 4 read byte data, 5 write word data, 6 read word data,
//! and 7/8 the block pair the `PoE` MCU uses. Word data is big-endian on the
//! wire — the trace writes an `LM75` 60 C setpoint as `3c 00`.

pub(super) const BASE: u64 = 0x1800_8000;
pub(super) const IRQ: u32 = 97;
pub(super) const REGISTER_SPACE_SIZE: u64 = 0x50;
/// Eight-bit write address of the `PoE` MCU; seven-bit 0x20.
const POE_ADDRESS: u32 = 0x40;
const ENABLE: u32 = 1 << 30;
const RESET: u32 = 1 << 31;
const DONE: u32 = 1 << 28;

#[derive(Debug, Default)]
pub(super) struct Smbus {
    regs: [u32; 20],
    asserted: bool,
    tx: Vec<u32>,
    tx_overflow: bool,
    rx: std::collections::VecDeque<u8>,
    poe_reply: Option<[u8; 12]>,
    poe: super::poe::Poe,
    i2c: super::i2c::Bus,
    complete_unknown_devices: bool,
}

impl Smbus {
    /// Creates the CMIC-side bus populated by the switch board's auxiliary
    /// devices. Unknown non-SFP peripherals complete with zeroed read data,
    /// which lets an incomplete device inventory fail safely without leaving
    /// the controller busy forever.
    pub(super) fn cmic() -> Self {
        Self {
            complete_unknown_devices: true,
            ..Self::default()
        }
    }

    pub(super) fn read(&mut self, offset: u64) -> u32 {
        if offset == 0x44 {
            return self
                .rx
                .pop_front()
                .map_or(0, |byte| (1 << 30) | u32::from(byte));
        }
        if offset == 0x4c {
            return 0;
        }
        if offset == 0xc {
            return self.regs[3] | (u32::try_from(self.rx.len()).unwrap_or(64) << 16);
        }
        self.regs.get((offset / 4) as usize).copied().unwrap_or(0)
    }

    pub(super) fn write(&mut self, offset: u64, value: u32) {
        let index = (offset / 4) as usize;
        if index >= self.regs.len() {
            return;
        }
        match offset {
            0 if value & RESET != 0 => {
                self.regs.fill(0);
                self.regs[0] = value & !ENABLE;
                self.tx.clear();
                self.tx_overflow = false;
                self.rx.clear();
            }
            0xc => {
                if value & RESET != 0 {
                    self.rx.clear();
                }
                if value & (1 << 30) != 0 {
                    self.tx.clear();
                    self.tx_overflow = false;
                }
                self.regs[index] = value & 0x0000_3f00;
            }
            0x10 => self.regs[index] = value & 0x0000_3f00,
            0x30 if value & RESET != 0 => {
                if self.regs[0] & (ENABLE | RESET) == ENABLE {
                    let status = self.transfer(value);
                    self.regs[index] = (value & !(RESET | (7 << 25))) | (status << 25);
                    self.regs[0x3c / 4] |= DONE;
                    self.tx.clear();
                    self.tx_overflow = false;
                }
            }
            0x3c => self.regs[index] &= !value,
            0x40 => {
                if self.tx.len() < 64 {
                    self.tx.push(value & (RESET | 0xff));
                } else {
                    self.tx_overflow = true;
                }
            }
            0x44 | 0x48 | 0x4c => {}
            _ => self.regs[index] = value,
        }
    }

    fn transfer(&mut self, command: u32) -> u32 {
        self.rx.clear();
        let Some(&address) = self.tx.first() else {
            return 2;
        };
        if std::env::var_os("UNIFI_SMB_TRACE").is_some() {
            let bytes: Vec<u8> = self.tx.iter().map(|w| w.to_le_bytes()[0]).collect();
            eprintln!(
                "smb addr={:#04x} proto={} cmd={:#x} tx={:02x?}",
                address & 0xff,
                (command >> 9) & 15,
                command & 0xff,
                bytes
            );
        }
        if address & 0xfe != POE_ADDRESS {
            let device = u8::try_from((address & 0xfe) >> 1).unwrap_or_default();
            if let Some(reply) = self.device_transfer(command, device) {
                self.rx.extend(reply);
                return 0;
            }
            if super::i2c::Bus::is_known_absent(device) {
                return 2;
            }
            if !self.complete_unknown_devices {
                return 2;
            }
            if address & 1 != 0 {
                let read_len = match (command >> 9) & 15 {
                    2 | 4 => 1,
                    6 => 2,
                    8 => (command & 0xff) as usize,
                    _ => 0,
                };
                self.rx.resize(read_len, 0);
            }
            return 0;
        }
        if address & 1 == 0 {
            self.poe_reply = None;
        }
        if self.tx_overflow {
            return 5;
        }
        if command & (1 << 8) != 0 || address & RESET != 0 {
            return 3;
        }
        let protocol = (command >> 9) & 15;
        match (protocol, address & 1) {
            (7, 0)
                if self.tx.len() == 13
                    && self.tx[12] & RESET != 0
                    && self.tx[..12].iter().all(|word| word & RESET == 0) =>
            {
                let mut frame = [0_u8; 12];
                for (byte, word) in frame.iter_mut().zip(&self.tx[1..]) {
                    *byte = word.to_le_bytes()[0];
                }
                let Some(reply) = self.poe.request(frame) else {
                    eprintln!("us24-poe: unsupported request {frame:02x?}");
                    return 3;
                };
                self.poe_reply = Some(reply);
                0
            }
            (8, 1) if self.tx.len() == 1 && command & 0xff == 12 => {
                let Some(frame) = self.poe_reply.take() else {
                    return 3;
                };
                self.rx.extend(frame);
                0
            }
            _ => 3,
        }
    }

    /// Decodes one transaction into an [`super::i2c::Op`] and offers it to the
    /// modelled devices. `None` means no modelled device answered, which
    /// leaves the caller's existing completion behaviour in charge.
    ///
    /// The transmit queue holds the eight-bit address first, so the device
    /// address is half of it. Word data is big-endian on this bus.
    fn device_transfer(&mut self, command: u32, device: u8) -> Option<Vec<u8>> {
        use super::i2c::Op;
        let bytes: Vec<u8> = self.tx.iter().map(|word| word.to_le_bytes()[0]).collect();
        let op = match ((command >> 9) & 15, bytes.as_slice()) {
            (0, [_]) => Op::Quick,
            (1, [_, value]) => Op::SendByte(*value),
            (2, [_]) => Op::ReceiveByte,
            (3, [_, register, value]) => Op::WriteByte {
                register: *register,
                value: *value,
            },
            (4, [_, register, _]) => Op::ReadByte {
                register: *register,
            },
            (5, [_, register, high, low]) => Op::WriteWord {
                register: *register,
                value: u16::from_be_bytes([*high, *low]),
            },
            (6, [_, register, _]) => Op::ReadWord {
                register: *register,
            },
            _ => return None,
        };
        self.i2c.transfer(device, op)
    }

    pub(super) fn irq_change(&mut self) -> Option<bool> {
        let level = self.regs[0] & (ENABLE | RESET) == ENABLE
            && self.regs[0x38 / 4] & self.regs[0x3c / 4] != 0;
        if level == self.asserted {
            return None;
        }
        self.asserted = level;
        Some(level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery(smb: &mut Smbus) {
        smb.write(0, ENABLE);
        smb.write(0x40, 0x40);
        for byte in [
            0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ] {
            smb.write(0x40, byte);
        }
        smb.write(0x40, RESET | 0x16);
        smb.write(0x30, RESET | (7 << 9));
    }

    #[test]
    fn firmware_i2c_block_discovery_returns_packet_without_smbus_length_prefix() {
        let mut smb = Smbus::default();
        discovery(&mut smb);
        assert_eq!(smb.read(0x30), 7 << 9);
        smb.write(0x40, 0x41);
        smb.write(0x30, RESET | (8 << 9) | 0x0c);
        assert_eq!(smb.read(0xc) >> 16, 12);
        let reply: Vec<_> = (0..12).map(|_| smb.read(0x44).to_le_bytes()[0]).collect();
        assert_eq!(
            &reply[..11],
            &[0x20, 0xff, 0, 24, 0, 0xe1, 0x21, 0x30, 0, 4, 2]
        );
        assert_eq!(reply[11], super::super::poe::checksum(&reply[..11]));
        assert_eq!(smb.read(0x44), 0);
        assert_eq!(smb.read(0xc) >> 16, 0);
    }

    #[test]
    fn read_without_pending_response_cannot_replay_a_consumed_packet() {
        let mut smb = Smbus::default();
        discovery(&mut smb);
        smb.write(0x40, 0x41);
        smb.write(0x30, RESET | (8 << 9) | 0x0c);
        smb.write(0x40, 0x41);
        smb.write(0x30, RESET | (8 << 9) | 0x0c);
        assert_eq!((smb.read(0x30) >> 25) & 7, 3);
        assert_eq!(smb.read(0x44), 0);
    }

    #[test]
    fn seven_bit_0x40_is_not_an_alias_of_wire_address_0x40() {
        let mut smb = Smbus::default();
        smb.write(0, ENABLE);
        smb.write(0x40, 0x80);
        smb.write(0x30, RESET | (7 << 9));
        assert_eq!((smb.read(0x30) >> 25) & 7, 2);
    }

    #[test]
    fn short_frame_is_data_nacked_without_a_reply() {
        let mut smb = Smbus::default();
        smb.write(0, ENABLE);
        smb.write(0x40, 0x40);
        smb.write(0x40, RESET | 0x20);
        smb.write(0x30, RESET | (7 << 9));
        assert_eq!((smb.read(0x30) >> 25) & 7, 3);
        assert_eq!(smb.poe_reply, None);
    }

    #[test]
    fn malformed_new_write_invalidates_the_previous_reply() {
        let mut smb = Smbus::default();
        discovery(&mut smb);
        smb.write(0x40, 0x40);
        smb.write(0x30, RESET | (7 << 9));
        smb.write(0x40, 0x41);
        smb.write(0x30, RESET | (8 << 9) | 0x0c);
        assert_eq!((smb.read(0x30) >> 25) & 7, 3);
        assert_eq!(smb.read(0x44), 0);
    }

    #[test]
    fn tx_fifo_is_bounded_and_flush_clears_overflow() {
        let mut smb = Smbus::default();
        for _ in 0..65 {
            smb.write(0x40, 0xffff_ffff);
        }
        assert_eq!(smb.tx, vec![RESET | 0xff; 64]);
        assert!(smb.tx_overflow);
        smb.write(0xc, (1 << 30) | 0x1200);
        assert!(smb.tx.is_empty());
        assert!(!smb.tx_overflow);
        assert_eq!(smb.read(0xc), 0x1200);
    }

    #[test]
    fn controller_reset_discards_queued_tx_bytes() {
        let mut smb = Smbus::default();
        smb.write(0x40, 0x40);
        smb.write(0, RESET);
        assert!(smb.tx.is_empty());
    }

    #[test]
    fn absent_slave_nacks_and_completion_can_be_masked_and_cleared() {
        let mut smb = Smbus::default();
        smb.write(0, ENABLE);
        smb.write(0x30, RESET | (3 << 9));
        assert_eq!(smb.read(0x30), (2 << 25) | (3 << 9));
        assert_eq!(smb.irq_change(), None);
        smb.write(0x38, DONE);
        assert_eq!(smb.irq_change(), Some(true));
        smb.write(0x3c, DONE);
        assert_eq!(smb.irq_change(), Some(false));
        assert_eq!(smb.read(0x44), 0);
    }

    #[test]
    fn reset_clears_pending_and_disabled_controller_cannot_complete() {
        let mut smb = Smbus::default();
        smb.write(0x30, RESET);
        assert_eq!(smb.read(0x3c), 0);
        smb.write(0, ENABLE);
        smb.write(0x38, DONE);
        smb.write(0x30, RESET);
        assert_eq!(smb.irq_change(), Some(true));
        smb.write(0, RESET);
        assert_eq!(smb.irq_change(), Some(false));
        assert_eq!(smb.read(0x3c), 0);
    }

    #[test]
    fn cmic_known_empty_addresses_nack_but_other_unknown_devices_complete() {
        let mut smb = Smbus::cmic();
        smb.write(0, ENABLE);

        for wire_address in [0x7e, 0xa0, 0xa2] {
            smb.write(0x40, wire_address);
            smb.write(0x30, RESET);
            assert_eq!((smb.read(0x30) >> 25) & 7, 2);
        }

        smb.write(0x40, 0x80);
        smb.write(0x30, RESET);
        assert_eq!((smb.read(0x30) >> 25) & 7, 0);
    }
}
