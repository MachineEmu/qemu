//! `CMICd` CMC interrupt aggregation, packet DMA and MIIM.
//! AXI masks/status offsets come from linux-user-bde's `_cmicd_interrupt`.
//! MIIM source bit 7 is defined by `OpenBCM` `include/soc/cmicm.h`.

pub(super) const IRQ: u32 = 184;
const STATUS: [u64; 7] = [0x400, 0x404, 0x408, 0x40c, 0x410, 0x4b0, 0x4b4];
const MASK: [u64; 7] = [0x428, 0x42c, 0x430, 0x434, 0x438, 0x4c0, 0x4c4];
const MIIM_DONE: u32 = 1 << 7;

// MIIM parameter word, register `+0x80`, as `cmicd_miim_op` at `0xc0014de0`
// assembles it: the ring select in bits 22..25, an external ring flag in bit
// 25, a clause 45 flag in bit 21, the PHY address in bits 16..21 and, for
// writes, the data in the low half.
const MIIM_PARAM_PHY: u32 = 0x1f_0000;
const MIIM_PARAM_RING: u32 = 0x1c0_0000;
const MIIM_PARAM_CLAUSE45: u32 = 1 << 21;
// Ring the `et` PHY answers on. `mdiobus_register` scans rings 1 and 2, the
// ring selects in the platform data of the two `iproc_cmicd_mdio` devices at
// `0xc14a62c8` and `0xc14a61c8`; both carry bus id 1, so `get_iproc_mdiobus`
// finds the PHY on either. Ring 2 is the bus id 1 device the lookup tries
// first; which ring carries the part on real hardware is not recoverable.
const MIIM_PHY_RING: u32 = 2;
// Start bits in the control register, `+0x8c`.
const MIIM_CTRL_WRITE: u32 = 1 << 0;
const MIIM_CTRL_READ: u32 = 1 << 1;
// Clause 22 register address, from the address register `+0x88`.
const MIIM_REGISTER: u32 = 0x1f;

use super::cmic_dma::PacketDma;
use super::cmic_sbus::{CopyDma, SChannel, SbusDma, SwitchStore};
use super::mdio::{self, Phy5461};
use board_core::MachineContext;

#[derive(Debug, Default)]
pub(super) struct Cmic {
    pending: [[u32; 7]; 3],
    masks: [[u32; 7]; 3],
    control: [u32; 3],
    miim_param: [u32; 3],
    miim_address: [u32; 3],
    /// Latched read data. `None` is an address nothing answered on, which
    /// reads back as the floating bus.
    miim_data: [Option<u16>; 3],
    phy: Phy5461,
    packet: [PacketDma; 3],
    sbus: [[SbusDma; 3]; 3],
    copy: [CopyDma; 3],
    schan: [SChannel; 3],
    store: SwitchStore,
    asserted: bool,
}

fn decode(offset: u64) -> Option<(usize, u64)> {
    let offset = offset.checked_sub(0x31000)?;
    (offset < 0x3000).then_some(((offset / 0x1000) as usize, offset % 0x1000))
}

impl Cmic {
    pub(super) fn read(&self, offset: u64) -> Option<u32> {
        let (cmc, reg) = decode(offset)?;
        if let Some(value) = self.packet[cmc].read(reg) {
            return Some(value);
        }
        if let Some(value) = self.schan[cmc].read(reg) {
            return Some(value);
        }
        if (0x600..0x6f0).contains(&reg) {
            return Some(
                self.sbus[cmc][((reg - 0x600) / 0x50) as usize].read((reg - 0x600) % 0x50),
            );
        }
        if (0x3a0..0x3c8).contains(&reg) {
            return Some(self.copy[cmc].read(reg - 0x3a0));
        }
        if let Some(bank) = STATUS.iter().position(|&item| item == reg) {
            return Some(
                self.pending[cmc][bank]
                    | if bank == 0 {
                        self.engine_pending(cmc)
                    } else {
                        0
                    },
            );
        }
        if let Some(bank) = MASK.iter().position(|&item| item == reg) {
            return Some(self.masks[cmc][bank]);
        }
        match reg {
            0x80 => Some(self.miim_param[cmc]),
            0x84 => Some(self.miim_data[cmc].map_or(0xffff, u32::from)),
            0x88 => Some(self.miim_address[cmc]),
            0x8c => Some(self.control[cmc]),
            0x90 => Some(u32::from(self.pending[cmc][0] & MIIM_DONE != 0)),
            _ => None,
        }
    }

    pub(super) fn write(&mut self, offset: u64, value: u32) -> bool {
        let Some((cmc, reg)) = decode(offset) else {
            return false;
        };
        if self.packet[cmc].write(reg, value) {
            return true;
        }
        if self.schan[cmc].write(reg, value, &mut self.store) {
            return true;
        }
        if (0x600..0x6f0).contains(&reg) {
            self.sbus[cmc][((reg - 0x600) / 0x50) as usize].write((reg - 0x600) % 0x50, value);
            return true;
        }
        if (0x3a0..0x3c8).contains(&reg) {
            self.copy[cmc].write(reg - 0x3a0, value);
            return true;
        }
        if STATUS.contains(&reg) || reg == 0x84 || reg == 0x90 {
            return true;
        }
        if let Some(bank) = MASK.iter().position(|&item| item == reg) {
            self.masks[cmc][bank] = value;
            return true;
        }
        if reg == 0x80 {
            self.miim_param[cmc] = value;
            return true;
        }
        if reg == 0x88 {
            self.miim_address[cmc] = value;
            return true;
        }
        if reg == 0x8c {
            self.control[cmc] = value;
            // Clearing the read/write start bits acknowledges the completion.
            if value & (MIIM_CTRL_READ | MIIM_CTRL_WRITE) != 0 {
                self.miim_transfer(cmc, value);
                self.pending[cmc][0] |= MIIM_DONE;
            } else {
                self.pending[cmc][0] &= !MIIM_DONE;
            }
            return true;
        }
        false
    }

    pub(super) fn irq_change(&mut self) -> Option<bool> {
        let level = self
            .pending
            .iter()
            .flatten()
            .zip(self.masks.iter().flatten())
            .any(|(pending, mask)| pending & mask != 0)
            || (0..3).any(|cmc| self.engine_pending(cmc) & self.masks[cmc][0] != 0);
        if level == self.asserted {
            return None;
        }
        self.asserted = level;
        Some(level)
    }

    pub(super) fn pump(&mut self, ctx: &mut MachineContext<'_>) {
        for packet in &mut self.packet {
            packet.pump(ctx);
        }
        for channels in &mut self.sbus {
            for channel in channels {
                channel.pump(ctx, &mut self.store);
            }
        }
        for copy in &mut self.copy {
            copy.pump(ctx);
        }
    }

    pub(super) fn receive(&mut self, ctx: &mut MachineContext<'_>, frame: &[u8]) {
        for packet in &mut self.packet {
            if packet.receive(ctx, frame) {
                break;
            }
        }
    }

    /// Runs the transfer `cmicd_miim_op` staged in the parameter and address
    /// registers. The hardware completes it and raises the MIIM source; the
    /// driver polls the done bit rather than taking the interrupt, so the
    /// whole transfer happens inside the write that starts it.
    ///
    /// One [`Phy5461`] answers at [`mdio::PHY_ADDRESS`] on [`MIIM_PHY_RING`].
    /// Every other address is an empty bus: `mdiobus_scan` reads `0xffff`
    /// there and registers no device, which is what keeps the scan from
    /// inventing a PHY per address.
    fn miim_transfer(&mut self, cmc: usize, control: u32) {
        let param = self.miim_param[cmc];
        let phy = (param & MIIM_PARAM_PHY) >> 16;
        let ring = (param & MIIM_PARAM_RING) >> 22;
        let register = self.miim_address[cmc] & MIIM_REGISTER;
        if ring != MIIM_PHY_RING || param & MIIM_PARAM_CLAUSE45 != 0 || phy != mdio::PHY_ADDRESS {
            self.miim_data[cmc] = None;
            return;
        }
        if control & MIIM_CTRL_WRITE != 0 {
            self.phy.write(register, param as u16);
        } else {
            self.miim_data[cmc] = Some(self.phy.read(register));
        }
    }

    fn engine_pending(&self, cmc: usize) -> u32 {
        self.packet[cmc].pending()
            | self.schan[cmc].pending()
            | if self.copy[cmc].done() { 1 << 21 } else { 0 }
            | self.sbus[cmc]
                .iter()
                .zip([2, 1, 0x40])
                .fold(0, |bits, (channel, mask)| {
                    bits | if channel.done() { mask } else { 0 }
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miim_completion_is_masked_and_acknowledged_at_its_source() {
        let mut cmic = Cmic::default();
        cmic.write(0x3308c, 2);
        assert_eq!(cmic.read(0x33400), Some(MIIM_DONE));
        assert_eq!(cmic.irq_change(), None);
        cmic.write(0x33428, MIIM_DONE);
        assert_eq!(cmic.irq_change(), Some(true));
        cmic.write(0x33400, MIIM_DONE);
        assert_eq!(cmic.read(0x33090), Some(1));
        cmic.write(0x3308c, 0);
        assert_eq!(cmic.irq_change(), Some(false));
        assert_eq!(cmic.read(0x33090), Some(0));
    }

    #[test]
    fn cmcs_share_a_level_without_losing_other_pending_sources() {
        let mut cmic = Cmic::default();
        cmic.write(0x31428, MIIM_DONE);
        cmic.write(0x33428, MIIM_DONE);
        cmic.write(0x3108c, 1);
        assert_eq!(cmic.irq_change(), Some(true));
        cmic.write(0x3308c, 2);
        cmic.write(0x31428, 0);
        assert_eq!(cmic.irq_change(), None);
        cmic.write(0x3308c, 0);
        assert_eq!(cmic.irq_change(), Some(false));
        cmic.write(0x31428, MIIM_DONE);
        assert_eq!(cmic.irq_change(), Some(true));
    }
}
