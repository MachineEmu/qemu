//! The BCM5461 gigabit PHY the vendor `et` driver drives over the `CMICd`
//! MDIO ring.
//!
//! The kernel reaches it through three layers, all of which the image pins
//! down exactly:
//!
//! * `chipphyrd` at `0xc001abfc` splits its second argument into a register
//!   bank (bits 8..12), a bank-select flag (bit 16) and a PHY address
//!   (`& 0xf`), then calls `phy5461_rd_reg` at `0xc00243c4`.
//! * `phy5461_rd_reg` and `phy5461_wr_reg` pass a hardcoded `0` argument of
//!   `1` to `iproc_mii_read`/`iproc_mii_write` — every PHY access the `et`
//!   driver makes goes to MDIO bus id 1.
//! * `get_iproc_mdiobus` at `0xc00152d4` resolves that id by looking for a
//!   registered PHY device named `iproc_mii:<n>:1:<addr>` for `n` in `0..=7`.
//!   When no such device exists it returns null and `iproc_mii_read` prints
//!   `iproc_mii_read : mdioubs:0:1 is invalid!` — the `0` is the null pointer
//!   and the `1` is the bus id, so the message names neither PHY nor register.
//!
//! Two `iproc_cmicd_mdio` platform devices carry bus id 1, at `0xc14a61c8`
//! and `0xc14a62c8`, with platform data `01 01 01 01` and `00 01 02 01`:
//! `{ unit, bus id, ring select, ... }`. `mdiobus_register` was observed
//! walking both rings, 1 and 2, across all 32 addresses. Since both devices
//! are bus id 1, `get_iproc_mdiobus` finds the PHY on either; which ring
//! carries the part on real hardware is not recoverable from the firmware,
//! and `cmic` puts it on the one the lookup reaches first.
//!
//! The address comes from `chipattach` at `0xc001c060`: it looks up the NVRAM
//! variable `et%dphyaddr` and, when unset — as it is against this model's
//! blank flash — falls back to `unit + 1`, so `et0` talks to address 1.

/// MDIO address `chipattach`'s `unit + 1` fallback selects for `et0`.
pub(super) const PHY_ADDRESS: u32 = 1;

/// Number of clause 22 registers.
const REGISTERS: usize = 32;

/// Basic mode control, register 0.
const BMCR: usize = 0;
/// Reset. Real silicon clears it once the reset completes; `phy5461_ge_reset`
/// at `0xc00246b0` polls it for 100 ms and prints `phy5461_ge_reset reset not
/// complete` if it is still set, so this model completes it within the write.
const BMCR_RESET: u16 = 1 << 15;
/// Restart autonegotiation, also self-clearing.
const BMCR_RESTART: u16 = 1 << 9;

/// Reset value: autonegotiation enabled, full duplex, 1000 Mbit/s.
/// `phy5461_ge_init` at `0xc00248ac` writes `0x1340` over it during bring-up.
const BMCR_RESET_VALUE: u16 = 0x1140;
/// Basic mode status, register 1: 100/10 capabilities, extended status,
/// autonegotiation complete, link up, autonegotiation able, extended
/// capability.
///
/// `phy5461_link_get` at `0xc0024a68` reads this register, and when the link
/// bit is set but autonegotiation has not completed it spins on it 50000
/// times at 10 us a turn. Reporting both bits together keeps that loop out of
/// the guest, which under TCG would cost half a second of wall time per poll.
const BMSR_RESET_VALUE: u16 = 0x792d;
/// PHY identifier, registers 2 and 3: Linux's `PHY_ID_BCM5461`, `0x002060c0`,
/// with revision 1 in the low nibble. `phy5461_init` at `0xc00249e4` reads
/// both and prints them.
const PHY_ID_HIGH: u16 = 0x0020;
const PHY_ID_LOW: u16 = 0x60c1;
/// Autonegotiation advertisement, register 4: 100/10 full and half, 802.3.
const ADVERTISE_RESET_VALUE: u16 = 0x01e1;
/// Link partner ability, register 5: the same, acknowledged.
const LPA_RESET_VALUE: u16 = 0x41e1;
/// Autonegotiation expansion, register 6: the link partner is able.
const EXPANSION_RESET_VALUE: u16 = 0x0001;
/// 1000BASE-T control, register 9: advertise 1000 full and half.
const GIGABIT_CONTROL_RESET_VALUE: u16 = 0x0300;
/// 1000BASE-T status, register 10: local and remote receiver OK, link partner
/// capable of 1000 full. `phy5461_speed_get` at `0xc0024d28` resolves the
/// speed from register 9 bit 9 against this register's bit 11.
const GIGABIT_STATUS_RESET_VALUE: u16 = 0x6800;
/// Extended status, register 15: 1000BASE-T full and half. `phy5461_speed_get`
/// at `0xc0024cc8` requires one of the four top bits before it reads the
/// 1000BASE-T pair.
const EXTENDED_STATUS_RESET_VALUE: u16 = 0x3000;

/// Registers the part drives itself; guest writes to them are dropped.
const READ_ONLY: [usize; 7] = [1, 2, 3, 5, 6, 10, 15];

#[derive(Debug)]
pub(super) struct Phy5461 {
    registers: [u16; REGISTERS],
}

impl Default for Phy5461 {
    fn default() -> Self {
        let mut registers = [0; REGISTERS];
        registers[BMCR] = BMCR_RESET_VALUE;
        registers[1] = BMSR_RESET_VALUE;
        registers[2] = PHY_ID_HIGH;
        registers[3] = PHY_ID_LOW;
        registers[4] = ADVERTISE_RESET_VALUE;
        registers[5] = LPA_RESET_VALUE;
        registers[6] = EXPANSION_RESET_VALUE;
        registers[9] = GIGABIT_CONTROL_RESET_VALUE;
        registers[10] = GIGABIT_STATUS_RESET_VALUE;
        registers[15] = EXTENDED_STATUS_RESET_VALUE;
        Self { registers }
    }
}

impl Phy5461 {
    pub(super) fn read(&self, register: u32) -> u16 {
        usize::try_from(register)
            .ok()
            .and_then(|register| self.registers.get(register).copied())
            .unwrap_or(0xffff)
    }

    pub(super) fn write(&mut self, register: u32, value: u16) {
        let Ok(register) = usize::try_from(register) else {
            return;
        };
        if register >= REGISTERS || READ_ONLY.contains(&register) {
            return;
        }
        if register == BMCR && value & BMCR_RESET != 0 {
            *self = Self::default();
            return;
        }
        self.registers[register] = if register == BMCR {
            value & !BMCR_RESTART
        } else {
            value
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_itself_as_a_bcm5461() {
        let phy = Phy5461::default();
        assert_eq!(phy.read(2), PHY_ID_HIGH);
        assert_eq!(phy.read(3), PHY_ID_LOW);
    }

    #[test]
    fn reports_a_settled_gigabit_link() {
        let phy = Phy5461::default();
        // `phy5461_link_get` needs the link bit, then autonegotiation
        // complete, or it spins for half a second on the second read.
        assert_eq!(phy.read(1) & 0x0004, 0x0004, "link up");
        assert_eq!(phy.read(1) & 0x0020, 0x0020, "autonegotiation complete");
        // `phy5461_speed_get` resolves 1000 full from this pair.
        assert_eq!(phy.read(9) & 0x0200, 0x0200);
        assert_eq!(phy.read(10) & 0x0800, 0x0800);
        assert_ne!(phy.read(15) & 0xf000, 0);
    }

    #[test]
    fn reset_completes_within_the_write_and_restores_defaults() {
        let mut phy = Phy5461::default();
        phy.write(4, 0);
        phy.write(BMCR as u32, BMCR_RESET_VALUE | BMCR_RESET);
        assert_eq!(phy.read(BMCR as u32) & BMCR_RESET, 0, "reset self-clears");
        assert_eq!(phy.read(4), ADVERTISE_RESET_VALUE);
    }

    #[test]
    fn autonegotiation_restart_self_clears_and_status_is_read_only() {
        let mut phy = Phy5461::default();
        phy.write(BMCR as u32, 0x1340);
        assert_eq!(phy.read(BMCR as u32), 0x1140);
        phy.write(1, 0);
        assert_eq!(phy.read(1), BMSR_RESET_VALUE);
    }

    #[test]
    fn registers_above_the_clause_22_window_read_as_floating() {
        assert_eq!(Phy5461::default().read(0x20), 0xffff);
    }
}
