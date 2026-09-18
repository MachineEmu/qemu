#![warn(missing_docs)]

//! Pure Rust register model for the board-local UDM Pro peripherals.
//!
//! PCI enumeration, QEMU memory regions, DMA, and interrupt delivery remain
//! in the thin QEMU adapter. This crate owns stable register semantics and
//! board constants so those semantics can be tested without QEMU.

/// Alpine Ethernet descriptor and register model.
pub mod ethernet;

use std::collections::HashMap;

use board_core::{AccessWidth, Describe, Machine, MachineContext, MmioError, Window};

/// Compatibility UART base address.
pub const UART_BASE: u64 = 0xfd88_3000;
/// Peripheral-bus-system base address.
pub const PBS_BASE: u64 = 0xfd8a_8000;
/// `SerDes` compatibility block base address.
pub const SERDES_BASE: u64 = 0xfd8c_0000;
/// `DesignWare` SPI controller base address.
pub const SPI_BASE: u64 = 0xfd88_2000;
/// Alpine PCI controller register base address.
pub const PCIE_CTRL_BASE: u64 = 0xfd80_0000;
/// Alpine PCI DBI base address.
pub const PCIE_DBI_BASE: u64 = 0xfd81_0000;
/// Internal PCI ECAM base address.
pub const INTERNAL_ECAM_BASE: u64 = 0xfbc0_0000;
/// Internal PCI MMIO base address.
pub const INTERNAL_MMIO_BASE: u64 = 0xfe00_0000;
/// Enabled Alpine SP805 watchdog base address.
pub const WDT0_BASE: u64 = 0xfd88_c000;
const GPIO_BASES: [u64; 6] = [
    0xfd88_7000,
    0xfd88_8000,
    0xfd88_9000,
    0xfd88_a000,
    0xfd88_b000,
    0xfd89_7000,
];

const UART_LSR: u64 = 0x14;
const UART_LSR_EMPTY: u32 = 0x60;
const PBS_REVISION: u64 = 0x15c;
const PBS_PCIE_CONF: u64 = 0xe4;
const PCIE_LINK_STATUS: u64 = 0x91c;
const PCIE_LINK_UP: u32 = 1 << 4;
const WDT_LOAD: u64 = 0x00;
const WDT_VALUE: u64 = 0x04;
const WDT_CONTROL: u64 = 0x08;
const WDT_INTCLR: u64 = 0x0c;
const WDT_RIS: u64 = 0x10;
const WDT_MIS: u64 = 0x14;
const WDT_BGLOAD: u64 = 0x18;
const WDT_PID0: u64 = 0xfe0;
const WDT_PID1: u64 = 0xfe4;
const WDT_PID2: u64 = 0xfe8;
const WDT_CID0: u64 = 0xff0;
const WDT_CID1: u64 = 0xff4;
const WDT_CID2: u64 = 0xff8;
const WDT_CID3: u64 = 0xffc;
const WDT_IRQ: u32 = 13;
const WDT_TICK_NS: u64 = 4;

/// Board state for the board-local compatibility registers.
#[derive(Debug, Default)]
pub struct UdmProBoard {
    uart_tx: Vec<u8>,
    registers: HashMap<u64, u32>,
    watchdog_load: u32,
    watchdog_control: u32,
    watchdog_ris: u32,
    watchdog_deadline: Option<board_core::VirtualTime>,
    gpio_values: [u8; 6],
    gpio_direction: [u8; 6],
}

const UDM_WINDOWS: [Window; 12] = [
    Window {
        base: PCIE_CTRL_BASE,
        size: 0x20_000,
        priority: 0,
        device: 3,
    },
    Window {
        base: SPI_BASE,
        size: 0x1000,
        priority: 0,
        device: 4,
    },
    Window {
        base: SERDES_BASE,
        size: 0x2400,
        priority: 0,
        device: 5,
    },
    Window {
        base: UART_BASE,
        size: 0x1000,
        priority: 0,
        device: 1,
    },
    Window {
        base: PBS_BASE,
        size: 0x1000,
        priority: 0,
        device: 2,
    },
    Window {
        base: WDT0_BASE,
        size: 0x1000,
        priority: 0,
        device: 6,
    },
    Window {
        base: GPIO_BASES[0],
        size: 0x1000,
        priority: 0,
        device: 10,
    },
    Window {
        base: GPIO_BASES[1],
        size: 0x1000,
        priority: 0,
        device: 11,
    },
    Window {
        base: GPIO_BASES[2],
        size: 0x1000,
        priority: 0,
        device: 12,
    },
    Window {
        base: GPIO_BASES[3],
        size: 0x1000,
        priority: 0,
        device: 13,
    },
    Window {
        base: GPIO_BASES[4],
        size: 0x1000,
        priority: 0,
        device: 14,
    },
    Window {
        base: GPIO_BASES[5],
        size: 0x1000,
        priority: 0,
        device: 15,
    },
];
const NO_IRQS: [u32; 0] = [];

impl Describe for UdmProBoard {
    fn windows(&self) -> &[Window] {
        &UDM_WINDOWS
    }
    fn irq_lines(&self) -> &[u32] {
        &NO_IRQS
    }
}

impl Machine for UdmProBoard {
    fn reset(&mut self, _ctx: &mut MachineContext<'_>) {
        self.registers.clear();
        self.uart_tx.clear();
        self.watchdog_load = 0;
        self.watchdog_control = 0;
        self.watchdog_ris = 0;
        self.watchdog_deadline = None;
        self.gpio_values = [0; 6];
        self.gpio_direction = [0; 6];
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
        Self::mmio_write(
            self,
            addr,
            u32::try_from(value).map_err(|_| MmioError::BusError)?,
        );
        self.watchdog_reschedule(ctx.now, addr, &mut ctx.events);
        Ok(())
    }
    fn advance_to(&mut self, ctx: &mut MachineContext<'_>) {
        let Some(deadline) = self.watchdog_deadline else {
            return;
        };
        if ctx.now < deadline {
            return;
        }
        self.watchdog_deadline = None;
        if self.watchdog_ris != 0 && self.watchdog_control & 0x2 != 0 {
            ctx.events.push(board_core::Event::ResetRequest);
        } else {
            self.watchdog_ris = 1;
            if self.watchdog_control & 0x1 != 0 {
                ctx.events.push(board_core::Event::IrqLevel {
                    line: WDT_IRQ,
                    level: true,
                });
            }
            self.watchdog_deadline = Some(
                ctx.now
                    .saturating_add(u64::from(self.watchdog_load).saturating_mul(WDT_TICK_NS)),
            );
        }
    }
    fn next_deadline(&self) -> Option<board_core::VirtualTime> {
        self.watchdog_deadline
    }
    fn take_uart_tx(&mut self) -> Option<u8> {
        self.take_uart_tx_byte()
    }
}

impl UdmProBoard {
    /// Creates a reset board state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads a 32-bit register at a physical address.
    pub fn mmio_read(&mut self, address: u64) -> u32 {
        if (UART_BASE..UART_BASE + 0x1000).contains(&address) {
            return match address - UART_BASE {
                UART_LSR => UART_LSR_EMPTY,
                _ => 0,
            };
        }
        if (PBS_BASE..PBS_BASE + 0x1000).contains(&address) {
            return match address - PBS_BASE {
                PBS_REVISION => 0x0001_0000,
                PBS_PCIE_CONF => 1,
                _ => 0,
            };
        }
        if (PCIE_CTRL_BASE..PCIE_CTRL_BASE + 0x20_000).contains(&address) {
            return match address - PCIE_CTRL_BASE {
                // Preserve the Alpine V2 controller contract from the old
                // virt adapter: RC mode, enabled LTSSM, and link state L0.
                0xc8 => 4,
                0x16c => 0,
                0x1000 => 1,
                0x1080 | 0x2080 => 0x11 << 3,
                0x2280 => u32::MAX,
                0x4 | 0x80 | 0x84 | 0x728 | 0x72c => 3,
                PCIE_LINK_STATUS => PCIE_LINK_UP,
                _ => self.registers.get(&address).copied().unwrap_or(0),
            };
        }
        if (WDT0_BASE..WDT0_BASE + 0x1000).contains(&address) {
            return match address - WDT0_BASE {
                WDT_LOAD | WDT_BGLOAD | WDT_VALUE => self.watchdog_load,
                WDT_CONTROL => self.watchdog_control,
                WDT_RIS => self.watchdog_ris,
                WDT_MIS => self.watchdog_ris & (self.watchdog_control >> 1),
                // SP805 PrimeCell identity: PID 0x05, 0x18, 0x04, 0x00;
                // CID 0x0d, 0xf0, 0x05, 0xb1.
                WDT_PID0 | WDT_CID2 => 0x05,
                WDT_PID1 => 0x18,
                WDT_PID2 => 0x04,
                WDT_CID0 => 0x0d,
                WDT_CID1 => 0xf0,
                WDT_CID3 => 0xb1,
                _ => 0,
            };
        }
        if let Some((index, offset)) = Self::gpio_address(address) {
            return match offset {
                0..=0x3fc => u32::from(self.gpio_values[index]) & (((offset >> 2) & 0xff) as u32),
                0x400 => u32::from(self.gpio_direction[index]),
                0xfe0 => 0x61,
                0xfe4 => 0x10,
                0xfe8 => 0x04,
                0xff0 => 0x0d,
                0xff4 => 0xf0,
                0xff8 => 0x05,
                0xffc => 0xb1,
                _ => 0,
            };
        }
        self.registers.get(&address).copied().unwrap_or(0)
    }

    /// Writes a 32-bit register at a physical address.
    pub fn mmio_write(&mut self, address: u64, value: u32) {
        if (UART_BASE..UART_BASE + 0x1000).contains(&address) && address == UART_BASE {
            self.uart_tx
                .push(u8::try_from(value & 0xff).unwrap_or_default());
            return;
        }
        if (PBS_BASE..PBS_BASE + 0x1000).contains(&address)
            || (SERDES_BASE..SERDES_BASE + 0x2400).contains(&address)
        {
            return;
        }
        if (WDT0_BASE..WDT0_BASE + 0x1000).contains(&address) {
            match address - WDT0_BASE {
                WDT_LOAD | WDT_BGLOAD => self.watchdog_load = value,
                WDT_CONTROL => self.watchdog_control = value & 0x3,
                WDT_INTCLR => self.watchdog_ris = 0,
                _ => {}
            }
            return;
        }
        if let Some((index, offset)) = Self::gpio_address(address) {
            match offset {
                0..=0x3fc => {
                    let mask = ((offset >> 2) & 0xff).to_le_bytes()[0];
                    self.gpio_values[index] =
                        (self.gpio_values[index] & !mask) | (value.to_le_bytes()[0] & mask);
                }
                0x400 => self.gpio_direction[index] = value.to_le_bytes()[0],
                _ => {}
            }
            return;
        }
        self.registers.insert(address, value);
    }

    fn gpio_address(address: u64) -> Option<(usize, u64)> {
        GPIO_BASES.iter().enumerate().find_map(|(index, base)| {
            address
                .checked_sub(*base)
                .filter(|offset| *offset < 0x1000)
                .map(|offset| (index, offset))
        })
    }

    fn watchdog_reschedule(
        &mut self,
        now: board_core::VirtualTime,
        address: u64,
        events: &mut Vec<board_core::Event>,
    ) {
        if !(WDT0_BASE..WDT0_BASE + 0x1000).contains(&address) {
            return;
        }
        match address - WDT0_BASE {
            WDT_LOAD | WDT_BGLOAD | WDT_CONTROL => {
                if self.watchdog_control & 0x1 != 0 {
                    self.watchdog_deadline =
                        Some(now.saturating_add(
                            u64::from(self.watchdog_load).saturating_mul(WDT_TICK_NS),
                        ));
                } else {
                    self.watchdog_deadline = None;
                }
            }
            WDT_INTCLR => {
                events.push(board_core::Event::IrqLevel {
                    line: WDT_IRQ,
                    level: false,
                });
                if self.watchdog_control & 0x1 != 0 {
                    self.watchdog_deadline =
                        Some(now.saturating_add(
                            u64::from(self.watchdog_load).saturating_mul(WDT_TICK_NS),
                        ));
                }
            }
            _ => {}
        }
    }

    /// Takes bytes written to the compatibility UART.
    pub fn take_uart_tx(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.uart_tx)
    }

    /// Removes one byte written by the guest, preserving FIFO order.
    pub fn take_uart_tx_byte(&mut self) -> Option<u8> {
        if self.uart_tx.is_empty() {
            None
        } else {
            Some(self.uart_tx.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_pcie_preserves_the_boot_probe_contract() {
        let mut board = UdmProBoard::new();
        let probe = [0xc8, 0x16c, 0x1000, 0x1080, 0x2080, 0x2280];
        let values = probe.map(|offset| board.mmio_read(PCIE_CTRL_BASE + offset));
        assert_eq!(values, [4, 0, 1, 0x88, 0x88, u32::MAX]);
    }

    #[test]
    fn pbs_and_pcie_status_are_deterministic() {
        let mut board = UdmProBoard::new();
        assert_eq!(board.mmio_read(PBS_BASE + PBS_REVISION), 0x0001_0000);
        assert_eq!(board.mmio_read(PBS_BASE + PBS_PCIE_CONF), 1);
        assert_eq!(
            board.mmio_read(PCIE_CTRL_BASE + PCIE_LINK_STATUS),
            PCIE_LINK_UP
        );
    }

    #[test]
    fn uart_tx_is_owned_by_the_board_model() {
        let mut board = UdmProBoard::new();
        board.mmio_write(UART_BASE, u32::from(b'X'));
        assert_eq!(board.take_uart_tx(), vec![b'X']);
    }

    #[test]
    fn pl061_gpio_data_register_preserves_masked_output_bits() {
        let mut board = UdmProBoard::new();
        board.mmio_write(GPIO_BASES[0] + 0x3fc, 0xa5);
        assert_eq!(board.mmio_read(GPIO_BASES[0] + 0x3fc), 0xa5);
    }

    #[test]
    fn pl061_gpio_direction_register_round_trips() {
        let mut board = UdmProBoard::new();
        board.mmio_write(GPIO_BASES[2] + 0x400, 0x3c);
        assert_eq!(board.mmio_read(GPIO_BASES[2] + 0x400), 0x3c);
    }

    #[test]
    fn sp805_watchdog_registers_round_trip() {
        let mut board = UdmProBoard::new();
        assert_eq!(board.mmio_read(WDT0_BASE + WDT_PID0), 0x05);
        assert_eq!(board.mmio_read(WDT0_BASE + WDT_CID3), 0xb1);
        board.mmio_write(WDT0_BASE + WDT_LOAD, 0x1234);
        board.mmio_write(WDT0_BASE + WDT_CONTROL, 0x3);
        assert_eq!(board.mmio_read(WDT0_BASE + WDT_VALUE), 0x1234);
        assert_eq!(board.mmio_read(WDT0_BASE + WDT_CONTROL), 0x3);
    }

    #[test]
    fn sp805_watchdog_expiry_raises_interrupt_then_requests_reset() {
        let mut board = UdmProBoard::new();
        let mut ctx = MachineContext::new(0);
        Machine::mmio_write(
            &mut board,
            &mut ctx,
            WDT0_BASE + WDT_LOAD,
            10,
            AccessWidth::U32,
        )
        .unwrap();
        Machine::mmio_write(
            &mut board,
            &mut ctx,
            WDT0_BASE + WDT_CONTROL,
            3,
            AccessWidth::U32,
        )
        .unwrap();
        ctx.now = 40;
        Machine::advance_to(&mut board, &mut ctx);
        assert!(ctx.events.contains(&board_core::Event::IrqLevel {
            line: WDT_IRQ,
            level: true,
        }));
        ctx.events.clear();
        ctx.now = 80;
        Machine::advance_to(&mut board, &mut ctx);
        assert!(ctx.events.contains(&board_core::Event::ResetRequest));
    }
}
