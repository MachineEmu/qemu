#![warn(missing_docs)]

//! Small, QEMU-independent contracts shared by the board models and tools.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

pub mod dma;
pub mod mmc;
pub mod spi_nor;
pub mod tracer;

/// Width of one bus access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessWidth {
    /// One byte.
    U8 = 1,
    /// Two bytes.
    U16 = 2,
    /// Four bytes.
    U32 = 4,
    /// Eight bytes.
    U64 = 8,
}

impl AccessWidth {
    /// Converts a byte count supplied by a host.
    pub const fn from_bytes(bytes: u8) -> Option<Self> {
        match bytes {
            1 => Some(Self::U8),
            2 => Some(Self::U16),
            4 => Some(Self::U32),
            8 => Some(Self::U64),
            _ => None,
        }
    }
    /// Returns the width in bytes.
    pub const fn bytes(self) -> u8 {
        self as u8
    }
}

/// Failure reported by a model access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MmioError {
    /// No window owns the address.
    #[error("unmapped address")]
    Unmapped,
    /// Width is not supported.
    #[error("invalid access width")]
    InvalidWidth,
    /// Address is not aligned.
    #[error("misaligned access")]
    Misaligned,
    /// The model or bus failed.
    #[error("bus error")]
    BusError,
}

/// A documented physical address window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// First address.
    pub base: u64,
    /// Window length.
    pub size: u64,
    /// Priority used to resolve overlaps.
    pub priority: u32,
    /// Stable device identifier.
    pub device: u32,
}

/// Sorted address map with deterministic overlap handling.
#[derive(Debug, Clone)]
pub struct AddressMap {
    windows: Vec<Window>,
}

impl AddressMap {
    /// Builds a map, rejecting equal-priority overlaps.
    pub fn new(mut windows: Vec<Window>) -> Result<Self, MmioError> {
        windows.sort_by_key(|w| w.base);
        for (index, left) in windows.iter().enumerate() {
            for right in windows.iter().skip(index + 1) {
                if right.base >= left.base.saturating_add(left.size) {
                    break;
                }
                if left.priority == right.priority {
                    return Err(MmioError::BusError);
                }
            }
        }
        Ok(Self { windows })
    }
    /// Returns the highest-priority window containing an address.
    pub fn lookup(&self, address: u64) -> Option<Window> {
        self.windows
            .iter()
            .filter(|w| address >= w.base && address - w.base < w.size)
            .max_by_key(|w| w.priority)
            .copied()
    }
    /// Returns the immutable metadata table.
    pub fn windows(&self) -> &[Window] {
        &self.windows
    }
}

/// Dense resettable register storage for a window.
#[derive(Debug, Clone)]
pub struct RegFile {
    reset: Box<[u32]>,
    values: Box<[u32]>,
}

impl RegFile {
    /// Creates a register file from its reset image.
    pub fn new(reset: Box<[u32]>) -> Self {
        Self {
            values: reset.clone(),
            reset,
        }
    }
    /// Reads a word offset.
    pub fn read(&self, offset: usize) -> Option<u32> {
        self.values.get(offset / 4).copied()
    }
    /// Writes a word offset.
    pub fn write(&mut self, offset: usize, value: u32) -> bool {
        self.values
            .get_mut(offset / 4)
            .map(|slot| *slot = value)
            .is_some()
    }
    /// Restores all registers to their reset image.
    pub fn reset(&mut self) {
        self.values.clone_from(&self.reset);
    }
}

/// Virtual nanoseconds.
pub type VirtualTime = u64;

/// An output generated while executing a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Changes an interrupt line.
    IrqLevel {
        /// Line number.
        line: u32,
        /// New level.
        level: bool,
    },
    /// Sends one UART byte.
    UartTx {
        /// Port number.
        port: u32,
        /// Byte.
        byte: u8,
    },
    /// A frame transmitted by a board Ethernet port.
    NetTx {
        /// Board Ethernet port.
        port: u32,
        /// Owned frame bytes.
        frame: Vec<u8>,
    },
    /// A normalized Ethernet packet requiring backend preparation.
    NetTxOffload {
        /// Board endpoint.
        port: u32,
        /// Hardware queue, scoped to this endpoint.
        queue: u32,
        /// Hardware-independent request.
        request: net_offload::Request,
        /// Owned unsegmented Ethernet bytes.
        frame: Vec<u8>,
    },
    /// A newline-terminated JSON snapshot for a host-side device display.
    FrontPanel {
        /// UTF-8 payload owned by the event batch.
        payload: Vec<u8>,
    },
    /// Requests a board reset.
    ResetRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deadline {
    at: VirtualTime,
    sequence: u64,
}
impl Ord for Deadline {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}
impl PartialOrd for Deadline {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-call context shared by a machine and its devices.
pub struct MachineContext<'a> {
    /// Current virtual time.
    pub now: VirtualTime,
    /// Outputs produced during this call.
    pub events: Vec<Event>,
    /// Optional host memory bus borrowed for this execution call.
    pub dma: Option<&'a mut dyn dma::DmaBus>,
    /// Optional bounded diagnostic tracer for this execution call.
    pub tracer: Option<&'a mut tracer::Tracer>,
    deadlines: BinaryHeap<Deadline>,
    next_sequence: u64,
}

impl MachineContext<'_> {
    /// Creates an empty execution context.
    pub fn new(now: VirtualTime) -> Self {
        Self {
            now,
            events: Vec::new(),
            dma: None,
            tracer: None,
            deadlines: BinaryHeap::new(),
            next_sequence: 0,
        }
    }
    /// Creates a context with a host DMA bus borrowed for this call.
    pub fn with_dma<'a>(now: VirtualTime, dma: &'a mut dyn dma::DmaBus) -> MachineContext<'a> {
        MachineContext {
            now,
            events: Vec::new(),
            dma: Some(dma),
            tracer: None,
            deadlines: BinaryHeap::new(),
            next_sequence: 0,
        }
    }
    /// Schedules work at a virtual time.
    pub fn schedule(&mut self, at: VirtualTime) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.deadlines.push(Deadline { at, sequence });
    }
    /// Returns the next scheduled time.
    pub fn next_deadline(&self) -> Option<VirtualTime> {
        self.deadlines.peek().map(|d| d.at)
    }
    /// Removes all pending work and outputs.
    pub fn clear(&mut self) {
        self.deadlines.clear();
        self.events.clear();
    }
}

/// The hot-path contract implemented by a board.
pub trait Machine {
    /// Resets model state.
    fn reset(&mut self, ctx: &mut MachineContext<'_>);
    /// Reads one MMIO value.
    fn mmio_read(
        &mut self,
        ctx: &mut MachineContext<'_>,
        addr: u64,
        width: AccessWidth,
    ) -> Result<u64, MmioError>;
    /// Writes one MMIO value.
    fn mmio_write(
        &mut self,
        ctx: &mut MachineContext<'_>,
        addr: u64,
        value: u64,
        width: AccessWidth,
    ) -> Result<(), MmioError>;
    /// Runs due scheduled work.
    fn advance_to(&mut self, ctx: &mut MachineContext<'_>);
    /// Returns the next deadline.
    fn next_deadline(&self) -> Option<VirtualTime>;
    /// Delivers one byte from a host-facing UART input.
    fn uart_rx(&mut self, _ctx: &mut MachineContext<'_>, _port: u32, _byte: u8) {}
    /// Takes one byte queued for a host-facing UART output.
    fn take_uart_tx(&mut self) -> Option<u8> {
        None
    }
    /// Reports whether an inbound Ethernet frame can consume guest state.
    fn net_can_receive(&self, _port: u32) -> bool {
        true
    }
    /// Delivers one inbound Ethernet frame to the board.
    fn net_rx(&mut self, _ctx: &mut MachineContext<'_>, _port: u32, _frame: &[u8]) {}
}

/// Cold-path board metadata.
pub trait Describe {
    /// Returns the address windows.
    fn windows(&self) -> &[Window];
    /// Returns interrupt line metadata.
    fn irq_lines(&self) -> &[u32];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_map_prefers_higher_priority_window() {
        let map = AddressMap::new(vec![
            Window {
                base: 0x100,
                size: 0x20,
                priority: 1,
                device: 1,
            },
            Window {
                base: 0x110,
                size: 0x20,
                priority: 2,
                device: 2,
            },
        ])
        .unwrap();
        assert_eq!(map.lookup(0x118).unwrap().device, 2);
    }

    #[test]
    fn equal_priority_overlap_is_rejected() {
        assert!(
            AddressMap::new(vec![
                Window {
                    base: 0,
                    size: 4,
                    priority: 0,
                    device: 1
                },
                Window {
                    base: 2,
                    size: 4,
                    priority: 0,
                    device: 2
                },
            ])
            .is_err()
        );
    }

    #[test]
    fn register_file_restores_reset_image() {
        let mut regs = RegFile::new(vec![1, 2].into_boxed_slice());
        assert!(regs.write(4, 9));
        regs.reset();
        assert_eq!(regs.read(4), Some(2));
    }

    #[test]
    fn deadlines_are_ordered_by_time_then_insertion() {
        let mut ctx = MachineContext::new(0);
        ctx.schedule(20);
        ctx.schedule(10);
        assert_eq!(ctx.next_deadline(), Some(10));
    }
}
