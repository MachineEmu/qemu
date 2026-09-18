//! Alpine Ethernet UDMA register and descriptor engine, independent of PCI.
//! Four M2S queues and the existing S2M queue retain the vendor ring layout.
use board_core::dma::{DmaBus, TransferStatus};
use net_offload::{IP_CHECKSUM, Request, TCP_CHECKSUM, UDP_CHECKSUM};
use std::collections::HashMap;

const MAX_RING: u32 = 65536;
const MAX_PACKET: usize = 65535;

/// One owned outbound packet. Hardware queue identity is endpoint-local.
#[derive(Debug)]
pub struct TxPacket {
    /// Hardware queue index.
    pub queue: u32,
    /// Normalized request.
    pub request: Request,
    /// Owned Ethernet payload.
    pub bytes: Vec<u8>,
}
/// Effects to deliver after the model's DMA operation finishes.
#[derive(Debug, Default)]
pub struct Effects {
    /// Completed packets.
    pub packets: Vec<TxPacket>,
    /// MSI-X vector bitset; the adapter handles PCI delivery.
    pub interrupts: u32,
    /// Invalid ring, descriptor or failed DMA.
    pub failed: bool,
}
#[derive(Debug, Default)]
struct TxQueue {
    base: u64,
    length: u32,
    head: u32,
    packet: Vec<u8>,
    flags: u32,
}
/// One Alpine Ethernet function, including its independent DMA queues.
#[derive(Debug)]
pub struct AlpineEthernet {
    registers: HashMap<u64, u32>,
    tx: [TxQueue; 4],
    rx_base: u64,
    rx_completion: u64,
    rx_length: u32,
    rx_head: u32,
    rx_posted: u32,
    mac: [u8; 6],
}
fn low(base: u64, value: u32) -> u64 {
    (base & 0xffff_ffff_0000_0000) | u64::from(value & !15)
}
fn high(base: u64, value: u32) -> u64 {
    (base & 0xffff_ffff) | (u64::from(value) << 32)
}
fn valid_ring(length: u32) -> bool {
    length.is_power_of_two() && length <= MAX_RING
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from(u32_at(b, at)) | (u64::from(u32_at(b, at + 4)) << 32)
}

impl AlpineEthernet {
    /// Construct a function with the guest-visible MAC address.
    #[must_use]
    pub fn new(mac: [u8; 6]) -> Self {
        let mut s = Self {
            registers: HashMap::new(),
            tx: std::array::from_fn(|_| TxQueue::default()),
            rx_base: 0,
            rx_completion: 0,
            rx_length: 0,
            rx_head: 0,
            rx_posted: 0,
            mac,
        };
        s.reset();
        s
    }
    /// Reset queues and restore the forwarding-table MAC registers.
    pub fn reset(&mut self) {
        self.registers.clear();
        self.registers.insert(
            0x868,
            u32::from_be_bytes([self.mac[2], self.mac[3], self.mac[4], self.mac[5]]),
        );
        self.registers.insert(
            0x86c,
            u32::from(u16::from_be_bytes([self.mac[0], self.mac[1]])),
        );
        self.tx = std::array::from_fn(|_| TxQueue::default());
        self.rx_base = 0;
        self.rx_completion = 0;
        self.rx_length = 0;
        self.rx_head = 0;
        self.rx_posted = 0;
    }
    /// Read a 32-bit register; unknown registers retain written values.
    #[must_use]
    pub fn read(&self, address: u64) -> u32 {
        if (0x1000..0x5000).contains(&address)
            && matches!(address & 0xfff, 0x34 | 0x3c | 0x40 | 0x4c)
        {
            return self.tx[((address - 0x1000) >> 12) as usize].head;
        }
        match address {
            4 => 1 | (0x11 << 5) | (1 << 11) | (1 << 29),
            0x220 => 0x3ff,
            0x91c => 1 << 4,
            0x11034 | 0x11040 | 0x1104c => self.rx_head,
            _ => self.registers.get(&address).copied().unwrap_or(0),
        }
    }
    /// Whether an RX descriptor is posted and its rings have valid geometry.
    #[must_use]
    pub fn can_receive(&self) -> bool {
        self.rx_base != 0
            && self.rx_completion != 0
            && valid_ring(self.rx_length)
            && self.rx_posted != 0
    }
    /// Write a register and execute bounded DMA work for doorbells.
    pub fn write(&mut self, bus: &mut dyn DmaBus, address: u64, value: u32) -> Effects {
        if address >= 0x20000 || address & 3 != 0 {
            return Effects {
                failed: true,
                ..Effects::default()
            };
        }
        self.registers.insert(address, value);
        if (0x1000..0x5000).contains(&address) {
            let q = ((address - 0x1000) >> 12) as usize;
            let tx = &mut self.tx[q];
            match address & 0xfff {
                0x28 => tx.base = low(tx.base, value),
                0x2c => tx.base = high(tx.base, value),
                0x30 => tx.length = value & 0x00ff_ffff,
                0x20 if value == 0 => {
                    tx.head = 0;
                    tx.packet.clear();
                    tx.flags = 0;
                }
                0x38 => return self.transmit(bus, q, value & 0x00ff_ffff),
                _ => (),
            }
        } else {
            match address {
                0x11028 => {
                    self.rx_base = low(self.rx_base, value);
                    self.rx_head = 0;
                    self.rx_posted = 0;
                }
                0x1102c => self.rx_base = high(self.rx_base, value),
                0x11030 => self.rx_length = value & 0x00ff_ffff,
                0x11044 => self.rx_completion = low(self.rx_completion, value),
                0x11048 => self.rx_completion = high(self.rx_completion, value),
                0x11038 => {
                    self.rx_posted = self
                        .rx_posted
                        .saturating_add(value & 0x00ff_ffff)
                        .min(self.rx_length);
                }
                _ => (),
            }
        }
        Effects::default()
    }
    fn transmit(&mut self, bus: &mut dyn DmaBus, queue: usize, count: u32) -> Effects {
        let mut result = Effects::default();
        let tx = &mut self.tx[queue];
        if count == 0 {
            return result;
        }
        if tx.base == 0 || !valid_ring(tx.length) || count > tx.length {
            result.failed = true;
            return result;
        }
        for _ in 0..count {
            let Some(address) = tx
                .base
                .checked_add(u64::from(tx.head & (tx.length - 1)) * 16)
            else {
                result.failed = true;
                break;
            };
            let mut descriptor = [0; 16];
            if bus.read(address, &mut descriptor) != TransferStatus::Complete {
                result.failed = true;
                break;
            }
            let control = u32_at(&descriptor, 0);
            let metadata = u32_at(&descriptor, 4);
            if control & (1 << 23) == 0 {
                let length = (control & 0xfffff) as usize;
                let buffer = u64_at(&descriptor, 8);
                if buffer == 0
                    || length == 0
                    || tx.packet.len() + length > MAX_PACKET
                    || buffer.checked_add(length as u64).is_none()
                {
                    result.failed = true;
                    break;
                }
                let mut fragment = vec![0; length];
                if bus.read(buffer, &mut fragment) != TransferStatus::Complete {
                    result.failed = true;
                    break;
                }
                if metadata & (1 << 13) != 0 {
                    tx.flags |= IP_CHECKSUM;
                }
                if metadata & (1 << 14) != 0 {
                    tx.flags |= TCP_CHECKSUM | UDP_CHECKSUM;
                }
                tx.packet.extend_from_slice(&fragment);
            }
            tx.head = tx.head.wrapping_add(1);
            if control & (1 << 27) != 0 && !tx.packet.is_empty() {
                result.packets.push(TxPacket {
                    queue: u32::try_from(queue).unwrap_or_default(),
                    request: Request {
                        flags: tx.flags,
                        ..Request::default()
                    },
                    bytes: std::mem::take(&mut tx.packet),
                });
                tx.flags = 0;
            }
        }
        // Earlier descriptors may have succeeded even if a later DMA failed.
        if !result.failed || !result.packets.is_empty() {
            result.interrupts |= 1 << (7 + queue);
        }
        result
    }
    /// Receive one wire-ready frame. Failed DMA never publishes completion.
    pub fn receive(&mut self, bus: &mut dyn DmaBus, bytes: &[u8]) -> Effects {
        let mut result = Effects::default();
        if !self.can_receive() || bytes.len() > MAX_PACKET {
            result.failed = true;
            return result;
        }
        let index = u64::from(self.rx_head & (self.rx_length - 1)) * 16;
        let (Some(address), Some(completion)) = (
            self.rx_base.checked_add(index),
            self.rx_completion.checked_add(index),
        ) else {
            result.failed = true;
            return result;
        };
        let mut descriptor = [0; 16];
        if bus.read(address, &mut descriptor) != TransferStatus::Complete {
            result.failed = true;
            return result;
        }
        let control = u32_at(&descriptor, 0);
        let buffer = u64_at(&descriptor, 8);
        if buffer == 0
            || bytes.len() > (control & 0xffff) as usize
            || bus.write(buffer, bytes) != TransferStatus::Complete
        {
            result.failed = true;
            return result;
        }
        let mut record = [0; 16];
        record[..4].copy_from_slice(
            &((control & 0x0300_0000) | (1 << 30) | (1 << 26) | (1 << 27)).to_le_bytes(),
        );
        record[4..8].copy_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_le_bytes());
        if bus.write(completion, &record) != TransferStatus::Complete {
            result.failed = true;
            return result;
        }
        self.rx_posted -= 1;
        self.rx_head = self.rx_head.wrapping_add(1);
        result.interrupts = 1 << 3;
        result
    }
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "bounded queue and memory fixtures"
)]
mod tests {
    use super::*;
    struct Memory {
        bytes: Vec<u8>,
        fail_write: Option<u64>,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                bytes: vec![0; 0x10000],
                fail_write: None,
            }
        }
        fn descriptor(&mut self, at: usize, control: u32, metadata: u32, buffer: u64) {
            self.bytes[at..at + 4].copy_from_slice(&control.to_le_bytes());
            self.bytes[at + 4..at + 8].copy_from_slice(&metadata.to_le_bytes());
            self.bytes[at + 8..at + 16].copy_from_slice(&buffer.to_le_bytes());
        }
    }
    impl DmaBus for Memory {
        fn read(&mut self, at: u64, out: &mut [u8]) -> TransferStatus {
            let Ok(at) = usize::try_from(at) else {
                return TransferStatus::Failed;
            };
            let Some(end) = at.checked_add(out.len()) else {
                return TransferStatus::Failed;
            };
            let Some(bytes) = self.bytes.get(at..end) else {
                return TransferStatus::Failed;
            };
            out.copy_from_slice(bytes);
            TransferStatus::Complete
        }
        fn write(&mut self, at: u64, bytes: &[u8]) -> TransferStatus {
            if self.fail_write == Some(at) {
                return TransferStatus::Failed;
            }
            let Ok(at) = usize::try_from(at) else {
                return TransferStatus::Failed;
            };
            let Some(end) = at.checked_add(bytes.len()) else {
                return TransferStatus::Failed;
            };
            let Some(out) = self.bytes.get_mut(at..end) else {
                return TransferStatus::Failed;
            };
            out.copy_from_slice(bytes);
            TransferStatus::Complete
        }
    }
    #[test]
    fn four_queues_preserve_independent_fragments_and_completions() {
        let mut m = AlpineEthernet::new([2, 0, 0, 0, 0, 1]);
        let mut bus = Memory::new();
        bus.bytes[0x8000..0x8006].copy_from_slice(b"abcdef");
        for q in 0..4 {
            let base = 0x1000 + q * 0x1000;
            m.write(&mut bus, base + 0x28, 0x100 + q as u32 * 0x100);
            m.write(&mut bus, base + 0x30, 2);
            bus.descriptor(0x100 + q as usize * 0x100, 3, 1 << 14, 0x8000);
            bus.descriptor(0x110 + q as usize * 0x100, 3 | (1 << 27), 0, 0x8003);
            assert!(m.write(&mut bus, base + 0x38, 1).packets.is_empty());
        }
        for q in (0..4).rev() {
            let base = 0x1000 + q * 0x1000;
            let e = m.write(&mut bus, base + 0x38, 1);
            assert!(!e.failed);
            assert_eq!(e.packets[0].bytes, b"abcdef");
            assert_eq!(e.packets[0].queue, q as u32);
            assert_eq!(e.packets[0].request.flags, TCP_CHECKSUM | UDP_CHECKSUM);
            assert_eq!(e.interrupts, 1 << (7 + q));
            assert_eq!(m.read(base + 0x4c), 2);
        }
    }
    #[test]
    fn failed_tx_dma_is_not_completed_and_can_be_retried() {
        let mut m = AlpineEthernet::new([0; 6]);
        let mut bus = Memory::new();
        m.write(&mut bus, 0x1028, 0x100);
        m.write(&mut bus, 0x1030, 2);
        bus.descriptor(0x100, 0x14 | (1 << 27), 0, 0xffff_fff0);
        assert!(m.write(&mut bus, 0x1038, 1).failed);
        assert_eq!(m.read(0x104c), 0);
        bus.descriptor(0x100, 0x14 | (1 << 27), 0, 0x8000);
        assert_eq!(m.write(&mut bus, 0x1038, 1).packets.len(), 1);
        assert_eq!(m.read(0x104c), 1);
        m.write(&mut bus, 0x1030, 3);
        assert!(m.write(&mut bus, 0x1038, 1).failed);
    }
    #[test]
    fn rx_completion_preserves_generation_and_failure_does_not_advance() {
        let mut m = AlpineEthernet::new([0; 6]);
        let mut bus = Memory::new();
        m.write(&mut bus, 0x11028, 0x100);
        m.write(&mut bus, 0x11044, 0x300);
        m.write(&mut bus, 0x11030, 1);
        m.write(&mut bus, 0x11038, 100);
        bus.descriptor(0x100, 0x600 | (2 << 24), 0, 0x8000);
        bus.fail_write = Some(0x300);
        assert!(m.receive(&mut bus, b"hello").failed);
        assert_eq!(m.read(0x1104c), 0);
        assert!(m.can_receive());
        bus.fail_write = None;
        assert_eq!(m.receive(&mut bus, b"hello").interrupts, 1 << 3);
        assert_eq!(u32_at(&bus.bytes, 0x300), 0x4e00_0000);
        assert_eq!(u32_at(&bus.bytes, 0x304), 5);
        assert!(!m.can_receive());
        m.write(&mut bus, 0x11038, 1);
        bus.descriptor(0x100, 0x600 | (3 << 24), 0, 0x8000);
        assert!(!m.receive(&mut bus, b"again").failed);
        assert_eq!(u32_at(&bus.bytes, 0x300), 0x4f00_0000);
        assert_eq!(m.read(0x1104c), 2);
        m.reset();
        assert!(!m.can_receive());
        assert_eq!(m.read(0x1104c), 0);
    }
}
