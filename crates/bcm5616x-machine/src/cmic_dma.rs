//! `CMICd` packet DMA for BCM56160 type-34 DCBs (16 words).
//!
//! Register/bit definitions: `OpenBCM` 6.5.27 include/soc/{mcm/cmicm.h,
//! cmicm.h,shared/dcbformats/type34.h}; acknowledgement behavior:
//! `src/soc/common/cmicm_dma.c`. This is the CPU packet endpoint, not a
//! model of the switch forwarding pipeline. See docs/us24pro/cmic-dma.md.

use board_core::{Event, MachineContext, dma::TransferStatus};

pub(super) const PORT: u32 = 1;
const TX: u32 = 1;
const ENABLE: u32 = 2;
const ABORT: u32 = 4;
const PACKET_BE: u32 = 0x10;
const DESC_BE: u32 = 0x20;
const CHAIN: u32 = 1 << 16;
const SG: u32 = 1 << 17;
const RELOAD: u32 = 1 << 18;
const PURGE: u32 = 1 << 22;
const DONE: u32 = 1 << 31;
const RX_END: u32 = 1 << 16;
const RX_START: u32 = 1 << 17;
const RX_ERROR: u32 = 1 << 18;
const DESCRIPTOR_READ_ERROR: u32 = 20;
const STATUS_WRITE_ERROR: u32 = 12;
const MAX_FRAME: usize = 16_379;
const MAX_DESCRIPTORS: usize = 4096;

#[derive(Debug, Default)]
struct Channel {
    control: u32,
    descriptor: u32,
    current: u32,
    cos: [u32; 2],
    active: bool,
    chain_done: bool,
    desc_done: bool,
    descriptor_irq: u32,
    // Descriptor read, packet data access, descriptor status write errors.
    errors: u32,
    tx_count: u32,
    rx_count: u32,
}

#[derive(Debug, Default)]
pub(super) struct PacketDma {
    channels: [Channel; 4],
}

impl PacketDma {
    pub(super) fn read(&self, reg: u64) -> Option<u32> {
        match reg {
            0x140..=0x14c => Some(self.channels[((reg - 0x140) / 4) as usize].control),
            0x158..=0x164 => Some(self.channels[((reg - 0x158) / 4) as usize].descriptor),
            0x168..=0x184 => {
                let index = ((reg - 0x168) / 4) as usize;
                Some(self.channels[index / 2].cos[index % 2])
            }
            0x1a8..=0x1b4 => Some(self.channels[((reg - 0x1a8) / 4) as usize].current),
            0x480..=0x49c => {
                let index = ((reg - 0x480) / 4) as usize;
                let channel = &self.channels[index / 2];
                Some(if index.is_multiple_of(2) {
                    channel.rx_count
                } else {
                    channel.tx_count
                })
            }
            0x150 => Some(self.channels.iter().enumerate().fold(0, |status, (i, ch)| {
                status
                    | ((u32::from(ch.chain_done)
                        | (u32::from(ch.desc_done) << 4)
                        | (u32::from(ch.active) << 8)
                        | ch.errors)
                        << i)
            })),
            0x130 | 0x1a4 => Some(0),
            _ => None,
        }
    }

    pub(super) fn write(&mut self, reg: u64, value: u32) -> bool {
        match reg {
            0x140..=0x14c => {
                let ch = &mut self.channels[((reg - 0x140) / 4) as usize];
                let old = ch.control;
                ch.control = value;
                if value & ENABLE == 0 {
                    ch.active = false;
                    ch.chain_done = false;
                    ch.errors = 0;
                } else if value & ABORT != 0 {
                    ch.active = false;
                } else if old & ENABLE == 0 {
                    ch.current = ch.descriptor;
                    ch.active = true;
                    ch.chain_done = false;
                    ch.errors = 0;
                }
            }
            0x158..=0x164 => self.channels[((reg - 0x158) / 4) as usize].descriptor = value,
            0x168..=0x184 => {
                let index = ((reg - 0x168) / 4) as usize;
                self.channels[index / 2].cos[index % 2] = value;
            }
            0x1a4 => {
                for (i, ch) in self.channels.iter_mut().enumerate() {
                    if value & (1 << i) != 0 {
                        ch.desc_done = false;
                        ch.descriptor_irq = 0;
                    }
                }
            }
            0x130 | 0x150 | 0x1a8..=0x1b4 | 0x480..=0x49c => {}
            _ => return false,
        }
        true
    }

    pub(super) fn pending(&self) -> u32 {
        self.channels
            .iter()
            .enumerate()
            .fold(0, |pending, (i, ch)| {
                pending | ((ch.descriptor_irq | (u32::from(ch.chain_done) * 0x8000)) >> (2 * i))
            })
    }

    pub(super) fn pump(&mut self, ctx: &mut MachineContext<'_>) {
        for channel in &mut self.channels {
            if channel.active && channel.control & TX != 0 {
                channel.transmit(ctx);
            }
        }
    }

    pub(super) fn receive(&mut self, ctx: &mut MachineContext<'_>, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > MAX_FRAME {
            return false;
        }
        let Some(ch) = self
            .channels
            .iter_mut()
            .find(|ch| ch.active && ch.control & TX == 0 && ch.cos[0] & 1 != 0)
        else {
            return false;
        };
        ch.receive(ctx, frame);
        true
    }
}

impl Channel {
    fn fail(&mut self, bit: u32) {
        self.errors |= 1 << bit;
        self.active = false;
        self.chain_done = true;
    }

    fn fetch(&mut self, ctx: &mut MachineContext<'_>) -> Option<[u32; 16]> {
        // Continuous/controlled-interrupt mode belongs to CMICdv2, not the
        // chained type-34 engine implemented here. Do not silently run it.
        if self.control & 0x300 != 0 || self.current & 3 != 0 {
            self.fail(DESCRIPTOR_READ_ERROR);
            return None;
        }
        let mut raw = [0; 64];
        if !read(ctx, self.current, &mut raw) {
            self.fail(DESCRIPTOR_READ_ERROR);
            return None;
        }
        let mut words = [0; 16];
        for (word, bytes) in words.iter_mut().zip(raw.chunks_exact(4)) {
            let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
            *word = if self.control & DESC_BE != 0 {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
        }
        Some(words)
    }

    fn store(&mut self, ctx: &mut MachineContext<'_>, offset: u32, words: &[u32]) -> bool {
        let mut raw = Vec::with_capacity(words.len() * 4);
        for word in words {
            raw.extend_from_slice(&if self.control & DESC_BE != 0 {
                word.to_be_bytes()
            } else {
                word.to_le_bytes()
            });
        }
        if !self
            .current
            .checked_add(offset)
            .is_some_and(|addr| write(ctx, addr, &raw))
        {
            self.fail(STATUS_WRITE_ERROR);
            return false;
        }
        true
    }

    fn complete(&mut self, ctx: &mut MachineContext<'_>, dcb: &[u32; 16], status: u32) -> bool {
        if !self.store(ctx, 60, &[DONE | status]) {
            return false;
        }
        self.desc_done = true;
        let packet_end = dcb[1] & RELOAD == 0
            && if self.control & TX != 0 {
                dcb[1] & SG == 0
            } else {
                status & RX_END != 0
            };
        if self.control & 8 != 0 || packet_end {
            self.descriptor_irq = 0x4000;
        }
        if dcb[1] & CHAIN == 0 {
            self.chain_done = true;
            self.active = false;
        } else if dcb[1] & RELOAD != 0 {
            self.current = dcb[0];
        } else if let Some(next) = self.current.checked_add(64) {
            self.current = next;
        } else {
            self.fail(DESCRIPTOR_READ_ERROR);
        }
        true
    }

    fn transmit(&mut self, ctx: &mut MachineContext<'_>) {
        let mut frame = Vec::new();
        let mut purge = false;
        for _ in 0..MAX_DESCRIPTORS {
            if !self.active {
                return;
            }
            let Some(dcb) = self.fetch(ctx) else {
                return;
            };
            if dcb[1] & RELOAD != 0 {
                if !self.complete(ctx, &dcb, 0) {
                    return;
                }
                continue;
            }
            let length = (dcb[1] & 0xffff) as usize;
            if length == 0 || frame.len() + length > MAX_FRAME {
                self.fail(16);
                return;
            }
            let mut payload = vec![
                0;
                if self.control & PACKET_BE != 0 {
                    length.next_multiple_of(4)
                } else {
                    length
                }
            ];
            if !read(ctx, dcb[0], &mut payload) {
                self.fail(16);
                return;
            }
            if self.control & PACKET_BE != 0 {
                swap_words(&mut payload);
            }
            frame.extend_from_slice(&payload[..length]);
            purge |= dcb[1] & PURGE != 0;
            if !self.complete(ctx, &dcb, dcb[1] & 0xffff) {
                return;
            }
            if dcb[1] & SG == 0 {
                if !purge {
                    ctx.events.push(Event::NetTx {
                        port: PORT,
                        frame: std::mem::take(&mut frame),
                    });
                    self.tx_count = self.tx_count.wrapping_add(1);
                }
                frame.clear();
                purge = false;
            } else if !self.active {
                // A terminated chain cannot transmit an unfinished frame.
                self.fail(16);
            }
        }
        if self.active {
            self.fail(DESCRIPTOR_READ_ERROR);
        }
    }

    fn receive(&mut self, ctx: &mut MachineContext<'_>, frame: &[u8]) {
        let mut packet = frame.to_vec();
        packet.extend_from_slice(&crc32(frame).to_le_bytes());
        let mut consumed = 0;
        for _ in 0..MAX_DESCRIPTORS {
            if !self.active {
                return;
            }
            let Some(mut dcb) = self.fetch(ctx) else {
                return;
            };
            if dcb[1] & RELOAD != 0 {
                if !self.complete(ctx, &dcb, 0) {
                    return;
                }
                continue;
            }
            let capacity = (dcb[1] & 0xffff) as usize;
            if capacity == 0 {
                self.fail(16);
                return;
            }
            let count = capacity.min(packet.len() - consumed);
            let end = consumed + count == packet.len();
            let truncated = !end && dcb[1] & CHAIN == 0;
            let mut payload = packet[consumed..consumed + count].to_vec();
            if self.control & PACKET_BE != 0 {
                payload.resize(count.next_multiple_of(4), 0);
                swap_words(&mut payload);
            }
            if !write(ctx, dcb[0], &payload) {
                self.fail(16);
                return;
            }
            // Raw endpoint ingress is COS 0, source port 0. Hardware policy
            // metadata is deliberately not invented by the DMA engine.
            dcb[2..15].fill(0);
            dcb[5] = u32::try_from(packet.len()).unwrap_or(0) << 8;
            if !self.store(ctx, 8, &dcb[2..15]) {
                return;
            }
            let status = u32::try_from(count).unwrap_or(0)
                | if consumed == 0 { RX_START } else { 0 }
                | if end || truncated { RX_END } else { 0 }
                | if truncated { RX_ERROR } else { 0 };
            if !self.complete(ctx, &dcb, status) {
                return;
            }
            consumed += count;
            if end || truncated {
                if end {
                    self.rx_count = self.rx_count.wrapping_add(1);
                }
                return;
            }
        }
        self.fail(DESCRIPTOR_READ_ERROR);
    }
}

pub(super) fn read(ctx: &mut MachineContext<'_>, address: u32, data: &mut [u8]) -> bool {
    u64::from(address) + data.len() as u64 <= 1 << 32
        && ctx
            .dma
            .as_deref_mut()
            .is_some_and(|bus| bus.read(u64::from(address), data) == TransferStatus::Complete)
}

pub(super) fn write(ctx: &mut MachineContext<'_>, address: u32, data: &[u8]) -> bool {
    u64::from(address) + data.len() as u64 <= 1 << 32
        && ctx
            .dma
            .as_deref_mut()
            .is_some_and(|bus| bus.write(u64::from(address), data) == TransferStatus::Complete)
}

fn swap_words(data: &mut [u8]) {
    for word in data.chunks_exact_mut(4) {
        word.reverse();
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use board_core::dma::DmaBus;

    struct Memory {
        bytes: Vec<u8>,
        fail_write: Option<u64>,
        reads: usize,
    }
    impl Default for Memory {
        fn default() -> Self {
            Self {
                bytes: vec![0xa5; 8192],
                fail_write: None,
                reads: 0,
            }
        }
    }
    impl DmaBus for Memory {
        fn read(&mut self, address: u64, data: &mut [u8]) -> TransferStatus {
            self.reads += 1;
            let Some(bytes) = self.bytes.get(
                usize::try_from(address).unwrap()..usize::try_from(address).unwrap() + data.len(),
            ) else {
                return TransferStatus::Failed;
            };
            data.copy_from_slice(bytes);
            TransferStatus::Complete
        }
        fn write(&mut self, address: u64, data: &[u8]) -> TransferStatus {
            if self.fail_write == Some(address) {
                return TransferStatus::Failed;
            }
            let Some(bytes) = self.bytes.get_mut(
                usize::try_from(address).unwrap()..usize::try_from(address).unwrap() + data.len(),
            ) else {
                return TransferStatus::Failed;
            };
            bytes.copy_from_slice(data);
            TransferStatus::Complete
        }
    }
    impl Memory {
        fn descriptor(&mut self, address: usize, buffer: u32, control: u32, big: bool) {
            self.bytes[address..address + 64].fill(0);
            for (i, value) in [buffer, control].iter().enumerate() {
                self.bytes[address + i * 4..address + i * 4 + 4].copy_from_slice(&if big {
                    value.to_be_bytes()
                } else {
                    value.to_le_bytes()
                });
            }
        }
        fn word(&self, address: usize, big: bool) -> u32 {
            let bytes: [u8; 4] = self.bytes[address..address + 4].try_into().unwrap();
            if big {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        }
    }
    fn arm(dma: &mut PacketDma, channel: u64, control: u32) {
        dma.write(0x158 + 4 * channel, 256);
        dma.write(0x140 + 4 * channel, control | ENABLE);
    }

    #[test]
    fn tx_scatter_reload_and_separate_acknowledgements() {
        for channel in 0..4 {
            let mut memory = Memory::default();
            memory.descriptor(256, 1024, CHAIN | SG | 3, false);
            memory.descriptor(320, 512, CHAIN | RELOAD, false);
            memory.descriptor(512, 2048, 4, false);
            memory.bytes[1024..1027].copy_from_slice(b"abc");
            memory.bytes[2048..2052].copy_from_slice(b"defg");
            let mut dma = PacketDma::default();
            arm(&mut dma, channel, TX);
            let mut ctx = MachineContext::with_dma(0, &mut memory);
            dma.pump(&mut ctx);
            assert!(
                matches!(&ctx.events[..], [Event::NetTx { port: 1, frame }] if frame == b"abcdefg")
            );
            dma.pump(&mut ctx);
            assert_eq!(ctx.events.len(), 1, "completed channels do not replay");
            drop(ctx);
            assert_eq!(memory.word(316, false), DONE | 3);
            assert_eq!(memory.word(380, false), DONE);
            assert_eq!(memory.word(572, false), DONE | 4);
            assert_eq!(dma.read(0x150), Some(0x11 << channel));
            assert_eq!(dma.pending(), 0xc000 >> (2 * channel));
            dma.write(0x150, u32::MAX);
            assert_eq!(dma.pending(), 0xc000 >> (2 * channel));
            dma.write(0x1a4, 1 << channel);
            assert_eq!(dma.pending(), 0x8000 >> (2 * channel));
            dma.write(0x140 + 4 * channel, 0);
            assert_eq!(dma.pending(), 0);
        }
    }

    #[test]
    fn descriptor_and_packet_byte_order_are_independent() {
        for desc_big in [false, true] {
            for packet_big in [false, true] {
                let mut memory = Memory::default();
                memory.descriptor(256, 1024, 7, desc_big);
                let mut payload = *b"abcdefg\0";
                if packet_big {
                    swap_words(&mut payload);
                }
                memory.bytes[1024..1032].copy_from_slice(&payload);
                let mut dma = PacketDma::default();
                arm(
                    &mut dma,
                    0,
                    TX | if desc_big { DESC_BE } else { 0 }
                        | if packet_big { PACKET_BE } else { 0 },
                );
                let mut ctx = MachineContext::with_dma(0, &mut memory);
                dma.pump(&mut ctx);
                assert!(
                    matches!(&ctx.events[..], [Event::NetTx { frame, .. }] if frame == b"abcdefg")
                );
                drop(ctx);
                assert_eq!(memory.word(316, desc_big), DONE | 7);
            }
        }
    }

    #[test]
    fn rx_scatters_fcs_and_metadata_and_waits_for_next_packet() {
        let mut memory = Memory::default();
        memory.descriptor(256, 1024, CHAIN | 3, false);
        memory.descriptor(320, 2048, CHAIN | 128, false);
        memory.descriptor(384, 3072, 128, false);
        let mut dma = PacketDma::default();
        arm(&mut dma, 2, 0);
        dma.write(0x178, 1); // COS 0 -> channel 2.
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(dma.receive(&mut ctx, b"123456789"));
        assert_eq!(dma.read(0x150), Some(0x110 << 2));
        drop(ctx);
        assert_eq!(&memory.bytes[1024..1027], b"123");
        assert_eq!(&memory.bytes[2048..2058], b"456789\x26\x39\xf4\xcb");
        assert_eq!(memory.word(316, false), DONE | RX_START | 3);
        assert_eq!(memory.word(380, false), DONE | RX_END | 0x0a);
        assert_eq!(memory.word(340, false), 13 << 8);
        assert_eq!(memory.word(444, false), 0);
        assert_eq!(dma.read(0x1b0), Some(384));
    }

    #[test]
    fn rx_requires_cos_mapping_and_reports_truncation() {
        let mut memory = Memory::default();
        memory.descriptor(256, 1024, 3, false);
        let mut dma = PacketDma::default();
        arm(&mut dma, 0, 0);
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(!dma.receive(&mut ctx, b"abcdef"));
        dma.write(0x168, 1);
        assert!(dma.receive(&mut ctx, b"abcdef"));
        drop(ctx);
        assert_eq!(
            memory.word(316, false),
            DONE | RX_START | RX_END | RX_ERROR | 3
        );
        assert_eq!(dma.read(0x150), Some(0x11));
        assert_eq!(memory.bytes[1027], 0xa5);
    }

    #[test]
    fn abort_and_disable_prevent_memory_access() {
        let mut memory = Memory::default();
        let mut dma = PacketDma::default();
        arm(&mut dma, 0, TX);
        dma.write(0x140, ENABLE | TX | ABORT);
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        dma.pump(&mut ctx);
        assert_eq!(dma.read(0x150), Some(0));
        dma.write(0x140, 0);
        dma.pump(&mut ctx);
        assert!(ctx.events.is_empty());
        drop(ctx);
        assert_eq!(memory.reads, 0);
    }

    #[test]
    fn dma_faults_do_not_transmit_or_report_descriptor_success() {
        for fault in 0..3 {
            let mut memory = Memory::default();
            memory.descriptor(256, if fault == 1 { 0xffff_fffc } else { 1024 }, 8, false);
            if fault == 2 {
                memory.fail_write = Some(316);
            }
            let mut dma = PacketDma::default();
            arm(&mut dma, 0, TX);
            if fault == 0 {
                dma.channels[0].current = 0xffff_fff0;
            }
            let mut ctx = MachineContext::with_dma(0, &mut memory);
            dma.pump(&mut ctx);
            assert!(ctx.events.is_empty());
            assert_eq!(dma.read(0x150), Some(1 | (1 << (20 - 4 * fault))));
            assert_eq!(dma.pending(), 0x8000);
            drop(ctx);
            assert_eq!(memory.word(316, false), 0);
        }
    }

    #[test]
    fn cyclic_reload_is_bounded() {
        let mut memory = Memory::default();
        memory.descriptor(256, 256, CHAIN | RELOAD, false);
        let mut dma = PacketDma::default();
        arm(&mut dma, 0, TX);
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        dma.pump(&mut ctx);
        assert!(ctx.events.is_empty());
        assert_eq!(dma.read(0x150), Some(0x0010_0011));
        drop(ctx);
        assert_eq!(memory.reads, MAX_DESCRIPTORS);
    }

    #[test]
    fn interrupt_selection_distinguishes_descriptors_from_packets() {
        for interrupt_each_descriptor in [false, true] {
            let mut memory = Memory::default();
            // First fragment completes, then the next descriptor faults.
            memory.descriptor(256, 1024, CHAIN | SG | 4, false);
            memory.descriptor(320, u32::MAX, 4, false);
            let mut dma = PacketDma::default();
            arm(
                &mut dma,
                0,
                TX | if interrupt_each_descriptor { 8 } else { 0 },
            );
            let mut ctx = MachineContext::with_dma(0, &mut memory);
            dma.pump(&mut ctx);
            assert!(ctx.events.is_empty());
            assert_eq!(dma.read(0x150), Some(0x0001_0011));
            assert_eq!(
                dma.pending(),
                if interrupt_each_descriptor {
                    0xc000
                } else {
                    0x8000
                }
            );
        }
    }

    #[test]
    fn rx_big_endian_preserves_descriptor_control_and_word_lanes() {
        let mut memory = Memory::default();
        memory.descriptor(256, 1024, 128, true);
        let mut dma = PacketDma::default();
        dma.write(0x168, 1);
        arm(&mut dma, 0, DESC_BE | PACKET_BE);
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(dma.receive(&mut ctx, b"123456789"));
        drop(ctx);
        assert_eq!(memory.word(260, true), 128);
        assert_eq!(memory.word(316, true), DONE | RX_START | RX_END | 0x0d);
        let mut expected = b"123456789\x26\x39\xf4\xcb\0\0\0".to_vec();
        swap_words(&mut expected);
        assert_eq!(&memory.bytes[1024..1040], &expected);
        assert_eq!(memory.bytes[1040], 0xa5);
    }
}
