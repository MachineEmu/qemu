//! `CMICd` SBUS DMA and a shared, sparse switch register/table store.
//! Layouts are from `OpenBCM` 6.5.27 `mcm/fields_c.i` (the BCM56160 register
//! mapping), `schanmsg.h` and `cmicm_sbusdma_{reg,desc}.c`. Unwritten entries
//! are zero, except modeled register reset defaults. Forwarding is not modeled.

use super::cmic_dma::{read, write};
use board_core::MachineContext;
use std::collections::BTreeMap;

const DONE: u32 = 1;
const ERROR: u32 = 2;
const HOST_WRITE: u32 = 1 << 2;
const HOST_READ: u32 = 1 << 3;
const BEAT_COUNT: u32 = 1 << 5;
const OPCODE: u32 = 1 << 6;
const NACK: u32 = 1 << 7;
const DESC_READ: u32 = 1 << 10;
const ACTIVE: u32 = (1 << 11) | (1 << 12);
const MAX_ENTRIES: usize = 65_536;
const MAX_WORDS: usize = 1_048_576;
const MAX_DESCRIPTORS: usize = 4096;
const L2_BASE: u32 = 0x1c00_0000;
const L2_ENTRIES: u32 = 16_384;
const L2_VALID: u32 = 1 << 6; // Entry bit 102.
const PER_PORT_AGE_CONTROL_64: u32 = 0x0200_0500;
const PER_PORT_AGE_START: u32 = 1 << 29;
const PER_PORT_AGE_COMPLETE: u32 = 1 << 30;

// Separate register/memory, destination block, access type and SBUS address.
type Key = (bool, u8, u8, u32);

#[derive(Debug, Default)]
pub(super) struct SwitchStore {
    entries: BTreeMap<Key, Vec<u32>>,
}

fn command(header: u32, address: u32) -> Result<(Key, bool), u32> {
    let op = header >> 26;
    if !matches!(op, 7 | 9 | 11 | 13) {
        return Err(OPCODE);
    }
    Ok((
        (
            op == 7 || op == 9,
            // BCM56166 uses the v4 header (7-bit block, 5-bit access type).
            ((header >> 19) & 127) as u8,
            ((header >> 14) & 31) as u8,
            address,
        ),
        op == 9 || op == 13,
    ))
}

impl SwitchStore {
    fn l2_command(&mut self, opcode: u32, words: &mut [u32]) -> (u32, u32) {
        // BCM56160 L2 view: key type 2:0, VLAN 14:3, MAC 62:15.
        // Associated data and hit/static/valid bits are not lookup keys.
        let matches = |entry: &[u32]| {
            entry.len() == 4
                && entry[3] & L2_VALID != 0
                && entry[0] == words[0]
                && entry[1] & 0x7fff_ffff == words[1] & 0x7fff_ffff
        };
        let found = self
            .entries
            .range((true, 10, 0, L2_BASE)..(true, 10, 0, L2_BASE + L2_ENTRIES))
            .find_map(|(key, entry)| matches(entry).then_some(*key));
        if let Some(key) = found {
            let old = match opcode {
                0x24 => self.entries.insert(key, words.to_vec()),
                0x26 => self.entries.remove(&key),
                _ => self.entries.get(&key).cloned(),
            };
            if let Some(old) = old {
                words.copy_from_slice(&old);
            }
            return (
                match opcode {
                    0x24 => 4,
                    0x26 => 5,
                    _ => 0,
                },
                key.3 - L2_BASE,
            );
        }
        if opcode != 0x24 {
            words.fill(0);
            return (1, 0); // NOT_FOUND, accompanied by NACK.
        }
        // Functional indexed storage, not ASIC hash-bucket placement. Sharing
        // the indexed store makes DMA writes and pipeline clears authoritative.
        let free = (0..L2_ENTRIES).find(|&index| {
            self.entries
                .get(&(true, 10, 0, L2_BASE + index))
                .is_none_or(|entry| entry.get(3).is_none_or(|word| word & L2_VALID == 0))
        });
        if let Some(index) = free {
            let key = (true, 10, 0, L2_BASE + index);
            if self.entries.len() < MAX_ENTRIES || self.entries.contains_key(&key) {
                self.entries.insert(key, words.to_vec());
                words.fill(0);
                return (3, index); // INSERTED.
            }
        }
        words.fill(0);
        (2, 0) // FULL.
    }

    fn register_default(key: Key) -> Option<u32> {
        // BCM56160 maps these to the BCM53400 TPID definitions in OpenBCM
        // allregs_{i,e}.i. The SDK seeds its software TPID cache from hardware.
        match key {
            (false, 10, 0, 0x0a00_0d00) | (false, 11, 0, 0x1200_1300) => Some(0x8100),
            (false, 10, 0, 0x0a00_0e00) | (false, 11, 0, 0x1200_1400) => Some(0x9100),
            (false, 10, 0, 0x0a00_0f00) | (false, 11, 0, 0x1200_1500) => Some(0x88a8),
            (false, 10, 0, 0x0a00_1000) | (false, 11, 0, 0x1200_1600) => Some(0),
            _ => Self::pipeline_reset_default(key),
        }
    }

    fn pipeline_reset_default(key: Key) -> Option<u32> {
        match key {
            (false, 10, 0, 0x0200_0300) => Some(0x1000),
            (false, 11, 0, 0x0200_0100) => Some(0x2000),
            _ => None,
        }
    }

    fn reset_pipeline(&mut self, key: Key, value: u32) -> u32 {
        const VALID: u32 = 1 << 17;
        const RESET_ALL: u32 = 1 << 16;
        const RESET_DONE: u32 = 1 << 18;
        // DONE is hardware-owned. Clearing VALID acknowledges completion.
        let value = value & 0x3_ffff;
        if value & VALID == 0 {
            return value;
        }
        let start_key = (false, key.1, 0, key.3 - 0x100);
        let start = self
            .entries
            .get(&start_key)
            .and_then(|words| words.first())
            .copied()
            .unwrap_or(0);
        let count = u64::from(value & 0xffff);
        // The sparse model completes atomically: only the selected pipeline's
        // memory is cleared, never its registers or another block's memory.
        self.entries.retain(|&(memory, block, _, address), _| {
            !(memory
                && block == key.1
                && (value & RESET_ALL != 0
                    || (u64::from(address) >= u64::from(start)
                        && u64::from(address) < u64::from(start) + count)))
        });
        value | RESET_DONE
    }

    fn complete_per_port_age(key: Key, words: &mut [u32]) -> Result<bool, u32> {
        if key != (false, 10, 0, PER_PORT_AGE_CONTROL_64) {
            return Ok(false);
        }
        if words.len() != 2 {
            return Err(BEAT_COUNT);
        }
        // PER_PORT_AGE_CONTROL_64 is an IPIPE command register. The SDK sets
        // START, then polls COMPLETE while flushing an interface from L2. The
        // sparse forwarding model has no independently learned entries to
        // walk, so complete the operation atomically as real hardware does
        // once its table walk finishes.
        if words[0] & PER_PORT_AGE_START != 0 {
            words[0] = (words[0] & !PER_PORT_AGE_START) | PER_PORT_AGE_COMPLETE;
        }
        Ok(true)
    }

    fn transfer(&mut self, key: Key, writing: bool, words: &mut [u32]) -> Result<(), u32> {
        if writing {
            // Missing memory already reads as zero. SDK table initialization
            // must not exhaust the sparse store by materializing empty entries.
            // Registers are excluded: explicit zero can override a reset value.
            if key.0 && words.iter().all(|&word| word == 0) {
                self.entries.remove(&key);
                return Ok(());
            }
            if self.entries.len() >= MAX_ENTRIES && !self.entries.contains_key(&key) {
                return Err(NACK);
            }
            if Self::complete_per_port_age(key, words)? {
                self.entries.insert(key, words.to_vec());
            } else if Self::pipeline_reset_default(key).is_some() {
                if words.len() != 1 {
                    return Err(BEAT_COUNT);
                }
                let value = self.reset_pipeline(key, words[0]);
                self.entries.insert(key, vec![value]);
            } else {
                self.entries.insert(key, words.to_vec());
            }
        } else {
            words.fill(0);
            if let Some(entry) = self.entries.get(&key) {
                for (word, stored) in words.iter_mut().zip(entry) {
                    *word = *stored;
                }
            } else if let Some(default) = Self::register_default(key)
                && let Some(word) = words.first_mut()
            {
                *word = default;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct SChannel {
    control: u32,
    messages: [u32; 22],
    beats: u32,
}

impl SChannel {
    pub(super) fn read(&self, reg: u64) -> Option<u32> {
        match reg {
            0 => Some(self.control),
            4 => Some(self.beats),
            8 => Some(0),
            0x0c..=0x60 => Some(self.messages[((reg - 0x0c) / 4) as usize]),
            _ => None,
        }
    }

    pub(super) fn write(&mut self, reg: u64, value: u32, store: &mut SwitchStore) -> bool {
        match reg {
            0 => {
                if value & 1 == 0 || value & 4 != 0 {
                    self.control = value & !2;
                    self.beats = 0;
                } else if self.control & 1 == 0 {
                    // CMIC owns START once the host launches the operation.
                    // Completion clears START and raises DONE atomically; the
                    // SDK polls START rather than DONE in its synchronous path.
                    self.control = (value & !1) | 2;
                    self.beats = 0;
                    if self.execute(store).is_err() {
                        self.control |= 1 << 21; // MSG_NAK
                        self.messages[0] |= 1; // header NACK
                    }
                }
            }
            4 | 8 => {}
            0x0c..=0x60 => self.messages[((reg - 0x0c) / 4) as usize] = value,
            _ => return false,
        }
        true
    }

    fn execute(&mut self, store: &mut SwitchStore) -> Result<(), u32> {
        let header = self.messages[0];
        let bytes = (header >> 7) & 127;
        let count = (bytes / 4) as usize;
        if matches!(header >> 26, 0x24 | 0x26 | 0x28) {
            return self.table_command(store);
        }
        let (key, writing) = command(header, self.messages[1])?;
        if bytes == 0 || !bytes.is_multiple_of(4) || count > 20 {
            return Err(BEAT_COUNT);
        }
        let mut words = self.messages[2..2 + count].to_vec();
        store.transfer(key, writing, &mut words)?;
        self.messages[0] = (header & 0x03ff_ff80) | (((header >> 26) + 1) << 26);
        if !writing {
            self.messages[1..=count].copy_from_slice(&words);
        }
        self.beats = if writing {
            0
        } else {
            u32::try_from(count).unwrap_or(0)
        };
        Ok(())
    }

    fn table_command(&mut self, store: &mut SwitchStore) -> Result<(), u32> {
        let header = self.messages[0];
        let opcode = header >> 26;
        let address = self.messages[1];
        // Hurricane3 advertises new_sbus_old_resp: type is 29:26, not 31:28.
        self.messages[0] = (header & 0x03ff_c000) | ((opcode + 1) << 26) | (20 << 7);
        self.messages[1] = 15 << 26; // Unsupported/malformed requests return ERROR.
        self.beats = 5;
        if ((header >> 7) & 127) != 16
            || ((header >> 19) & 127) != 10
            || ((header >> 14) & 31) != 0
            || header & 6 != 0 // Bank-restricted hash placement is not modeled.
            || address != L2_BASE
            || self.messages[2] & 7 != 0 // Only the VLAN + MAC L2 key view.
            || (opcode == 0x24 && self.messages[5] & L2_VALID == 0)
        {
            self.messages[2..6].fill(0);
            return Err(NACK);
        }
        let (kind, index) = store.l2_command(opcode, &mut self.messages[2..6]);
        self.messages[1] = (kind << 26) | index;
        if matches!(kind, 1 | 2) {
            Err(NACK)
        } else {
            Ok(())
        }
    }

    pub(super) fn pending(&self) -> u32 {
        if self.control & 2 != 0 { 1 << 20 } else { 0 }
    }
}

#[derive(Debug, Default)]
pub(super) struct SbusDma {
    // Control, request, count, opcode, SBUS address, host address, descriptor,
    // status, current addresses/config and debug registers (0x00..0x4c).
    registers: [u32; 20],
    queued: bool,
}

impl SbusDma {
    pub(super) fn read(&self, reg: u64) -> u32 {
        self.registers[(reg / 4) as usize]
    }

    pub(super) fn write(&mut self, reg: u64, value: u32) {
        if reg == 0 {
            let old = self.registers[0];
            self.registers[0] = value & 15;
            if value & 1 == 0 {
                self.registers[7] = 0;
                self.queued = false;
            } else if value & 2 != 0 {
                self.registers[7] = DONE;
                self.queued = false;
            } else if old & 1 == 0 {
                self.registers[7] = ACTIVE;
                self.queued = true;
            }
        } else if reg < 0x1c {
            self.registers[(reg / 4) as usize] = value;
        } else if reg == 0x44 {
            self.registers[16] &= !value;
        }
    }

    pub(super) fn done(&self) -> bool {
        self.registers[7] & DONE != 0
    }

    pub(super) fn pump(&mut self, ctx: &mut MachineContext<'_>, store: &mut SwitchStore) {
        if !std::mem::take(&mut self.queued) {
            return;
        }
        let result = if self.registers[0] & 4 != 0 {
            self.descriptors(ctx, store)
        } else {
            let mut budget = MAX_WORDS;
            self.transfer(ctx, store, &mut budget)
        };
        self.registers[7] = DONE | result.err().map_or(0, |error| ERROR | error);
    }

    fn descriptors(
        &mut self,
        ctx: &mut MachineContext<'_>,
        store: &mut SwitchStore,
    ) -> Result<(), u32> {
        let mut address = self.registers[6];
        let mut next_host = None;
        let mut budget = MAX_WORDS;
        for _ in 0..MAX_DESCRIPTORS {
            self.registers[10] = address;
            let mut bytes = [0; 24];
            if address & 3 != 0 || !read(ctx, address, &mut bytes) {
                return Err(DESC_READ);
            }
            let mut desc = [0u32; 6];
            for (word, bytes) in desc.iter_mut().zip(bytes.chunks_exact(4)) {
                let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
                *word = if self.registers[0] & 8 != 0 {
                    u32::from_be_bytes(bytes)
                } else {
                    u32::from_le_bytes(bytes)
                };
            }
            // Jump descriptors are not emitted by the SDK's normal builder;
            // reject them until their target format is independently verified.
            if desc[0] & (1 << 29) != 0 {
                return Err(DESC_READ);
            }
            if desc[0] & (1 << 30) == 0 {
                self.registers[1..6].copy_from_slice(&desc[1..6]);
                if desc[0] & (1 << 28) != 0 {
                    self.registers[5] = next_host.ok_or(DESC_READ)?;
                }
                self.transfer(ctx, store, &mut budget)?;
                next_host = Some(self.registers[8]);
                self.registers[16] |= 1;
            }
            if desc[0] & (1 << 31) != 0 {
                return Ok(());
            }
            address = address.checked_add(24).ok_or(DESC_READ)?;
        }
        Err(DESC_READ)
    }

    fn transfer(
        &mut self,
        ctx: &mut MachineContext<'_>,
        store: &mut SwitchStore,
        budget: &mut usize,
    ) -> Result<(), u32> {
        let req = self.registers[1];
        let count = self.registers[2] as usize;
        let header = self.registers[3];
        let (mut key, writing) = command(header, self.registers[4])?;
        let width = (if writing { (req >> 5) & 31 } else { req & 31 }) as usize;
        if width == 0 || count > MAX_ENTRIES || count * width > *budget {
            return Err(BEAT_COUNT);
        }
        // This variant's nullspace and 64-bit word-swap modes are not used
        // by ordinary table operations. Fail instead of copying wrong data.
        if req & 0x3000 != 0 {
            return Err(NACK);
        }
        *budget -= count * width;
        let mut host = self.registers[5];
        if host & 3 != 0 {
            return Err(if writing { HOST_READ } else { HOST_WRITE });
        }
        let step = if req & (1 << 29) != 0 {
            0
        } else {
            1u32 << ((req >> 24) & 31)
        };
        let bytes_per_entry = width * 4;
        let host_step = if req & (1 << 30) != 0 {
            0
        } else {
            u32::try_from(bytes_per_entry).unwrap_or(0)
        };
        // Register-mode drivers supply the high starting address for DECR.
        let descending = req & (1 << 31) != 0;
        self.registers[11..16].copy_from_slice(&[
            req,
            u32::try_from(count).unwrap_or(0),
            key.3,
            host,
            header,
        ]);
        self.registers[8] = host;
        self.registers[9] = key.3;
        for i in 0..count {
            let mut bytes = vec![0; bytes_per_entry];
            let mut words = vec![0; width];
            if writing {
                if !read(ctx, host, &mut bytes) {
                    return Err(HOST_READ);
                }
                for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(4)) {
                    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
                    *word = if req & (1 << 10) != 0 {
                        u32::from_be_bytes(bytes)
                    } else {
                        u32::from_le_bytes(bytes)
                    };
                }
            }
            store.transfer(key, writing, &mut words)?;
            if !writing {
                for (bytes, word) in bytes.chunks_exact_mut(4).zip(words) {
                    bytes.copy_from_slice(&if req & (1 << 11) != 0 {
                        word.to_be_bytes()
                    } else {
                        word.to_le_bytes()
                    });
                }
                if !write(ctx, host, &bytes) {
                    return Err(HOST_WRITE);
                }
            }
            self.registers[12] = u32::try_from(count - i - 1).unwrap_or(0);
            // Address wrap is not a license to DMA into another region.
            host =
                host.checked_add(host_step)
                    .ok_or(if writing { HOST_READ } else { HOST_WRITE })?;
            self.registers[8] = host;
            if i + 1 < count {
                key.3 = if descending {
                    key.3.checked_sub(step)
                } else {
                    key.3.checked_add(step)
                }
                .ok_or(NACK)?;
            }
            self.registers[9] = key.3;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct CopyDma {
    registers: [u32; 10],
    queued: bool,
}

impl CopyDma {
    pub(super) fn read(&self, reg: u64) -> u32 {
        self.registers[(reg / 4) as usize]
    }
    pub(super) fn write(&mut self, reg: u64, value: u32) {
        if reg == 0x0c {
            let old = self.registers[3];
            self.registers[3] = value & 15;
            if value & 1 == 0 {
                self.registers[4] = 0;
                self.queued = false;
            } else if value & 2 != 0 {
                self.registers[4] = DONE;
                self.queued = false;
            } else if old & 1 == 0 {
                self.registers[4] = 0;
                self.queued = true;
            }
        } else if reg < 0x0c {
            self.registers[(reg / 4) as usize] = value;
        }
    }
    pub(super) fn done(&self) -> bool {
        self.registers[4] & DONE != 0
    }
    pub(super) fn pump(&mut self, ctx: &mut MachineContext<'_>) {
        if !std::mem::take(&mut self.queued) {
            return;
        }
        self.registers[5] = self.registers[0];
        self.registers[6] = self.registers[1];
        self.registers[4] = DONE;
        if self.registers[2] as usize > MAX_WORDS
            || (self.registers[0] | self.registers[1]) & 3 != 0
        {
            self.registers[4] |= ERROR;
            return;
        }
        for _ in 0..self.registers[2] {
            let mut word = [0; 4];
            if !read(ctx, self.registers[5], &mut word) {
                self.registers[4] |= ERROR;
                break;
            }
            if ((self.registers[3] >> 2) ^ (self.registers[3] >> 3)) & 1 != 0 {
                word.reverse();
            }
            if !write(ctx, self.registers[6], &word) {
                self.registers[4] |= ERROR;
                break;
            }
            let Some(src) = self.registers[5].checked_add(4) else {
                self.registers[4] |= ERROR;
                break;
            };
            let Some(dst) = self.registers[6].checked_add(4) else {
                self.registers[4] |= ERROR;
                break;
            };
            self.registers[5] = src;
            self.registers[6] = dst;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cmic::Cmic;
    use super::*;
    use board_core::dma::{DmaBus, TransferStatus};

    struct Memory(Vec<u8>);
    impl Memory {
        fn new() -> Self {
            Self(vec![0; 8192])
        }
        fn words(&mut self, address: usize, words: &[u32], big: bool) {
            for (bytes, word) in self.0[address..].chunks_exact_mut(4).zip(words) {
                bytes.copy_from_slice(&if big {
                    word.to_be_bytes()
                } else {
                    word.to_le_bytes()
                });
            }
        }
    }
    impl DmaBus for Memory {
        fn read(&mut self, address: u64, data: &mut [u8]) -> TransferStatus {
            let Ok(start) = usize::try_from(address) else {
                return TransferStatus::Failed;
            };
            let Some(end) = start.checked_add(data.len()) else {
                return TransferStatus::Failed;
            };
            let Some(bytes) = self.0.get(start..end) else {
                return TransferStatus::Failed;
            };
            data.copy_from_slice(bytes);
            TransferStatus::Complete
        }
        fn write(&mut self, address: u64, data: &[u8]) -> TransferStatus {
            let Ok(start) = usize::try_from(address) else {
                return TransferStatus::Failed;
            };
            let Some(end) = start.checked_add(data.len()) else {
                return TransferStatus::Failed;
            };
            let Some(bytes) = self.0.get_mut(start..end) else {
                return TransferStatus::Failed;
            };
            bytes.copy_from_slice(data);
            TransferStatus::Complete
        }
    }

    #[test]
    fn v4_header_preserves_odd_blocks_and_all_access_bits() {
        let header = (13 << 26) | (11 << 19) | (19 << 14) | (4 << 7);
        assert_eq!(
            command(header, 0x0200_0100),
            Ok(((false, 11, 19, 0x0200_0100), true))
        );
    }

    fn l2_request(store: &mut SwitchStore, opcode: u32, entry: [u32; 4]) -> SChannel {
        let mut channel = SChannel::default();
        channel.write(0x0c, (opcode << 26) | (10 << 19) | (16 << 7), store);
        channel.write(0x10, L2_BASE, store);
        for (index, word) in entry.into_iter().enumerate() {
            channel.write(0x14 + u64::try_from(index).unwrap() * 4, word, store);
        }
        channel.write(0, 1, store);
        channel
    }

    #[test]
    fn absent_l2_lookup_returns_done_not_found_and_nack() {
        let mut store = SwitchStore::default();
        let reply = l2_request(&mut store, 0x28, [0xa981_fff0, 0x292a_002a, 0, 0]);
        assert_eq!(reply.messages[0] >> 26, 0x29);
        assert_eq!(reply.messages[1], 1 << 26);
        assert_eq!(reply.control & ((1 << 21) | 2), (1 << 21) | 2);
        assert_eq!(reply.messages[0] & 1, 1);
        assert_eq!(reply.beats, 5);
        assert!(store.entries.is_empty());
    }

    #[test]
    fn inserted_l2_is_found_by_key_without_associated_data() {
        let mut store = SwitchStore::default();
        let entry = [0xa981_fff0, 0x292a_002a, 0x0001_0000, L2_VALID | 0x10];
        let insert = l2_request(&mut store, 0x24, entry);
        assert_eq!(insert.messages[1], 3 << 26);
        assert_eq!(insert.messages[0] & 1, 0);
        let found = l2_request(&mut store, 0x28, [entry[0], entry[1], 0, 0]);
        assert_eq!(found.messages[1], 0);
        assert_eq!(&found.messages[2..6], &entry);
        let mut indexed = [0; 4];
        store
            .transfer((true, 10, 0, L2_BASE), false, &mut indexed)
            .unwrap();
        assert_eq!(indexed, entry);
    }

    #[test]
    fn l2_replacement_returns_old_data_and_delete_removes_indexed_entry() {
        let mut store = SwitchStore::default();
        let old = [0x100, 0, 1, L2_VALID];
        l2_request(&mut store, 0x24, old);
        let new = [0x100, 0, 2, L2_VALID | 0x10];
        let replaced = l2_request(&mut store, 0x24, new);
        assert_eq!(replaced.messages[1], 4 << 26);
        assert_eq!(&replaced.messages[2..6], &old);
        let deleted = l2_request(&mut store, 0x26, [0x100, 0, 0, 0]);
        assert_eq!(deleted.messages[1], 5 << 26);
        assert_eq!(&deleted.messages[2..6], &new);
        assert!(!store.entries.contains_key(&(true, 10, 0, L2_BASE)));
        assert_eq!(
            l2_request(&mut store, 0x26, [0x100, 0, 0, 0]).messages[1],
            1 << 26
        );
    }

    #[test]
    fn indexed_writes_and_pipeline_clear_are_visible_to_l2_lookup() {
        let mut store = SwitchStore::default();
        let mut entry = [0x200, 0, 0, L2_VALID];
        store
            .transfer((true, 10, 0, L2_BASE + 23), true, &mut entry)
            .unwrap();
        assert_eq!(
            l2_request(&mut store, 0x28, [0x200, 0, 0, 0]).messages[1],
            23
        );
        store
            .transfer((false, 10, 0, 0x0200_0300), true, &mut [0x30000])
            .unwrap();
        assert_eq!(
            l2_request(&mut store, 0x28, [0x200, 0, 0, 0]).messages[1],
            1 << 26
        );
    }

    #[test]
    fn l2_key_distinguishes_vlan_and_mac_but_ignores_invalid_entries() {
        let mut store = SwitchStore::default();
        l2_request(&mut store, 0x24, [0x100, 0, 0, L2_VALID]);
        for key in [[0x108, 0, 0, 0], [0x100, 1, 0, 0]] {
            assert_eq!(l2_request(&mut store, 0x28, key).messages[1], 1 << 26);
        }
        store
            .transfer((true, 10, 0, L2_BASE), true, &mut [0x100, 0, 0, 0])
            .unwrap();
        assert_eq!(
            l2_request(&mut store, 0x28, [0x100, 0, 0, 0]).messages[1],
            1 << 26
        );
    }

    #[test]
    fn full_l2_table_reports_full_but_allows_replacement() {
        let mut store = SwitchStore::default();
        for index in 0..L2_ENTRIES {
            store
                .transfer(
                    (true, 10, 0, L2_BASE + index),
                    true,
                    &mut [index << 3, 0, 0, L2_VALID],
                )
                .unwrap();
        }
        assert_eq!(
            l2_request(&mut store, 0x24, [L2_ENTRIES << 3, 0, 0, L2_VALID]).messages[1],
            2 << 26
        );
        assert_eq!(
            l2_request(&mut store, 0x24, [0, 0, 1, L2_VALID]).messages[1],
            4 << 26
        );
    }

    #[test]
    fn unsupported_l2_key_and_invalid_insert_are_errors_without_mutation() {
        let mut store = SwitchStore::default();
        for entry in [[1, 0, 0, L2_VALID], [0, 0, 0, 0]] {
            let reply = l2_request(&mut store, 0x24, entry);
            assert_eq!(reply.messages[1], 15 << 26);
            assert_eq!(reply.messages[0] & 1, 1);
        }
        assert!(store.entries.is_empty());
    }

    #[test]
    fn unsupported_table_namespace_width_or_bank_mask_cannot_insert() {
        let header = (0x24 << 26) | (10 << 19) | (16 << 7);
        let mut store = SwitchStore::default();
        for (request, address) in [
            (header ^ (1 << 19), L2_BASE),
            (header | (1 << 14), L2_BASE),
            (header | 2, L2_BASE),
            (header ^ (16 << 7) ^ (12 << 7), L2_BASE),
            (header, L2_BASE + 1),
        ] {
            let mut channel = SChannel::default();
            channel.write(0x0c, request, &mut store);
            channel.write(0x10, address, &mut store);
            channel.write(0x20, L2_VALID, &mut store);
            channel.write(0, 1, &mut store);
            assert_eq!(channel.messages[0] >> 26, 0x25);
            assert_eq!(channel.messages[1], 15 << 26);
            assert_ne!(channel.control & (1 << 21), 0);
        }
        assert!(store.entries.is_empty());
    }

    #[test]
    fn clearing_large_empty_tables_does_not_consume_sparse_capacity() {
        let mut store = SwitchStore::default();
        for address in 0..=u32::try_from(MAX_ENTRIES).unwrap() {
            store
                .transfer((true, 10, 0, 0x0804_0000 + address), true, &mut [0; 3])
                .unwrap();
        }
        assert!(store.entries.is_empty());
    }

    #[test]
    fn zero_write_removes_old_data_and_frees_capacity_even_when_full() {
        let mut store = SwitchStore::default();
        for address in 0..u32::try_from(MAX_ENTRIES).unwrap() {
            store
                .transfer((true, 10, 0, address), true, &mut [1])
                .unwrap();
        }
        store.transfer((true, 10, 0, 0), true, &mut [0]).unwrap();
        store
            .transfer((true, 10, 0, u32::MAX), true, &mut [2])
            .unwrap();
        let mut result = [1; 3];
        store
            .transfer((true, 10, 0, 0), false, &mut result)
            .unwrap();
        assert_eq!(result, [0; 3]);
    }

    #[test]
    fn tpid_reset_defaults_are_visible_through_schannel() {
        let mut cmic = Cmic::default();
        for (block, base) in [(10, 0x0a00_0d00), (11, 0x1200_1300)] {
            for (index, expected) in [0x8100, 0x9100, 0x88a8, 0].into_iter().enumerate() {
                cmic.write(0x31000, 0);
                cmic.write(0x3100c, (11 << 26) | (block << 19) | (4 << 7));
                cmic.write(0x31010, base + u32::try_from(index).unwrap() * 0x100);
                cmic.write(0x31000, 1);
                assert_eq!(cmic.read(0x31010), Some(expected));
            }
        }
    }

    #[test]
    fn tpid_zero_write_overrides_default_until_new_device_state() {
        let key = (false, 10, 0, 0x0a00_0d00);
        let mut store = SwitchStore::default();
        store.transfer(key, true, &mut [0]).unwrap();
        let mut result = [1];
        store.transfer(key, false, &mut result).unwrap();
        assert_eq!(result, [0]);
        let mut fresh = SwitchStore::default();
        fresh.transfer(key, false, &mut result).unwrap();
        assert_eq!(result, [0x8100]);
    }

    #[test]
    fn tpid_defaults_do_not_alias_memory_blocks_or_access_types() {
        let mut store = SwitchStore::default();
        for key in [
            (true, 10, 0, 0x0a00_0d00),
            (false, 11, 0, 0x0a00_0d00),
            (false, 10, 1, 0x0a00_0d00),
            (false, 10, 0, 0x0a00_0d01),
        ] {
            let mut result = [1];
            store.transfer(key, false, &mut result).unwrap();
            assert_eq!(result, [0]);
        }
    }

    #[test]
    fn pipeline_reset_completes_through_firmware_schannel_sequence() {
        for (block, address, count) in [(10, 0x0200_0300, 0x4000), (11, 0x0200_0100, 0x2000)] {
            let mut cmic = Cmic::default();
            cmic.write(0x3100c, (13 << 26) | (block << 19) | (4 << 7));
            cmic.write(0x31010, address);
            cmic.write(0x31014, 0x30000 | count);
            cmic.write(0x31000, 1);
            cmic.write(0x31000, 0);
            cmic.write(0x3100c, (11 << 26) | (block << 19) | (4 << 7));
            cmic.write(0x31010, address);
            cmic.write(0x31000, 1);
            assert_eq!(cmic.read(0x31010), Some(0x70000 | count));
        }
    }

    #[test]
    fn per_port_age_command_completes_through_schannel() {
        let mut cmic = Cmic::default();
        let header = (13 << 26) | (10 << 19) | (8 << 7);
        cmic.write(0x3100c, header);
        cmic.write(0x31010, PER_PORT_AGE_CONTROL_64);
        cmic.write(0x31014, PER_PORT_AGE_START | (3 << 26) | 7);
        cmic.write(0x31018, 0);
        cmic.write(0x31000, 1);
        cmic.write(0x31000, 0);

        cmic.write(0x3100c, (11 << 26) | (10 << 19) | (8 << 7));
        cmic.write(0x31010, PER_PORT_AGE_CONTROL_64);
        cmic.write(0x31000, 1);
        assert_eq!(
            cmic.read(0x31010),
            Some(PER_PORT_AGE_COMPLETE | (3 << 26) | 7)
        );
        assert_eq!(cmic.read(0x31014), Some(0));
    }

    #[test]
    fn targeted_pipeline_clear_preserves_neighbouring_entries_and_registers() {
        let mut store = SwitchStore::default();
        for key in [
            (true, 10, 0, 0x100),
            (true, 10, 0, 0x101),
            (true, 10, 0, 0x102),
            (true, 11, 0, 0x101),
            (false, 10, 0, 0x101),
        ] {
            store.transfer(key, true, &mut [42]).unwrap();
        }
        store
            .transfer((false, 10, 0, 0x0200_0200), true, &mut [0x101])
            .unwrap();
        store
            .transfer((false, 10, 0, 0x0200_0300), true, &mut [0x20001])
            .unwrap();
        let remaining: Vec<_> = store
            .entries
            .keys()
            .filter(|key| key.3 < 0x200)
            .copied()
            .collect();
        assert_eq!(
            remaining,
            vec![
                (false, 10, 0, 0x101),
                (true, 10, 0, 0x100),
                (true, 10, 0, 0x102),
                (true, 11, 0, 0x101)
            ]
        );
    }

    #[test]
    fn reset_all_clears_only_selected_pipeline_memory() {
        let mut store = SwitchStore::default();
        store
            .transfer((true, 11, 3, 0x8765_4321), true, &mut [42])
            .unwrap();
        store
            .transfer((true, 10, 0, 0x8765_4321), true, &mut [43])
            .unwrap();
        store
            .transfer((false, 11, 0, 0x0200_0100), true, &mut [0x32000])
            .unwrap();
        assert_eq!(store.entries.get(&(true, 11, 3, 0x8765_4321)), None);
        assert_eq!(
            store.entries.get(&(true, 10, 0, 0x8765_4321)),
            Some(&vec![43])
        );
    }

    #[test]
    fn reset_done_cannot_be_forged_and_clears_when_valid_is_removed() {
        let mut store = SwitchStore::default();
        let key = (false, 11, 0, 0x0200_0100);
        store.transfer(key, true, &mut [0x32000]).unwrap();
        store.transfer(key, true, &mut [0x40000]).unwrap();
        let mut result = [u32::MAX];
        store.transfer(key, false, &mut result).unwrap();
        assert_eq!(result, [0]);
    }

    #[test]
    fn reset_defaults_do_not_report_completion() {
        let mut store = SwitchStore::default();
        let mut result = [0];
        store
            .transfer((false, 10, 0, 0x0200_0300), false, &mut result)
            .unwrap();
        assert_eq!(result, [0x1000]);
    }

    fn program(cmic: &mut Cmic, base: u64, words: [u32; 5]) {
        cmic.write(base, 0);
        for (i, word) in words.into_iter().enumerate() {
            cmic.write(base + 4 + i as u64 * 4, word);
        }
        cmic.write(base, 1);
    }

    #[test]
    fn sbus_round_trip_across_all_cmcs_channels_and_schannel() {
        let mut cmic = Cmic::default();
        let mut memory = Memory::new();
        memory.words(
            256,
            &[0x1234_5678, 0x8765_4321, 0xaabb_ccdd, 0x1122_3344],
            false,
        );
        // Write two 2-word memory entries in block 5, access type 2.
        let header = (9 << 26) | (5 << 19) | (2 << 14) | (8 << 7);
        program(&mut cmic, 0x31600, [2 << 5, 2, header, 0x2000, 256]);
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(cmic.read(0x3161c), Some(1));
        for cmc in 0..3 {
            for (channel, interrupt) in [2, 1, 0x40].into_iter().enumerate() {
                let base = 0x31600 + cmc * 0x1000 + channel as u64 * 0x50;
                program(&mut cmic, base, [2, 2, header ^ (14 << 26), 0x2000, 1024]);
                cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
                assert_eq!(cmic.read(base + 0x1c), Some(1));
                assert_eq!(&memory.0[256..272], &memory.0[1024..1040]);
                cmic.write(0x31428 + cmc * 0x1000, interrupt);
                assert_eq!(cmic.irq_change(), Some(true));
                cmic.write(base, 0);
                assert_eq!(cmic.irq_change(), Some(false));
                cmic.write(0x31428 + cmc * 0x1000, 0);
            }
        }
        // S-channel sees the same memory; header/address live in message 0/1.
        cmic.write(0x3300c, header ^ (14 << 26));
        cmic.write(0x33010, 0x2001);
        cmic.write(0x33000, 1);
        assert_eq!(cmic.read(0x33000), Some(2));
        assert_eq!(cmic.read(0x33010), Some(0xaabb_ccdd));
        assert_eq!(cmic.read(0x33014), Some(0x1122_3344));
    }

    #[test]
    fn descriptors_append_skip_and_endian_controls() {
        for big in [false, true] {
            let mut cmic = Cmic::default();
            let mut memory = Memory::new();
            let req = (1 << 5) | if big { 1 << 10 } else { 0 };
            memory.words(256, &[0, req, 1, 9 << 26, 0x40, 2048], big);
            memory.words(280, &[1 << 30, 0, 0, 0, 0, 0], big);
            memory.words(304, &[(1 << 31) | (1 << 28), req, 1, 9 << 26, 0x41, 0], big);
            memory.words(2048, &[0x1234_5678, 0x9abc_def0], big);
            cmic.write(0x33618, 256);
            cmic.write(0x33600, 5 | if big { 8 } else { 0 });
            cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
            assert_eq!(cmic.read(0x3361c), Some(1));
            assert_eq!(cmic.read(0x33628), Some(304));
            program(
                &mut cmic,
                0x31600,
                [1 | if big { 1 << 11 } else { 0 }, 2, 7 << 26, 0x40, 4096],
            );
            cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
            assert_eq!(&memory.0[2048..2056], &memory.0[4096..4104]);
        }
    }

    #[test]
    fn fixed_host_fill_decrement_and_namespace_isolation() {
        let mut cmic = Cmic::default();
        let mut memory = Memory::new();
        memory.words(256, &[0x55aa_eeff], false);
        let header = (13 << 26) | (7 << 19) | (3 << 14);
        program(
            &mut cmic,
            0x31600,
            [
                (1 << 5) | (1 << 30) | (1 << 31) | (2 << 24),
                3,
                header,
                0x108,
                256,
            ],
        );
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        program(
            &mut cmic,
            0x32600,
            [1 | (2 << 24), 3, header ^ (6 << 26), 0x100, 1024],
        );
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(&memory.0[1024..1036], &[0xff, 0xee, 0xaa, 0x55].repeat(3));
        program(&mut cmic, 0x32600, [1, 1, 7 << 26, 0x100, 1024]);
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(&memory.0[1024..1028], &[0; 4]);
    }

    #[test]
    fn failures_set_specific_status_and_acknowledge_only_at_source() {
        let cases = [
            ([1 << 5, 1, 9 << 26, 0, 8192], HOST_READ),
            ([1, 1, 7 << 26, 0, 8192], HOST_WRITE),
            ([0, 1, 7 << 26, 0, 256], BEAT_COUNT),
            ([1, u32::MAX, 7 << 26, 0, 256], BEAT_COUNT),
            ([1, 1, 63 << 26, 0, 256], OPCODE),
        ];
        for (config, error) in cases {
            let mut cmic = Cmic::default();
            let mut memory = Memory::new();
            cmic.write(0x31428, 2);
            program(&mut cmic, 0x31600, config);
            cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
            assert_eq!(cmic.read(0x3161c), Some(DONE | ERROR | error));
            assert_eq!(cmic.irq_change(), Some(true));
            cmic.write(0x31400, 2);
            cmic.write(0x3161c, u32::MAX);
            assert_eq!(cmic.irq_change(), None);
            cmic.write(0x31600, 0);
            assert_eq!(cmic.irq_change(), Some(false));
        }
    }

    #[test]
    fn descriptor_fault_abort_and_missing_dma_bus_terminate() {
        let mut cmic = Cmic::default();
        let mut memory = Memory::new();
        cmic.write(0x31618, 8192);
        cmic.write(0x31600, 5);
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(cmic.read(0x3161c), Some(DONE | ERROR | DESC_READ));
        program(&mut cmic, 0x31600, [1 << 5, 1, 9 << 26, 0, 256]);
        cmic.write(0x31600, 3);
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(cmic.read(0x3161c), Some(DONE));
        program(&mut cmic, 0x31600, [1 << 5, 1, 9 << 26, 0, 256]);
        cmic.pump(&mut MachineContext::new(0));
        assert_eq!(cmic.read(0x3161c), Some(DONE | ERROR | HOST_READ));
    }

    #[test]
    fn copy_dma_and_miim_hold_shared_interrupt_until_both_acknowledge() {
        for cmc in 0..3 {
            for endian in [0, 4, 8, 12] {
                let mut cmic = Cmic::default();
                let mut memory = Memory::new();
                memory.words(256, &[0x1234_5678, 0xaabb_ccdd], false);
                let base = 0x31000 + cmc * 0x1000;
                cmic.write(base + 0x428, (1 << 21) | 0x80);
                cmic.write(base + 0x8c, 2);
                cmic.write(base + 0x3a0, 256);
                cmic.write(base + 0x3a4, 1024);
                cmic.write(base + 0x3a8, 2);
                cmic.write(base + 0x3ac, 1 | endian);
                cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
                assert_eq!(cmic.read(base + 0x3b0), Some(1));
                assert_eq!(cmic.irq_change(), Some(true));
                let mut expected = memory.0[256..264].to_vec();
                if endian == 4 || endian == 8 {
                    for word in expected.chunks_exact_mut(4) {
                        word.reverse();
                    }
                }
                assert_eq!(&memory.0[1024..1032], &expected);
                cmic.write(base + 0x3ac, 0);
                assert_eq!(cmic.irq_change(), None);
                cmic.write(base + 0x8c, 0);
                assert_eq!(cmic.irq_change(), Some(false));
            }
        }
    }

    #[test]
    fn copy_faults_are_reported_and_abort_prevents_a_queued_copy() {
        for (source, destination, count) in [
            (8192, 1024, 1),
            (256, 8192, 1),
            (257, 1024, 1),
            (256, 1024, u32::MAX),
        ] {
            let mut dma = CopyDma::default();
            let mut memory = Memory::new();
            dma.write(0, source);
            dma.write(4, destination);
            dma.write(8, count);
            dma.write(12, 1);
            dma.pump(&mut MachineContext::with_dma(0, &mut memory));
            assert_eq!(dma.read(16), DONE | ERROR);
            dma.write(12, 0);
            assert_eq!(dma.read(16), 0);
            dma.write(12, 1);
            dma.write(12, 3);
            dma.pump(&mut MachineContext::with_dma(0, &mut memory));
            assert_eq!(dma.read(16), DONE);
        }
    }

    #[test]
    fn schannel_write_is_visible_to_dma_and_unknown_commands_nack() {
        let mut cmic = Cmic::default();
        let mut memory = Memory::new();
        for (reg, value) in [
            (0x3300c, (13 << 26) | (4 << 7)),
            (0x33010, 0x48),
            (0x33014, 0x1234_5678),
            (0x33000, 1),
        ] {
            cmic.write(reg, value);
        }
        program(&mut cmic, 0x31600, [1, 1, 11 << 26, 0x48, 1024]);
        cmic.pump(&mut MachineContext::with_dma(0, &mut memory));
        assert_eq!(&memory.0[1024..1028], &0x1234_5678u32.to_le_bytes());
        cmic.write(0x33000, 0);
        cmic.write(0x3300c, 63 << 26);
        cmic.write(0x33000, 1);
        assert_eq!(cmic.read(0x33000), Some(0x0020_0002));
    }
}
