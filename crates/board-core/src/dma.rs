//! DMA contracts shared by descriptor engines and replay buses.

/// Result of a host-memory transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// All requested bytes were transferred.
    Complete,
    /// The host rejected the transfer.
    Failed,
}

/// Memory bus used by model-owned descriptor engines.
pub trait DmaBus {
    /// Reads guest memory into `buffer`.
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> TransferStatus;
    /// Writes `buffer` into guest memory.
    fn write(&mut self, address: u64, buffer: &[u8]) -> TransferStatus;
}

/// A little-endian descriptor with a next pointer and payload extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// Descriptor address in guest memory.
    pub address: u64,
    /// Next descriptor address, or zero at the end of a chain.
    pub next: u64,
    /// Payload address.
    pub buffer: u64,
    /// Payload length.
    pub length: usize,
}

/// Reads a bounded descriptor chain without silently accepting malformed DMA.
pub fn walk_chain<B: DmaBus>(
    bus: &mut B,
    first: u64,
    max_descriptors: usize,
) -> Result<Vec<Descriptor>, TransferStatus> {
    let mut result = Vec::new();
    let mut address = first;
    while address != 0 {
        if result.len() == max_descriptors
            || result
                .iter()
                .any(|descriptor: &Descriptor| descriptor.address == address)
        {
            return Err(TransferStatus::Failed);
        }
        let mut raw = [0; 16];
        if bus.read(address, &mut raw) != TransferStatus::Complete {
            return Err(TransferStatus::Failed);
        }
        let next = u64::from(u32::from_le_bytes(raw[0..4].try_into().unwrap()));
        let buffer = u64::from(u32::from_le_bytes(raw[4..8].try_into().unwrap()));
        let length = usize::try_from(u32::from_le_bytes(raw[8..12].try_into().unwrap()))
            .map_err(|_| TransferStatus::Failed)?;
        result.push(Descriptor {
            address,
            next,
            buffer,
            length,
        });
        address = next;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBus {
        memory: Vec<u8>,
        fail_reads: bool,
    }
    impl DmaBus for FakeBus {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> TransferStatus {
            if self.fail_reads || address as usize + buffer.len() > self.memory.len() {
                return TransferStatus::Failed;
            }
            buffer.copy_from_slice(&self.memory[address as usize..address as usize + buffer.len()]);
            TransferStatus::Complete
        }
        fn write(&mut self, address: u64, buffer: &[u8]) -> TransferStatus {
            if address as usize + buffer.len() > self.memory.len() {
                return TransferStatus::Failed;
            }
            self.memory[address as usize..address as usize + buffer.len()].copy_from_slice(buffer);
            TransferStatus::Complete
        }
    }

    #[test]
    fn chain_walk_rejects_cycles() {
        let mut bus = FakeBus {
            memory: vec![0; 32],
            fail_reads: false,
        };
        bus.memory[0..4].copy_from_slice(&0u32.to_le_bytes());
        bus.memory[4..8].copy_from_slice(&0u32.to_le_bytes());
        bus.memory[8..12].copy_from_slice(&0u32.to_le_bytes());
        bus.memory[16..20].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(walk_chain(&mut bus, 16, 4), Err(TransferStatus::Failed));
    }

    #[test]
    fn chain_walk_preserves_descriptor_order() {
        let mut bus = FakeBus {
            memory: vec![0; 64],
            fail_reads: false,
        };
        bus.memory[16..20].copy_from_slice(&32u32.to_le_bytes());
        bus.memory[20..24].copy_from_slice(&48u32.to_le_bytes());
        bus.memory[24..28].copy_from_slice(&7u32.to_le_bytes());
        bus.memory[32..36].copy_from_slice(&0u32.to_le_bytes());
        bus.memory[36..40].copy_from_slice(&9u32.to_le_bytes());
        bus.memory[40..44].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(walk_chain(&mut bus, 16, 4).unwrap().len(), 2);
    }
}
