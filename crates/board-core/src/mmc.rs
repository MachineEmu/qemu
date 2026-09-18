//! Deterministic MMC/eMMC identity and block storage model.

use std::collections::{BTreeMap, BTreeSet};

/// MMC command number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Send operating condition.
    SendOpCond,
    /// Return CID.
    AllSendCid,
    /// Set relative address.
    SetRelativeAddress,
    /// Return CSD.
    SendCsd,
    /// Return card status.
    SendStatus,
    /// Read one or more blocks.
    Read {
        /// First block number.
        block: u64,
        /// Number of blocks.
        blocks: usize,
    },
    /// Write one or more blocks.
    Write {
        /// First block number.
        block: u64,
        /// Number of blocks.
        blocks: usize,
    },
}

/// Response and data result from one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response words in controller register order.
    pub words: [u32; 4],
    /// Data returned by a read command.
    pub data: Vec<u8>,
}

/// Card model error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Command was not valid for the model.
    #[error("unsupported MMC command")]
    Unsupported,
    /// Request exceeds backing storage.
    #[error("MMC block range is outside the card")]
    OutOfRange,
    /// Write payload has the wrong length.
    #[error("MMC write payload length does not match command")]
    InvalidLength,
}

/// Bytes in one addressable block.
pub const BLOCK_SIZE: usize = 512;

/// Operating conditions reported by [`Command::SendOpCond`].
///
/// Bit 30 (sector mode) is clear, so the host addresses the card by byte
/// offset rather than by block number.
const OCR: u32 = 0x80ff_8080;
const OCR_SECTOR_MODE: u32 = 1 << 30;

/// A block-addressed eMMC card.
///
/// Storage is sparse: only blocks that have been written or loaded are held.
/// The card can therefore advertise the full capacity reported by its CSD -
/// a GPT keeps its backup header in the last block of the device - without
/// allocating that capacity up front.
#[derive(Debug, Clone)]
pub struct MmcCard {
    blocks: BTreeMap<u64, [u8; BLOCK_SIZE]>,
    dirty: BTreeSet<u64>,
    block_count: u64,
    block_size: usize,
}

impl MmcCard {
    /// Creates a zero-filled card with the given block count.
    pub fn new(blocks: usize) -> Self {
        Self {
            blocks: BTreeMap::new(),
            dirty: BTreeSet::new(),
            block_count: blocks as u64,
            block_size: BLOCK_SIZE,
        }
    }

    /// Returns the number of addressable blocks.
    #[must_use]
    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Converts a controller read/write command argument into a block number.
    ///
    /// Linux shifts the argument by nine bits for a card that does not report
    /// sector mode in its OCR, so a model that reads the argument as a block
    /// number lands 512 times too far into the card and fails every access
    /// past the first megabyte.
    #[must_use]
    pub fn block_address(&self, argument: u32) -> u64 {
        if OCR & OCR_SECTOR_MODE == 0 {
            u64::from(argument) / self.block_size as u64
        } else {
            u64::from(argument)
        }
    }
    /// Executes an identity, status, read, or write command.
    pub fn command(&mut self, command: Command, write_data: &[u8]) -> Result<Response, Error> {
        let words = match command {
            Command::SendOpCond => [OCR, 0, 0, 0],
            // CID words in controller register order (RESP0..RESP3).  The
            // MSDC driver reassembles an R2 response as
            // resp[0] = RESP3 .. resp[3] = RESP0, and the CSD below reports
            // MMCA spec version 0, so Linux decodes a 24-bit manufacturer id
            // from bits 104..127 and a seven character product name from
            // bits 48..103.  Keeping the fields aligned with that layout is
            // what makes `mmcblk0` announce a printable name instead of the
            // raw placeholder bytes.
            Command::AllSendCid => [0x3456_0001, 0x4d43_0012, 0x3650_454d, 0x4d54_4b55],
            Command::SetRelativeAddress => [0x0001_0000, 0, 0, 0],
            Command::SendCsd => [0x0a40_4000, 0xc007_bf80, 0x5b59_03ff, 0x400e_0032],
            Command::SendStatus => [0x0000_0900, 0, 0, 0],
            Command::Read { block, blocks } => {
                self.check(block, blocks)?;
                let mut data = Vec::with_capacity(blocks * self.block_size);
                for index in 0..blocks as u64 {
                    match self.blocks.get(&(block + index)) {
                        Some(stored) => data.extend_from_slice(stored),
                        None => data.extend(std::iter::repeat_n(0, self.block_size)),
                    }
                }
                return Ok(Response {
                    words: [0; 4],
                    data,
                });
            }
            Command::Write { block, blocks } => {
                self.check(block, blocks)?;
                if write_data.len() != blocks * self.block_size {
                    return Err(Error::InvalidLength);
                }
                for (index, chunk) in write_data.chunks_exact(self.block_size).enumerate() {
                    let block = block + index as u64;
                    self.store(block, chunk);
                    self.dirty.insert(block);
                }
                return Ok(Response {
                    words: [0; 4],
                    data: Vec::new(),
                });
            }
        };
        Ok(Response {
            words,
            data: Vec::new(),
        })
    }
    /// Replaces the card contents with an image, padding short images with
    /// zeroes and rejecting images larger than the card.
    pub fn load_image(&mut self, image: &[u8]) -> Result<(), Error> {
        if image.len() > self.capacity() {
            return Err(Error::OutOfRange);
        }
        self.blocks.clear();
        self.dirty.clear();
        for (index, chunk) in image.chunks(self.block_size).enumerate() {
            if chunk.len() == self.block_size {
                self.store(index as u64, chunk);
            } else {
                let mut padded = vec![0; self.block_size];
                padded[..chunk.len()].copy_from_slice(chunk);
                self.store(index as u64, &padded);
            }
        }
        Ok(())
    }

    /// Writes one image at a block offset, leaving the rest of the card intact.
    pub fn write_blocks(&mut self, block: u64, image: &[u8]) -> Result<(), Error> {
        let blocks = image.len().div_ceil(self.block_size);
        self.check(block, blocks)?;
        for (index, chunk) in image.chunks(self.block_size).enumerate() {
            let mut padded = [0; BLOCK_SIZE];
            padded[..chunk.len()].copy_from_slice(chunk);
            self.store(block + index as u64, &padded);
        }
        Ok(())
    }

    /// Removes and returns the blocks written by the guest since the last
    /// call, as `(block number, contents)` pairs.
    ///
    /// Blocks placed by [`MmcCard::load_image`] or [`MmcCard::write_blocks`]
    /// are not reported: those come from the backing image or the board's
    /// seeded defaults and are already on the host side.
    pub fn take_dirty(&mut self) -> Vec<(u64, [u8; BLOCK_SIZE])> {
        let dirty = std::mem::take(&mut self.dirty);
        dirty
            .into_iter()
            .map(|block| {
                (
                    block,
                    self.blocks.get(&block).copied().unwrap_or([0; BLOCK_SIZE]),
                )
            })
            .collect()
    }

    /// Marks every block currently present as needing to be persisted.
    ///
    /// Used when a backing image is created from scratch, so the board's
    /// seeded contents are written into it and the file becomes a complete
    /// image of the card rather than a partial overlay.
    pub fn mark_all_dirty(&mut self) {
        self.dirty.extend(self.blocks.keys().copied());
    }

    /// Returns whether the guest has written blocks that are not yet taken.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    fn capacity(&self) -> usize {
        usize::try_from(self.block_count)
            .unwrap_or(usize::MAX)
            .saturating_mul(self.block_size)
    }

    fn store(&mut self, block: u64, data: &[u8]) {
        if data.iter().all(|byte| *byte == 0) {
            self.blocks.remove(&block);
            return;
        }
        let mut stored = [0; BLOCK_SIZE];
        stored.copy_from_slice(data);
        self.blocks.insert(block, stored);
    }

    fn check(&self, block: u64, blocks: usize) -> Result<(), Error> {
        let blocks = u64::try_from(blocks).map_err(|_| Error::OutOfRange)?;
        let end = block.checked_add(blocks).ok_or(Error::OutOfRange)?;
        if end > self.block_count {
            Err(Error::OutOfRange)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_recorded_controller_responses() {
        let mut card = MmcCard::new(4);
        assert_eq!(
            card.command(Command::SendOpCond, &[]).unwrap().words[0],
            0x80ff_8080
        );
        assert_eq!(
            card.command(Command::AllSendCid, &[]).unwrap().words[3],
            0x4d54_4b55
        );
    }
    #[test]
    fn only_guest_writes_are_reported_as_dirty() {
        let mut card = MmcCard::new(64);

        // Seeded and loaded content belongs to the host already.
        card.write_blocks(4, &[0x11; BLOCK_SIZE]).unwrap();
        card.load_image(&[0x22; BLOCK_SIZE]).unwrap();
        assert!(!card.is_dirty());
        assert!(card.take_dirty().is_empty());

        // A guest write is pending until it is taken.
        card.command(
            Command::Write {
                block: 7,
                blocks: 1,
            },
            &[0x5a; BLOCK_SIZE],
        )
        .unwrap();
        assert!(card.is_dirty());
        let taken = card.take_dirty();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].0, 7);
        assert_eq!(taken[0].1, [0x5a; BLOCK_SIZE]);
        assert!(!card.is_dirty());

        // A write of zeroes clears the block but must still be persisted, or
        // the backing image would keep stale contents at that offset.
        card.command(
            Command::Write {
                block: 7,
                blocks: 1,
            },
            &[0; BLOCK_SIZE],
        )
        .unwrap();
        let taken = card.take_dirty();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0], (7, [0; BLOCK_SIZE]));

        // Marking the whole card pending covers the seeded blocks.
        card.mark_all_dirty();
        assert!(card.is_dirty());
    }

    #[test]
    fn block_round_trip_rejects_wrong_payload() {
        let mut card = MmcCard::new(2);
        assert_eq!(
            card.command(
                Command::Write {
                    block: 0,
                    blocks: 1
                },
                &[1]
            )
            .unwrap_err(),
            Error::InvalidLength
        );
        let payload = vec![0x5a; 512];
        card.command(
            Command::Write {
                block: 1,
                blocks: 1,
            },
            &payload,
        )
        .unwrap();
        assert_eq!(
            card.command(
                Command::Read {
                    block: 1,
                    blocks: 1
                },
                &[]
            )
            .unwrap()
            .data,
            payload
        );
    }
}
