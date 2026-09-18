//! Small deterministic JEDEC SPI-NOR device model.

/// SPI-NOR command bytes used by the board firmware.
pub mod command {
    /// Read JEDEC manufacturer and device identification.
    pub const READ_ID: u8 = 0x9f;
    /// Read data with a three-byte address.
    pub const READ: u8 = 0x03;
    /// Fast read with a dummy byte.
    pub const FAST_READ: u8 = 0x0b;
    /// Quad fast read with a dummy byte.
    pub const QUAD_READ: u8 = 0x6b;
    /// Read status register one.
    pub const READ_STATUS: u8 = 0x05;
    /// Write enable latch.
    pub const WRITE_ENABLE: u8 = 0x06;
    /// Write disable latch.
    pub const WRITE_DISABLE: u8 = 0x04;
    /// Write status register one.
    pub const WRITE_STATUS: u8 = 0x01;
    /// Write status register two.
    pub const WRITE_STATUS2: u8 = 0x31;
}

/// Errors returned by an SPI-NOR transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The requested address or length exceeds the device.
    #[error("SPI-NOR range is outside the device")]
    OutOfRange,
    /// The command requires a write-enable latch.
    #[error("SPI-NOR write is not enabled")]
    WriteDisabled,
    /// The command is not implemented by this device.
    #[error("unsupported SPI-NOR command 0x{0:02x}")]
    Unsupported(u8),
}

/// A JEDEC SPI-NOR chip with byte-addressable storage.
#[derive(Debug, Clone)]
pub struct SpiNor {
    storage: Vec<u8>,
    manufacturer: u8,
    memory_type: u8,
    capacity: u8,
    status: u8,
    status2: u8,
    write_enabled: bool,
}

impl SpiNor {
    /// Creates an erased chip with the supplied JEDEC identity.
    pub fn new(size: usize, jedec_id: [u8; 3]) -> Self {
        Self {
            storage: vec![0xff; size],
            manufacturer: jedec_id[0],
            memory_type: jedec_id[1],
            capacity: jedec_id[2],
            status: 0,
            status2: 0,
            write_enabled: false,
        }
    }
    /// Returns the JEDEC response bytes.
    pub const fn jedec_id(&self) -> [u8; 3] {
        [self.manufacturer, self.memory_type, self.capacity]
    }
    /// Replaces the chip contents with an image, rejecting oversized images.
    pub fn load_image(&mut self, image: &[u8]) -> Result<(), Error> {
        if image.len() > self.storage.len() {
            return Err(Error::OutOfRange);
        }
        self.storage.fill(0xff);
        self.storage[..image.len()].copy_from_slice(image);
        Ok(())
    }
    /// Loads a host-supplied partition without changing adjacent flash bytes.
    /// This is image initialization, not a guest NOR programming operation.
    ///
    /// # Errors
    /// Returns `OutOfRange` without modifying flash if the region exceeds it.
    pub fn load_region(&mut self, address: usize, image: &[u8]) -> Result<(), Error> {
        let end = address.checked_add(image.len()).ok_or(Error::OutOfRange)?;
        self.storage
            .get_mut(address..end)
            .ok_or(Error::OutOfRange)?
            .copy_from_slice(image);
        Ok(())
    }
    /// Executes a read command into `out`.
    pub fn read(&self, opcode: u8, address: usize, out: &mut [u8]) -> Result<(), Error> {
        match opcode {
            command::READ_ID => {
                if address != 0 || out.len() > 3 {
                    return Err(Error::OutOfRange);
                }
                let length = out.len();
                let id = self.jedec_id();
                out[..length].copy_from_slice(&id[..length]);
                Ok(())
            }
            command::READ | command::FAST_READ | command::QUAD_READ => {
                let end = address.checked_add(out.len()).ok_or(Error::OutOfRange)?;
                if end > self.storage.len() {
                    return Err(Error::OutOfRange);
                }
                out.copy_from_slice(&self.storage[address..end]);
                Ok(())
            }
            command::READ_STATUS => {
                if out.len() != 1 {
                    return Err(Error::OutOfRange);
                }
                out[0] = self.status | u8::from(self.write_enabled) << 1;
                Ok(())
            }
            _ => Err(Error::Unsupported(opcode)),
        }
    }
    /// Enables subsequent mutating commands.
    pub fn write_enable(&mut self) {
        self.write_enabled = true;
    }
    /// Disables subsequent mutating commands.
    pub fn write_disable(&mut self) {
        self.write_enabled = false;
    }
    /// Programs bytes using NOR semantics (only one-bits may become zero).
    pub fn program(&mut self, address: usize, data: &[u8]) -> Result<(), Error> {
        self.require_write_enable()?;
        let end = address.checked_add(data.len()).ok_or(Error::OutOfRange)?;
        if end > self.storage.len() {
            return Err(Error::OutOfRange);
        }
        for (current, incoming) in self.storage[address..end].iter_mut().zip(data) {
            *current &= *incoming;
        }
        self.write_enabled = false;
        Ok(())
    }
    /// Updates status register one.
    pub fn write_status(&mut self, value: u8) -> Result<(), Error> {
        self.require_write_enable()?;
        self.status = value & !0x03;
        self.write_enabled = false;
        Ok(())
    }
    /// Updates status register two.
    pub fn write_status2(&mut self, value: u8) -> Result<(), Error> {
        self.require_write_enable()?;
        self.status2 = value;
        self.write_enabled = false;
        Ok(())
    }
    /// Returns the second status register.
    pub const fn status2(&self) -> u8 {
        self.status2
    }
    fn require_write_enable(&self) -> Result<(), Error> {
        if self.write_enabled {
            Ok(())
        } else {
            Err(Error::WriteDisabled)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_import_preserves_adjacent_bytes_and_rejects_overflow_atomically() {
        let mut chip = SpiNor::new(8, [1, 2, 3]);
        chip.load_image(&[0x11; 8]).unwrap();
        chip.load_region(2, &[0xaa, 0xbb]).unwrap();
        let expected = [0x11, 0x11, 0xaa, 0xbb, 0x11, 0x11, 0x11, 0x11];
        assert_eq!(chip.storage, expected);
        assert_eq!(chip.load_region(7, &[0; 2]), Err(Error::OutOfRange));
        assert_eq!(
            chip.load_region(usize::MAX, &[0; 2]),
            Err(Error::OutOfRange)
        );
        assert_eq!(chip.storage, expected);
    }

    #[test]
    fn reads_identity_and_erased_storage() {
        let chip = SpiNor::new(16, [0xef, 0x40, 0x18]);
        let mut id = [0; 3];
        chip.read(command::READ_ID, 0, &mut id).unwrap();
        assert_eq!(id, [0xef, 0x40, 0x18]);
        let mut data = [0; 2];
        chip.read(command::READ, 4, &mut data).unwrap();
        assert_eq!(data, [0xff; 2]);
    }

    #[test]
    fn programming_requires_latch_and_is_nor_safe() {
        let mut chip = SpiNor::new(4, [1, 2, 3]);
        assert_eq!(chip.program(0, &[0x0f]), Err(Error::WriteDisabled));
        chip.write_enable();
        chip.program(0, &[0x0f]).unwrap();
        chip.write_enable();
        chip.program(0, &[0xf0]).unwrap();
        let mut value = [0];
        chip.read(command::READ, 0, &mut value).unwrap();
        assert_eq!(value[0], 0);
    }
}
