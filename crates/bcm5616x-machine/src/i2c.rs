//! The board's I2C devices other than the `PoE` MCU.
//!
//! Every address below was read off the model's own `SMBus` trace of a stock
//! boot, not taken from the `switchdrvr` device tables — those are per board
//! variant and the one carrying `adt0` names addresses this board does not
//! use. The trace logs the eight-bit address, so the seven-bit address is
//! half of what it prints:
//!
//! ```text
//! 0xe0 -> 0x70  channel mux        writes 01,02,04,08,10,20,40,80 and 00
//! 0x42 -> 0x21  I/O expander       regs 03, 06, 07 <- ff, 77, 77
//! 0x5c -> 0x2e  ADT7475            TACH1 at 28/29, PWM config at 30..32
//! 0x90 -> 0x48  LM75               Tos <- 0x3c00, Thyst <- 0x3200
//! 0x92 -> 0x49  LM75               likewise
//! 0x94 -> 0x4a  LM75               likewise
//! 0x96 -> 0x4b  LM75               likewise
//! 0xa6 -> 0x53  EEPROM             pointer write then twelve byte reads
//! ```
//!
//! `switchdrvr` carries the `adt7475`, `lm63` and `max664x` SDK drivers and
//! names the part `OnSemi ADT7475 Thermal Monitor and Fan Controller`. The
//! four LM75s plus the ADT7475's own channels are the five thermal sensors
//! `BOXSERV` reports, and its TACH1 pair is the fan reading.
//!
//! The SFP pages at `0x50` and `0x51` are probed and deliberately left
//! unanswered: the cages are empty on this emulated board, and an absent
//! module is what a bare cage reports.

/// Channel mux. A single control byte selects channels as a bitmask.
const MUX: u8 = 0x70;
/// I/O expander, in the `PCA9555` register order: input pair, output pair,
/// polarity pair, then direction pair.
const EXPANDER: u8 = 0x21;
/// Thermal monitor and fan controller.
const ADT7475: u8 = 0x2e;
/// The four discrete temperature sensors, consecutive addresses.
const LM75_FIRST: u8 = 0x48;
const LM75_COUNT: usize = 4;
const LM75_END: u8 = 0x4c;
/// Board EEPROM, read twelve bytes at a time from a written pointer.
const EEPROM: u8 = 0x53;
/// Bytes the EEPROM answers with. Blank serial EEPROM reads erased.
const EEPROM_SIZE: usize = 256;

/// Synthetic ambient temperature this board reports, in whole degrees.
const AMBIENT_CELSIUS: i16 = 25;
/// Fan speed the tachometer reports. The ADT7475 counts a 90 kHz clock, so
/// the register pair holds `90000 * 60 / rpm`.
const FAN_RPM: u32 = 5000;

/// `ADT7475` temperatures are offset binary: the register holds the
/// temperature plus 64, so 25 C reads as 89.
const ADT7475_TEMP_OFFSET: i16 = 64;
/// Device, company and revision identification, registers `0x3d`..`0x3f`.
const ADT7475_DEVICE_ID: u8 = 0x75;
const ADT7475_COMPANY_ID: u8 = 0x41;
const ADT7475_REVISION: u8 = 0x69;
/// Remote 1, local and remote 2 temperature registers.
const ADT7475_TEMPERATURES: [u8; 3] = [0x25, 0x26, 0x27];
/// Tachometer register pairs, low byte first. The trace reads the first pair.
const ADT7475_TACH_FIRST: u8 = 0x28;
const ADT7475_TACH_PAIRS: u8 = 4;

/// `LM75` register pointers: temperature, configuration, hysteresis, setpoint.
const LM75_TEMPERATURE: u8 = 0;
const LM75_CONFIGURATION: u8 = 1;

/// One transaction, decoded from the controller's protocol field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    /// Address-only presence probe.
    Quick,
    /// One data byte with no register.
    SendByte(u8),
    /// One data byte read from the current pointer.
    ReceiveByte,
    WriteByte {
        register: u8,
        value: u8,
    },
    ReadByte {
        register: u8,
    },
    WriteWord {
        register: u8,
        value: u16,
    },
    ReadWord {
        register: u8,
    },
}

#[derive(Debug)]
pub(super) struct Bus {
    mux: u8,
    expander: Expander,
    adt7475: Adt7475,
    lm75: [Lm75; LM75_COUNT],
    eeprom: Eeprom,
}

impl Default for Bus {
    fn default() -> Self {
        Self {
            mux: 0,
            expander: Expander::default(),
            adt7475: Adt7475::default(),
            lm75: [Lm75::default(); LM75_COUNT],
            eeprom: Eeprom::default(),
        }
    }
}

impl Bus {
    /// Runs one transaction. `None` is a device that does not answer, which
    /// the controller reports as a NACK.
    ///
    /// The mux channel is tracked but not enforced: the trace walks every
    /// channel looking for devices, and no two modelled devices share an
    /// address, so gating on the selection would only hide them.
    pub(super) fn transfer(&mut self, address: u8, op: Op) -> Option<Vec<u8>> {
        match address {
            MUX => self.mux_transfer(op),
            EXPANDER => self.expander.transfer(op),
            ADT7475 => self.adt7475.transfer(op),
            EEPROM => self.eeprom.transfer(op),
            _ if (LM75_FIRST..LM75_END).contains(&address) => {
                Some(self.lm75[usize::from(address - LM75_FIRST)].transfer(op))
            }
            _ => None,
        }
    }

    /// Returns true for addresses that a real, empty board deliberately
    /// leaves unanswered rather than treating as generic synthetic devices.
    pub(super) const fn is_known_absent(address: u8) -> bool {
        matches!(address, 0x3f | 0x50 | 0x51)
    }

    fn mux_transfer(&mut self, op: Op) -> Option<Vec<u8>> {
        match op {
            Op::Quick => Some(Vec::new()),
            Op::SendByte(value) => {
                self.mux = value;
                Some(Vec::new())
            }
            Op::ReceiveByte => Some(vec![self.mux]),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn selected_channels(&self) -> u8 {
        self.mux
    }
}

/// `PCA9555`-style expander. Direction and polarity default to inputs, and
/// an unconnected input reads high.
#[derive(Debug)]
struct Expander {
    registers: [u8; 8],
}

impl Default for Expander {
    fn default() -> Self {
        let mut registers = [0; 8];
        registers[0] = 0xff;
        registers[1] = 0xff;
        registers[6] = 0xff;
        registers[7] = 0xff;
        Self { registers }
    }
}

impl Expander {
    fn transfer(&mut self, op: Op) -> Option<Vec<u8>> {
        match op {
            Op::Quick => Some(Vec::new()),
            Op::WriteByte { register, value } => {
                // The input pair is driven by the pins, not the host.
                if usize::from(register) < self.registers.len() && register >= 2 {
                    self.registers[usize::from(register)] = value;
                }
                Some(Vec::new())
            }
            Op::ReadByte { register } => Some(vec![
                self.registers
                    .get(usize::from(register))
                    .copied()
                    .unwrap_or(0xff),
            ]),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Adt7475 {
    registers: [u8; 256],
}

impl Default for Adt7475 {
    fn default() -> Self {
        let mut registers = [0; 256];
        let count = u16::try_from(90_000 * 60 / FAN_RPM).unwrap_or(u16::MAX);
        for pair in 0..ADT7475_TACH_PAIRS {
            let base = usize::from(ADT7475_TACH_FIRST + pair * 2);
            registers[base] = count.to_le_bytes()[0];
            registers[base + 1] = count.to_le_bytes()[1];
        }
        registers[0x3d] = ADT7475_DEVICE_ID;
        registers[0x3e] = ADT7475_COMPANY_ID;
        registers[0x3f] = ADT7475_REVISION;
        Self { registers }
    }
}

impl Adt7475 {
    fn transfer(&mut self, op: Op) -> Option<Vec<u8>> {
        match op {
            Op::Quick => Some(Vec::new()),
            Op::WriteByte { register, value } => {
                // Identification and the measured channels are driven by the
                // part; everything else stores what the driver configures.
                if !Self::read_only(register) {
                    self.registers[usize::from(register)] = value;
                }
                Some(Vec::new())
            }
            Op::ReadByte { register } => Some(vec![self.read(register)]),
            _ => None,
        }
    }

    fn read_only(register: u8) -> bool {
        ADT7475_TEMPERATURES.contains(&register)
            || (0x3d..=0x3f).contains(&register)
            || (ADT7475_TACH_FIRST..ADT7475_TACH_FIRST + ADT7475_TACH_PAIRS * 2).contains(&register)
    }

    fn read(&self, register: u8) -> u8 {
        if ADT7475_TEMPERATURES.contains(&register) {
            if self.registers[0x7c] & 1 != 0 {
                return i8::try_from(AMBIENT_CELSIUS)
                    .unwrap_or_default()
                    .to_ne_bytes()[0];
            }
            return u8::try_from(AMBIENT_CELSIUS + ADT7475_TEMP_OFFSET).unwrap_or_default();
        }
        self.registers[usize::from(register)]
    }
}

/// `LM75`-compatible sensor. Word registers are big-endian on this bus: the
/// trace writes the 60 C setpoint as `3c 00`.
#[derive(Clone, Copy, Debug)]
struct Lm75 {
    pointer: u8,
    configuration: u8,
    hysteresis: u16,
    setpoint: u16,
}

impl Default for Lm75 {
    fn default() -> Self {
        Self {
            pointer: LM75_TEMPERATURE,
            configuration: 0,
            // Power-on defaults: 75 C hysteresis, 80 C O.S. setpoint.
            hysteresis: 0x4b00,
            setpoint: 0x5000,
        }
    }
}

impl Lm75 {
    fn temperature() -> u16 {
        (AMBIENT_CELSIUS as u16) << 8
    }

    fn word(self, register: u8) -> u16 {
        match register {
            LM75_TEMPERATURE => Self::temperature(),
            LM75_CONFIGURATION => u16::from(self.configuration) << 8,
            2 => self.hysteresis,
            _ => self.setpoint,
        }
    }

    fn transfer(&mut self, op: Op) -> Vec<u8> {
        match op {
            Op::Quick => Vec::new(),
            // A bare byte moves the register pointer, which is how the trace
            // parks the part on the temperature register before reading it.
            Op::SendByte(register) => {
                self.pointer = register & 3;
                Vec::new()
            }
            Op::WriteByte { register, value } => {
                if register & 3 == LM75_CONFIGURATION {
                    self.configuration = value;
                }
                self.pointer = register & 3;
                Vec::new()
            }
            Op::WriteWord { register, value } => {
                match register & 3 {
                    LM75_TEMPERATURE => {}
                    LM75_CONFIGURATION => self.configuration = value.to_be_bytes()[0],
                    2 => self.hysteresis = value,
                    _ => self.setpoint = value,
                }
                self.pointer = register & 3;
                Vec::new()
            }
            Op::ReadWord { register } => self.word(register & 3).to_be_bytes().to_vec(),
            Op::ReceiveByte => vec![self.word(self.pointer).to_be_bytes()[0]],
            Op::ReadByte { register } => vec![self.word(register & 3).to_be_bytes()[0]],
        }
    }
}

/// Serial EEPROM read from a written byte pointer. Nothing has been
/// programmed into this model's part, so it reads erased.
#[derive(Debug)]
struct Eeprom {
    pointer: usize,
    bytes: [u8; EEPROM_SIZE],
}

impl Default for Eeprom {
    fn default() -> Self {
        Self {
            pointer: 0,
            bytes: [0xff; EEPROM_SIZE],
        }
    }
}

impl Eeprom {
    fn transfer(&mut self, op: Op) -> Option<Vec<u8>> {
        match op {
            Op::Quick => Some(Vec::new()),
            Op::SendByte(pointer) => {
                self.pointer = usize::from(pointer);
                Some(Vec::new())
            }
            Op::WriteByte { register, .. } => {
                self.pointer = usize::from(register);
                Some(Vec::new())
            }
            Op::ReceiveByte => {
                let byte = self.bytes[self.pointer % EEPROM_SIZE];
                self.pointer = self.pointer.wrapping_add(1);
                Some(vec![byte])
            }
            Op::ReadByte { register } => Some(vec![self.bytes[usize::from(register)]]),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mux_stores_and_reports_its_channel_selection() {
        let mut bus = Bus::default();
        // The trace walks every channel, then parks on one.
        for channel in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x00] {
            assert_eq!(bus.transfer(MUX, Op::SendByte(channel)), Some(Vec::new()));
            assert_eq!(bus.selected_channels(), channel);
        }
        assert_eq!(bus.transfer(MUX, Op::Quick), Some(Vec::new()));
    }

    #[test]
    fn captured_expander_configuration_is_accepted_and_reads_back() {
        let mut bus = Bus::default();
        for (register, value) in [(0x03, 0xff), (0x06, 0x77), (0x07, 0x77)] {
            assert_eq!(
                bus.transfer(EXPANDER, Op::WriteByte { register, value }),
                Some(Vec::new())
            );
            assert_eq!(
                bus.transfer(EXPANDER, Op::ReadByte { register }),
                Some(vec![value])
            );
        }
    }

    #[test]
    fn the_thermal_monitor_identifies_itself_and_reports_a_running_fan() {
        let mut bus = Bus::default();
        assert_eq!(
            bus.transfer(ADT7475, Op::ReadByte { register: 0x3d }),
            Some(vec![ADT7475_DEVICE_ID])
        );
        assert_eq!(
            bus.transfer(ADT7475, Op::ReadByte { register: 0x3e }),
            Some(vec![ADT7475_COMPANY_ID])
        );
        // The trace reads the first tachometer pair, low byte then high.
        let low = bus
            .transfer(ADT7475, Op::ReadByte { register: 0x28 })
            .unwrap()[0];
        let high = bus
            .transfer(ADT7475, Op::ReadByte { register: 0x29 })
            .unwrap()[0];
        let count = u32::from(u16::from_le_bytes([low, high]));
        assert_ne!(count, 0, "a stopped fan reads as 0xffff, not as a count");
        assert_eq!(90_000 * 60 / count, FAN_RPM);
    }

    #[test]
    fn the_thermal_monitor_reports_ambient_and_keeps_driver_configuration() {
        let mut bus = Bus::default();
        for register in ADT7475_TEMPERATURES {
            let value = bus.transfer(ADT7475, Op::ReadByte { register }).unwrap()[0];
            assert_eq!(i16::from(value) - ADT7475_TEMP_OFFSET, AMBIENT_CELSIUS);
        }
        // The captured boot selects backwards-compatible two's-complement
        // temperature encoding before reading the channels.
        bus.transfer(
            ADT7475,
            Op::WriteByte {
                register: 0x7c,
                value: 0x0d,
            },
        );
        for register in ADT7475_TEMPERATURES {
            assert_eq!(
                bus.transfer(ADT7475, Op::ReadByte { register }),
                Some(vec![u8::try_from(AMBIENT_CELSIUS).unwrap()])
            );
        }
        // Captured configuration writes must stick.
        for (register, value) in [(0x5c, 0xe0), (0x5f, 0xca), (0x7c, 0x0d), (0x30, 0x40)] {
            bus.transfer(ADT7475, Op::WriteByte { register, value });
            assert_eq!(
                bus.transfer(ADT7475, Op::ReadByte { register }),
                Some(vec![value])
            );
        }
        // A measured channel is not writable.
        bus.transfer(
            ADT7475,
            Op::WriteByte {
                register: 0x26,
                value: 0,
            },
        );
        assert_ne!(
            bus.transfer(ADT7475, Op::ReadByte { register: 0x26 }),
            Some(vec![0])
        );
    }

    #[test]
    fn captured_lm75_setpoints_are_accepted_by_all_four_sensors() {
        let mut bus = Bus::default();
        for address in LM75_FIRST..LM75_END {
            assert_eq!(bus.transfer(address, Op::Quick), Some(Vec::new()));
            // The trace writes 60 C then 50 C, big-endian, then parks the
            // pointer on the temperature register.
            for (register, value) in [(0x03, 0x3c00_u16), (0x02, 0x3200)] {
                assert_eq!(
                    bus.transfer(address, Op::WriteWord { register, value }),
                    Some(Vec::new())
                );
                assert_eq!(
                    bus.transfer(address, Op::ReadWord { register }),
                    Some(value.to_be_bytes().to_vec())
                );
            }
            bus.transfer(
                address,
                Op::WriteByte {
                    register: 0,
                    value: 0,
                },
            );
            let reading = bus.transfer(address, Op::ReadWord { register: 0 }).unwrap();
            assert_eq!(i16::from(reading[0]), AMBIENT_CELSIUS);
        }
    }

    #[test]
    fn the_eeprom_reads_sequentially_from_the_written_pointer() {
        let mut bus = Bus::default();
        bus.transfer(
            EEPROM,
            Op::WriteByte {
                register: 0,
                value: 0,
            },
        );
        // The trace takes twelve bytes one at a time.
        for _ in 0..12 {
            assert_eq!(bus.transfer(EEPROM, Op::ReceiveByte), Some(vec![0xff]));
        }
    }

    #[test]
    fn the_empty_sfp_cages_do_not_answer() {
        let mut bus = Bus::default();
        for address in [0x50, 0x51] {
            assert_eq!(bus.transfer(address, Op::Quick), None);
        }
        // Nor does an address the trace probes with nothing behind it.
        assert_eq!(bus.transfer(0x3f, Op::Quick), None);
    }
}
