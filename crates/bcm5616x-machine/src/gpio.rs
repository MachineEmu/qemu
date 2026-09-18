//! GPIOG interrupt registers recovered from the vendor kernel's IRQ chip.

pub(super) const BASE: u64 = 0x1800_a000;
pub(super) const IRQ: u32 = 96;
const PINS: u32 = 0xfff0;

#[derive(Debug)]
pub(super) struct Gpio {
    input: u32,
    output: u32,
    output_enable: u32,
    sense: u32,
    both_edges: u32,
    polarity: u32,
    enable: u32,
    edges: u32,
    asserted: bool,
}

impl Default for Gpio {
    fn default() -> Self {
        Self {
            // Synthetic board inputs are pulled high, including reset bit 14.
            input: PINS,
            output: 0,
            output_enable: 0,
            sense: 0,
            both_edges: 0,
            polarity: 0,
            enable: 0,
            edges: 0,
            asserted: false,
        }
    }
}

impl Gpio {
    fn trace(&self, operation: &str, offset: u64, value: u32) {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *ENABLED.get_or_init(|| std::env::var_os("UNIFI_TRACE_GPIO").is_some()) {
            eprintln!(
                "GPIOG {operation} offset={offset:#x} value={value:#06x} reset_released={} pins={:#06x} sense={:#06x} polarity={:#06x} enable={:#06x} raw={:#06x} irq96={}",
                self.pins() & (1 << 14) != 0,
                self.pins(),
                self.sense,
                self.polarity,
                self.enable,
                self.raw(),
                self.raw() & self.enable != 0,
            );
        }
    }

    fn pins(&self) -> u32 {
        (self.input & !self.output_enable) | (self.output & self.output_enable)
    }

    fn raw(&self) -> u32 {
        ((!(self.pins() ^ self.polarity) & self.sense) | (self.edges & !self.sense)) & PINS
    }

    pub(super) fn read(&self, offset: u64) -> Option<u32> {
        let value = match offset {
            0 => self.pins(),
            4 => self.output,
            8 => self.output_enable,
            0xc => self.sense,
            0x10 => self.both_edges,
            0x14 => self.polarity,
            0x18 => self.enable,
            0x1c => self.raw(),
            0x20 => self.raw() & self.enable,
            0x24 => 0,
            _ => return None,
        };
        self.trace("read", offset, value);
        Some(value)
    }

    pub(super) fn write(&mut self, offset: u64, value: u32) -> bool {
        let old = self.pins();
        let value = value & PINS;
        match offset {
            0 | 0x1c | 0x20 => {}
            4 => self.output = value,
            8 => self.output_enable = value,
            0xc => self.sense = value,
            0x10 => self.both_edges = value,
            0x14 => self.polarity = value,
            0x18 => self.enable = value,
            0x24 => self.edges &= !value,
            _ => return false,
        }
        self.latch_edges(old);
        self.trace("write", offset, value);
        true
    }

    fn latch_edges(&mut self, old: u32) {
        let pins = self.pins();
        self.edges |=
            (old ^ pins) & (self.both_edges | !(pins ^ self.polarity)) & !self.sense & PINS;
    }

    pub(super) fn set_input(&mut self, value: u32) {
        let old = self.pins();
        self.input = value & PINS;
        self.latch_edges(old);
        self.trace("input", 0, value);
    }

    pub(super) fn irq_change(&mut self) -> Option<bool> {
        let level = self.raw() & self.enable != 0;
        if self.asserted == level {
            return None;
        }
        self.asserted = level;
        self.trace("irq", 0x20, u32::from(level));
        Some(level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RESET: u32 = 1 << 14;

    #[test]
    fn low_level_reset_stays_pending_until_released() {
        let mut gpio = Gpio::default();
        gpio.write(0xc, RESET);
        gpio.write(0x18, RESET);
        assert_eq!(gpio.irq_change(), None);
        gpio.set_input(PINS & !RESET);
        assert_eq!(gpio.irq_change(), Some(true));
        gpio.write(0x24, RESET);
        assert_eq!(gpio.read(0x20), Some(RESET));
        gpio.set_input(PINS);
        assert_eq!(gpio.irq_change(), Some(false));
    }

    #[test]
    fn falling_edge_latches_while_masked_and_acknowledges() {
        let mut gpio = Gpio::default();
        gpio.set_input(PINS & !RESET);
        gpio.set_input(PINS);
        assert_eq!(gpio.irq_change(), None);
        assert_eq!(gpio.read(0x1c), Some(RESET));
        gpio.write(0x18, RESET);
        assert_eq!(gpio.irq_change(), Some(true));
        gpio.write(0x24, RESET);
        assert_eq!(gpio.irq_change(), Some(false));
    }

    #[test]
    fn rising_and_both_edges_respect_polarity() {
        let mut gpio = Gpio::default();
        gpio.write(0x14, RESET);
        gpio.set_input(PINS & !RESET);
        assert_eq!(gpio.read(0x1c), Some(0));
        gpio.set_input(PINS);
        assert_eq!(gpio.read(0x1c), Some(RESET));
        gpio.write(0x24, RESET);
        gpio.write(0x10, RESET);
        gpio.set_input(PINS & !RESET);
        assert_eq!(gpio.read(0x1c), Some(RESET));
    }
}
