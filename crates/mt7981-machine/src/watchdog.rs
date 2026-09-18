use crate::*;

/// Minimal MT7981 watchdog state.
#[derive(Debug, Default)]
pub struct Watchdog {
    pub(crate) mode: u32,
    length: u32,
    restart_count: u32,
    status: u32,
}

impl Watchdog {
    pub(crate) fn read(&self, offset: u64) -> u32 {
        match offset {
            WATCHDOG_MODE => self.mode,
            WATCHDOG_LENGTH => self.length,
            WATCHDOG_STATUS => self.status,
            _ => 0,
        }
    }

    pub(crate) fn write(&mut self, offset: u64, value: u32) -> bool {
        match offset {
            WATCHDOG_MODE => self.mode = value,
            WATCHDOG_LENGTH => self.length = value,
            WATCHDOG_RESTART => self.restart_count = self.restart_count.wrapping_add(1),
            _ => return false,
        }
        true
    }
}
