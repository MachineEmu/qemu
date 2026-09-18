//! Bounded, category-filtered diagnostic tracing.

use std::collections::VecDeque;

/// Diagnostic trace categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Category {
    /// Ethernet and descriptor engine.
    Eth = 0,
    /// Wireless DMA.
    Wfdma = 1,
    /// Wireless system registers.
    Wfsys = 2,
    /// MMC/eMMC.
    Msdc = 3,
    /// SPI.
    Spi = 4,
    /// Unknown compatibility accesses.
    Unknown = 5,
}

/// One diagnostic record retained by a tracer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Virtual timestamp.
    pub now_ns: u64,
    /// Record category.
    pub category: Category,
    /// Human-readable message.
    pub message: String,
}

/// Bounded category-filtered trace ring.
#[derive(Debug)]
pub struct Tracer {
    enabled: u32,
    records: VecDeque<Record>,
    capacity: usize,
    dropped: u64,
}

impl Tracer {
    /// Creates a tracer with all categories disabled.
    pub fn new(capacity: usize) -> Self {
        Self {
            enabled: 0,
            records: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }
    /// Enables a category.
    pub fn enable(&mut self, category: Category) {
        self.enabled |= 1 << category as u32;
    }
    /// Enables categories from a comma-separated environment-style mask.
    pub fn from_mask(mask: &str, capacity: usize) -> Self {
        let mut tracer = Self::new(capacity);
        for name in mask.split(',') {
            let category = match name.trim() {
                "eth" => Some(Category::Eth),
                "wfdma" => Some(Category::Wfdma),
                "wfsys" => Some(Category::Wfsys),
                "msdc" => Some(Category::Msdc),
                "spi" => Some(Category::Spi),
                "unknown" => Some(Category::Unknown),
                _ => None,
            };
            if let Some(category) = category {
                tracer.enable(category);
            }
        }
        tracer
    }
    /// Records a message when enabled, retaining at most the configured capacity.
    pub fn record(&mut self, now_ns: u64, category: Category, message: impl Into<String>) {
        if self.enabled & (1 << category as u32) == 0 {
            return;
        }
        if self.capacity == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.records.push_back(Record {
            now_ns,
            category,
            message: message.into(),
        });
    }
    /// Removes all retained records in FIFO order.
    pub fn drain(&mut self) -> impl Iterator<Item = Record> + '_ {
        self.records.drain(..)
    }
    /// Returns the number of records evicted due to the capacity bound.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_categories_do_not_enter_ring() {
        let mut tracer = Tracer::new(2);
        tracer.record(0, Category::Eth, "ignored");
        assert_eq!(tracer.drain().count(), 0);
    }
    #[test]
    fn ring_reports_evictions_instead_of_silently_dropping() {
        let mut tracer = Tracer::from_mask("unknown", 1);
        tracer.record(1, Category::Unknown, "first");
        tracer.record(2, Category::Unknown, "second");
        assert_eq!(tracer.dropped(), 1);
        assert_eq!(tracer.drain().next().unwrap().message, "second");
    }
}
