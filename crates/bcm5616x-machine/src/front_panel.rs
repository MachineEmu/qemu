//! Host-visible decoding of the CMIC LEDUP0 data RAM.

use serde_json::json;

use crate::CMIC_BLOCK_BASE;

const DATA_BASE: u64 = CMIC_BLOCK_BASE + 0x20_400;
const DATA_SIZE: usize = 0x400;
const PORT_COUNT: usize = 26;
const LINK_BASE: usize = 0xa0;

/// Shadow of the byte-addressed LED microprocessor data RAM.
#[derive(Debug)]
pub(crate) struct FrontPanel {
    data: [u8; DATA_SIZE],
    sequence: u64,
    published: bool,
}

impl Default for FrontPanel {
    fn default() -> Self {
        Self {
            data: [0; DATA_SIZE],
            sequence: 0,
            published: false,
        }
    }
}

impl FrontPanel {
    /// Applies a CMIC word write and returns a snapshot when LED host data changes.
    pub(crate) fn write(&mut self, address: u64, value: u64) -> Option<Vec<u8>> {
        let offset = usize::try_from(address.checked_sub(DATA_BASE)?).ok()?;
        if offset.checked_add(4)? > self.data.len() {
            return None;
        }
        let bytes = value.to_le_bytes();
        if self.published && self.data[offset..offset + 4] == bytes[..4] {
            return None;
        }
        self.data[offset..offset + 4].copy_from_slice(&bytes[..4]);
        self.sequence = self.sequence.saturating_add(1);
        self.published = true;
        Some(self.snapshot())
    }

    fn snapshot(&self) -> Vec<u8> {
        let ports = (1..=PORT_COUNT)
            .map(|port| {
                let status = port * 2;
                json!({
                    "port": port,
                    "kind": if port <= 24 { "rj45" } else { "sfp" },
                    "rx": self.data[status],
                    "tx": self.data[status + 1],
                    "link": self.data[LINK_BASE + port] & 1 != 0,
                    "speed_mbps": null,
                    "poe": null
                })
            })
            .collect::<Vec<_>>();
        let mut payload = serde_json::to_vec(&json!({
            "schema": "unifi.frontpanel.v1",
            "kind": "state",
            "sequence": self.sequence,
            "source": "cmic-ledup0",
            "ports": ports,
        }))
        .expect("front-panel snapshot contains only serializable values");
        payload.push(b'\n');
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_host_data_is_published_for_front_panel_port() {
        let mut panel = FrontPanel::default();
        let address = DATA_BASE + u64::try_from(LINK_BASE).unwrap();
        let frame = panel.write(address, 1 << 8).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(value["schema"], "unifi.frontpanel.v1");
        assert_eq!(value["ports"][0]["link"], true);
        assert_eq!(value["ports"][0]["kind"], "rj45");
        assert_eq!(value["ports"][24]["kind"], "sfp");
    }

    #[test]
    fn initial_zero_state_publishes_once_and_program_ram_writes_do_not_publish() {
        let mut panel = FrontPanel::default();
        assert!(panel.write(DATA_BASE, 0).is_some());
        assert!(panel.write(DATA_BASE, 0).is_none());
        assert!(panel.write(DATA_BASE + DATA_SIZE as u64, 1).is_none());
    }
}
