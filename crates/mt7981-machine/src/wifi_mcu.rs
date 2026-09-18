//! Validated startup configuration for the vendor MCU compatibility frontend.
//!
//! These commands configure the model; they do not implement wireless TX/RX.

use std::collections::{BTreeMap, HashMap};
mod airtime;
mod mac_config;
mod radio_config;
mod records;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WifiCipher {
    Wep,
    Tkip,
    Ccmp,
    Ccmp256,
    Gcmp,
    Gcmp256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WifiKey {
    pub(super) cipher: WifiCipher,
    pub(super) cipher_id: u8,
    pub(super) id: u8,
    pub(super) material: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct StartupConfig {
    mac_enabled: [bool; 2],
    station_table: HashMap<u16, BTreeMap<u16, Vec<u8>>>,
    dwrr: HashMap<(u32, u16), [u8; 8]>,
    group_tokens: [[u8; 16]; 16],
    group_quantum: [u8; 16],
    airtime: airtime::Airtime,
    radio: radio_config::RadioConfig,
    mac: mac_config::MacConfig,
    records: records::Records,
}

impl StartupConfig {
    pub(super) fn bssid_for_own(&self, band: u8, own: u8) -> Option<[u8; 6]> {
        self.records.bssid_for_own(band, own)
    }

    pub(super) fn station(&self, id: u16) -> Option<records::StationInfo> {
        self.records.lookup_station(id)
    }

    pub(super) fn station_for_peer(&self, band: u8, peer: &[u8]) -> Option<records::StationInfo> {
        self.records.station_for_peer(band, peer)
    }

    pub(super) fn data_keys(&self, station: u16, key_id: Option<u8>) -> Vec<WifiKey> {
        let Some(keys) = self
            .station_table
            .get(&station)
            .and_then(|table| table.get(&17))
        else {
            return Vec::new();
        };
        keys[8..]
            .chunks_exact(36)
            .filter_map(|record| {
                let length = usize::from(record[3]);
                let cipher = match (record[0], length) {
                    (1, 5) | (5, 13) | (7, 16) => WifiCipher::Wep,
                    (2, 32) => WifiCipher::Tkip,
                    (4, 16) => WifiCipher::Ccmp,
                    (10, 32) => WifiCipher::Ccmp256,
                    (11, 16) => WifiCipher::Gcmp,
                    (12, 32) => WifiCipher::Gcmp256,
                    _ => return None,
                };
                (record[2] <= 3 && key_id.is_none_or(|id| id == record[2])).then(|| WifiKey {
                    cipher,
                    cipher_id: record[0],
                    id: record[2],
                    material: record[4..4 + length].to_vec(),
                })
            })
            .collect()
    }

    pub(super) fn channel(&self, band: usize) -> Option<u8> {
        if band < 2 && self.mac_enabled[band] && self.mac.powered(band) {
            self.radio.channel(band)
        } else {
            None
        }
    }

    pub(super) fn own_mac(&self, band: u8, destination: &[u8]) -> Option<u8> {
        self.records.own_mac(band, destination)
    }

    pub(super) fn beacons(&self) -> Vec<(u8, u8, u16, Vec<u8>)> {
        self.records.beacons()
    }

    /// Returns (extended event ID, payload), or None for unsupported commands.
    pub(super) fn command(&mut self, cid: u8, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
        match cid {
            0x07 => Some((0, result(cid, self.mac.set_radio_power(payload)))),
            0x08 => Some((0, result(cid, self.radio.switch_channel(payload)))),
            0x0f => Some((0, result(cid, self.mac.set_ps_flush(payload)))),
            0x25 | 0x26 | 0x2a => Some((
                0,
                self.records.command(cid, payload, &mut self.station_table),
            )),
            0x27 => Some((0, result(cid, self.mac.set_edca(payload)))),
            0x38 => self.radio.set_features(payload).map(|reply| (cid, reply)),
            0x3e => Some((0, result(cid, self.mac.set_protection(payload)))),
            0x46 => Some((0, result(cid, self.set_mac(payload)))),
            0x4e => Some((0, result(cid, self.radio.set_paths(payload)))),
            0x5a => self.mac.read_mib(payload).map(|reply| (cid, reply)),
            0x32 => Some((0, result(cid, self.update_station_table(payload)))),
            0x36 => Some((0x36, self.set_dwrr(payload))),
            0x37 => Some((0x37, self.set_group(payload))),
            0x4a | 0x4b => self
                .airtime
                .command(cid, payload)
                .map(|response| (cid, response)),
            _ => None,
        }
    }

    fn set_mac(&mut self, payload: &[u8]) -> bool {
        // MtCmdSetMacTxRx @ 0x640bc0: enable, band, two reserved bytes.
        let [enable @ 0..=1, band @ 0..=1, 0, 0] = payload else {
            return false;
        };
        self.mac_enabled[usize::from(*band)] = *enable != 0;
        true
    }

    fn update_station_table(&mut self, payload: &[u8]) -> bool {
        // CmdExtWtblUpdate: 1 resets then sets, 2 updates, 4 resets all.
        // MtAsicDelWcidTabByFw deletes one entry with operation 1/no TLVs.
        let Some([low, operation, count_low, count_high, high @ 0..=3, 0, 0, 0]) = payload.get(..8)
        else {
            return false;
        };
        let station = u16::from(*low) | (u16::from(*high) << 8);
        let count = u16::from_le_bytes([*count_low, *count_high]);
        let Some(tags) = records::parse_wtbl_tags(&payload[8..], count, false) else {
            return false;
        };
        match operation {
            1 | 2 => {
                if *operation == 1 {
                    self.station_table.remove(&station);
                }
                if !tags.is_empty() {
                    records::merge_wtbl(self.station_table.entry(station).or_default(), tags);
                }
            }
            4 if station == 0 && tags.is_empty() => self.station_table.clear(),
            _ => return false,
        }
        true
    }

    fn set_dwrr(&mut self, payload: &[u8]) -> Vec<u8> {
        // MtCmdSetVoWDRRCtrl @ 0x63cde8 expects 20 bytes, not the generic
        // eight-byte result. Callback 0x62ee88 copies all 20 bytes and the
        // caller tests byte 5 == 1. vow_set_sta encodes a 10-bit station ID.
        let mut response = vec![0; 20];
        if payload.len() != 20 {
            return response;
        }
        response.copy_from_slice(payload);
        response[5] = 0;
        let field = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if !matches!(field, 0..=9 | 0x10 | 0x11 | 0x20..=0x28 | 0x30)
            || payload[5] != 0
            || payload[6] > 3
            || payload[7..12] != [0; 5]
        {
            return response;
        }
        let station = u16::from(payload[4]) | (u16::from(payload[6]) << 8);
        if matches!(field, 0x10 | 0x11 | 0x20..=0x28) && station != 0 {
            return response;
        }
        let mut value = [0; 8];
        value.copy_from_slice(&payload[12..]);
        self.dwrr.insert((field, station), value);
        response[5] = 1;
        response
    }

    fn set_group(&mut self, payload: &[u8]) -> Vec<u8> {
        // vow_set_group @ 0x43ff30 and vow_fill_group_all @ 0x43fb58:
        // 16-byte header, sixteen packed 16-byte token records, then sixteen
        // quantum bytes. MtCmdSetVoWGroupCtrl expects the whole 0x120-byte
        // response and, like DWRR, checks success at byte 5.
        let mut response = vec![0; 0x120];
        if payload.len() != response.len() {
            return response;
        }
        response.copy_from_slice(payload);
        response[5] = 0;
        if payload[4] >= 16 || payload[5..12] != [0; 7] {
            return response;
        }
        let field = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let group = usize::from(payload[4]);
        match field {
            0 => {
                self.group_tokens[group]
                    .copy_from_slice(&payload[16 + group * 16..32 + group * 16]);
            }
            0x10 => {
                for (record, data) in self
                    .group_tokens
                    .iter_mut()
                    .zip(payload[16..272].chunks_exact(16))
                {
                    record.copy_from_slice(data);
                }
            }
            0x20..=0x2f if field == 0x20 + u32::from(payload[4]) => {
                self.group_quantum[group] = payload[272 + group];
            }
            0x30 => self.group_quantum.copy_from_slice(&payload[272..288]),
            // Individual packed token-field updates still need decoding.
            _ => return response,
        }
        response[5] = 1;
        response
    }
}

fn result(cid: u8, ok: bool) -> Vec<u8> {
    vec![cid, 0, 0, 0, u8::from(!ok), 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_configuration_keeps_bands_independent() {
        let mut state = StartupConfig::default();
        state.command(0x46, &[1, 1, 0, 0]);
        state.command(0x46, &[1, 0, 0, 0]);
        state.command(0x46, &[0, 1, 0, 0]);
        assert_eq!(state.mac_enabled, [true, false]);
    }

    #[test]
    fn malformed_mac_configuration_does_not_change_state() {
        let mut state = StartupConfig::default();
        for payload in [&[2, 0, 0, 0][..], &[1, 2, 0, 0], &[1, 0, 1, 0], &[1, 0, 0]] {
            assert_eq!(state.command(0x46, payload), Some((0, result(0x46, false))));
            assert_eq!(state.mac_enabled, [false; 2]);
        }
    }

    #[test]
    fn station_reset_uses_high_index_bits() {
        let mut state = StartupConfig::default();
        state
            .station_table
            .insert(1, BTreeMap::from([(0, vec![1])]));
        state
            .station_table
            .insert(257, BTreeMap::from([(0, vec![2])]));
        state.command(0x32, &[1, 1, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            state.station_table,
            HashMap::from([(1, BTreeMap::from([(0, vec![1])]))])
        );
    }

    #[test]
    fn station_reset_all_clears_entries() {
        let mut state = StartupConfig::default();
        state.station_table.insert(1, BTreeMap::new());
        state.station_table.insert(257, BTreeMap::new());
        state.command(0x32, &[0, 4, 0, 0, 0, 0, 0, 0]);
        assert!(state.station_table.is_empty());
    }

    #[test]
    fn station_updates_merge_fields_and_reset_replaces_them() {
        let mut state = StartupConfig::default();
        let update = [31, 2, 1, 0, 2, 0, 0, 0, 6, 0, 8, 0, 1, 1, 0, 0];
        assert_eq!(state.command(0x32, &update), Some((0, result(0x32, true))));
        let mut other = update;
        other[8] = 5;
        other[13] = 0;
        state.command(0x32, &other);
        assert_eq!(state.station_table[&543][&6], update[8..]);
        assert_eq!(state.station_table[&543][&5], other[8..]);
        other[1] = 1;
        state.command(0x32, &other);
        assert_eq!(state.station_table[&543].len(), 1);
        assert!(state.station_table[&543].contains_key(&5));
    }

    #[test]
    fn station_key_install_rekey_and_remove_preserve_other_fields() {
        let mut state = StartupConfig::default();
        let mut p = vec![31, 2, 1, 0, 2, 0, 0, 0, 17, 0, 80, 0, 0, 2, 0, 0];
        for (cipher, id) in [(5, 1), (10, 4)] {
            p.extend([cipher, 36, id, 16]);
            p.extend([0xa5; 32]);
        }
        assert_eq!(state.command(0x32, &p), Some((0, result(0x32, true))));
        assert_eq!(state.station_table[&543][&17][5], 2);
        p.truncate(52);
        p[10] = 44;
        p[13] = 1;
        p[20..36].fill(0x5a);
        assert_eq!(state.command(0x32, &p), Some((0, result(0x32, true))));
        let stored = &state.station_table[&543][&17];
        assert_eq!(stored[5], 2);
        assert_eq!(stored[12..28], [0x5a; 16]);
        assert_eq!(stored[48..64], [0xa5; 16]);
        state.command(0x32, &[31, 2, 1, 0, 2, 0, 0, 0, 6, 0, 8, 0, 1, 1, 0, 0]);
        p[12] = 1;
        p[13..].fill(0);
        assert_eq!(state.command(0x32, &p), Some((0, result(0x32, true))));
        assert!(!state.station_table[&543].contains_key(&17));
        assert!(state.station_table[&543].contains_key(&6));
    }

    #[test]
    fn malformed_key_install_does_not_replace_existing_key() {
        let mut state = StartupConfig::default();
        let mut p = vec![
            31, 2, 1, 0, 2, 0, 0, 0, 17, 0, 44, 0, 0, 1, 0, 0, 5, 36, 1, 16,
        ];
        p.extend([0xa5; 32]);
        state.command(0x32, &p);
        let original = state.station_table.clone();
        for (offset, value) in [
            (10, 43),
            (12, 2),
            (13, 2),
            (14, 1),
            (16, 255),
            (17, 35),
            (18, 8),
            (19, 33),
        ] {
            let mut bad = p.clone();
            bad[offset] = value;
            assert_eq!(state.command(0x32, &bad), Some((0, result(0x32, false))));
            assert_eq!(state.station_table, original);
        }
    }

    #[test]
    fn malformed_station_batch_preserves_existing_fields() {
        let mut state = StartupConfig::default();
        let update = [31, 2, 1, 0, 2, 0, 0, 0, 6, 0, 8, 0, 1, 1, 0, 0];
        state.command(0x32, &update);
        let original = state.station_table.clone();
        for n in 0..update.len() {
            assert_eq!(
                state.command(0x32, &update[..n]),
                Some((0, result(0x32, false)))
            );
            assert_eq!(state.station_table, original);
        }
        let mut bad = update.to_vec();
        bad[1] = 1;
        bad[2] = 2;
        bad.extend_from_slice(&[255, 0, 8, 0, 0, 0, 0, 0]);
        assert_eq!(state.command(0x32, &bad), Some((0, result(0x32, false))));
        assert_eq!(state.station_table, original);
    }

    #[test]
    fn unsupported_station_tlv_does_not_get_success() {
        let mut state = StartupConfig::default();
        assert_eq!(
            state.command(0x32, &[0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0]),
            Some((0, result(0x32, false)))
        );
    }

    #[test]
    fn dwrr_values_keep_field_and_station_separate() {
        let mut state = StartupConfig::default();
        for (field, high, value) in [(1, 0, 8), (1, 1, 12), (0x30, 1, 20)] {
            let mut payload = [0; 20];
            payload[0] = field;
            payload[4] = 1;
            payload[6] = high;
            payload[12] = value;
            let response = state.command(0x36, &payload).unwrap();
            payload[5] = 1;
            assert_eq!(response, (0x36, payload.to_vec()));
        }
        assert_eq!(state.dwrr.get(&(1, 1)).unwrap()[0], 8);
        assert_eq!(state.dwrr.get(&(1, 257)).unwrap()[0], 12);
        assert_eq!(state.dwrr.get(&(0x30, 257)).unwrap()[0], 20);
    }

    #[test]
    fn invalid_dwrr_fields_leave_configuration_unchanged() {
        let mut state = StartupConfig::default();
        for (offset, value) in [(0, 0xff), (5, 1), (6, 4), (7, 1), (11, 1)] {
            let mut payload = [0; 20];
            payload[offset] = value;
            assert_eq!(state.command(0x36, &payload).unwrap().1[5], 0);
            assert!(state.dwrr.is_empty());
        }
    }

    #[test]
    fn global_dwrr_configuration_rejects_station_specific_index() {
        let mut state = StartupConfig::default();
        let mut payload = [0; 20];
        payload[0] = 0x28;
        payload[4] = 1;
        assert_eq!(state.command(0x36, &payload).unwrap().1[5], 0);
        assert!(state.dwrr.is_empty());
    }

    #[test]
    fn group_bulk_and_single_updates_preserve_other_groups() {
        let mut state = StartupConfig::default();
        let mut payload = [0; 0x120];
        payload[0] = 0x10;
        payload[16..272].fill(0xa5);
        state.command(0x37, &payload);
        payload[0] = 0;
        payload[4] = 15;
        payload[256..272].fill(0x5a);
        state.command(0x37, &payload);
        assert_eq!(state.group_tokens[0..15], [[0xa5; 16]; 15]);
        assert_eq!(state.group_tokens[15], [0x5a; 16]);
    }

    #[test]
    fn group_quantum_bulk_and_single_updates_preserve_token_records() {
        let mut state = StartupConfig::default();
        let mut payload = [0; 0x120];
        payload[0] = 0x30;
        payload[272..288].fill(8);
        state.command(0x37, &payload);
        payload[0] = 0x2f;
        payload[4] = 15;
        payload[287] = 12;
        state.command(0x37, &payload);
        assert_eq!(state.group_quantum[0..15], [8; 15]);
        assert_eq!(state.group_quantum[15], 12);
        assert_eq!(state.group_tokens, [[0; 16]; 16]);
    }

    #[test]
    fn unsupported_or_invalid_group_update_does_not_change_state() {
        let mut state = StartupConfig::default();
        for (field, group) in [(1, 0), (0, 16), (0x20, 1), (0xff, 0)] {
            let mut payload = [0; 0x120];
            payload[0] = field;
            payload[4] = group;
            assert_eq!(state.command(0x37, &payload).unwrap().1[5], 0);
            assert_eq!(state, StartupConfig::default());
        }
    }
}
