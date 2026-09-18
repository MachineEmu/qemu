//! Airtime configuration decoded from the original U6+ driver, not an RF model.

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Airtime {
    rx_enabled: bool,
    rx_feature_3: bool,
    ed_offset: u8,
    own_mac_wmm: [bool; 4],
    bss_wmm: [u8; 32],
    backoff: [[u16; 4]; 8],
    non_wifi_time: [u32; 2],
    obss_time: [u32; 2],
    mib_obss_time: [u32; 2],
    estimator_enabled: bool,
    estimator_period: u16,
    group_max_ratio: [u16; 16],
    group_min_ratio: [u16; 16],
    group_band: [u8; 32],
}

impl Airtime {
    pub(super) fn command(&mut self, cid: u8, payload: &[u8]) -> Option<Vec<u8>> {
        let size = match cid {
            0x4a => 68,
            0x4b => 100,
            _ => return None,
        };
        // Both producers zero a 24-byte control header. The callbacks only
        // log set/get status words at +4/+8. Unsupported layouts get no
        // success event; recognized mapping requests can return a rejection.
        if payload.len() != size || payload[4..24] != [0; 20] {
            return None;
        }
        let field = half(payload, 0);
        let subfield = half(payload, 2);
        let mut response = payload.to_vec();
        // The driver passes hardware BSS indices, including 25/26, rather
        // than the 16-entry estimator-ratio index. Keep their mappings
        // distinct. For invalid mapping values, use a model-defined nonzero
        // set status (1), not a fabricated successful configuration. The
        // original callbacks log this word but do not interpret error codes.
        let invalid_mapping = match (cid, field, subfield) {
            (0x4a, 2, 4) if only_field(payload, 32..34) => payload[32] >= 32 || payload[33] >= 4,
            (0x4b, 1, 4) if only_field(payload, 96..98) => payload[96] >= 32 || payload[97] >= 2,
            _ => false,
        };
        if invalid_mapping {
            response[4..8].copy_from_slice(&1_u32.to_le_bytes());
            return Some(response);
        }
        if cid == 0x4a {
            self.rx_command(field, subfield, payload, &mut response)?;
        } else {
            self.estimator_command(field, subfield, payload)?;
        }
        Some(response)
    }

    fn rx_command(
        &mut self,
        field: u16,
        subfield: u16,
        p: &[u8],
        response: &mut [u8],
    ) -> Option<()> {
        // vow_init_rx @ 0x442130 supplies this startup sequence. Member
        // offsets below are verified against the AArch64 stores, not the
        // older MT7615 layout (which differs for feature 3).
        match (field, subfield) {
            (1, 1) if only_field(p, 24..25) && p[24] <= 1 => self.rx_enabled = p[24] != 0,
            (1, 3) if only_field(p, 26..27) && p[26] <= 1 => self.rx_feature_3 = p[26] != 0,
            (2, 1) if only_field(p, 24..25) && p[24] == 1 => {
                self.non_wifi_time = [0; 2];
                self.obss_time = [0; 2];
                self.mib_obss_time = [0; 2];
            }
            (2, 3) if only_field(p, 28..30) && p[28] < 4 && p[29] <= 1 => {
                self.own_mac_wmm[usize::from(p[28])] = p[29] != 0;
            }
            (2, 4) if only_field(p, 32..34) && p[32] < 32 && p[33] < 4 => {
                self.bss_wmm[usize::from(p[32])] = p[33];
            }
            (3, 1) if only_field(p, 24..25) => self.ed_offset = p[24],
            (3, 3) => self.set_backoff(p)?,
            (4, 1 | 2) => {
                let offset = if subfield == 1 { 24 } else { 32 };
                if !only_field(p, offset + 4..offset + 5) || p[offset + 4] > 1 {
                    return None;
                }
                let band = usize::from(p[offset + 4]);
                let value = if subfield == 1 {
                    self.non_wifi_time[band]
                } else {
                    self.obss_time[band]
                };
                response[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            _ => return None,
        }
        Some(())
    }

    fn set_backoff(&mut self, p: &[u8]) -> Option<()> {
        // vow_set_backoff_time @ 0x4410c0: four LE16 AC values at +32,
        // group at +40 and AC mask at +41. Groups 6/7 are scalar timers.
        let group = usize::from(p[40]);
        if group >= 8 || !only_field(p, 32..42) {
            return None;
        }
        if group >= 6 {
            if p[34..40] != [0; 6] || p[41] != 0 {
                return None;
            }
            self.backoff[group][0] = half(p, 32);
        } else {
            if p[41] == 0 || p[41] & !0x0f != 0 {
                return None;
            }
            for (ac, value) in self.backoff[group].iter_mut().enumerate() {
                if p[41] & (1 << ac) != 0 {
                    *value = half(p, 32 + ac * 2);
                }
            }
        }
        Some(())
    }

    fn estimator_command(&mut self, field: u16, subfield: u16, p: &[u8]) -> Option<()> {
        // vow_set_at_estimator{,_group} @ 0x441700 / 0x441968. The bad-node
        // producer uses a different/ambiguous field ID and is not aliased here.
        if field != 1 {
            return None;
        }
        match subfield {
            1 if only_field(p, 24..25) && p[24] <= 1 => self.estimator_enabled = p[24] != 0,
            2 if only_field(p, 26..28) => self.estimator_period = half(p, 26),
            3 if only_field(p, 28..96) => {
                let mask = u32::from_le_bytes([p[28], p[29], p[30], p[31]]);
                if mask == 0 || mask > 0xffff {
                    return None;
                }
                for group in 0..16 {
                    if mask & (1 << group) != 0 {
                        self.group_max_ratio[group] = half(p, 32 + 2 * group);
                        self.group_min_ratio[group] = half(p, 64 + 2 * group);
                    }
                }
            }
            4 if only_field(p, 96..98) && p[96] < 32 && p[97] < 2 => {
                self.group_band[usize::from(p[96])] = p[97];
            }
            _ => return None,
        }
        Some(())
    }
}

fn half(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn only_field(payload: &[u8], field: std::ops::Range<usize>) -> bool {
    payload
        .iter()
        .enumerate()
        .skip(24)
        .all(|(offset, byte)| *byte == 0 || field.contains(&offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(size: usize, field: u16, subfield: u16) -> Vec<u8> {
        let mut p = vec![0; size];
        p[..2].copy_from_slice(&field.to_le_bytes());
        p[2..4].copy_from_slice(&subfield.to_le_bytes());
        p
    }

    #[test]
    fn bss_mapping_updates_one_entry() {
        let mut state = Airtime::default();
        for (bss, wmm) in [(0, 1), (15, 3), (0, 2)] {
            let mut p = request(68, 2, 4);
            p[32] = bss;
            p[33] = wmm;
            assert_eq!(state.command(0x4a, &p), Some(p));
        }
        assert_eq!(state.bss_wmm[0], 2);
        assert_eq!(state.bss_wmm[15], 3);
        assert_eq!(state.bss_wmm[1..15], [0; 14]);
    }

    #[test]
    fn backoff_mask_preserves_unselected_access_categories() {
        let mut state = Airtime::default();
        let mut p = request(68, 3, 3);
        p[40] = 5;
        p[41] = 15;
        for ac in 0..4 {
            p[32 + ac * 2] = 10 + u8::try_from(ac).unwrap();
        }
        state.command(0x4a, &p);
        p[41] = 2;
        p[34..36].copy_from_slice(&500_u16.to_le_bytes());
        state.command(0x4a, &p);
        assert_eq!(state.backoff[5], [10, 500, 12, 13]);
        assert_eq!(state.backoff[4], [0; 4]);
    }

    #[test]
    fn scalar_backoff_rejects_ac_mask_without_changing_state() {
        let mut state = Airtime::default();
        let mut p = request(68, 3, 3);
        p[40] = 7;
        p[32..34].copy_from_slice(&4096_u16.to_le_bytes());
        assert!(state.command(0x4a, &p).is_some());
        p[41] = 1;
        p[32] = 3;
        assert!(state.command(0x4a, &p).is_none());
        assert_eq!(state.backoff[7], [4096, 0, 0, 0]);
    }

    #[test]
    fn estimator_ratio_mask_preserves_other_groups() {
        let mut state = Airtime::default();
        let mut p = request(100, 1, 3);
        p[28..32].copy_from_slice(&0x8001_u32.to_le_bytes());
        p[32..34].copy_from_slice(&1000_u16.to_le_bytes());
        p[62..64].copy_from_slice(&900_u16.to_le_bytes());
        p[64..66].copy_from_slice(&100_u16.to_le_bytes());
        p[94..96].copy_from_slice(&90_u16.to_le_bytes());
        state.command(0x4b, &p);
        p[28..32].copy_from_slice(&1_u32.to_le_bytes());
        p[32..96].fill(0);
        state.command(0x4b, &p);
        assert_eq!(state.group_max_ratio[0], 0);
        assert_eq!(state.group_max_ratio[15], 900);
        assert_eq!(state.group_min_ratio[15], 90);
    }

    #[test]
    fn estimator_period_and_band_mapping_do_not_overwrite_each_other() {
        let mut state = Airtime::default();
        let mut p = request(100, 1, 2);
        p[26..28].copy_from_slice(&1000_u16.to_le_bytes());
        state.command(0x4b, &p);
        let mut p = request(100, 1, 4);
        p[96] = 15;
        p[97] = 1;
        state.command(0x4b, &p);
        assert_eq!(state.estimator_period, 1000);
        assert_eq!(state.group_band[15], 1);
    }

    #[test]
    fn counter_queries_read_model_state_and_clear_command_resets_it() {
        let mut state = Airtime {
            non_wifi_time: [10, 20],
            obss_time: [30, 40],
            ..Airtime::default()
        };
        let mut p = request(68, 4, 2);
        p[36] = 1;
        let response = state.command(0x4a, &p).unwrap();
        assert_eq!(&response[32..36], &40_u32.to_le_bytes());
        let mut clear = request(68, 2, 1);
        clear[24] = 1;
        state.command(0x4a, &clear);
        let response = state.command(0x4a, &p).unwrap();
        assert_eq!(&response[32..36], &[0; 4]);
        assert_eq!(state.non_wifi_time, [0; 2]);
    }

    #[test]
    fn invalid_mapping_and_reserved_bytes_never_receive_success() {
        let mut state = Airtime::default();
        for (offset, value) in [(40, 1), (4, 1), (12, 1)] {
            let mut p = request(68, 2, 4);
            p[offset] = value;
            assert!(state.command(0x4a, &p).is_none());
            assert_eq!(state, Airtime::default());
        }
    }

    #[test]
    fn extended_bss_mappings_do_not_alias_low_indices() {
        let mut state = Airtime::default();
        for index in [0, 9, 15, 16, 25, 26, 31] {
            let mut p = request(68, 2, 4);
            p[32] = index;
            p[33] = if index < 16 { 1 } else { 3 };
            assert_eq!(state.command(0x4a, &p), Some(p));
            let mut p = request(100, 1, 4);
            p[96] = index;
            p[97] = u8::from(index >= 16);
            assert_eq!(state.command(0x4b, &p), Some(p));
        }
        assert_eq!(state.bss_wmm[9], 1);
        assert_eq!(state.bss_wmm[25], 3);
        assert_eq!(state.group_band[9], 0);
        assert_eq!(state.group_band[25], 1);
        assert_eq!(state.bss_wmm[31], 3);
        assert_eq!(state.group_band[31], 1);
    }

    #[test]
    fn invalid_mapping_completes_with_failure_and_preserves_existing_state() {
        let mut state = Airtime::default();
        state.bss_wmm[26] = 2;
        state.group_band[26] = 1;
        for (cid, size, field, offset, index, value) in [
            (0x4a, 68, 2, 32, 26, 0xe8), // Captured from the original driver.
            (0x4a, 68, 2, 32, 26, 4),
            (0x4a, 68, 2, 32, 32, 0),
            (0x4a, 68, 2, 32, 255, 0),
            (0x4b, 100, 1, 96, 26, 2),
            (0x4b, 100, 1, 96, 32, 0),
        ] {
            let mut p = request(size, field, 4);
            p[offset] = index;
            p[offset + 1] = value;
            let response = state.command(cid, &p).unwrap();
            p[4..8].copy_from_slice(&1_u32.to_le_bytes());
            assert_eq!(response, p);
            assert_eq!(state.bss_wmm[26], 2);
            assert_eq!(state.group_band[26], 1);
        }
    }

    #[test]
    fn unsupported_commands_and_lengths_never_receive_success() {
        let mut state = Airtime::default();
        for (cid, p) in [
            (0x4a, request(67, 1, 1)),
            (0x4b, request(101, 1, 1)),
            (0x4a, request(68, 1, 2)),
            (0x4b, request(100, 2, 1)),
            (0x4a, request(68, 4, 3)),
        ] {
            assert!(state.command(cid, &p).is_none());
            assert_eq!(state, Airtime::default());
        }
    }
}
