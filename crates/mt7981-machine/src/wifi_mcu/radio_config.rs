//! Driver-facing configuration storage, not radio execution or a scheduler.

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct RadioConfig {
    channels: [Option<[u8; 76]>; 2],
    paths: [Option<[u8; 76]>; 2],
    bss_enabled: u16,
    features: u16,
    time_tokens: u16,
    length_tokens: u16,
    // Preserve the MT7981-specific packed extension for a future scheduler.
    // Its policy is not executed by this configuration-only frontend.
    feature_extension: [u8; 6],
}

impl RadioConfig {
    pub(super) fn channel(&self, band: usize) -> Option<u8> {
        self.channels[band].as_ref().map(|p| p[0])
    }

    pub(super) fn set_paths(&mut self, payload: &[u8]) -> bool {
        // MtCmdSetTxRxPath @ 0x6350c8 uses the channel envelope, but byte 4
        // is an RX chain MASK (including 0x5/0xf), not a stream count.
        // Unlike channel switching it leaves power/SKU/secondary AP fields
        // zero. Keep this state separate from the channel/power table.
        let Ok(p) = <&[u8; 76]>::try_from(payload) else {
            return false;
        };
        if !(1..=196).contains(&p[0])
            || !(1..=196).contains(&p[1])
            || p[2] > 6
            || !(1..=4).contains(&p[3])
            || p[4] & !0x0f != 0
            || !matches!(p[5], 0 | 5 | 14 | 100 | 105 | 114)
            || p[6] > 1
            || p[7] > 196
            || p[8..10] != [0; 2]
            || p[10] > 1
            || p[11..17] != [0; 6]
            || p[17] > 6
            || p[18..] != [0; 58]
        {
            return false;
        }
        self.paths[usize::from(p[6])] = Some(*p);
        true
    }

    pub(super) fn switch_channel(&mut self, payload: &[u8]) -> bool {
        // MtCmdChannelSwitch @ 0x634798 sends 76 bytes, while its callback
        // EventExtCmdResult @ 0x62d540 expects an eight-byte generic result.
        let Ok(p) = <&[u8; 76]>::try_from(payload) else {
            return false;
        };
        if !(1..=196).contains(&p[0])
            || !(1..=196).contains(&p[1])
            || p[2] > 6
            || !(1..=4).contains(&p[3])
            || !(1..=4).contains(&p[4])
            || !matches!(p[5], 0 | 5 | 9 | 14 | 100 | 105 | 109 | 114)
            || p[6] > 1
            || p[7] > 196
            || p[8..10] != [0; 2]
            || p[10] > 1
            || p[11] != 0
            || p[17] > 6
            || p[18] > 196
            || p[19] != 0
            || p[69..] != [0; 7]
        {
            return false;
        }
        // Includes out-of-band frequency, power drop, AP bandwidth/center,
        // and the driver's 49-byte power table. No RF traffic is generated.
        self.channels[usize::from(p[6])] = Some(*p);
        true
    }

    pub(super) fn set_features(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        // vow_set_feature_all @ 0x4404f8, MtCmdSetVoWFeatureCtrl @ 0x63d1e0:
        // masks precede values by 20 bytes; callback 0x62f050 copies all 40.
        let p = <&[u8; 40]>::try_from(payload).ok()?;
        let selectors = half(p, 2);
        if selectors & !0xf231 != 0
            || half(p, 22) & !0xf237 != 0
            || p[6..8] != [0; 2]
            || p[10..20] != [0; 10]
            || p[26..28] != [0; 2]
            || p[30..32] != [0; 2]
            || p[38..40] != [0; 2]
        {
            return None;
        }
        merge(&mut self.bss_enabled, half(p, 0), half(p, 20));
        merge(&mut self.time_tokens, half(p, 4), half(p, 24));
        merge(&mut self.length_tokens, half(p, 8), half(p, 28));
        // Refill-period selector bit 0 controls a THREE-bit value. All other
        // supported selectors map directly to one value bit.
        let mask = (selectors & !1) | if selectors & 1 != 0 { 7 } else { 0 };
        merge(&mut self.features, mask, half(p, 22));
        self.feature_extension.copy_from_slice(&p[32..38]);
        let mut response = p.to_vec();
        for (offset, value) in [
            (20, self.bss_enabled),
            (22, self.features),
            (24, self.time_tokens),
            (28, self.length_tokens),
        ] {
            response[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        Some(response)
    }
}

fn half(p: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([p[offset], p[offset + 1]])
}

fn merge(state: &mut u16, mask: u16, value: u16) {
    *state = (*state & !mask) | (value & mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(band: u8, primary: u8, center: u8) -> [u8; 76] {
        let mut p = [0; 76];
        p[..7].copy_from_slice(&[primary, center, 1, 2, 2, 0, band]);
        p[20..69].fill(0x3f);
        p
    }

    #[test]
    fn channel_switch_preserves_other_band_and_power_table() {
        let mut state = RadioConfig::default();
        let p0 = channel(0, 6, 8);
        let p1 = channel(1, 36, 38);
        assert!(state.switch_channel(&p0));
        assert!(state.switch_channel(&p1));
        let next = channel(0, 2, 2);
        assert!(state.switch_channel(&next));
        assert_eq!(state.channels, [Some(next), Some(p1)]);
    }

    #[test]
    fn invalid_channel_requests_do_not_replace_configuration() {
        let mut state = RadioConfig::default();
        let p = channel(0, 6, 8);
        state.switch_channel(&p);
        for (offset, value) in [
            (0, 0),
            (1, 0),
            (2, 7),
            (3, 0),
            (4, 5),
            (5, 255),
            (6, 2),
            (10, 2),
            (11, 1),
            (75, 1),
        ] {
            let mut invalid = p;
            invalid[offset] = value;
            assert!(!state.switch_channel(&invalid));
            assert_eq!(state.channels, [Some(p), None]);
        }
        assert!(!state.switch_channel(&p[..75]));
        assert!(!state.switch_channel(&[0; 77]));
    }

    #[test]
    fn path_masks_are_not_stream_counts_and_do_not_replace_channels() {
        let mut state = RadioConfig::default();
        let ch = channel(0, 6, 8);
        assert!(state.switch_channel(&ch));
        let mut p = ch;
        p[20..69].fill(0);
        for mask in [0, 1, 3, 5, 15] {
            p[4] = mask;
            assert!(state.set_paths(&p));
        }
        let p0 = p;
        p[6] = 1;
        assert!(state.set_paths(&p));
        assert_eq!(state.paths, [Some(p0), Some(p)]);
        assert_eq!(state.channels, [Some(ch), None]);
        assert!(!state.switch_channel(&p)); // 15 is not a stream count.
    }

    #[test]
    fn invalid_paths_preserve_previous_configuration() {
        let mut state = RadioConfig::default();
        let mut p = channel(0, 6, 8);
        p[20..69].fill(0);
        assert!(state.set_paths(&p));
        for (offset, value) in [
            (0, 0),
            (1, 0),
            (2, 7),
            (3, 0),
            (3, 5),
            (4, 16),
            (5, 9),
            (6, 2),
            (7, 197),
            (8, 1),
            (10, 2),
            (11, 1),
            (12, 1),
            (17, 7),
            (18, 1),
            (75, 1),
        ] {
            let mut bad = p;
            bad[offset] = value;
            assert!(!state.set_paths(&bad), "offset {offset}");
            assert_eq!(state.paths, [Some(p), None]);
        }
        assert!(!state.set_paths(&p[..75]));
        assert!(!state.set_paths(&[0; 77]));
    }

    #[test]
    fn feature_masks_preserve_unselected_bss_and_token_bits() {
        let mut state = RadioConfig::default();
        let mut p = [0; 40];
        for offset in [0, 4, 8, 20, 24, 28] {
            p[offset..offset + 2].copy_from_slice(&0x8001_u16.to_le_bytes());
        }
        state.set_features(&p).unwrap();
        for offset in [0, 4, 8] {
            p[offset..offset + 2].copy_from_slice(&1_u16.to_le_bytes());
        }
        p[20..32].fill(0);
        let reply = state.set_features(&p).unwrap();
        assert_eq!(
            (state.bss_enabled, state.time_tokens, state.length_tokens),
            (0x8000, 0x8000, 0x8000)
        );
        assert_eq!(half(&reply, 20), 0x8000);
    }

    #[test]
    fn refill_selector_updates_all_three_value_bits_only() {
        let mut state = RadioConfig::default();
        let mut p = [0; 40];
        p[3] = 0x20;
        p[23] = 0x20;
        state.set_features(&p).unwrap();
        p[3] = 0;
        p[2] = 1;
        p[22] = 7;
        let reply = state.set_features(&p).unwrap();
        assert_eq!(half(&reply, 22), 0x2007);
        p[22] = 2;
        assert_eq!(half(&state.set_features(&p).unwrap(), 22), 0x2002);
    }

    #[test]
    fn feature_extensions_are_retained_without_claiming_scheduler_execution() {
        let mut state = RadioConfig::default();
        let mut p = [0; 40];
        p[32..38].copy_from_slice(&[4, 0, 0, 0, 0x40, 0]);
        assert_eq!(state.set_features(&p), Some(p.to_vec()));
        assert_eq!(state.feature_extension, p[32..38]);
    }

    #[test]
    fn invalid_features_do_not_apply_partial_updates() {
        let mut state = RadioConfig::default();
        for offset in [6, 10, 19, 26, 30, 38, 39] {
            let mut p = [0; 40];
            p[0] = 1;
            p[20] = 1;
            p[offset] = 1;
            assert!(state.set_features(&p).is_none());
            assert_eq!(state, RadioConfig::default());
        }
        let mut p = [0; 40];
        p[2] = 2;
        assert!(state.set_features(&p).is_none());
        assert!(state.set_features(&p[..39]).is_none());
        assert!(state.set_features(&[0; 41]).is_none());
    }
}
