//! Protection and queue policy storage plus idle-radio MIB queries.
//! No protection frames, station flushing, or RF traffic are executed here.

// IDs requested by UpdatePreACSInfo, UpdateChannelInfo, MtAsicGetCCACnt,
// scan_next_channel, and mt7981_update_mib_bucket in the original U6+ driver.
const MIB_IDS: [u32; 6] = [0x1ea, 6, 8, 0x1eb, 0, 0x34];
const MAX_MIB_RECORDS: usize = 64;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct MacConfig {
    rts_thresholds: [Option<[u32; 2]>; 2],
    protection: [Option<[u8; 8]>; 2],
    ps_flush: Option<PsFlush>,
    radio_on: [bool; 2],
    edca: [Edca; 24],
    // An idle simulated radio has no accumulated activity. Future datapath
    // integration must update these counters; reads never invent activity.
    mib: [[u64; MIB_IDS.len()]; 2],
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Edca {
    aifs: u8,
    cw_min: u8,
    cw_max: u16,
    txop: u16,
    tx_mode: Option<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct PsFlush {
    per_station_max: u16,
    total_threshold: u16,
    enabled: bool,
}

impl MacConfig {
    pub(super) fn powered(&self, band: usize) -> bool {
        self.radio_on[band]
    }

    pub(super) fn set_radio_power(&mut self, payload: &[u8]) -> bool {
        // MtCmdExtPmStateCtrl @ 0x634500, AsicRadioOnOffCtrl @ 0x58b708.
        // PM5: state 1 is radio off, 2 is radio on (not a boolean enable).
        // PM4 station power-save transitions are deliberately unsupported.
        let Ok(p) = <&[u8; 32]>::try_from(payload) else {
            return false;
        };
        if p[0] != 5
            || !matches!(p[1], 1 | 2)
            || p[20] > 1
            || p[2..20].iter().chain(&p[21..]).any(|b| *b != 0)
        {
            return false;
        }
        self.radio_on[usize::from(p[20])] = p[1] == 2;
        true
    }

    pub(super) fn set_edca(&mut self, payload: &[u8]) -> bool {
        // MtCmdEdcaParameterSet @ 0x63b158: 4-byte header + N*8.
        // MtAsicSetEdcaParm @ 0x617050 supplies TXMODE when byte 2 is 1;
        // wmm_ctrl_show_entry @ 0x4c8ee8 identifies that field, NOT band.
        // MtAsicSetWmmParam @ 0x616e60 sends single-field masked updates.
        let Some(h) = payload.get(..4) else {
            return false;
        };
        if h[0] > 24
            || h[1] != 0
            || h[2] > 1
            || (h[2] == 0 && h[3] != 0)
            || payload.len() != 4 + usize::from(h[0]) * 8
        {
            return false;
        }
        let mut queues = self.edca;
        let mut seen = [false; 24];
        for p in payload[4..].chunks_exact(8) {
            let index = usize::from(p[0]);
            if index >= queues.len() || seen[index] || p[1] & !0x0f != 0 {
                return false;
            }
            seen[index] = true;
            let queue = &mut queues[index];
            if p[1] & 1 != 0 {
                queue.aifs = p[2];
            }
            if p[1] & 2 != 0 {
                queue.cw_min = p[3];
            }
            if p[1] & 4 != 0 {
                queue.cw_max = u16::from_le_bytes([p[4], p[5]]);
            }
            if p[1] & 8 != 0 {
                queue.txop = u16::from_le_bytes([p[6], p[7]]);
            }
            if h[2] == 1 {
                queue.tx_mode = Some(h[3]);
            }
        }
        self.edca = queues;
        true
    }

    pub(super) fn set_protection(&mut self, payload: &[u8]) -> bool {
        // MtCmdUpdateProtect @ 0x63f170, producers @ 0x616ae8/0x616b70:
        // 12-byte union, generic eight-byte result. Threshold and protection
        // operations update independent state on the selected band.
        let Ok(p) = <&[u8; 12]>::try_from(payload) else {
            return false;
        };
        if p[1] > 1 || p[2..4] != [0; 2] {
            return false;
        }
        let band = usize::from(p[1]);
        match p[0] {
            1 if u8::try_from(word(p, 8)).is_ok() => {
                self.rts_thresholds[band] = Some([word(p, 4), word(p, 8)]);
            }
            2 if p[4..11].iter().all(|value| *value <= 1) => {
                let mut modes = [0; 8];
                modes.copy_from_slice(&p[4..]);
                self.protection[band] = Some(modes);
            }
            _ => return false,
        }
        true
    }

    pub(super) fn set_ps_flush(&mut self, payload: &[u8]) -> bool {
        // MtCmdPsStaFlushCtrl @ 0x6473c8 sends this eight-byte request to
        // WA (destination 3), using EventExtCmdResult for its reply.
        let [max_lo, max_hi, total_lo, total_hi, enabled @ 0..=1, 0, 0, 0] = payload else {
            return false;
        };
        self.ps_flush = Some(PsFlush {
            per_station_max: u16::from_le_bytes([*max_lo, *max_hi]),
            total_threshold: u16::from_le_bytes([*total_lo, *total_hi]),
            enabled: *enabled != 0,
        });
        true
    }

    pub(super) fn read_mib(&self, payload: &[u8]) -> Option<Vec<u8>> {
        // MtCmdMultipleMibRegAccessRead @ 0x635d78 sends 16-byte records:
        // band:u32, id:u32, reserved:u64. Callback 0x62d330 copies id/value
        // from offsets 4/8 and computes count = (payload_len - 20) / 16.
        // The driver's exact length check therefore requires 20 TRAILING
        // bytes, not a prefix and not the generic result format.
        if payload.is_empty()
            || !payload.len().is_multiple_of(16)
            || payload.len() / 16 > MAX_MIB_RECORDS
        {
            return None;
        }
        let mut response = Vec::with_capacity(payload.len() + 20);
        for record in payload.chunks_exact(16) {
            let band = usize::try_from(word(record, 0)).ok()?;
            let counters = self.mib.get(band)?;
            let id = word(record, 4);
            let index = MIB_IDS.iter().position(|supported| *supported == id)?;
            if record[8..] != [0; 8] {
                return None;
            }
            response.extend_from_slice(&record[..8]);
            response.extend_from_slice(&counters[index].to_le_bytes());
        }
        response.resize(payload.len() + 20, 0);
        Some(response)
    }
}

fn word(p: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([p[offset], p[offset + 1], p[offset + 2], p[offset + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radio_pm5_state_two_is_on_and_bands_are_independent() {
        let mut state = MacConfig::default();
        let mut p = [0; 32];
        p[..2].copy_from_slice(&[5, 2]);
        assert!(state.set_radio_power(&p));
        p[20] = 1;
        assert!(state.set_radio_power(&p));
        p[1] = 1;
        assert!(state.set_radio_power(&p));
        assert_eq!(state.radio_on, [true, false]);
        for (offset, value) in [(0, 4), (1, 0), (1, 3), (2, 1), (20, 2), (21, 1), (31, 1)] {
            let mut bad = p;
            bad[offset] = value;
            assert!(!state.set_radio_power(&bad));
            assert_eq!(state.radio_on, [true, false]);
        }
        assert!(!state.set_radio_power(&p[..31]));
        assert!(!state.set_radio_power(&[0; 33]));
    }

    #[test]
    fn edca_partial_updates_preserve_other_fields_queues_and_txmode() {
        let mut state = MacConfig::default();
        let p = [
            2, 0, 1, 1, 1, 15, 3, 4, 6, 0, 0, 0, 2, 15, 1, 3, 4, 0, 94, 0,
        ];
        assert!(state.set_edca(&p));
        let initial = state.edca;
        assert!(state.set_edca(&[1, 0, 0, 0, 1, 8, 0, 0, 0, 0, 187, 0]));
        assert_eq!(
            state.edca[1],
            Edca {
                txop: 187,
                ..initial[1]
            }
        );
        assert_eq!(state.edca[2], initial[2]);
        assert!(state.set_edca(&[1, 0, 0, 0, 1, 1, 7, 0, 0, 0, 0, 0]));
        assert!(state.set_edca(&[1, 0, 0, 0, 1, 2, 0, 9, 0, 0, 0, 0]));
        assert!(state.set_edca(&[1, 0, 0, 0, 1, 4, 0, 0, 0x34, 0x12, 0, 0]));
        assert_eq!(
            state.edca[1],
            Edca {
                aifs: 7,
                cw_min: 9,
                cw_max: 0x1234,
                txop: 187,
                tx_mode: Some(1)
            }
        );
        let saved = state.edca;
        assert!(state.set_edca(&[0; 4]));
        assert_eq!(state.edca, saved);
        for (offset, value) in [(0, 25), (1, 1), (2, 2), (12, 1), (12, 24), (13, 16)] {
            let mut bad = p;
            bad[offset] = value;
            assert!(!state.set_edca(&bad));
            assert_eq!(state.edca, saved);
        }
        for n in 0..p.len() {
            assert!(!state.set_edca(&p[..n]));
        }
    }

    #[test]
    fn protection_operations_and_bands_are_independent() {
        let mut state = MacConfig::default();
        let mut p = [1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 32, 0, 0, 0];
        assert!(state.set_protection(&p));
        p[1] = 1;
        p[8] = 255;
        assert!(state.set_protection(&p));
        let modes = [2, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0x1f];
        assert!(state.set_protection(&modes));
        assert_eq!(
            state.rts_thresholds,
            [Some([u32::MAX, 32]), Some([u32::MAX, 255])]
        );
        assert_eq!(state.protection, [Some([1, 1, 0, 1, 0, 1, 1, 0x1f]), None]);
    }

    #[test]
    fn invalid_protection_leaves_state_unchanged() {
        let mut state = MacConfig::default();
        let p = [1, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0];
        assert!(state.set_protection(&p));
        for (offset, value) in [(0, 0), (0, 3), (1, 2), (2, 1), (3, 1), (9, 1)] {
            let mut bad = p;
            bad[offset] = value;
            assert!(!state.set_protection(&bad));
            assert_eq!(state.rts_thresholds, [Some([0, 32]), None]);
        }
        assert!(!state.set_protection(&[2, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(state.protection, [None; 2]);
        assert!(!state.set_protection(&p[..11]));
        assert!(!state.set_protection(&[0; 13]));
    }

    #[test]
    fn ps_flush_retains_thresholds_and_disable_updates() {
        let mut state = MacConfig::default();
        let mut p = [0x34, 0x12, 0x78, 0x56, 1, 0, 0, 0];
        assert!(state.set_ps_flush(&p));
        assert_eq!(
            state.ps_flush,
            Some(PsFlush {
                per_station_max: 0x1234,
                total_threshold: 0x5678,
                enabled: true,
            })
        );
        p[4] = 0;
        assert!(state.set_ps_flush(&p));
        assert_eq!(
            state.ps_flush,
            Some(PsFlush {
                per_station_max: 0x1234,
                total_threshold: 0x5678,
                enabled: false,
            })
        );
        for (offset, value) in [(4, 2), (5, 1), (6, 1), (7, 1)] {
            let mut bad = p;
            bad[offset] = value;
            assert!(!state.set_ps_flush(&bad));
            assert_eq!(state.ps_flush.as_ref().unwrap().per_station_max, 0x1234);
            assert!(!state.ps_flush.as_ref().unwrap().enabled);
        }
        assert!(!state.set_ps_flush(&p[..7]));
        assert!(!state.set_ps_flush(&[0; 9]));
    }

    fn mib_record(band: u32, id: u32) -> Vec<u8> {
        [band.to_le_bytes(), id.to_le_bytes(), [0; 4], [0; 4]].concat()
    }

    #[test]
    fn mib_reads_preserve_order_band_and_full_64_bit_values() {
        let mut state = MacConfig::default();
        state.mib[0][0] = 0x1234_5678_9abc_def0;
        state.mib[1][0] = 42;
        let mut p = mib_record(1, 0x1ea);
        p.extend(mib_record(0, 0x1ea));
        p.extend(mib_record(1, 0x1ea));
        let reply = state.read_mib(&p).unwrap();
        assert_eq!(reply.len(), 3 * 16 + 20);
        for (i, value) in [42_u64, 0x1234_5678_9abc_def0, 42].into_iter().enumerate() {
            assert_eq!(&reply[i * 16..i * 16 + 8], &p[i * 16..i * 16 + 8]);
            assert_eq!(reply[i * 16 + 8..i * 16 + 16], value.to_le_bytes());
        }
        assert_eq!(reply[48..], [0; 20]);
        assert_eq!(state.read_mib(&p), Some(reply)); // not read-to-clear
    }

    #[test]
    fn mib_startup_counters_are_idle_and_queries_are_bounded() {
        let state = MacConfig::default();
        for band in 0..2 {
            let p: Vec<_> = MIB_IDS
                .iter()
                .flat_map(|id| mib_record(band, *id))
                .collect();
            assert_eq!(state.read_mib(&p), Some([p, vec![0; 20]].concat()));
        }
        let p = mib_record(0, 0);
        assert!(state.read_mib(&p.repeat(MAX_MIB_RECORDS)).is_some());
        assert!(state.read_mib(&p.repeat(MAX_MIB_RECORDS + 1)).is_none());
    }

    #[test]
    fn invalid_mib_batch_does_not_return_partial_or_invented_counters() {
        let state = MacConfig::default();
        let p = mib_record(0, 0);
        for bad in [mib_record(2, 0), mib_record(0, 0xffff), vec![1; 16]] {
            assert!(state.read_mib(&[p.clone(), bad].concat()).is_none());
        }
        let mut bad = p.clone();
        bad[8] = 1;
        assert!(state.read_mib(&bad).is_none());
        assert!(state.read_mib(&[]).is_none());
        assert!(state.read_mib(&p[..15]).is_none());
        assert!(state.read_mib(&[0; 17]).is_none());
        assert_eq!(state, MacConfig::default());
    }
}
