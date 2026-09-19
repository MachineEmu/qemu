//! Device/BSS/station configuration records, not a wireless datapath.
//! Layouts come from the original U6+ `mt7981_wifi.ko` producers/callbacks.

use std::collections::{BTreeMap, HashMap};

type Tags = BTreeMap<u16, Vec<u8>>;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Records {
    devices: HashMap<(u8, u8), [u8; 12]>,
    bsses: HashMap<u8, Tags>,
    stations: HashMap<u16, Station>,
}

#[derive(Debug, PartialEq, Eq)]
struct Station {
    bss: u8,
    muar: u8,
    tags: Tags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StationInfo {
    pub(crate) id: u16,
    pub(crate) bss: u8,
    pub(crate) band: u8,
    pub(crate) own_mac: [u8; 6],
    pub(crate) bssid: [u8; 6],
    pub(crate) peer: [u8; 6],
}

// Explicit startup TLV schemas. Unknown tags must not receive a success ACK.
const BSS_TAGS: &[(u16, usize)] = &[
    (0, 16),
    (1, 28),
    (2, 12),
    (8, 16),
    (9, 16),
    (10, 44),
    (11, 16),
    (12, 8),
    (13, 20),
    (14, 24),
];
const STATION_TAGS: &[(u16, usize)] = &[(0, 20), (8, 8), (13, 288), (14, 28)];
const WTBL_TAGS: &[(u16, usize)] = &[
    (0, 20),
    (1, 12),
    (2, 8),
    (9, 8),
    (13, 8),
    (3, 8),
    (5, 8),
    (6, 8),
    (12, 12),
    (16, 8),
    (21, 8),
];

impl Records {
    pub(super) fn bssid_for_own(&self, band: u8, own: u8) -> Option<[u8; 6]> {
        self.bsses.values().find_map(|tags| {
            let omac = tags.get(&0)?;
            let basic = tags.get(&1)?;
            (omac[5] == own && omac[6] == band && basic[8] != 0)
                .then(|| basic[12..18].try_into().ok())
                .flatten()
        })
    }

    pub(super) fn lookup_station(&self, id: u16) -> Option<StationInfo> {
        let station = self.stations.get(&id)?;
        let basic = station.tags.get(&0)?;
        if !matches!(basic[8], 1 | 2) {
            return None;
        }
        let bss = self.bsses.get(&station.bss)?;
        let bss_basic = bss.get(&1)?;
        let omac = bss.get(&0)?;
        let device = self.devices.get(&(omac[6], station.muar))?;
        Some(StationInfo {
            id,
            bss: station.bss,
            band: omac[6],
            own_mac: device[6..12].try_into().ok()?,
            bssid: bss_basic[12..18].try_into().ok()?,
            peer: basic[12..18].try_into().ok()?,
        })
    }

    pub(super) fn station_for_peer(&self, band: u8, peer: &[u8]) -> Option<StationInfo> {
        self.stations
            .keys()
            .filter_map(|id| self.lookup_station(*id))
            .filter(|station| station.band == band && station.peer == peer)
            .min_by_key(|station| station.id)
    }

    pub(super) fn own_mac(&self, band: u8, destination: &[u8]) -> Option<u8> {
        self.devices
            .iter()
            .filter_map(|(&(b, own), p)| {
                (b == band && p[4] != 0 && (destination[0] & 1 != 0 || p[6..12] == *destination))
                    .then_some(own)
            })
            .min()
    }

    pub(super) fn beacons(&self) -> Vec<(u8, u8, u16, Vec<u8>)> {
        self.bsses
            .iter()
            .filter_map(|(&id, tags)| {
                let basic = tags.get(&1)?;
                let omac = tags.get(&0)?;
                let beacon = tags.get(&15)?;
                let sync = tags.get(&9)?;
                if basic[8] == 0
                    || beacon[5] == 0
                    || sync[6] == 0
                    || self.own_mac(omac[6], &basic[12..18]) != Some(omac[5])
                {
                    return None;
                }
                let interval = short(basic, 10);
                if interval == 0 {
                    return None;
                }
                let mut offset = 8;
                while offset + 4 <= beacon.len() {
                    let len = usize::from(short(beacon, offset + 2));
                    let child = beacon.get(offset..offset + len)?;
                    if short(child, 0) == 3 {
                        let packet = child.get(12..12 + usize::from(short(child, 10)))?;
                        // Firmware beacon content includes the 32-byte TMAC descriptor.
                        let frame = packet.get(32..)?;
                        if frame.len() >= 36 && frame[0] == 0x80 {
                            return Some((id, omac[6], interval, frame.to_vec()));
                        }
                        return None;
                    }
                    if len < 4 {
                        return None;
                    }
                    offset += len;
                }
                None
            })
            .collect()
    }

    pub(super) fn command(&mut self, cid: u8, p: &[u8], wtbl: &mut HashMap<u16, Tags>) -> Vec<u8> {
        let ok = match cid {
            0x2a => self.device(p),
            0x26 => self.bss(p),
            0x25 => self.station(p, wtbl),
            _ => false,
        };
        // Callbacks @ 0x64e6e0/0x64e9d8/0x64e7a8 require 16 bytes.
        // Insert/delete @ 0x650f08/0x651138 use WCID low at 9, high at 13.
        let mut reply = super::result(cid, ok);
        reply.resize(16, 0);
        if let Some(h) = p.get(..8) {
            reply[8] = h[0];
            reply[10..12].copy_from_slice(&h[2..4]);
            if cid == 0x25 {
                reply[9] = h[1];
                reply[12] = h[5];
                reply[13] = h[6] & 3;
            }
        }
        reply
    }

    fn device(&mut self, p: &[u8]) -> bool {
        // CmdExtDevInfoUpdate @ 0x654dc8: own MAC, band, count, append.
        let Some(h) = p.get(..8) else {
            return false;
        };
        if h[1] > 1 || h[4..8] != [1, 0, 0, 0] {
            return false;
        }
        let Some(tags) = parse_tags(&p[8..], short(h, 2), &[(0, 12)], false) else {
            return false;
        };
        if let Some(t) = tags.get(&0) {
            if t[4] > 1 || t[5] != h[1] {
                return false;
            }
            let mut record = [0; 12];
            record.copy_from_slice(t);
            self.devices.insert((h[1], h[0]), record);
        }
        true
    }

    fn bss(&mut self, p: &[u8]) -> bool {
        // CmdExtBssInfoUpdate @ 0x6563e0. Updates append/replace individual
        // tags; a basic active=0 update must not discard unrelated settings.
        let Some(h) = p.get(..8) else {
            return false;
        };
        if h[1] != 0 || h[4..8] != [1, 0, 0, 0] {
            return false;
        }
        let Some(tags) = parse_records(
            &p[8..],
            short(h, 2),
            BSS_TAGS.len() + 1,
            false,
            |tag, length| {
                BSS_TAGS.contains(&(tag, length)) || tag == 15 && (8..=4096).contains(&length)
            },
        ) else {
            return false;
        };
        for (&tag, t) in &tags {
            let valid = match tag {
                0 => t[6] <= 1 && t[7] == 0 && t[12..16] == [0; 4],
                1 => t[8] <= 1 && t[9] == 0 && t[25] <= 3 && t[26..28] == [0; 2],
                2 => t[8] <= 1 && t[9] <= 1 && t[10..12] == [0; 2],
                8 => t[8] <= 1 && t[9..16] == [0; 7],
                9 => t[6] <= 1 && t[8..16] == [0; 8],
                12 => t[4] <= 1 && t[5] <= 63 && t[6..8] == [0; 2],
                15 => valid_beacon(t),
                _ => true,
            };
            if !valid {
                return false;
            }
        }
        if !tags.is_empty() {
            merge(self.bsses.entry(h[0]).or_default(), tags);
        }
        true
    }

    fn station(&mut self, p: &[u8], wtbl: &mut HashMap<u16, Tags>) -> bool {
        // CmdExtStaRecUpdate @ 0x6552e8. Full 10-bit WCID, not just byte 1.
        let Some(h) = p.get(..8) else {
            return false;
        };
        if h[4] != 1 || h[6] > 3 || h[7] != 0 {
            return false;
        }
        let id = u16::from(h[1]) | (u16::from(h[6]) << 8);
        let Some(mut tags) = parse_tags(&p[8..], short(h, 2), STATION_TAGS, false) else {
            return false;
        };
        let basic = tags.get(&0);
        if basic.is_some_and(|t| t[8] > 2 || t[9] > 1 || short(t, 18) & !3 != 0) {
            return false;
        }
        let delete = basic.is_some_and(|t| t[8] == 0);
        let new = basic.is_some_and(|t| short(t, 18) & 2 != 0);
        if let Some(t) = tags.get(&13) {
            // StaRecUpdateWtbl @ 0x653298 always emits a zero-padded 288
            // byte container. Its inner header carries the SAME station ID.
            if t[4] != h[1]
                || t[5] != 1
                || t[8] != h[6]
                || t[9..12] != [0; 3]
                || parse_wtbl_tags(&t[12..], short(t, 6), true).is_none()
            {
                return false;
            }
        }
        if let Some(old) = self.stations.get(&id) {
            if !new && (old.bss != h[0] || old.muar != h[5]) {
                return false;
            }
        } else if basic.is_none() && !tags.is_empty() {
            return false;
        }
        // No state changes until the entire outer AND nested batch validates.
        if delete {
            if tags.len() != 1 {
                return false;
            }
            self.stations.remove(&id);
            wtbl.remove(&id);
        } else if !tags.is_empty() {
            if new {
                self.stations.remove(&id);
                wtbl.remove(&id);
            }
            // One authoritative WTBL store, shared with CID 0x32 resets.
            if let Some(table) = tags.remove(&13) {
                // Nested RESET_AND_SET replaces the same table used by
                // standalone CID 0x32 updates. Parsing was validated above.
                if let Some(inner) = parse_wtbl_tags(&table[12..], short(table, 6), true) {
                    let mut replacement = Tags::new();
                    merge_wtbl(&mut replacement, inner);
                    wtbl.insert(id, replacement);
                }
            }
            let station = self.stations.entry(id).or_insert_with(|| Station {
                bss: h[0],
                muar: h[5],
                tags: Tags::new(),
            });
            merge(&mut station.tags, tags);
        }
        true
    }
}

fn short(p: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([p[offset], p[offset + 1]])
}

pub(super) fn parse_wtbl_tags(p: &[u8], count: u16, padded: bool) -> Option<BTreeMap<u16, &[u8]>> {
    let tags = parse_records(p, count, WTBL_TAGS.len() + 1, padded, |tag, length| {
        WTBL_TAGS.contains(&(tag, length)) || tag == 17 && matches!(length, 8 | 44 | 80 | 116)
    })?;
    if tags.get(&17).is_some_and(|key| !valid_keys(key)) {
        return None;
    }
    Some(tags)
}

fn valid_keys(p: &[u8]) -> bool {
    // fill_key_install_cmd_v2 / fill_wtbl_key_info_struc_v2:
    // action (0 install, 1 remove), count, two reserved bytes, followed by
    // 36-byte cipher/length/key-id/key-length/material records. Removal may
    // retain the allocation size of an install, but zeroes all records.
    if p[6..8] != [0; 2] {
        return false;
    }
    if p[4] == 1 {
        return p[5] == 0 && p[8..].iter().all(|b| *b == 0);
    }
    if p[4] != 0 || !(1..=3).contains(&p[5]) || p.len() != 8 + usize::from(p[5]) * 36 {
        return false;
    }
    let mut slots = std::collections::BTreeSet::new();
    p[8..].chunks_exact(36).all(|key| {
        matches!(key[0], 1..=8 | 10..=12)
            && key[1] == 36
            && key[2] <= 7
            && (1..=32).contains(&key[3])
            && slots.insert((key[0], key[2]))
    })
}

pub(super) fn merge_wtbl(table: &mut Tags, updates: BTreeMap<u16, &[u8]>) {
    for (tag, value) in updates {
        if tag != 17 {
            table.insert(tag, value.to_vec());
            continue;
        }
        if value[4] == 1 {
            table.remove(&17);
            continue;
        }
        // A rekey replaces the addressed cipher/key-id slots, preserving
        // unrelated data and management keys for the same station.
        let mut keys = BTreeMap::new();
        if let Some(old) = table.get(&17) {
            for key in old[8..].chunks_exact(36) {
                keys.insert((key[0], key[2]), key.to_vec());
            }
        }
        for key in value[8..].chunks_exact(36) {
            keys.insert((key[0], key[2]), key.to_vec());
        }
        let mut stored = vec![17, 0, 0, 0, 0, 0, 0, 0];
        // Validation bounds the key space to eleven ciphers times eight IDs.
        stored[5] = u8::try_from(keys.len()).unwrap_or(0);
        for key in keys.into_values() {
            stored.extend(key);
        }
        let length = u16::try_from(stored.len()).unwrap_or(0);
        stored[2..4].copy_from_slice(&length.to_le_bytes());
        table.insert(17, stored);
    }
}

fn parse_tags<'a>(
    p: &'a [u8],
    count: u16,
    schema: &[(u16, usize)],
    padded: bool,
) -> Option<BTreeMap<u16, &'a [u8]>> {
    parse_records(p, count, schema.len(), padded, |tag, length| {
        schema.contains(&(tag, length))
    })
}

fn parse_records(
    mut p: &[u8],
    count: u16,
    max_count: usize,
    padded: bool,
    valid_length: impl Fn(u16, usize) -> bool,
) -> Option<BTreeMap<u16, &[u8]>> {
    if usize::from(count) > max_count {
        return None;
    }
    let mut tags = BTreeMap::new();
    for _ in 0..count {
        let h = p.get(..4)?;
        let tag = short(h, 0);
        let length = usize::from(short(h, 2));
        if length < 4 || !valid_length(tag, length) {
            return None;
        }
        let record = p.get(..length)?;
        if tags.insert(tag, record).is_some() {
            return None;
        }
        p = &p[length..];
    }
    if !(p.is_empty() || padded && p.iter().all(|b| *b == 0)) {
        return None;
    }
    Some(tags)
}

fn valid_beacon(p: &[u8]) -> bool {
    // bss_update_offload_pkt @ 0x651578: type, enable, subelement count.
    // Store the requested beacon template/offload configuration only. This
    // does not schedule or transmit beacons. Bound the model to 4 KiB/TLV.
    if p[4] != 0 || p[5] > 1 {
        return false;
    }
    let Some(tags) = parse_records(&p[8..], short(p, 6), 5, false, |tag, len| {
        match tag {
            0 | 1 | 5 => len == 8, // CSA, color-change countdown, BTWT offset
            2 => len == 80,        // MBSSID bitmap/TIM offsets
            3 => (12..=4088).contains(&len) && len.is_multiple_of(4),
            _ => false,
        }
    }) else {
        return false;
    };
    if let Some(content) = tags.get(&3) {
        let packet_length = usize::from(short(content, 10));
        if packet_length == 0 || (12 + packet_length).next_multiple_of(4) != content.len() {
            return false;
        }
        // The producer appends TXD + beacon then alignment bytes from its
        // packet buffer. Those alignment bytes are not guaranteed zero.
        for offset in [4, 6, 8] {
            if usize::from(short(content, offset)) > packet_length {
                return false;
            }
        }
    }
    true
}

fn merge(destination: &mut Tags, tags: BTreeMap<u16, &[u8]>) {
    destination.extend(tags.into_iter().map(|(tag, data)| (tag, data.to_vec())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi_mcu::StartupConfig;

    fn tlv(tag: u16, len: usize) -> Vec<u8> {
        let mut p = vec![0; len];
        p[..2].copy_from_slice(&tag.to_le_bytes());
        p[2..4].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
        p
    }

    fn station(id: u16, state: u8, extra: u16, nested: bool) -> Vec<u8> {
        let [low, high] = id.to_le_bytes();
        let mut p = vec![3, low, 1 + u8::from(nested), 0, 1, 14, high, 0];
        let mut basic = tlv(0, 20);
        basic[8] = state;
        basic[18..20].copy_from_slice(&extra.to_le_bytes());
        p.extend(basic);
        if nested {
            let mut table = tlv(13, 288);
            table[4..12].copy_from_slice(&[low, 1, 1, 0, high, 0, 0, 0]);
            table[12..32].copy_from_slice(&tlv(0, 20));
            p.extend(table);
        }
        p
    }

    #[test]
    fn captured_original_driver_requests_get_exact_reply_lengths_and_ids() {
        // Small, self-contained selection from the original U6+ startup capture.
        // Keeping the requests here makes this crate independently testable after
        // being moved out of the source-tree fixture layout.
        const STARTUP_REQUESTS: &[(&str, &str)] = &[
            ("2a", "000001000100000000000c000100020000798103"),
            (
                "07",
                "0502000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "25",
                "001f0100010e0200000014002000010000000000ffffffffffff0100",
            ),
            ("27", "00000000"),
        ];

        let mut state = StartupConfig::default();
        for &(cid, hex) in STARTUP_REQUESTS {
            let cid = u8::from_str_radix(cid, 16).unwrap();
            let p: Vec<_> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let (event, reply) = state.command(cid, &p).unwrap();
            assert_eq!(event, 0);
            assert_eq!(
                &reply[..8],
                super::super::result(cid, true),
                "CID {cid:02x}"
            );
            assert_eq!(
                reply.len(),
                if matches!(cid, 0x25 | 0x26 | 0x2a) {
                    16
                } else {
                    8
                }
            );
            if cid == 0x25 {
                assert_eq!(&reply[8..], &[p[0], p[1], p[2], p[3], p[5], p[6], 0, 0]);
            }
        }
    }

    #[test]
    fn station_insert_partial_update_delete_and_wtbl_reset_keep_full_id() {
        let mut state = StartupConfig::default();
        for id in [31, 543, 1023] {
            let p = station(id, 2, 3, true);
            let (_, reply) = state.command(0x25, &p).unwrap();
            assert_eq!(reply[4], 0);
            assert_eq!(u16::from(reply[9]) | u16::from(reply[13]) << 8, id);
            assert!(state.station_table.contains_key(&id));
        }
        let mut update = station(543, 2, 1, false);
        update.truncate(8);
        let mut tx = tlv(8, 8);
        tx[4] = 7;
        update.extend(tx);
        assert_eq!(state.command(0x25, &update).unwrap().1[4], 0);
        assert_eq!(state.records.stations[&543].tags[&8][4], 7);
        assert!(state.records.stations[&543].tags.contains_key(&0));
        assert!(!state.records.stations[&543].tags.contains_key(&13));
        state.command(0x32, &[31, 1, 0, 0, 2, 0, 0, 0]);
        assert!(!state.station_table.contains_key(&543));
        assert!(state.station_table.contains_key(&31));
        assert!(state.records.stations.contains_key(&543));
        state.command(0x25, &station(543, 2, 3, true));
        assert!(!state.records.stations[&543].tags.contains_key(&8));
        assert_eq!(
            state.command(0x25, &station(543, 0, 1, false)).unwrap().1[4],
            0
        );
        assert!(!state.records.stations.contains_key(&543));
        assert!(!state.station_table.contains_key(&543));
        assert!(state.records.stations.contains_key(&31));
        assert!(state.records.stations.contains_key(&1023));
    }

    #[test]
    fn invalid_station_batches_never_apply_partial_state() {
        let mut state = StartupConfig::default();
        let p = station(543, 2, 3, true);
        state.command(0x25, &p);
        let original_table = state.station_table[&543].clone();
        // Header flags/count, basic state, TLV length/tag, nested station,
        // operation/count, nested length, reserved and nonzero padding.
        for (offset, value) in [
            (2, 255),
            (3, 1),
            (4, 0),
            (6, 4),
            (7, 1),
            (8, 99),
            (10, 19),
            (16, 3),
            (17, 2),
            (26, 4),
            (32, 30),
            (33, 4),
            (34, 12),
            (36, 1),
            (37, 1),
            (40, 99),
            (42, 0),
            (315, 1),
        ] {
            let mut bad = p.clone();
            bad[offset] = value;
            assert_eq!(
                state.command(0x25, &bad).unwrap().1[4],
                1,
                "offset {offset}"
            );
            assert_eq!(state.station_table[&543], original_table);
            assert_eq!(state.records.stations[&543].tags[&0], p[8..28]);
            assert_eq!(state.records.stations.len(), 1);
        }
        for n in 0..p.len() {
            assert_eq!(state.command(0x25, &p[..n]).unwrap().1[4], 1, "length {n}");
            assert_eq!(state.station_table[&543], original_table);
        }
        let mut duplicate = p.clone();
        duplicate[2] = 3;
        duplicate.extend_from_slice(&p[8..28]);
        assert_eq!(state.command(0x25, &duplicate).unwrap().1[4], 1);
        let mut trailing = p.clone();
        trailing.push(0);
        assert_eq!(state.command(0x25, &trailing).unwrap().1[4], 1);
        assert_eq!(
            state.command(0x25, &station(543, 0, 1, true)).unwrap().1[4],
            1
        );
        assert!(state.records.stations.contains_key(&543));
    }

    #[test]
    fn device_and_bss_updates_keep_other_records_and_unselected_tags() {
        let mut records = Records::default();
        for band in 0..2 {
            let mut p = vec![17, band, 1, 0, 1, 0, 0, 0];
            let mut t = tlv(0, 12);
            t[4] = 1;
            t[5] = band;
            t[11] = band + 1;
            p.extend(t);
            assert!(records.device(&p));
            p[12] = 0;
            assert!(records.device(&p));
        }
        assert_eq!(records.devices.len(), 2);
        assert_eq!(records.devices[&(1, 17)][11], 2);
        let mut p = vec![7, 0, 2, 0, 1, 0, 0, 0];
        let mut basic = tlv(1, 28);
        basic[8] = 1;
        p.extend(&basic);
        let mut color = tlv(12, 8);
        color[5] = 26;
        p.extend(&color);
        assert!(records.bss(&p));
        p[0] = 8;
        assert!(records.bss(&p));
        p[0] = 7;
        p[2] = 1;
        p.truncate(36);
        p[16] = 0;
        assert!(records.bss(&p));
        assert_eq!(records.bsses[&7][&1][8], 0);
        assert_eq!(records.bsses[&8][&1][8], 1);
        assert_eq!(records.bsses[&7][&12], color);
        p[2] = 2;
        color[5] = 64;
        p.extend(color);
        p[16] = 1;
        assert!(!records.bss(&p));
        assert_eq!(records.bsses[&7][&1][8], 0);
    }

    #[test]
    fn tlv_parser_rejects_count_duplicates_unknown_lengths_and_padding() {
        let p = tlv(0, 12);
        assert!(parse_tags(&p, 1, &[(0, 12)], false).is_some());
        for (data, count) in [
            (p[..11].to_vec(), 1),
            (p.clone(), 0),
            (p.clone(), 2),
            (tlv(1, 12), 1),
            (tlv(0, 8), 1),
            ([p.clone(), p.clone()].concat(), 2),
            ([p.clone(), vec![0; 4]].concat(), 1),
        ] {
            assert!(parse_tags(&data, count, &[(0, 12), (1, 8)], false).is_none());
        }
        assert!(parse_tags(&[p.clone(), vec![0; 4]].concat(), 1, &[(0, 12)], true).is_some());
        assert!(parse_tags(&[p, vec![1; 4]].concat(), 1, &[(0, 12)], true).is_none());
    }

    #[test]
    fn beacon_nested_lengths_and_packet_alignment_are_validated_atomically() {
        let mut records = Records::default();
        // Same outer length as the original driver's link-up beacon command.
        let mut beacon = tlv(15, 388);
        beacon[5] = 1;
        beacon[6] = 1;
        beacon[8..].copy_from_slice(&tlv(3, 380));
        beacon[18..20].copy_from_slice(&367_u16.to_le_bytes());
        beacon[387] = 0xa5; // alignment byte from producer packet buffer
        let p = [vec![4, 0, 1, 0, 1, 0, 0, 0], beacon.clone()].concat();
        assert!(records.bss(&p));
        assert_eq!(records.bsses[&4][&15], beacon);
        for (offset, value) in [
            (12, 1),
            (13, 2),
            (14, 6),
            (15, 1),
            (16, 4),
            (18, 0),
            (21, 255),
            (26, 0),
            (27, 0),
        ] {
            let mut bad = p.clone();
            bad[offset] = value;
            assert!(!records.bss(&bad), "offset {offset}");
            assert_eq!(records.bsses[&4][&15], beacon);
        }
        for n in 8..p.len() {
            assert!(!records.bss(&p[..n]));
        }
        // Disable without a content subelement is a valid configuration.
        let disable = [vec![4, 0, 1, 0, 1, 0, 0, 0], tlv(15, 8)].concat();
        assert!(records.bss(&disable));
        assert_eq!(records.bsses[&4][&15], tlv(15, 8));
    }
}
