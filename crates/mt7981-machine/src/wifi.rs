//! Bounded MT7981 wireless DMA frontend.
use super::{MachineContext, Mt7981Board, WFDMA0_INT_SOURCE};
use crate::wifi_frame;
use crate::wifi_mcu::{WifiCipher, WifiKey};
use std::collections::{HashMap, VecDeque};

const LIMIT: usize = 256;

/// A raw 802.11 frame without radiotap or FCS, addressed to a simulated radio.
#[derive(Debug)]
pub struct WifiFrame {
    /// Physical band (0 or 1), not a virtual BSS index.
    pub band: u8,
    /// Primary-channel frequency in MHz.
    pub frequency: u32,
    /// Raw 802.11 frame, including its MAC header.
    pub frame: Vec<u8>,
    /// WTBL station used for this frame, when applicable.
    pub station: Option<u16>,
    /// Selected legacy hwsim rate index.
    pub rate_index: u8,
    /// Whether hardware aggregation was requested for this frame.
    pub aggregate: bool,
}

/// Reception metadata supplied by the simulated wireless medium.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiRxInfo {
    /// Physical band, zero or one.
    pub band: u8,
    /// Primary-channel frequency in MHz.
    pub frequency: u32,
    /// Received signal strength in dBm.
    pub signal_dbm: i32,
    /// Selected legacy hwsim rate index.
    pub rate_index: u8,
    /// Frame belongs to an aggregate.
    pub aggregate: bool,
}

/// Per-station data-plane counters maintained by the emulated hardware.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WifiStationStats {
    /// Frames accepted from the simulated medium.
    pub rx_packets: u64,
    /// Ethernet payload bytes accepted from the simulated medium.
    pub rx_bytes: u64,
    /// Frames submitted to the simulated medium.
    pub tx_packets: u64,
    /// Ethernet payload bytes submitted to the simulated medium.
    pub tx_bytes: u64,
    /// Frames rejected by validation, authentication, replay, or DMA backpressure.
    pub failed: u64,
    /// Frames accepted by the host injection transport.
    pub tx_accepted: u64,
    /// Frames rejected by the host injection transport.
    pub tx_rejected: u64,
    /// Most recent received signal strength in dBm.
    pub signal_dbm: i32,
    /// Most recent selected legacy hwsim rate index.
    pub rate_index: u8,
    /// Received frames marked as aggregated by the medium.
    pub rx_aggregated: u64,
    /// Frames submitted with hardware aggregation enabled.
    pub tx_aggregated: u64,
}

#[derive(Debug, Default)]
pub(super) struct Wireless {
    online: [bool; 2],
    tx: VecDeque<WifiFrame>,
    tokens: VecDeque<(u8, u16)>,
    beacons: HashMap<u8, (u64, u16)>,
    targets: [Option<u32>; 2],
    sequences: HashMap<u16, u16>,
    tx_pn: HashMap<(u16, u8, u8), u64>,
    rx_pn: HashMap<(u16, u8, u8, u8), u64>,
    stats: HashMap<u16, WifiStationStats>,
}

struct DecodedTx {
    band: u8,
    token: u16,
    station: Option<u16>,
    own: u8,
    ethernet: bool,
    frame: Vec<u8>,
    protected: bool,
    rate_index: u8,
    aggregate: bool,
}

impl Wireless {
    pub(super) fn reset_tx_rings(&mut self, mask: u32) {
        for band in 0..2 {
            if mask & (1 << (18 + band)) != 0 {
                self.targets[band] = None;
                self.tokens.retain(|(b, _)| usize::from(*b) != band);
                self.tx.retain(|frame| usize::from(frame.band) != band);
            }
        }
    }
}

fn frequency(channel: u8) -> Option<u32> {
    match channel {
        1..=13 => Some(2407 + u32::from(channel) * 5),
        14 => Some(2484),
        36..=177 => Some(5000 + u32::from(channel) * 5),
        _ => None,
    }
}

#[expect(
    clippy::verbose_bit_mask,
    reason = "802.11 field masks are clearer than zero counts"
)]
fn management(frame: &[u8]) -> bool {
    // No protocol extension, DS addressing, fragmentation, encryption or HT control.
    (24..=2304).contains(&frame.len())
        && frame[0] & 0x0f == 0
        && frame[1] & 0xc7 == 0
        && frame[22] & 15 == 0
}

#[expect(
    clippy::verbose_bit_mask,
    reason = "802.11 field masks are clearer than zero counts"
)]
fn wireless_frame(frame: &[u8]) -> bool {
    management(frame)
        || ((24..=2304).contains(&frame.len())
            && frame[0] & 0x0f == 0
            && frame[1] & 0xc7 == 0x40
            && frame[22] & 15 == 0)
        || wifi_frame::data_header(frame).is_some()
}

fn decrypt_key(frame: &[u8], key: &WifiKey) -> Option<(u8, u64, Vec<u8>)> {
    match key.cipher {
        WifiCipher::Wep => wifi_frame::decrypt_wep(frame, &key.material),
        WifiCipher::Tkip => wifi_frame::decrypt_tkip(frame, &key.material),
        WifiCipher::Ccmp | WifiCipher::Ccmp256 => wifi_frame::decrypt_ccmp(frame, &key.material),
        WifiCipher::Gcmp | WifiCipher::Gcmp256 => wifi_frame::decrypt_gcmp(frame, &key.material),
    }
}

fn encrypt_key(frame: &[u8], key: &WifiKey, pn: u64) -> Option<Vec<u8>> {
    match key.cipher {
        WifiCipher::Wep => wifi_frame::encrypt_wep(frame, &key.material, key.id, pn),
        WifiCipher::Tkip => wifi_frame::encrypt_tkip(frame, &key.material, key.id, pn),
        WifiCipher::Ccmp | WifiCipher::Ccmp256 => {
            wifi_frame::encrypt_ccmp(frame, &key.material, key.id, pn)
        }
        WifiCipher::Gcmp | WifiCipher::Gcmp256 => {
            wifi_frame::encrypt_gcmp(frame, &key.material, key.id, pn)
        }
    }
}

impl Mt7981Board {
    /// Set transport readiness. Disconnect discards queued frames, not air ACKs.
    pub fn wifi_online(&mut self, radios: [bool; 2]) {
        self.wifi.online = radios;
        self.wifi.tx.retain(|p| radios[usize::from(p.band)]);
        if !radios.iter().any(|v| *v) {
            self.wifi.beacons.clear();
        }
    }

    /// Drain one frame for the host's raw wireless adapter.
    pub fn wifi_take_tx(&mut self) -> Option<WifiFrame> {
        self.wifi.tx.pop_front()
    }

    /// Return the current emulated hardware counters for one WTBL station.
    #[must_use]
    pub fn wifi_station_stats(&self, station: u16) -> Option<WifiStationStats> {
        self.wifi_startup
            .station(station)
            .map(|_| self.wifi.stats.get(&station).copied().unwrap_or_default())
    }

    /// Record the result returned by the host transport for a submitted frame.
    pub fn wifi_tx_result(&mut self, station: Option<u16>, accepted: bool) {
        if let Some(station) = station {
            let stats = self.wifi.stats.entry(station).or_default();
            if accepted {
                stats.tx_accepted += 1;
            } else {
                stats.tx_rejected += 1;
                stats.failed += 1;
            }
        }
    }

    /// Emit enabled firmware beacon templates and return cut-through buffers.
    pub fn wifi_poll(&mut self, ctx: &mut MachineContext<'_>) {
        self.wifi_reclaim(ctx);
        for ring in 2..4 {
            if let Some(target) = self.wifi.targets[ring - 2] {
                self.wifi_drain_tx(ctx, ring, target);
            }
        }
        self.wifi_reclaim(ctx);
        self.wifi_beacons(ctx);
    }

    fn wifi_reclaim(&mut self, ctx: &mut MachineContext<'_>) {
        while let Some(&(band, token)) = self.wifi.tokens.front() {
            // mtf_txdone_handle @ 0x61d408: v4 resource-only TXFREE, one token.
            // No MPDU status header: buffer reclamation does NOT assert air ACK.
            let mut packet = Vec::with_capacity(12);
            packet.extend_from_slice(&((6u32 << 27) | (1 << 16) | 0x0c).to_le_bytes());
            packet.extend_from_slice(&(4u32 << 16).to_le_bytes());
            packet.extend_from_slice(&(u32::from(token) | (0x7fff << 15)).to_le_bytes());
            if !self.wifi_post(ctx, 2 + band, &packet) {
                break;
            }
            self.wifi.tokens.pop_front();
        }
    }

    fn wifi_beacons(&mut self, ctx: &MachineContext<'_>) {
        for (id, band, interval, mut frame) in self.wifi_startup.beacons() {
            let b = usize::from(band);
            if b >= 2 || !self.wifi.online[b] || !management(&frame) {
                continue;
            }
            let Some(frequency) = self.wifi_startup.channel(b).and_then(frequency) else {
                continue;
            };
            let (deadline, sequence) = self.wifi.beacons.entry(id).or_default();
            if ctx.now < *deadline || self.wifi.tx.len() >= LIMIT {
                continue;
            }
            *deadline = ctx.now.saturating_add(u64::from(interval) * 1_024_000);
            frame[24..32].copy_from_slice(&(ctx.now / 1000).to_le_bytes());
            frame[22..24].copy_from_slice(&(*sequence << 4).to_le_bytes());
            *sequence = sequence.wrapping_add(1) & 0xfff;
            self.wifi.tx.push_back(WifiFrame {
                band,
                frequency,
                frame,
                station: None,
                rate_index: 0,
                aggregate: false,
            });
        }
    }

    /// Deliver a management or data frame to an enabled, tuned radio and owned RXD.
    /// The result means DMA delivery; multicast delivery must not become an ACK.
    pub fn wifi_rx(
        &mut self,
        ctx: &mut MachineContext<'_>,
        info: WifiRxInfo,
        frame: &[u8],
    ) -> bool {
        let band = info.band;
        let b = usize::from(band);
        if b >= 2 || !self.wifi.online[b] || !wireless_frame(frame) {
            return false;
        }
        let Some(channel) = self.wifi_startup.channel(b) else {
            return false;
        };
        if frequency(channel) != Some(info.frequency) {
            return false;
        }
        let Some(own) = self.wifi_startup.own_mac(band, &frame[4..10]) else {
            return false;
        };
        if let Some(header) = wifi_frame::data_header(frame) {
            return self.wifi_rx_data(ctx, channel, own, info, frame, header);
        }
        let mut management_frame = frame.to_vec();
        let mut station_id = 1023u16;
        let mut security = 0;
        let mut replay = None;
        if frame[1] & 0x40 != 0 {
            let Some(station) = self.wifi_startup.station_for_peer(band, &frame[10..16]) else {
                return false;
            };
            let key_id = frame.get(27).map(|value| value >> 6);
            let Some((key, (key_id, pn, plain))) = self
                .wifi_startup
                .data_keys(station.id, key_id)
                .into_iter()
                .find_map(|key| decrypt_key(frame, &key).map(|plain| (key, plain)))
            else {
                self.wifi.stats.entry(station.id).or_default().failed += 1;
                return false;
            };
            if self
                .wifi
                .rx_pn
                .get(&(station.id, key.cipher_id, key_id, 0))
                .is_some_and(|old| pn <= *old)
            {
                self.wifi.stats.entry(station.id).or_default().failed += 1;
                return false;
            }
            management_frame.truncate(24);
            management_frame[1] &= !0x40;
            management_frame.extend_from_slice(&plain);
            station_id = station.id;
            security = u32::from(key.cipher_id) << 16 | 1 << 31;
            replay = Some((station.id, key.cipher_id, key_id, pn));
        }
        // mtf_trans_rxd_into_rxblk @ 0x61c678: RXD24 + group3(8) + MAC frame.
        let mut packet = vec![0; 32 + management_frame.len()];
        let length = u32::try_from(packet.len()).unwrap_or(0);
        packet[..4].copy_from_slice(&((2 << 27) | length).to_le_bytes());
        packet[4..8].copy_from_slice(
            &(u32::from(station_id) | (1 << 13) | security | (u32::from(band) << 28)).to_le_bytes(),
        );
        packet[8..12]
            .copy_from_slice(&(u32::from(own) | (12 << 8) | (1 << 29) | (1 << 30)).to_le_bytes());
        packet[13] = channel;
        packet[14] = if frame[4..10] == [255; 6] {
            3
        } else if frame[4] & 1 != 0 {
            2
        } else {
            1
        };
        let rcpi = u8::try_from((info.signal_dbm.clamp(-110, 0) + 110) * 2).unwrap_or(0);
        packet[24..28].copy_from_slice(&u32::from(info.rate_index).to_le_bytes());
        packet[28..32].fill(rcpi);
        packet[32..].copy_from_slice(&management_frame);
        let posted = self.wifi_post(ctx, 4 + band, &packet);
        if posted && let Some((station, cipher, key_id, pn)) = replay {
            self.wifi.rx_pn.insert((station, cipher, key_id, 0), pn);
        }
        posted
    }

    fn wifi_rx_data(
        &mut self,
        ctx: &mut MachineContext<'_>,
        channel: u8,
        own: u8,
        info: WifiRxInfo,
        frame: &[u8],
        header: wifi_frame::DataHeader,
    ) -> bool {
        let Some(station) = self
            .wifi_startup
            .station_for_peer(info.band, &header.transmitter)
        else {
            return false;
        };
        let (plain, replay) = if header.protected {
            let key_id = frame.get(header.length + 3).map(|value| value >> 6);
            let Some((key, (key_id, pn, plain))) = self
                .wifi_startup
                .data_keys(station.id, key_id)
                .into_iter()
                .find_map(|key| decrypt_key(frame, &key).map(|plain| (key, plain)))
            else {
                self.wifi.stats.entry(station.id).or_default().failed += 1;
                return false;
            };
            if self
                .wifi
                .rx_pn
                .get(&(station.id, key.cipher_id, key_id, header.priority))
                .is_some_and(|old| pn <= *old)
            {
                self.wifi.stats.entry(station.id).or_default().failed += 1;
                return false;
            }
            (plain, Some((key.cipher_id, key_id, pn)))
        } else {
            (frame[header.length..].to_vec(), None)
        };
        let Some(ethernet) = wifi_frame::ethernet(frame, &plain) else {
            self.wifi.stats.entry(station.id).or_default().failed += 1;
            return false;
        };
        // RXD24, group4 (original 802.11 header fields), group3 (RSSI), then
        // the Ethernet frame produced by hardware header translation.
        let mut packet = vec![0; 48 + ethernet.len()];
        let length = u32::try_from(packet.len()).unwrap_or(0);
        packet[..4].copy_from_slice(&((2 << 27) | length).to_le_bytes());
        let security = if let Some((cipher, _, _)) = replay {
            u32::from(cipher) << 16 | 1 << 31
        } else {
            0
        };
        packet[4..8].copy_from_slice(
            &(u32::from(station.id)
                | (1 << 13)
                | (1 << 14)
                | security
                | (u32::from(info.band) << 28))
                .to_le_bytes(),
        );
        packet[8..12].copy_from_slice(
            &(u32::from(own)
                | (u32::try_from(header.length / 2).unwrap_or(0) << 8)
                | (1 << 13)
                | (u32::from(header.priority) << 16)
                | (u32::from(!info.aggregate) << 30))
                .to_le_bytes(),
        );
        packet[13] = channel;
        packet[14] = if frame[4] & 1 != 0 { 2 } else { 1 };
        packet[24..26].copy_from_slice(&frame[..2]);
        packet[26..32].copy_from_slice(&header.transmitter);
        packet[32..34].copy_from_slice(&header.sequence.to_le_bytes());
        let rcpi = u8::try_from((info.signal_dbm.clamp(-110, 0) + 110) * 2).unwrap_or(0);
        packet[40..44].copy_from_slice(&u32::from(info.rate_index).to_le_bytes());
        packet[44..48].fill(rcpi);
        packet[48..].copy_from_slice(&ethernet);
        if !self.wifi_post(ctx, 4 + info.band, &packet) {
            self.wifi.stats.entry(station.id).or_default().failed += 1;
            return false;
        }
        if let Some((cipher, key_id, pn)) = replay {
            self.wifi
                .rx_pn
                .insert((station.id, cipher, key_id, header.priority), pn);
        }
        let stats = self.wifi.stats.entry(station.id).or_default();
        stats.rx_packets += 1;
        stats.rx_bytes += u64::try_from(ethernet.len()).unwrap_or(0);
        stats.signal_dbm = info.signal_dbm;
        stats.rate_index = info.rate_index;
        stats.rx_aggregated += u64::from(info.aggregate);
        true
    }

    fn wifi_post(&mut self, ctx: &mut MachineContext<'_>, ring: u8, packet: &[u8]) -> bool {
        let regs = 0x1802_4500 + u64::from(ring) * 16;
        let base = self.control_regs.get(&regs).copied().unwrap_or(0);
        let count = self.control_regs.get(&(regs + 4)).copied().unwrap_or(0);
        let index = self.control_regs.get(&(regs + 12)).copied().unwrap_or(0);
        if base == 0 || !(1..=4096).contains(&count) || index >= count {
            return false;
        }
        let descriptor = u64::from(base) + u64::from(index) * 16;
        let Some(desc) = Self::dma_read(ctx, descriptor, 8) else {
            return false;
        };
        let buffer = Self::word(&desc, 0).unwrap_or(0);
        let control = Self::word(&desc, 4).unwrap_or(0);
        let Ok(length) = u32::try_from(packet.len()) else {
            return false;
        };
        if buffer == 0 || control & (1 << 31) != 0 || (control >> 16) & 0x3fff < length {
            return false;
        }
        if !Self::dma_write(ctx, u64::from(buffer), packet)
            || !Self::dma_write(
                ctx,
                descriptor + 4,
                &((control & 0xffff) | 0xc000_0000 | (length << 16)).to_le_bytes(),
            )
        {
            return false;
        }
        self.control_regs.insert(regs + 12, (index + 1) % count);
        // MT7981 ISR @ 0x605a88: low four event bits, data bits 22/23.
        let bit = if ring < 4 { ring } else { ring + 18 };
        *self.control_regs.entry(WFDMA0_INT_SOURCE).or_default() |= 1 << bit;
        self.update_wifi_irq(ctx);
        true
    }

    pub(super) fn wifi_kick(&mut self, ctx: &mut MachineContext<'_>, ring: usize, target: u32) {
        self.wifi.targets[ring - 2] = Some(target);
        self.wifi_drain_tx(ctx, ring, target);
        self.wifi_reclaim(ctx);
    }

    fn wifi_prepare_tx(&mut self, tx: &mut DecodedTx) -> Option<usize> {
        let ethernet_length = tx.ethernet.then_some(tx.frame.len());
        let mut rejected = false;
        if tx.ethernet {
            let destination: Option<[u8; 6]> =
                tx.frame.get(..6).and_then(|value| value.try_into().ok());
            if destination.is_some_and(|mac| mac[0] & 1 != 0) {
                if let Some(bssid) = self.wifi_startup.bssid_for_own(tx.band, tx.own) {
                    tx.frame = wifi_frame::from_ethernet(
                        &tx.frame,
                        bssid,
                        destination.expect("multicast address was checked above"),
                        0,
                    )
                    .unwrap_or_default();
                } else {
                    tx.frame.clear();
                }
            } else if let Some(id) = tx.station {
                if let Some(config) = self.wifi_startup.station(id) {
                    let sequence = self.wifi.sequences.entry(id).or_default();
                    tx.frame =
                        wifi_frame::from_ethernet(&tx.frame, config.bssid, config.peer, *sequence)
                            .unwrap_or_default();
                    *sequence = sequence.wrapping_add(1) & 0xfff;
                } else {
                    rejected = true;
                    tx.frame.clear();
                }
            } else {
                tx.frame.clear();
            }
            rejected |= tx.frame.is_empty();
        }
        if let Some(id) = tx.station {
            if tx.protected {
                if let Some(key) = self.wifi_startup.data_keys(id, None).into_iter().next() {
                    if !tx.frame.is_empty() {
                        let pn = self
                            .wifi
                            .tx_pn
                            .entry((id, key.cipher_id, key.id))
                            .or_insert(0);
                        *pn += 1;
                        if tx.frame.len() >= 2 {
                            tx.frame[1] &= !0x40;
                        }
                        tx.frame = encrypt_key(&tx.frame, &key, *pn).unwrap_or_default();
                    }
                } else {
                    rejected = true;
                    tx.frame.clear();
                }
            }
            rejected |= tx.frame.is_empty();
            if rejected {
                self.wifi.stats.entry(id).or_default().failed += 1;
            }
        }
        ethernet_length
    }

    fn wifi_drain_tx(&mut self, ctx: &mut MachineContext<'_>, ring: usize, target: u32) {
        let count = self.wfdma_tx_count[ring];
        if !(1..=4096).contains(&count) || self.wfdma_tx_base[ring] == 0 {
            return;
        }
        while self.wfdma_tx_didx[ring] != target % count {
            if self.wifi.tx.len() >= LIMIT || self.wifi.tokens.len() >= LIMIT {
                break;
            }
            let index = self.wfdma_tx_didx[ring];
            let addr = u64::from(self.wfdma_tx_base[ring]) + u64::from(index) * 16;
            let Some(desc) = Self::dma_read(ctx, addr, 16) else {
                break;
            };
            let control = Self::word(&desc, 4).unwrap_or(0);
            if control & (1 << 31) != 0 {
                break;
            }
            let length = ((control >> 16) & 0x3fff) as usize;
            // Cut-through path: TMAC32 plus the 44-byte WA TXP scatter list.
            if length != 76 {
                break;
            }
            let Some(header) =
                Self::dma_read(ctx, u64::from(Self::word(&desc, 0).unwrap_or(0)), length)
            else {
                break;
            };
            let Some(mut tx) = Self::wifi_decode_ct(ctx, &header) else {
                break;
            };
            let ethernet_length = self.wifi_prepare_tx(&mut tx);
            if !Self::dma_write(ctx, addr + 4, &(control | (1 << 31)).to_le_bytes()) {
                break;
            }
            self.wfdma_tx_didx[ring] = (index + 1) % count;
            self.wifi.tokens.push_back((tx.band, tx.token));
            if self.wifi.online[usize::from(tx.band)]
                && !tx.frame.is_empty()
                && let Some(frequency) = self
                    .wifi_startup
                    .channel(usize::from(tx.band))
                    .and_then(frequency)
            {
                self.wifi.tx.push_back(WifiFrame {
                    band: tx.band,
                    frequency,
                    frame: tx.frame,
                    station: tx.station,
                    rate_index: tx.rate_index,
                    aggregate: tx.aggregate,
                });
                if let (Some(id), Some(ethernet_length)) = (tx.station, ethernet_length) {
                    let stats = self.wifi.stats.entry(id).or_default();
                    stats.tx_packets += 1;
                    stats.tx_bytes += u64::try_from(ethernet_length).unwrap_or(0);
                    stats.rate_index = tx.rate_index;
                    stats.tx_aggregated += u64::from(tx.aggregate);
                }
            }
        }
        if self.wfdma_tx_didx[ring] == target % count {
            self.wifi.targets[ring - 2] = None;
        }
    }

    fn wifi_decode_ct(ctx: &mut MachineContext<'_>, h: &[u8]) -> Option<DecodedTx> {
        let h = h.get(..76)?;
        let dw1 = Self::word(h, 4)?;
        let format = (dw1 >> 16) & 3;
        if format > 2 || h[32] & 0x84 == 0 || !(1..=6).contains(&h[39]) {
            return None;
        }
        let token = u16::from_le_bytes([h[34], h[35]]);
        if token >= 0x7fff {
            return None;
        }
        let mut frame = Vec::new();
        for i in 0..usize::from(h[39]) {
            let length = usize::from(u16::from_le_bytes([h[64 + i * 2], h[65 + i * 2]]));
            if length == 0 || length > 4095 || frame.len() + length > 2304 {
                return None;
            }
            frame.extend(Self::dma_read(
                ctx,
                u64::from(Self::word(h, 40 + i * 4)?),
                length,
            )?);
        }
        let ethernet = format == 0;
        if !(ethernet && (14..=2304).contains(&frame.len()) || !ethernet && wireless_frame(&frame))
        {
            return None;
        }
        // Fixed-rate TMAC encodes physical band in bit 30, independent of BSS ID.
        let id = (dw1 & 0x3ff) as u16;
        let own = ((dw1 >> 24) & 0x3f) as u8;
        let protected = Self::word(h, 12)? & 2 != 0;
        let station = (ethernet || protected && id != 0x3ff).then_some(id);
        let rate_index = u8::try_from((Self::word(h, 24)? >> 16) & 0x3f).ok()?;
        let aggregate = dw1 & (1 << 23) != 0 || Self::word(h, 28)? & (1 << 10) != 0;
        Some(DecodedTx {
            band: u8::try_from((dw1 >> 30) & 1).ok()?,
            token,
            station,
            own,
            ethernet,
            frame,
            protected,
            rate_index,
            aggregate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use board_core::{
        Machine,
        dma::{DmaBus, TransferStatus},
    };

    struct Memory {
        bytes: Vec<u8>,
        fail_write: Option<u64>,
    }

    fn configure_station(board: &mut Mt7981Board, peer: [u8; 6]) {
        assert_eq!(
            board.wifi_startup.command(0x46, &[1, 0, 0, 0]).unwrap().1[4],
            0
        );
        let mut power = [0; 32];
        power[..2].copy_from_slice(&[5, 2]);
        assert_eq!(board.wifi_startup.command(0x07, &power).unwrap().1[4], 0);
        let mut channel = [0; 76];
        channel[..7].copy_from_slice(&[6, 6, 0, 1, 1, 0, 0]);
        assert_eq!(board.wifi_startup.command(0x08, &channel).unwrap().1[4], 0);

        let bssid = [2, 0, 0, 0x79, 0x81, 2];
        let mut device = vec![14, 0, 1, 0, 1, 0, 0, 0, 0, 0, 12, 0, 1, 0];
        device.extend_from_slice(&bssid);
        assert_eq!(board.wifi_startup.command(0x2a, &device).unwrap().1[4], 0);
        let mut bss = vec![3, 0, 2, 0, 1, 0, 0, 0];
        let mut omac = vec![0, 0, 16, 0, 0, 14, 0, 0];
        omac.resize(16, 0);
        let mut basic = vec![1, 0, 28, 0, 0, 0, 0, 0, 1, 0, 100, 0];
        basic.extend_from_slice(&bssid);
        basic.resize(28, 0);
        bss.extend(omac);
        bss.extend(basic);
        assert_eq!(board.wifi_startup.command(0x26, &bss).unwrap().1[4], 0);
        let mut station = vec![3, 1, 1, 0, 1, 14, 0, 0];
        let mut station_basic = vec![0, 0, 20, 0, 0, 0, 0, 0, 2, 0, 0, 0];
        station_basic.extend_from_slice(&peer);
        station_basic.extend_from_slice(&2u16.to_le_bytes());
        station.extend(station_basic);
        assert_eq!(board.wifi_startup.command(0x25, &station).unwrap().1[4], 0);
        assert!(board.wifi_startup.station(1).is_some());
    }

    fn install_key(board: &mut Mt7981Board, cipher: u8, key: &[u8]) {
        let mut command = vec![
            1,
            2,
            1,
            0,
            0,
            0,
            0,
            0,
            17,
            0,
            44,
            0,
            0,
            1,
            0,
            0,
            cipher,
            36,
            0,
            u8::try_from(key.len()).unwrap(),
        ];
        command.extend_from_slice(key);
        command.resize(52, 0);
        assert_eq!(board.wifi_startup.command(0x32, &command).unwrap().1[4], 0);
    }

    fn install_ccmp_key(board: &mut Mt7981Board, key: [u8; 16]) {
        install_key(board, 4, &key);
    }
    impl DmaBus for Memory {
        fn read(&mut self, address: u64, out: &mut [u8]) -> TransferStatus {
            let start = usize::try_from(address).unwrap();
            let Some(data) = self.bytes.get(start..start + out.len()) else {
                return TransferStatus::Failed;
            };
            out.copy_from_slice(data);
            TransferStatus::Complete
        }
        fn write(&mut self, address: u64, data: &[u8]) -> TransferStatus {
            if self.fail_write == Some(address) {
                return TransferStatus::Failed;
            }
            let start = usize::try_from(address).unwrap();
            let Some(out) = self.bytes.get_mut(start..start + data.len()) else {
                return TransferStatus::Failed;
            };
            out.copy_from_slice(data);
            TransferStatus::Complete
        }
    }

    #[test]
    fn payload_and_descriptor_dma_failures_do_not_publish_rx() {
        for failed in [0x2000, 0x1004] {
            let mut board = Mt7981Board::new();
            let mut memory = Memory {
                bytes: vec![0; 0x4000],
                fail_write: Some(failed),
            };
            board.control_regs.insert(0x1802_4540, 0x1000);
            board.control_regs.insert(0x1802_4544, 2);
            memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
            memory.bytes[0x1004..0x1008].copy_from_slice(&(256u32 << 16).to_le_bytes());
            let mut ctx = MachineContext::with_dma(0, &mut memory);
            assert!(!board.wifi_post(&mut ctx, 4, &[7; 56]));
            assert!(ctx.events.is_empty());
            assert_eq!(board.mmio_read(0x1802_454c), 0);
            assert_eq!(board.mmio_read(WFDMA0_INT_SOURCE), 0);
        }
    }

    #[test]
    fn reset_clears_radio_queues_tokens_targets_and_rx_dma_addresses() {
        let mut board = Mt7981Board::new();
        board.wifi_online([true; 2]);
        board.wifi.tokens.push_back((0, 1));
        board.wifi.targets[0] = Some(1);
        board.wifi.beacons.insert(0, (100, 1));
        board.wifi.tx.push_back(WifiFrame {
            band: 0,
            frequency: 2412,
            frame: vec![0; 24],
            station: None,
            rate_index: 0,
            aggregate: false,
        });
        board.mmio_write(0x1802_4540, 0x1000);
        board.reset(&mut MachineContext::new(0));
        assert_eq!(board.wifi.online, [false; 2]);
        assert!(board.wifi.tokens.is_empty());
        assert!(board.wifi.beacons.is_empty());
        assert!(board.wifi.tx.is_empty());
        assert_eq!(board.wifi.targets, [None; 2]);
        assert_eq!(board.mmio_read(0x1802_4540), 0);
    }

    #[test]
    fn disconnect_discards_frames_and_stops_beacon_schedule() {
        let mut board = Mt7981Board::new();
        board.wifi.beacons.insert(0, (100, 1));
        board.wifi.tx.push_back(WifiFrame {
            band: 0,
            frequency: 2412,
            frame: vec![0; 24],
            station: None,
            rate_index: 0,
            aggregate: false,
        });
        board.wifi_online([false; 2]);
        assert!(board.wifi_take_tx().is_none());
        assert!(board.wifi.beacons.is_empty());
    }

    #[test]
    fn only_complete_unencrypted_management_frames_are_supported() {
        let mut frame = [0; 24];
        assert!(management(&frame));
        for flag in [1, 2, 4, 0x40, 0x80] {
            frame[1] = flag;
            assert!(!management(&frame));
        }
        frame[1] = 0;
        frame[0] = 8; // Data frames need offload/key/station handling.
        assert!(!management(&frame));
        frame[0] = 0;
        frame[22] = 1;
        assert!(!management(&frame));
        assert!(!management(&frame[..23]));
    }

    #[test]
    fn queue_backpressure_retains_doorbell_and_resumes_after_drain() {
        let mut board = Mt7981Board::new();
        let mut memory = Memory {
            bytes: vec![0; 0x5000],
            fail_write: None,
        };
        let word = |bytes: &mut [u8], offset: usize, value: u32| {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        word(&mut memory.bytes, 0x1000, 0x2000);
        word(&mut memory.bytes, 0x1004, 76 << 16);
        word(&mut memory.bytes, 0x2004, 1 << 16);
        memory.bytes[0x2020] = 4;
        memory.bytes[0x2027] = 1;
        word(&mut memory.bytes, 0x2028, 0x3000);
        memory.bytes[0x2040] = 24;
        board.wfdma_tx_base[2] = 0x1000;
        board.wfdma_tx_count[2] = 2;
        board.wifi.tokens.extend((0..256).map(|token| (0, token)));
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        board.wifi_kick(&mut ctx, 2, 1);
        assert_eq!(board.wfdma_tx_didx[2], 0);
        assert_eq!(board.wifi.targets[0], Some(1));
        board.wifi.tokens.clear();
        board.wifi_poll(&mut ctx);
        assert_eq!(board.wfdma_tx_didx[2], 1);
        assert_eq!(board.wifi.targets[0], None);
        assert_eq!(board.wifi.tokens.len(), 1);
    }

    #[test]
    fn vendor_raw_80211_header_format_two_does_not_stall_the_ring() {
        let mut board = Mt7981Board::new();
        let mut memory = Memory {
            bytes: vec![0; 0x5000],
            fail_write: None,
        };
        let frame = [
            0x50, 0, 0, 0, 2, 0, 0, 0, 1, 0, 2, 0, 0, 0, 2, 0, 2, 0, 0, 0, 1, 0, 0, 0,
        ];
        memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
        memory.bytes[0x1004..0x1008].copy_from_slice(&(76u32 << 16).to_le_bytes());
        memory.bytes[0x2004..0x2008].copy_from_slice(&(2u32 << 16).to_le_bytes());
        memory.bytes[0x2020] = 4;
        memory.bytes[0x2022..0x2024].copy_from_slice(&42u16.to_le_bytes());
        memory.bytes[0x2027] = 1;
        memory.bytes[0x2028..0x202c].copy_from_slice(&0x3000u32.to_le_bytes());
        memory.bytes[0x2040..0x2042]
            .copy_from_slice(&u16::try_from(frame.len()).unwrap().to_le_bytes());
        memory.bytes[0x3000..0x3000 + frame.len()].copy_from_slice(&frame);
        board.wfdma_tx_base[2] = 0x1000;
        board.wfdma_tx_count[2] = 2;
        board.wifi_online([true, false]);
        // Radio setup is irrelevant to descriptor consumption; it only gates emission.
        board.wifi_kick(&mut MachineContext::with_dma(0, &mut memory), 2, 1);
        assert_eq!(board.wfdma_tx_didx[2], 1);
        assert_eq!(board.wifi.tokens.front(), Some(&(0, 42)));
    }

    #[test]
    fn station_data_rx_is_header_translated_and_accounted() {
        let mut board = Mt7981Board::new();
        let peer = [2, 0, 0, 0, 1, 0];
        configure_station(&mut board, peer);
        board.wifi_online([true, false]);
        let mut memory = Memory {
            bytes: vec![0; 0x5000],
            fail_write: None,
        };
        board.control_regs.insert(0x1802_4540, 0x1000);
        board.control_regs.insert(0x1802_4544, 2);
        memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
        memory.bytes[0x1004..0x1008].copy_from_slice(&(4096u32 << 16).to_le_bytes());
        let bssid = [2, 0, 0, 0x79, 0x81, 2];
        let destination = [2, 0, 0, 0, 2, 0];
        let mut frame = vec![0x08, 0x01, 0, 0];
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&destination);
        frame.extend_from_slice(&0x30u16.to_le_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 0x45]);
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(board.wifi_rx(
            &mut ctx,
            WifiRxInfo {
                band: 0,
                frequency: 2437,
                signal_dbm: -55,
                rate_index: 3,
                aggregate: true
            },
            &frame
        ));
        assert_eq!(&memory.bytes[0x2030..0x203c], &[destination, peer].concat());
        assert_eq!(&memory.bytes[0x203c..0x203f], &[0x08, 0x00, 0x45]);
        assert_ne!(
            u32::from_le_bytes(memory.bytes[0x2008..0x200c].try_into().unwrap()) & (1 << 13),
            0
        );
        assert_eq!(board.wifi_station_stats(1).unwrap().rx_packets, 1);
        assert_eq!(board.wifi_station_stats(1).unwrap().signal_dbm, -55);
        assert_eq!(board.wifi_station_stats(1).unwrap().rate_index, 3);
        assert_eq!(board.wifi_station_stats(1).unwrap().rx_aggregated, 1);
        assert_eq!(
            u32::from_le_bytes(memory.bytes[0x2028..0x202c].try_into().unwrap()),
            3
        );
        assert_eq!(
            u32::from_le_bytes(memory.bytes[0x2008..0x200c].try_into().unwrap()) >> 30 & 1,
            0
        );
    }

    #[test]
    fn ethernet_cut_through_tx_becomes_from_ds_wireless_data() {
        let mut board = Mt7981Board::new();
        let peer = [2, 0, 0, 0, 1, 0];
        configure_station(&mut board, peer);
        board.wifi_online([true, false]);
        let mut memory = Memory {
            bytes: vec![0; 0x6000],
            fail_write: None,
        };
        let ethernet = [peer.as_slice(), &[2, 0, 0, 0, 2, 0, 0x08, 0x00, 0x45]].concat();
        memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
        memory.bytes[0x1004..0x1008].copy_from_slice(&(76u32 << 16).to_le_bytes());
        memory.bytes[0x2004..0x2008].copy_from_slice(&1u32.to_le_bytes());
        memory.bytes[0x2020] = 4;
        memory.bytes[0x2027] = 1;
        memory.bytes[0x2028..0x202c].copy_from_slice(&0x3000u32.to_le_bytes());
        memory.bytes[0x2040..0x2042]
            .copy_from_slice(&u16::try_from(ethernet.len()).unwrap().to_le_bytes());
        memory.bytes[0x3000..0x3000 + ethernet.len()].copy_from_slice(&ethernet);
        board.wfdma_tx_base[2] = 0x1000;
        board.wfdma_tx_count[2] = 2;
        board.wifi_kick(&mut MachineContext::with_dma(0, &mut memory), 2, 1);
        let frame = board.wifi_take_tx().unwrap().frame;
        assert_eq!(&frame[..2], &[0x08, 0x02]);
        assert_eq!(&frame[4..10], &peer);
        assert_eq!(
            wifi_frame::ethernet(&frame, &frame[24..]).unwrap(),
            ethernet
        );
        assert_eq!(board.wifi_station_stats(1).unwrap().tx_packets, 1);
        board.wifi_tx_result(Some(1), true);
        board.wifi_tx_result(Some(1), false);
        let stats = board.wifi_station_stats(1).unwrap();
        assert_eq!(stats.tx_accepted, 1);
        assert_eq!(stats.tx_rejected, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn multicast_ethernet_uses_own_mac_bss_and_fw_txp_flag() {
        let mut board = Mt7981Board::new();
        configure_station(&mut board, [2, 0, 0, 0, 1, 0]);
        board.wifi_online([true, false]);
        let mut memory = Memory {
            bytes: vec![0; 0x6000],
            fail_write: None,
        };
        let destination = [1, 0x80, 0xc2, 0, 0, 0x0e];
        let ethernet = [
            destination.as_slice(),
            &[2, 0, 0, 0x79, 0x81, 2, 0x88, 0xcc, 2, 7],
        ]
        .concat();
        memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
        memory.bytes[0x1004..0x1008].copy_from_slice(&(76u32 << 16).to_le_bytes());
        memory.bytes[0x2004..0x2008].copy_from_slice(&(14u32 << 24).to_le_bytes());
        memory.bytes[0x2020] = 0x80;
        memory.bytes[0x2027] = 1;
        memory.bytes[0x2028..0x202c].copy_from_slice(&0x3000u32.to_le_bytes());
        memory.bytes[0x2040..0x2042]
            .copy_from_slice(&u16::try_from(ethernet.len()).unwrap().to_le_bytes());
        memory.bytes[0x3000..0x3000 + ethernet.len()].copy_from_slice(&ethernet);
        board.wfdma_tx_base[2] = 0x1000;
        board.wfdma_tx_count[2] = 2;
        board.wifi_kick(&mut MachineContext::with_dma(0, &mut memory), 2, 1);
        let frame = board.wifi_take_tx().unwrap().frame;
        assert_eq!(&frame[4..10], &destination);
        assert_eq!(&frame[10..16], &[2, 0, 0, 0x79, 0x81, 2]);
        assert_eq!(board.wfdma_tx_didx[2], 1);
    }

    #[test]
    fn ccmp_rx_uses_wtbl_key_and_rejects_replay() {
        let mut board = Mt7981Board::new();
        let peer = [2, 0, 0, 0, 1, 0];
        let bssid = [2, 0, 0, 0x79, 0x81, 2];
        let key = [0x5a; 16];
        configure_station(&mut board, peer);
        install_ccmp_key(&mut board, key);
        board.wifi_online([true, false]);
        let mut memory = Memory {
            bytes: vec![0; 0x6000],
            fail_write: None,
        };
        board.control_regs.insert(0x1802_4540, 0x1000);
        board.control_regs.insert(0x1802_4544, 2);
        for index in 0..2 {
            let descriptor = 0x1000 + index * 16;
            memory.bytes[descriptor..descriptor + 4]
                .copy_from_slice(&(0x2000 + u32::try_from(index).unwrap() * 0x1000).to_le_bytes());
            memory.bytes[descriptor + 4..descriptor + 8]
                .copy_from_slice(&(4096u32 << 16).to_le_bytes());
        }
        let destination = [2, 0, 0, 0, 2, 0];
        let mut frame = vec![0x08, 0x01, 0, 0];
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&peer);
        frame.extend_from_slice(&destination);
        frame.extend_from_slice(&0x10u16.to_le_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 0x45]);
        let protected = wifi_frame::encrypt_ccmp(&frame, &key, 0, 9).unwrap();
        let info = WifiRxInfo {
            band: 0,
            frequency: 2437,
            signal_dbm: -42,
            rate_index: 4,
            aggregate: false,
        };
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(board.wifi_rx(&mut ctx, info, &protected));
        assert!(!board.wifi_rx(&mut ctx, info, &protected));
        assert_eq!(
            (u32::from_le_bytes(memory.bytes[0x2004..0x2008].try_into().unwrap()) >> 16) & 0x1f,
            4
        );
        assert_eq!(board.wifi_station_stats(1).unwrap().failed, 1);
    }

    #[test]
    fn wtbl_legacy_gcmp_and_256_bit_ciphers_reach_the_rx_datapath() {
        for (cipher, material) in [
            (1, vec![0x11; 5]),
            (5, vec![0x22; 13]),
            (7, vec![0x27; 16]),
            (2, {
                let mut key = vec![0x33; 32];
                key[24..32].copy_from_slice(&[0x33; 8]);
                key
            }),
            (10, vec![0x55; 32]),
            (11, vec![0x66; 16]),
            (12, vec![0x77; 32]),
        ] {
            let mut board = Mt7981Board::new();
            let peer = [2, 0, 0, 0, 1, 0];
            let bssid = [2, 0, 0, 0x79, 0x81, 2];
            configure_station(&mut board, peer);
            install_key(&mut board, cipher, &material);
            board.wifi_online([true, false]);
            let mut memory = Memory {
                bytes: vec![0; 0x4000],
                fail_write: None,
            };
            board.control_regs.insert(0x1802_4540, 0x1000);
            board.control_regs.insert(0x1802_4544, 1);
            memory.bytes[0x1000..0x1004].copy_from_slice(&0x2000u32.to_le_bytes());
            memory.bytes[0x1004..0x1008].copy_from_slice(&(4096u32 << 16).to_le_bytes());
            let mut frame = vec![0x08, 0x01, 0, 0];
            frame.extend_from_slice(&bssid);
            frame.extend_from_slice(&peer);
            frame.extend_from_slice(&[2, 0, 0, 0, 2, 0]);
            frame.extend_from_slice(&0x10u16.to_le_bytes());
            frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0, 0x45]);
            let key = board.wifi_startup.data_keys(1, Some(0)).remove(0);
            let protected = encrypt_key(&frame, &key, 9).unwrap();
            let info = WifiRxInfo {
                band: 0,
                frequency: 2437,
                signal_dbm: -42,
                rate_index: 4,
                aggregate: false,
            };
            assert!(board.wifi_rx(
                &mut MachineContext::with_dma(0, &mut memory),
                info,
                &protected
            ));
            let rxd = u32::from_le_bytes(memory.bytes[0x2004..0x2008].try_into().unwrap());
            assert_eq!((rxd >> 16) & 0x1f, u32::from(cipher));
        }
    }

    #[test]
    fn wpa3_protected_management_uses_pairwise_key_and_replay_window() {
        let mut board = Mt7981Board::new();
        let peer = [2, 0, 0, 0, 1, 0];
        let bssid = [2, 0, 0, 0x79, 0x81, 2];
        let key = [0x6b; 16];
        configure_station(&mut board, peer);
        install_ccmp_key(&mut board, key);
        board.wifi_online([true, false]);
        let mut memory = Memory {
            bytes: vec![0; 0x6000],
            fail_write: None,
        };
        board.control_regs.insert(0x1802_4540, 0x1000);
        board.control_regs.insert(0x1802_4544, 2);
        for index in 0..2 {
            let descriptor = 0x1000 + index * 16;
            memory.bytes[descriptor..descriptor + 4]
                .copy_from_slice(&(0x2000 + u32::try_from(index).unwrap() * 0x1000).to_le_bytes());
            memory.bytes[descriptor + 4..descriptor + 8]
                .copy_from_slice(&(4096u32 << 16).to_le_bytes());
        }
        let mut deauth = vec![0xc0, 0, 0, 0];
        deauth.extend_from_slice(&bssid);
        deauth.extend_from_slice(&peer);
        deauth.extend_from_slice(&bssid);
        deauth.extend_from_slice(&0x10u16.to_le_bytes());
        deauth.extend_from_slice(&[6, 0]);
        let protected = wifi_frame::encrypt_ccmp(&deauth, &key, 0, 11).unwrap();
        let info = WifiRxInfo {
            band: 0,
            frequency: 2437,
            signal_dbm: -48,
            rate_index: 2,
            aggregate: false,
        };
        let mut ctx = MachineContext::with_dma(0, &mut memory);
        assert!(board.wifi_rx(&mut ctx, info, &protected));
        assert!(!board.wifi_rx(&mut ctx, info, &protected));
        assert_eq!(&memory.bytes[0x2020..0x2020 + deauth.len()], &deauth);
        let rxd = u32::from_le_bytes(memory.bytes[0x2004..0x2008].try_into().unwrap());
        assert_eq!(rxd & 0x3ff, 1);
        assert_eq!(rxd >> 16 & 0x1f, 4);
    }
}
