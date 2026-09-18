//! Board-independent Ethernet checksum, segmentation and virtio-header engine.
//! Callers normalize hardware descriptors before submitting requests.

/// Maximum IPv6 packet plus Ethernet header and two VLAN tags.
pub const MAX_PACKET: usize = 65_597;
/// Complete the IPv4 header checksum.
pub const IP_CHECKSUM: u32 = 1;
/// Complete a TCP checksum.
pub const TCP_CHECKSUM: u32 = 2;
/// Complete a UDP checksum.
pub const UDP_CHECKSUM: u32 = 4;
/// Segment TCP using the explicit MSS.
pub const TSO: u32 = 8;
/// Insert an 802.1Q tag.
pub const VLAN: u32 = 16;
/// Backend supports partial checksums.
pub const CAP_CHECKSUM: u32 = 1;
/// Backend supports `TCPv4` GSO.
pub const CAP_TSO4: u32 = 2;
/// Backend supports `TCPv6` GSO.
pub const CAP_TSO6: u32 = 4;

/// Versioned C-compatible normalized request. Checksums are recomputed from
/// packet addresses; no caller-provided partial checksum seed is trusted.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// Must be 1.
    pub version: u32,
    /// Combination of the request flags above.
    pub flags: u32,
    /// Explicit TCP MSS, zero when TSO is absent.
    pub mss: u16,
    /// Tag control information when VLAN is present.
    pub vlan_tci: u16,
    /// Must be zero.
    pub reserved: u32,
}
impl Default for Request {
    fn default() -> Self {
        Self {
            version: 1,
            flags: 0,
            mss: 0,
            vlan_tci: 0,
            reserved: 0,
        }
    }
}
impl Request {
    /// Whether the request conforms to this ABI version.
    #[must_use]
    pub fn valid(self) -> bool {
        self.version == 1
            && self.reserved == 0
            && self.flags & !31 == 0
            && (self.flags & TSO != 0 || self.mss == 0)
    }
}

/// An owned packet with a little-endian, non-mergeable virtio network header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Ten-byte virtio network header, all zero for wire-ready packets.
    pub header: [u8; 10],
    /// Ethernet bytes following the header.
    pub bytes: Vec<u8>,
}
/// Result of packet preparation; fallback is visible to the transport counters.
#[derive(Debug)]
pub struct Batch {
    /// Prepared output packets.
    pub packets: Vec<Packet>,
    /// A valid request needed software completion despite a requested backend.
    pub fallback: bool,
}
/// Invalid packet or normalized request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPacket;

/// Locate a TCP checksum field for hardware adapters that encode MSS there.
#[must_use]
pub fn tcp_checksum_offset(frame: &[u8]) -> Option<usize> {
    let h = headers(frame)?;
    (h.protocol == 6 && !h.fragmented && h.end - h.transport >= 20).then_some(h.transport + 16)
}

#[derive(Clone, Copy)]
struct Headers {
    ip: usize,
    transport: usize,
    end: usize,
    protocol: u8,
    ipv6: bool,
    fragmented: bool,
}

fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn headers(frame: &[u8]) -> Option<Headers> {
    let mut kind = word(frame, 12)?;
    let mut ip = 14;
    for _ in 0..2 {
        if !matches!(kind, 0x8100 | 0x88a8) {
            break;
        }
        kind = word(frame, ip + 2)?;
        ip += 4;
    }
    match kind {
        0x0800 => {
            let first = *frame.get(ip)?;
            let size = usize::from(first & 15) * 4;
            let length = usize::from(word(frame, ip + 2)?);
            if first >> 4 != 4 || size < 20 || length < size {
                return None;
            }
            frame.get(ip..ip + length)?;
            Some(Headers {
                ip,
                transport: ip + size,
                end: ip + length,
                protocol: frame[ip + 9],
                ipv6: false,
                fragmented: word(frame, ip + 6)? & 0x3fff != 0,
            })
        }
        0x86dd => {
            if *frame.get(ip)? >> 4 != 6 {
                return None;
            }
            let end = ip + 40 + usize::from(word(frame, ip + 4)?);
            frame.get(ip..end)?;
            let mut protocol = frame[ip + 6];
            let mut transport = ip + 40;
            for _ in 0..8 {
                if !matches!(protocol, 0 | 43 | 60) {
                    break;
                }
                let next = *frame.get(transport)?;
                let length = (usize::from(*frame.get(transport + 1)?) + 1) * 8;
                if transport + length > end {
                    return None;
                }
                transport += length;
                protocol = next;
            }
            Some(Headers {
                ip,
                transport,
                end,
                protocol,
                ipv6: true,
                fragmented: protocol == 44,
            })
        }
        _ => None,
    }
}

fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) + u32::from(*p.get(1).unwrap_or(&0)))
        .sum()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "carry folding bounds the result to 16 bits"
)]
fn finish(mut value: u32) -> u16 {
    while value >> 16 != 0 {
        value = (value & 0xffff) + (value >> 16);
    }
    !(value as u16)
}

fn put(frame: &mut [u8], offset: usize, value: u16) {
    frame[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "IP lengths were validated as 16-bit fields"
)]
fn checksums(frame: &mut [u8], h: Headers, request: Request) -> Option<()> {
    if !h.ipv6 && request.flags & IP_CHECKSUM != 0 {
        put(frame, h.ip + 10, 0);
        put(frame, h.ip + 10, finish(sum(&frame[h.ip..h.transport])));
    }
    if h.fragmented {
        return Some(());
    }
    let (offset, minimum, bit) = match h.protocol {
        6 => (16, 20, TCP_CHECKSUM),
        17 => (6, 8, UDP_CHECKSUM),
        _ => return Some(()),
    };
    if request.flags & bit == 0 {
        return Some(());
    }
    if h.end - h.transport < minimum {
        return None;
    }
    let length = if h.protocol == 17 {
        let length = usize::from(word(frame, h.transport + 4)?);
        if length < 8 || length > h.end - h.transport {
            return None;
        }
        length
    } else {
        h.end - h.transport
    };
    put(frame, h.transport + offset, 0);
    let address_sum = if h.ipv6 {
        sum(&frame[h.ip + 8..h.ip + 40])
    } else {
        sum(&frame[h.ip + 12..h.ip + 20])
    };
    let checksum = finish(
        address_sum
            + length as u32
            + u32::from(h.protocol)
            + sum(&frame[h.transport..h.transport + length]),
    );
    put(
        frame,
        h.transport + offset,
        if h.protocol == 17 && checksum == 0 {
            0xffff
        } else {
            checksum
        },
    );
    Some(())
}

impl Request {
    /// Invalid offload requests are dropped, never emitted as malformed frames.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "IP lengths and segment count are bounded; VLAN TCI and IP ID intentionally wrap to 16 bits"
    )]
    #[must_use]
    pub fn frames(self, mut frame: Vec<u8>) -> Vec<Vec<u8>> {
        if !self.valid() || frame.len() > MAX_PACKET {
            return Vec::new();
        }
        if self.flags & VLAN != 0 {
            if frame.len() < 14 {
                return Vec::new();
            }
            let tci = self.vlan_tci.to_be_bytes();
            frame.splice(12..12, [0x81, 0, tci[0], tci[1]]);
        }
        if self.flags & (IP_CHECKSUM | TCP_CHECKSUM | UDP_CHECKSUM | TSO) == 0 {
            return vec![frame];
        }
        let Some(h) = headers(&frame) else {
            return Vec::new();
        };
        if self.flags & TSO == 0 {
            return if checksums(&mut frame, h, self).is_some() {
                vec![frame]
            } else {
                Vec::new()
            };
        }
        if h.fragmented || h.protocol != 6 || h.end - h.transport < 20 {
            return Vec::new();
        }
        let tcp_size = usize::from(frame[h.transport + 12] >> 4) * 4;
        let payload = h.transport + tcp_size;
        if tcp_size < 20 || payload > h.end {
            return Vec::new();
        }
        let Some(mss) = Some(self.mss).filter(|mss| *mss != 0) else {
            return Vec::new();
        };
        let sequence = u32::from_be_bytes(
            frame[h.transport + 4..h.transport + 8]
                .try_into()
                .unwrap_or_default(),
        );
        let id = word(&frame, h.ip + 4).unwrap_or_default();
        let mut result = Vec::new();
        let count = (h.end - payload).div_ceil(usize::from(mss)).max(1);
        // Bound amplification of corrupt descriptors/MSS values.
        if count > 2048 {
            return Vec::new();
        }
        for index in 0..count {
            let start = payload + index * usize::from(mss);
            let end = (start + usize::from(mss)).min(h.end);
            let mut segment = frame[..payload].to_vec();
            segment.extend_from_slice(&frame[start..end]);
            let size = segment.len();
            if h.ipv6 {
                put(&mut segment, h.ip + 4, (size - h.ip - 40) as u16);
            } else {
                put(&mut segment, h.ip + 2, (size - h.ip) as u16);
                put(&mut segment, h.ip + 4, id.wrapping_add(index as u16));
            }
            segment[h.transport + 4..h.transport + 8].copy_from_slice(
                &sequence
                    .wrapping_add((start - payload) as u32)
                    .to_be_bytes(),
            );
            if index + 1 != count {
                segment[h.transport + 13] &= !(0x01 | 0x08);
            }
            if index != 0 {
                segment[h.transport + 13] &= !0x80;
            }
            let sh = Headers { end: size, ..h };
            if checksums(
                &mut segment,
                sh,
                Request {
                    flags: IP_CHECKSUM | TCP_CHECKSUM | UDP_CHECKSUM,
                    ..Request::default()
                },
            )
            .is_none()
            {
                return Vec::new();
            }
            result.push(segment);
        }
        result
    }
}

fn software(request: Request, frame: Vec<u8>, capabilities: u32) -> Result<Batch, InvalidPacket> {
    let frames = request.frames(frame);
    if frames.is_empty() {
        return Err(InvalidPacket);
    }
    Ok(Batch {
        fallback: capabilities != 0 && request.flags != 0,
        packets: frames
            .into_iter()
            .map(|bytes| Packet {
                header: [0; 10],
                bytes,
            })
            .collect(),
    })
}

fn seed_checksum(
    frame: &mut [u8],
    h: Headers,
    offset: usize,
    tso: bool,
) -> Result<(), InvalidPacket> {
    let transport_len = h.end - h.transport;
    let addresses = if h.ipv6 {
        &frame[h.ip + 8..h.ip + 40]
    } else {
        &frame[h.ip + 12..h.ip + 20]
    };
    let pseudo = sum(addresses)
        + u32::from(h.protocol)
        + if tso {
            0
        } else {
            u32::try_from(transport_len).map_err(|_| InvalidPacket)?
        };
    // CHECKSUM_PARTIAL stores the folded, non-complemented pseudoheader sum.
    put(frame, h.transport + offset, !finish(pseudo));
    Ok(())
}

/// Prepare a normalized request for a backend, or complete it in software.
///
/// # Errors
/// Returns `InvalidPacket` for malformed requests, headers or excessive output.
pub fn prepare(
    mut request: Request,
    mut frame: Vec<u8>,
    capabilities: u32,
) -> Result<Batch, InvalidPacket> {
    if !request.valid()
        || frame.len() < 14
        || frame.len() > MAX_PACKET - 4
        || capabilities & !7 != 0
    {
        return Err(InvalidPacket);
    }
    if request.flags & VLAN != 0 {
        frame.splice(
            12..12,
            [
                0x81,
                0,
                request.vlan_tci.to_be_bytes()[0],
                request.vlan_tci.to_be_bytes()[1],
            ],
        );
        request.flags &= !VLAN;
    }
    if request.flags == 0 || capabilities & CAP_CHECKSUM == 0 {
        return software(request, frame, capabilities);
    }
    let h = headers(&frame).ok_or(InvalidPacket)?;
    if h.fragmented {
        return software(request, frame, capabilities);
    }
    let tso = request.flags & TSO != 0;
    let offset = match h.protocol {
        6 if tso || request.flags & TCP_CHECKSUM != 0 => 16,
        17 if !tso && request.flags & UDP_CHECKSUM != 0 => 6,
        _ => return software(request, frame, capabilities),
    };
    let transport_len = h.end - h.transport;
    let tcp_len = if h.protocol == 6 {
        if transport_len < 20 {
            return Err(InvalidPacket);
        }
        let len = usize::from(frame[h.transport + 12] >> 4) * 4;
        if len < 20 || len > transport_len {
            return Err(InvalidPacket);
        }
        len
    } else {
        let len = usize::from(word(&frame, h.transport + 4).ok_or(InvalidPacket)?);
        if len < 8 || len > transport_len {
            return Err(InvalidPacket);
        }
        if len != transport_len {
            return software(request, frame, capabilities);
        }
        8
    };
    if tso {
        if request.mss == 0 || (transport_len - tcp_len).div_ceil(usize::from(request.mss)) > 2048 {
            return Err(InvalidPacket);
        }
        let needed = if h.ipv6 { CAP_TSO6 } else { CAP_TSO4 };
        // First implementation delegates only ordinary IP/TCP headers. The
        // software engine retains support for bounded IPv6 extension chains.
        if capabilities & needed == 0
            || (h.ipv6 && h.transport != h.ip + 40)
            || (!h.ipv6 && h.transport != h.ip + 20)
            || frame[h.transport + 13] & 0x26 != 0
        {
            return software(request, frame, capabilities);
        }
    }
    if !h.ipv6 && (tso || request.flags & IP_CHECKSUM != 0) {
        put(&mut frame, h.ip + 10, 0);
        let checksum = finish(sum(&frame[h.ip..h.transport]));
        put(&mut frame, h.ip + 10, checksum);
    }
    seed_checksum(&mut frame, h, offset, tso)?;
    let mut header = [0; 10];
    header[0] = 1; // VIRTIO_NET_HDR_F_NEEDS_CSUM
    if tso {
        header[1] = if h.ipv6 { 4 } else { 1 };
        if frame[h.transport + 13] & 0x80 != 0 {
            header[1] |= 0x80;
        }
        header[2..4].copy_from_slice(
            &u16::try_from(h.transport + tcp_len)
                .map_err(|_| InvalidPacket)?
                .to_le_bytes(),
        );
        header[4..6].copy_from_slice(&request.mss.to_le_bytes());
    }
    header[6..8].copy_from_slice(
        &u16::try_from(h.transport)
            .map_err(|_| InvalidPacket)?
            .to_le_bytes(),
    );
    header[8..10].copy_from_slice(&(if offset == 16 { 16_u16 } else { 6_u16 }).to_le_bytes());
    frame.truncate(h.end);
    Ok(Batch {
        fallback: false,
        packets: vec![Packet {
            header,
            bytes: frame,
        }],
    })
}

/// Normalize host RX to a wire-ready Ethernet frame.
///
/// # Errors
/// Rejects GSO, unknown flags, truncation and out-of-bounds checksum metadata.
pub fn receive(header: &[u8; 10], mut bytes: Vec<u8>) -> Result<Vec<u8>, InvalidPacket> {
    if bytes.len() < 14 || bytes.len() > MAX_PACKET || header[0] & !3 != 0 || header[1] != 0 {
        return Err(InvalidPacket);
    }
    if header[0] & 1 != 0 {
        let start = usize::from(u16::from_le_bytes([header[6], header[7]]));
        let offset = usize::from(u16::from_le_bytes([header[8], header[9]]));
        let at = start.checked_add(offset).ok_or(InvalidPacket)?;
        if start < 14 || at + 2 > bytes.len() {
            return Err(InvalidPacket);
        }
        let checksum = finish(sum(&bytes[start..]));
        put(&mut bytes, at, checksum);
    }
    Ok(bytes)
}

/// Normalize host RX, segmenting TCPv4/TCPv6 GSO into ordinary wire frames.
///
/// # Errors
/// Rejects unsupported GSO types, inconsistent metadata, malformed packets,
/// unknown flags, truncation and excessive segment amplification.
pub fn receive_batch(header: &[u8; 10], bytes: Vec<u8>) -> Result<Vec<Vec<u8>>, InvalidPacket> {
    let gso_type = header[1] & 0x7f;
    if gso_type == 0 {
        return receive(header, bytes).map(|frame| vec![frame]);
    }
    if bytes.len() < 14
        || bytes.len() > MAX_PACKET
        || header[0] & !3 != 0
        || !matches!(gso_type, 1 | 4)
    {
        return Err(InvalidPacket);
    }
    let h = headers(&bytes).ok_or(InvalidPacket)?;
    if h.protocol != 6 || h.fragmented || h.end - h.transport < 20 {
        return Err(InvalidPacket);
    }
    if (gso_type == 4) != h.ipv6 {
        return Err(InvalidPacket);
    }
    let tcp_size = usize::from(bytes[h.transport + 12] >> 4) * 4;
    let header_len = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let mss = u16::from_le_bytes([header[4], header[5]]);
    let checksum_start = usize::from(u16::from_le_bytes([header[6], header[7]]));
    let checksum_offset = u16::from_le_bytes([header[8], header[9]]);
    if tcp_size < 20
        || h.transport + tcp_size > h.end
        || header_len != h.transport + tcp_size
        || mss == 0
        || checksum_start != h.transport
        || checksum_offset != 16
    {
        return Err(InvalidPacket);
    }
    let frames = Request {
        flags: IP_CHECKSUM | TCP_CHECKSUM | TSO,
        mss,
        ..Request::default()
    }
    .frames(bytes);
    (!frames.is_empty() && frames.len() <= 256)
        .then_some(frames)
        .ok_or(InvalidPacket)
}

impl Request {
    /// Stable little-endian capture representation, independent of C padding.
    #[must_use]
    pub fn encode(self) -> [u8; 16] {
        let mut result = [0; 16];
        result[0..4].copy_from_slice(&self.version.to_le_bytes());
        result[4..8].copy_from_slice(&self.flags.to_le_bytes());
        result[8..10].copy_from_slice(&self.mss.to_le_bytes());
        result[10..12].copy_from_slice(&self.vlan_tci.to_le_bytes());
        result[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        result
    }
}

#[cfg(test)]
#[expect(clippy::cast_possible_truncation, reason = "bounded packet fixtures")]
mod tests {
    use super::*;
    fn packet(ipv6: bool, udp: bool, payload: usize) -> Vec<u8> {
        let ip_size = if ipv6 { 40 } else { 20 };
        let tcp = 14 + ip_size;
        let mut p = vec![0; tcp + if udp { 8 } else { 20 } + payload];
        put(&mut p, 12, if ipv6 { 0x86dd } else { 0x0800 });
        let len = p.len();
        p[14] = if ipv6 { 0x60 } else { 0x45 };
        if ipv6 {
            put(&mut p, 18, (len - 54) as u16);
            p[20] = if udp { 17 } else { 6 };
            p[21] = 64;
            p[29] = 1;
            p[45] = 2;
        } else {
            put(&mut p, 16, (len - 14) as u16);
            put(&mut p, 18, 0xfffe);
            p[22] = 64;
            p[23] = if udp { 17 } else { 6 };
            p[26..34].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        }
        put(&mut p, tcp, 1234);
        put(&mut p, tcp + 2, 8080);
        if udp {
            put(&mut p, tcp + 4, (8 + payload) as u16);
        } else {
            p[tcp + 4..tcp + 8].copy_from_slice(&0xffff_fff0u32.to_be_bytes());
            p[tcp + 12] = 0x50;
            p[tcp + 13] = 0x99;
        }
        let data = tcp + if udp { 8 } else { 20 };
        for (i, b) in p[data..].iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    fn valid(p: &[u8]) {
        let h = headers(p).unwrap();
        if !h.ipv6 {
            assert_eq!(finish(sum(&p[h.ip..h.transport])), 0);
        }
        let addresses = if h.ipv6 {
            &p[h.ip + 8..h.ip + 40]
        } else {
            &p[h.ip + 12..h.ip + 20]
        };
        assert_eq!(
            finish(
                sum(addresses)
                    + (h.end - h.transport) as u32
                    + u32::from(h.protocol)
                    + sum(&p[h.transport..h.end])
            ),
            0
        );
    }

    #[test]
    fn delegated_checksums_match_software_on_wire() {
        for ipv6 in [false, true] {
            for udp in [false, true] {
                for vlan in [false, true] {
                    let request = Request {
                        flags: IP_CHECKSUM
                            | TCP_CHECKSUM
                            | UDP_CHECKSUM
                            | if vlan { VLAN } else { 0 },
                        vlan_tci: 123,
                        ..Request::default()
                    };
                    let input = packet(ipv6, udp, 137);
                    let software = request.frames(input.clone());
                    let mut batch = prepare(request, input, CAP_CHECKSUM).unwrap();
                    assert!(!batch.fallback);
                    assert_eq!(batch.packets.len(), 1);
                    let p = batch.packets.remove(0);
                    assert_eq!(p.header[0], 1);
                    assert_eq!(p.header[1], 0);
                    let wire = receive(&p.header, p.bytes).unwrap();
                    assert_eq!(wire, software[0]);
                    valid(&wire);
                }
            }
        }
    }
    #[test]
    fn tso_translates_mss_checksum_seed_offsets_and_vlan() {
        for ipv6 in [false, true] {
            let request = Request {
                flags: IP_CHECKSUM | TCP_CHECKSUM | TSO | VLAN,
                mss: 1000,
                vlan_tci: 321,
                ..Request::default()
            };
            let input = packet(ipv6, false, 2501);
            let software = request.frames(input.clone());
            let batch = prepare(request, input.clone(), 7).unwrap();
            assert!(!batch.fallback);
            assert_eq!(batch.packets.len(), 1);
            let p = &batch.packets[0];
            let h = headers(&p.bytes).unwrap();
            assert_eq!(p.header[1], if ipv6 { 0x84 } else { 0x81 });
            assert_eq!(u16::from_le_bytes([p.header[4], p.header[5]]), 1000);
            assert_eq!(
                u16::from_le_bytes([p.header[6], p.header[7]]) as usize,
                h.transport
            );
            assert_eq!(u16::from_le_bytes([p.header[8], p.header[9]]), 16);
            let addresses = if ipv6 {
                &p.bytes[h.ip + 8..h.ip + 40]
            } else {
                &p.bytes[h.ip + 12..h.ip + 20]
            };
            assert_eq!(
                word(&p.bytes, h.transport + 16),
                Some(!finish(sum(addresses) + 6))
            );
            let fallback = prepare(request, input, CAP_CHECKSUM).unwrap();
            assert!(fallback.fallback);
            assert_eq!(
                fallback
                    .packets
                    .into_iter()
                    .map(|p| p.bytes)
                    .collect::<Vec<_>>(),
                software
            );
            for p in software {
                valid(&p);
            }
        }
    }
    #[test]
    fn invalid_requests_and_rx_gso_are_rejected() {
        let p = packet(false, false, 20);
        assert!(
            prepare(
                Request {
                    version: 2,
                    ..Request::default()
                },
                p.clone(),
                7
            )
            .is_err()
        );
        assert!(
            prepare(
                Request {
                    flags: TSO,
                    ..Request::default()
                },
                p.clone(),
                7
            )
            .is_err()
        );
        assert!(
            prepare(
                Request {
                    flags: 32,
                    ..Request::default()
                },
                p.clone(),
                7
            )
            .is_err()
        );
        for n in 0..14 {
            assert!(prepare(Request::default(), p[..n].to_vec(), 7).is_err());
        }
        let mut hdr = [0; 10];
        hdr[1] = 2;
        assert!(receive(&hdr, p.clone()).is_err());
        hdr[1] = 0;
        hdr[0] = 1;
        hdr[6..8].copy_from_slice(&65535u16.to_le_bytes());
        assert!(receive(&hdr, p).is_err());
    }

    #[test]
    fn rx_tcp_gso_is_normalized_into_wire_frames() {
        for ipv6 in [false, true] {
            let packet = packet(ipv6, false, 2501);
            let h = headers(&packet).unwrap();
            let tcp_size = usize::from(packet[h.transport + 12] >> 4) * 4;
            let mut header = [0; 10];
            header[0] = 1;
            header[1] = if ipv6 { 4 } else { 1 };
            header[2..4].copy_from_slice(&((h.transport + tcp_size) as u16).to_le_bytes());
            header[4..6].copy_from_slice(&1000_u16.to_le_bytes());
            header[6..8].copy_from_slice(&(h.transport as u16).to_le_bytes());
            header[8..10].copy_from_slice(&16_u16.to_le_bytes());

            let frames = receive_batch(&header, packet).unwrap();
            assert_eq!(frames.len(), 3);
            for frame in frames {
                valid(&frame);
            }
        }
    }

    #[test]
    fn rx_gso_rejects_inconsistent_metadata() {
        let packet = packet(false, false, 2501);
        let h = headers(&packet).unwrap();
        let mut header = [0; 10];
        header[0] = 1;
        header[1] = 1;
        header[2..4].copy_from_slice(&((h.transport + 20) as u16).to_le_bytes());
        header[4..6].copy_from_slice(&1000_u16.to_le_bytes());
        header[6..8].copy_from_slice(&(h.transport as u16).to_le_bytes());
        header[8..10].copy_from_slice(&6_u16.to_le_bytes());
        assert!(receive_batch(&header, packet).is_err());
    }

    #[test]
    fn rx_gso_accepts_full_size_ipv4_and_ipv6_batches() {
        for ipv6 in [false, true] {
            let packet = packet(ipv6, false, 65_495);
            let h = headers(&packet).unwrap();
            let mut header = [0; 10];
            header[0] = 1;
            header[1] = if ipv6 { 4 } else { 1 };
            header[2..4].copy_from_slice(&((h.transport + 20) as u16).to_le_bytes());
            header[4..6].copy_from_slice(&1460_u16.to_le_bytes());
            header[6..8].copy_from_slice(&(h.transport as u16).to_le_bytes());
            header[8..10].copy_from_slice(&16_u16.to_le_bytes());
            assert!(!receive_batch(&header, packet).unwrap().is_empty());
        }
    }
}
