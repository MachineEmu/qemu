//! `MediaTek` `NETSYS_V2` descriptor decoding for the shared packet engine.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Offload {
    pub control: u32,
    pub vlan: u32,
}
impl Offload {
    pub fn request(self, frame: &[u8]) -> net_offload::Request {
        let mut r = net_offload::Request::default();
        if self.control & (1 << 30) != 0 {
            r.flags |= net_offload::IP_CHECKSUM;
        }
        if self.control & (1 << 29) != 0 {
            r.flags |= net_offload::TCP_CHECKSUM;
        }
        if self.control & (1 << 28) != 0 {
            r.flags |= net_offload::UDP_CHECKSUM;
        }
        if self.control & (1 << 31) != 0 {
            r.flags |= net_offload::TSO;
            r.mss = net_offload::tcp_checksum_offset(frame)
                .and_then(|at| frame.get(at..at + 2))
                .map_or(0, |b| u16::from_be_bytes([b[0], b[1]]));
        }
        if self.vlan & (1 << 16) != 0 {
            r.flags |= net_offload::VLAN;
            r.vlan_tci = (self.vlan & 0xffff) as u16;
        }
        r
    }
    pub fn frames(self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        self.request(&frame).frames(frame)
    }
}

#[cfg(test)]
mod fixtures {
    use super::Offload;
    #[derive(Clone, Copy)]
    struct Headers {
        ip: usize,
        transport: usize,
        end: usize,
        protocol: u8,
        ipv6: bool,
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

    #[cfg(test)]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "bounded packet fixtures and intentional wraparound tests"
    )]
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
        fn tcp_udp_ipv4_ipv6_checksums_include_odd_payload() {
            for ipv6 in [false, true] {
                for udp in [false, true] {
                    let frames = Offload {
                        control: 0x7000_0000,
                        vlan: 0,
                    }
                    .frames(packet(ipv6, udp, 13));
                    assert_eq!(frames.len(), 1);
                    valid(&frames[0]);
                }
            }
        }

        #[test]
        fn tso_preserves_payload_updates_sequence_flags_lengths_and_vlan() {
            for ipv6 in [false, true] {
                let mut input = packet(ipv6, false, 2501);
                let h = headers(&input).unwrap();
                put(&mut input, h.transport + 16, 1000);
                let frames = Offload {
                    control: 0xf000_0000,
                    vlan: 0x1007b,
                }
                .frames(input.clone());
                assert_eq!(frames.len(), 3);
                let mut payload = Vec::new();
                for (i, frame) in frames.iter().enumerate() {
                    valid(frame);
                    assert_eq!(&frame[12..16], &[0x81, 0, 0, 123]);
                    let h = headers(frame).unwrap();
                    assert_eq!(word(frame, h.transport + 2), Some(8080));
                    assert_eq!(
                        u32::from_be_bytes(
                            frame[h.transport + 4..h.transport + 8].try_into().unwrap()
                        ),
                        0xffff_fff0u32.wrapping_add(i as u32 * 1000)
                    );
                    assert_eq!(frame[h.transport + 13], [0x90, 0x10, 0x19][i]);
                    if !ipv6 {
                        assert_eq!(
                            word(frame, h.ip + 4),
                            Some(0xfffeu16.wrapping_add(i as u16))
                        );
                    }
                    payload.extend_from_slice(&frame[h.transport + 20..]);
                }
                assert_eq!(payload, input[h.transport + 20..]);
            }
        }

        #[test]
        fn disabled_offload_preserves_frame_exactly() {
            let p = packet(false, false, 9);
            assert_eq!(Offload::default().frames(p.clone()), vec![p]);
        }

        #[test]
        fn malformed_and_zero_mss_requests_are_bounded() {
            let offload = Offload {
                control: 0xf000_0000,
                vlan: 0,
            };
            let p = packet(false, false, 12);
            for length in 0..p.len() {
                assert!(offload.frames(p[..length].to_vec()).is_empty());
            }
            assert!(offload.frames(p).is_empty());
        }

        #[test]
        fn ipv4_fragments_do_not_get_transport_checksum() {
            let mut p = packet(false, true, 13);
            put(&mut p, 20, 0x2000);
            let payload = p[34..].to_vec();
            let frames = Offload {
                control: 0x7000_0000,
                vlan: 0,
            }
            .frames(p);
            assert_eq!(frames[0][34..], payload);
            assert_eq!(finish(sum(&frames[0][14..34])), 0);
        }
    }
}
