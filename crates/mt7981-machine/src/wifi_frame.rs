//! 802.11 data framing and CCMP primitives used by the MT7981 model.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

const SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DataHeader {
    pub(super) length: usize,
    pub(super) destination: [u8; 6],
    pub(super) source: [u8; 6],
    pub(super) transmitter: [u8; 6],
    pub(super) sequence: u16,
    pub(super) priority: u8,
    pub(super) protected: bool,
}

pub(super) fn data_header(frame: &[u8]) -> Option<DataHeader> {
    if frame.len() < 24 || frame[0] & 0x0f != 8 || frame[1] & 0x84 != 0 {
        return None;
    }
    let four_addresses = frame[1] & 3 == 3;
    let qos = frame[0] & 0x80 != 0;
    let length = 24 + usize::from(four_addresses) * 6 + usize::from(qos) * 2;
    if frame.len() < length || frame[22] & 15 != 0 {
        return None;
    }
    let a1: [u8; 6] = frame[4..10].try_into().ok()?;
    let a2: [u8; 6] = frame[10..16].try_into().ok()?;
    let a3: [u8; 6] = frame[16..22].try_into().ok()?;
    let (destination, source) = match frame[1] & 3 {
        0 => (a1, a2),
        1 => (a3, a2),
        2 => (a1, a3),
        3 => (a3, frame[24..30].try_into().ok()?),
        _ => unreachable!(),
    };
    let priority = if qos { frame[length - 2] & 15 } else { 0 };
    Some(DataHeader {
        length,
        destination,
        source,
        transmitter: a2,
        sequence: u16::from_le_bytes([frame[22], frame[23]]),
        priority,
        protected: frame[1] & 0x40 != 0,
    })
}

pub(super) fn ethernet(frame: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let header = data_header(frame)?;
    let payload = plaintext.strip_prefix(&SNAP)?;
    if payload.len() < 2 {
        return None;
    }
    let mut result = Vec::with_capacity(12 + payload.len());
    result.extend_from_slice(&header.destination);
    result.extend_from_slice(&header.source);
    result.extend_from_slice(payload);
    Some(result)
}

pub(super) fn from_ethernet(
    ethernet: &[u8],
    bssid: [u8; 6],
    peer: [u8; 6],
    sequence: u16,
) -> Option<Vec<u8>> {
    if !(14..=2304).contains(&ethernet.len()) || ethernet[0..6] != peer {
        return None;
    }
    let mut frame = Vec::with_capacity(24 + 8 + ethernet.len() - 14);
    frame.extend_from_slice(&[0x08, 0x02, 0, 0]); // data, from DS
    frame.extend_from_slice(&peer);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&ethernet[6..12]);
    frame.extend_from_slice(&(sequence << 4).to_le_bytes());
    frame.extend_from_slice(&SNAP);
    frame.extend_from_slice(&ethernet[12..]);
    Some(frame)
}

#[expect(
    clippy::verbose_bit_mask,
    reason = "802.11 field masks are clearer than zero counts"
)]
fn crypto_fields(frame: &[u8]) -> Option<(usize, u8, [u8; 6])> {
    if let Some(header) = data_header(frame) {
        return Some((header.length, header.priority, header.transmitter));
    }
    if frame.len() >= 24 && frame[0] & 0x0f == 0 && frame[1] & 0x87 == 0 && frame[22] & 15 == 0 {
        return Some((24, 0, frame[10..16].try_into().ok()?));
    }
    None
}

fn aad(frame: &[u8], length: usize, priority: u8) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(30);
    let management = frame[0] & 0x0c == 0;
    let frame_type = if management {
        frame[0]
    } else {
        frame[0] & 0x8f
    };
    let mut flags = frame[1] & 0xc7 | 0x40;
    if frame[0] & 0x80 != 0 {
        flags &= !0x80;
    }
    result.extend_from_slice(&[frame_type, flags]);
    result.extend_from_slice(&frame[4..22]);
    result.extend_from_slice(&[frame[22] & 0x0f, 0]);
    if frame[1] & 3 == 3 {
        result.extend_from_slice(frame.get(24..30)?);
    }
    if frame[0] & 0x80 != 0 {
        result.extend_from_slice(&[priority, 0]);
    }
    debug_assert!(length >= 24);
    Some(result)
}

enum AesKey {
    Bits128(Box<Aes128>),
    Bits256(Box<Aes256>),
}

impl AesKey {
    fn new(key: &[u8]) -> Option<Self> {
        match key.len() {
            16 => Some(Self::Bits128(Box::new(Aes128::new_from_slice(key).ok()?))),
            32 => Some(Self::Bits256(Box::new(Aes256::new_from_slice(key).ok()?))),
            _ => None,
        }
    }

    fn block(&self, data: &mut [u8; 16]) {
        match self {
            Self::Bits128(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(data)),
            Self::Bits256(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(data)),
        }
    }
}

fn xor_block(left: &mut [u8], right: &[u8]) {
    for (destination, source) in left.iter_mut().zip(right) {
        *destination ^= source;
    }
}

fn nonce(frame: &[u8], priority: u8, transmitter: [u8; 6], pn: u64) -> [u8; 13] {
    let mut result = [0; 13];
    result[0] = priority | u8::from(frame[0] & 0x0c == 0) << 4;
    result[1..7].copy_from_slice(&transmitter);
    result[7..13].copy_from_slice(&pn.to_be_bytes()[2..]);
    result
}

fn ccmp_mic(
    cipher: &AesKey,
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
    tag_length: usize,
) -> Option<Vec<u8>> {
    let length = u16::try_from(plaintext.len()).ok()?;
    let mut state = [0; 16];
    state[0] = 0x41 | (u8::try_from((tag_length - 2) / 2).ok()? << 3);
    state[1..14].copy_from_slice(nonce);
    state[14..].copy_from_slice(&length.to_be_bytes());
    cipher.block(&mut state);

    let aad_length = u16::try_from(aad.len()).ok()?;
    let mut authenticated = Vec::with_capacity(2 + aad.len() + 15);
    authenticated.extend_from_slice(&aad_length.to_be_bytes());
    authenticated.extend_from_slice(aad);
    authenticated.resize(authenticated.len().next_multiple_of(16), 0);
    authenticated.extend_from_slice(plaintext);
    authenticated.resize(authenticated.len().next_multiple_of(16), 0);
    for chunk in authenticated.chunks_exact(16) {
        xor_block(&mut state, chunk);
        cipher.block(&mut state);
    }
    Some(state[..tag_length].to_vec())
}

fn stream(cipher: &AesKey, nonce: &[u8; 13], counter: u16) -> [u8; 16] {
    let mut result = [0; 16];
    result[0] = 1; // L - 1 for a two-byte counter.
    result[1..14].copy_from_slice(nonce);
    result[14..].copy_from_slice(&counter.to_be_bytes());
    cipher.block(&mut result);
    result
}

pub(super) fn encrypt_ccmp(frame: &[u8], key: &[u8], key_id: u8, pn: u64) -> Option<Vec<u8>> {
    if pn >= 1 << 48 || key_id > 3 {
        return None;
    }
    let (length, priority, transmitter) = crypto_fields(frame)?;
    if frame[1] & 0x40 != 0 {
        return None;
    }
    let plain = frame.get(length..)?;
    let aad = aad(frame, length, priority)?;
    let nonce = nonce(frame, priority, transmitter, pn);
    let cipher = AesKey::new(key)?;
    let tag_length = if key.len() == 16 { 8 } else { 16 };
    let mut tag = ccmp_mic(&cipher, &nonce, &aad, plain, tag_length)?;
    xor_block(&mut tag, &stream(&cipher, &nonce, 0));
    let mut encrypted = plain.to_vec();
    for (index, chunk) in encrypted.chunks_mut(16).enumerate() {
        xor_block(
            chunk,
            &stream(&cipher, &nonce, u16::try_from(index + 1).ok()?),
        );
    }
    let mut result = frame[..length].to_vec();
    result[1] |= 0x40;
    result.extend_from_slice(&pn_header(key_id, pn));
    result.extend_from_slice(&encrypted);
    result.extend_from_slice(&tag);
    Some(result)
}

pub(super) fn decrypt_ccmp(frame: &[u8], key: &[u8]) -> Option<(u8, u64, Vec<u8>)> {
    let (length, priority, transmitter) = crypto_fields(frame)?;
    let tag_length = match key.len() {
        16 => 8,
        32 => 16,
        _ => return None,
    };
    if frame[1] & 0x40 == 0 || frame.len() < length + 8 + tag_length {
        return None;
    }
    let ccmp = &frame[length..length + 8];
    if ccmp[2] != 0 || ccmp[3] & 0x20 == 0 {
        return None;
    }
    let key_id = ccmp[3] >> 6;
    let pn = u64::from(ccmp[0])
        | u64::from(ccmp[1]) << 8
        | u64::from(ccmp[4]) << 16
        | u64::from(ccmp[5]) << 24
        | u64::from(ccmp[6]) << 32
        | u64::from(ccmp[7]) << 40;
    let nonce = nonce(frame, priority, transmitter, pn);
    let cipher = AesKey::new(key)?;
    let encrypted = &frame[length + 8..frame.len() - tag_length];
    let mut plain = encrypted.to_vec();
    for (index, chunk) in plain.chunks_mut(16).enumerate() {
        xor_block(
            chunk,
            &stream(&cipher, &nonce, u16::try_from(index + 1).ok()?),
        );
    }
    let aad = aad(frame, length, priority)?;
    let mut expected = ccmp_mic(&cipher, &nonce, &aad, &plain, tag_length)?;
    xor_block(&mut expected, &stream(&cipher, &nonce, 0));
    (expected == frame[frame.len() - tag_length..]).then_some((key_id, pn, plain))
}

fn pn_header(key_id: u8, pn: u64) -> [u8; 8] {
    let bytes = pn.to_le_bytes();
    [
        bytes[0],
        bytes[1],
        0,
        0x20 | key_id << 6,
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
    ]
}

fn gcmp_nonce(transmitter: [u8; 6], pn: u64) -> [u8; 12] {
    let mut result = [0; 12];
    result[..6].copy_from_slice(&transmitter);
    result[6..].copy_from_slice(&pn.to_be_bytes()[2..]);
    result
}

fn parse_pn_header(header: &[u8]) -> Option<(u8, u64)> {
    if header.len() != 8 || header[2] != 0 || header[3] & 0x20 == 0 {
        return None;
    }
    Some((
        header[3] >> 6,
        u64::from(header[0])
            | u64::from(header[1]) << 8
            | u64::from(header[4]) << 16
            | u64::from(header[5]) << 24
            | u64::from(header[6]) << 32
            | u64::from(header[7]) << 40,
    ))
}

pub(super) fn encrypt_gcmp(frame: &[u8], key: &[u8], key_id: u8, pn: u64) -> Option<Vec<u8>> {
    if pn >= 1 << 48 || key_id > 3 {
        return None;
    }
    let (length, priority, transmitter) = crypto_fields(frame)?;
    if frame[1] & 0x40 != 0 {
        return None;
    }
    let mut payload = frame[length..].to_vec();
    let associated = aad(frame, length, priority)?;
    let nonce_bytes = gcmp_nonce(transmitter, pn);
    let tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .ok()?
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &associated, &mut payload)
            .ok()?,
        32 => Aes256Gcm::new_from_slice(key)
            .ok()?
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), &associated, &mut payload)
            .ok()?,
        _ => return None,
    };
    let mut result = frame[..length].to_vec();
    result[1] |= 0x40;
    result.extend_from_slice(&pn_header(key_id, pn));
    result.extend_from_slice(&payload);
    result.extend_from_slice(&tag);
    Some(result)
}

pub(super) fn decrypt_gcmp(frame: &[u8], key: &[u8]) -> Option<(u8, u64, Vec<u8>)> {
    let (length, priority, transmitter) = crypto_fields(frame)?;
    if frame[1] & 0x40 == 0 || frame.len() < length + 24 {
        return None;
    }
    let (key_id, pn) = parse_pn_header(&frame[length..length + 8])?;
    let mut payload = frame[length + 8..frame.len() - 16].to_vec();
    let associated = aad(frame, length, priority)?;
    let nonce_bytes = gcmp_nonce(transmitter, pn);
    let tag = GenericArray::from_slice(&frame[frame.len() - 16..]);
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .ok()?
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                &associated,
                &mut payload,
                tag,
            )
            .ok()?,
        32 => Aes256Gcm::new_from_slice(key)
            .ok()?
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                &associated,
                &mut payload,
                tag,
            )
            .ok()?,
        _ => return None,
    }
    Some((key_id, pn, payload))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn rc4(key: &[u8], data: &mut [u8]) {
    let mut state = [0u8; 256];
    for (value, byte) in (0u8..=255).zip(&mut state) {
        *byte = value;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + usize::from(state[i]) + usize::from(key[i % key.len()])) & 255;
        state.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for byte in data {
        i = (i + 1) & 255;
        j = (j + usize::from(state[i])) & 255;
        state.swap(i, j);
        *byte ^= state[(usize::from(state[i]) + usize::from(state[j])) & 255];
    }
}

pub(super) fn encrypt_wep(frame: &[u8], key: &[u8], key_id: u8, iv: u64) -> Option<Vec<u8>> {
    if !matches!(key.len(), 5 | 13 | 16) || key_id > 3 || iv >= 1 << 24 {
        return None;
    }
    let (length, _, _) = crypto_fields(frame)?;
    if frame[1] & 0x40 != 0 {
        return None;
    }
    let bytes = iv.to_be_bytes();
    let header = [bytes[5], bytes[6], bytes[7], key_id << 6];
    let mut payload = frame[length..].to_vec();
    payload.extend_from_slice(&crc32(&payload).to_le_bytes());
    let mut rc4_key = header[..3].to_vec();
    rc4_key.extend_from_slice(key);
    rc4(&rc4_key, &mut payload);
    let mut result = frame[..length].to_vec();
    result[1] |= 0x40;
    result.extend_from_slice(&header);
    result.extend(payload);
    Some(result)
}

pub(super) fn decrypt_wep(frame: &[u8], key: &[u8]) -> Option<(u8, u64, Vec<u8>)> {
    if !matches!(key.len(), 5 | 13 | 16) {
        return None;
    }
    let (length, _, _) = crypto_fields(frame)?;
    if frame[1] & 0x40 == 0 || frame.len() < length + 8 {
        return None;
    }
    let header = &frame[length..length + 4];
    if header[3] & 0x3f != 0 {
        return None;
    }
    let iv = u64::from(header[0]) << 16 | u64::from(header[1]) << 8 | u64::from(header[2]);
    let mut payload = frame[length + 4..].to_vec();
    let mut rc4_key = header[..3].to_vec();
    rc4_key.extend_from_slice(key);
    rc4(&rc4_key, &mut payload);
    let split = payload.len().checked_sub(4)?;
    (crc32(&payload[..split]).to_le_bytes() == payload[split..])
        .then(|| (header[3] >> 6, iv, payload[..split].to_vec()))
}

fn aes_sbox(value: u8) -> u8 {
    fn mul(mut a: u8, mut b: u8) -> u8 {
        let mut r = 0;
        while b != 0 {
            if b & 1 != 0 {
                r ^= a;
            }
            a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
            b >>= 1;
        }
        r
    }
    let inverse = if value == 0 {
        0
    } else {
        let mut r = 1;
        for _ in 0..254 {
            r = mul(r, value);
        }
        r
    };
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

fn tkip_s(value: u16) -> u16 {
    fn entry(value: u8) -> u16 {
        let s = aes_sbox(value);
        u16::from((s << 1) ^ if s & 0x80 != 0 { 0x1b } else { 0 }) << 8
            | u16::from(s ^ ((s << 1) ^ if s & 0x80 != 0 { 0x1b } else { 0 }))
    }
    let bytes = value.to_le_bytes();
    entry(bytes[0]) ^ entry(bytes[1]).swap_bytes()
}
fn tk_word(key: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([key[offset], key[offset + 1]])
}

fn tkip_rc4_key(tk: &[u8], transmitter: [u8; 6], pn: u64) -> Option<[u8; 16]> {
    if tk.len() != 16 || pn >= 1 << 48 {
        return None;
    }
    let pn_bytes = pn.to_le_bytes();
    let iv16 = u16::from_le_bytes(pn_bytes[..2].try_into().ok()?);
    let iv32 = u32::from_le_bytes(pn_bytes[2..6].try_into().ok()?);
    let iv32_bytes = iv32.to_le_bytes();
    let mut p = [
        u16::from_le_bytes(iv32_bytes[..2].try_into().ok()?),
        u16::from_le_bytes(iv32_bytes[2..].try_into().ok()?),
        u16::from_le_bytes([transmitter[0], transmitter[1]]),
        u16::from_le_bytes([transmitter[2], transmitter[3]]),
        u16::from_le_bytes([transmitter[4], transmitter[5]]),
    ];
    for i in 0u16..8 {
        let j = usize::from(2 * (i & 1));
        p[0] = p[0].wrapping_add(tkip_s(p[4] ^ tk_word(tk, j)));
        p[1] = p[1].wrapping_add(tkip_s(p[0] ^ tk_word(tk, 4 + j)));
        p[2] = p[2].wrapping_add(tkip_s(p[1] ^ tk_word(tk, 8 + j)));
        p[3] = p[3].wrapping_add(tkip_s(p[2] ^ tk_word(tk, 12 + j)));
        p[4] = p[4]
            .wrapping_add(tkip_s(p[3] ^ tk_word(tk, j)))
            .wrapping_add(i);
    }
    let mut q = [p[0], p[1], p[2], p[3], p[4], p[4].wrapping_add(iv16)];
    for i in 0..6 {
        q[i] = q[i].wrapping_add(tkip_s(q[(i + 5) % 6] ^ tk_word(tk, 2 * i)));
    }
    for i in 0..6 {
        q[i] = q[i].wrapping_add((q[(i + 5) % 6] ^ tk_word(tk, 12 + 2 * (i & 1))).rotate_right(1));
    }
    let mut key = [0; 16];
    key[0] = (iv16 >> 8) as u8;
    key[1] = (key[0] | 0x20) & 0x7f;
    key[2] = iv16.to_le_bytes()[0];
    key[3] = ((q[5] ^ tk_word(tk, 0)) >> 1).to_le_bytes()[0];
    for (out, word) in key[4..].chunks_exact_mut(2).zip(q) {
        out.copy_from_slice(&word.to_le_bytes());
    }
    Some(key)
}

fn michael(key: &[u8], header: DataHeader, payload: &[u8]) -> Option<[u8; 8]> {
    fn xswap(v: u32) -> u32 {
        ((v & 0x00ff_00ff) << 8) | ((v & 0xff00_ff00) >> 8)
    }
    fn block(l: &mut u32, r: &mut u32, m: u32) {
        *l ^= m;
        *r ^= l.rotate_left(17);
        *l = l.wrapping_add(*r);
        *r ^= xswap(*l);
        *l = l.wrapping_add(*r);
        *r ^= l.rotate_left(3);
        *l = l.wrapping_add(*r);
        *r ^= l.rotate_right(2);
        *l = l.wrapping_add(*r);
    }
    if key.len() != 8 {
        return None;
    }
    let mut bytes = Vec::with_capacity(16 + payload.len() + 8);
    bytes.extend_from_slice(&header.destination);
    bytes.extend_from_slice(&header.source);
    bytes.extend_from_slice(&[header.priority, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes.push(0x5a);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&[0; 4]);
    let mut l = u32::from_le_bytes(key[..4].try_into().ok()?);
    let mut r = u32::from_le_bytes(key[4..].try_into().ok()?);
    for word in bytes.chunks_exact(4) {
        block(&mut l, &mut r, u32::from_le_bytes(word.try_into().ok()?));
    }
    let mut result = [0; 8];
    result[..4].copy_from_slice(&l.to_le_bytes());
    result[4..].copy_from_slice(&r.to_le_bytes());
    Some(result)
}

pub(super) fn encrypt_tkip(frame: &[u8], key: &[u8], key_id: u8, pn: u64) -> Option<Vec<u8>> {
    if key.len() != 32 || key_id > 3 {
        return None;
    }
    let header = data_header(frame)?;
    if header.protected {
        return None;
    }
    let pn_bytes = pn.to_le_bytes();
    let iv16 = u16::from_le_bytes(pn_bytes[..2].try_into().ok()?);
    let iv32 = u32::from_le_bytes(pn_bytes[2..6].try_into().ok()?);
    let iv = [
        (iv16 >> 8) as u8,
        ((iv16 >> 8) as u8 | 0x20) & 0x7f,
        iv16.to_le_bytes()[0],
        0x20 | key_id << 6,
        iv32.to_le_bytes()[0],
        iv32.to_le_bytes()[1],
        iv32.to_le_bytes()[2],
        iv32.to_le_bytes()[3],
    ];
    let mut payload = frame[header.length..].to_vec();
    payload.extend_from_slice(&michael(&key[16..24], header, &payload)?);
    payload.extend_from_slice(&crc32(&payload).to_le_bytes());
    rc4(
        &tkip_rc4_key(&key[..16], header.transmitter, pn)?,
        &mut payload,
    );
    let mut result = frame[..header.length].to_vec();
    result[1] |= 0x40;
    result.extend_from_slice(&iv);
    result.extend(payload);
    Some(result)
}

pub(super) fn decrypt_tkip(frame: &[u8], key: &[u8]) -> Option<(u8, u64, Vec<u8>)> {
    if key.len() != 32 {
        return None;
    }
    let header = data_header(frame)?;
    if !header.protected || frame.len() < header.length + 20 {
        return None;
    }
    let iv = &frame[header.length..header.length + 8];
    if iv[1] != (iv[0] | 0x20) & 0x7f || iv[3] & 0x3f != 0x20 {
        return None;
    }
    let iv16 = u16::from(iv[2]) | u16::from(iv[0]) << 8;
    let iv32 = u32::from_le_bytes(iv[4..8].try_into().ok()?);
    let pn = u64::from(iv16) | (u64::from(iv32) << 16);
    let mut payload = frame[header.length + 8..].to_vec();
    rc4(
        &tkip_rc4_key(&key[..16], header.transmitter, pn)?,
        &mut payload,
    );
    let icv = payload.len().checked_sub(4)?;
    if crc32(&payload[..icv]).to_le_bytes() != payload[icv..] {
        return None;
    }
    payload.truncate(icv);
    let mic_at = payload.len().checked_sub(8)?;
    if michael(&key[24..32], header, &payload[..mic_at])? != payload[mic_at..] {
        return None;
    }
    payload.truncate(mic_at);
    Some((iv[3] >> 6, pn, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_packet() -> Vec<u8> {
        [
            [2, 0, 0, 0, 1, 0].as_slice(),
            [2, 0, 0, 0, 2, 0].as_slice(),
            [0x08, 0x00, 0x45, 0, 0, 20].as_slice(),
        ]
        .concat()
    }

    #[test]
    fn llc_snap_round_trip_preserves_ethernet_addresses_and_protocol() {
        let packet = ethernet_packet();
        let frame = from_ethernet(
            &packet,
            [2, 0, 0, 0, 3, 0],
            packet[..6].try_into().unwrap(),
            7,
        )
        .unwrap();
        let header = data_header(&frame).unwrap();
        assert_eq!(header.sequence, 7 << 4);
        assert_eq!(ethernet(&frame, &frame[header.length..]).unwrap(), packet);
    }

    #[test]
    fn ccmp_round_trip_authenticates_header_payload_and_key() {
        let packet = ethernet_packet();
        let frame = from_ethernet(
            &packet,
            [2, 0, 0, 0, 3, 0],
            packet[..6].try_into().unwrap(),
            9,
        )
        .unwrap();
        let key = [0x11; 16];
        let protected = encrypt_ccmp(&frame, &key, 2, 0x0102_0304_0506).unwrap();
        let (key_id, pn, plain) = decrypt_ccmp(&protected, &key).unwrap();
        assert_eq!((key_id, pn), (2, 0x0102_0304_0506));
        assert_eq!(ethernet(&protected, &plain).unwrap(), packet);
        for offset in [4, protected.len() - 1] {
            let mut corrupt = protected.clone();
            corrupt[offset] ^= 1;
            assert!(decrypt_ccmp(&corrupt, &key).is_none());
        }
        assert!(decrypt_ccmp(&protected, &[0x22; 16]).is_none());
    }

    #[test]
    fn ccmp_protects_unicast_robust_management_for_wpa3_pmf() {
        let mut frame = vec![0xc0, 0, 0, 0];
        frame.extend_from_slice(&[2, 0, 0, 0, 1, 0]);
        frame.extend_from_slice(&[2, 0, 0, 0, 3, 0]);
        frame.extend_from_slice(&[2, 0, 0, 0, 3, 0]);
        frame.extend_from_slice(&0x30u16.to_le_bytes());
        frame.extend_from_slice(&[6, 0]);
        let protected = encrypt_ccmp(&frame, &[0x77; 16], 0, 4).unwrap();
        let (_, pn, plain) = decrypt_ccmp(&protected, &[0x77; 16]).unwrap();
        assert_eq!(pn, 4);
        assert_eq!(plain, [6, 0]);
    }

    #[test]
    fn rc4_crc_and_aes_substitution_match_published_primitives() {
        let mut plaintext = b"Plaintext".to_vec();
        rc4(b"Key", &mut plaintext);
        assert_eq!(
            plaintext,
            [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]
        );
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(
            (aes_sbox(0), aes_sbox(0x53), tkip_s(0)),
            (0x63, 0xed, 0x6363)
        );
    }

    #[test]
    fn wep_round_trip_checks_icv_and_key() {
        let packet = ethernet_packet();
        let frame = from_ethernet(
            &packet,
            [2, 0, 0, 0, 3, 0],
            packet[..6].try_into().unwrap(),
            1,
        )
        .unwrap();
        let protected = encrypt_wep(&frame, b"abcde", 1, 0x12_3456).unwrap();
        let (id, iv, plain) = decrypt_wep(&protected, b"abcde").unwrap();
        assert_eq!((id, iv, plain), (1, 0x12_3456, frame[24..].to_vec()));
        assert!(decrypt_wep(&protected, b"vwxyz").is_none());
        let mut corrupt = protected;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decrypt_wep(&corrupt, b"abcde").is_none());
    }

    #[test]
    fn tkip_round_trip_checks_michael_icv_and_temporal_key() {
        let packet = ethernet_packet();
        let frame = from_ethernet(
            &packet,
            [2, 0, 0, 0, 3, 0],
            packet[..6].try_into().unwrap(),
            2,
        )
        .unwrap();
        let mut key = [0u8; 32];
        for (value, byte) in (0u8..).zip(&mut key) {
            *byte = value;
        }
        let mic = key[16..24].to_vec();
        key[24..32].copy_from_slice(&mic);
        let protected = encrypt_tkip(&frame, &key, 2, 0x1020_3040_5060).unwrap();
        let (id, pn, plain) = decrypt_tkip(&protected, &key).unwrap();
        assert_eq!((id, pn, plain), (2, 0x1020_3040_5060, frame[24..].to_vec()));
        let mut corrupt = protected;
        corrupt[35] ^= 1;
        assert!(decrypt_tkip(&corrupt, &key).is_none());
        let mut wrong = key;
        wrong[0] ^= 1;
        assert!(decrypt_tkip(&corrupt, &wrong).is_none());
    }

    #[test]
    fn ccmp_256_and_gcmp_suites_round_trip_and_authenticate() {
        let packet = ethernet_packet();
        let frame = from_ethernet(
            &packet,
            [2, 0, 0, 0, 3, 0],
            packet[..6].try_into().unwrap(),
            3,
        )
        .unwrap();
        let ccmp = encrypt_ccmp(&frame, &[0x33; 32], 0, 7).unwrap();
        assert_eq!(decrypt_ccmp(&ccmp, &[0x33; 32]).unwrap().2, frame[24..]);
        for key in [&[0x44; 16][..], &[0x55; 32][..]] {
            let protected = encrypt_gcmp(&frame, key, 3, 8).unwrap();
            assert_eq!(
                decrypt_gcmp(&protected, key).unwrap(),
                (3, 8, frame[24..].to_vec())
            );
            let mut corrupt = protected;
            *corrupt.last_mut().unwrap() ^= 1;
            assert!(decrypt_gcmp(&corrupt, key).is_none());
        }
    }
}
