//! Small, transport-independent usbredir 0.7 codec.
//!
//! QEMU is the usbredir guest and this module is the host side.  It deliberately
//! accepts only the MVP's control, bulk, and interrupt packets; ISO and stream
//! packets are rejected before they can reach a browser adapter.

use remote_device_protocol::{MAX_PAYLOAD, UsbRequest, UsbStatus, UsbTransferType};
use thiserror::Error;

const HEADER32: usize = 12;
const HEADER64: usize = 16;
const HELLO: u32 = 0;
const CAP_64BIT_IDS: u32 = 5;
const CONTROL: u32 = 100;
const BULK: u32 = 101;
const INTERRUPT: u32 = 103;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UsbRedirError {
    #[error("short usbredir frame")]
    ShortFrame,
    #[error("usbredir packet length exceeds {0} bytes")]
    TooLarge(usize),
    #[error("unsupported usbredir packet type {0}")]
    Unsupported(u32),
    #[error("malformed usbredir packet: {0}")]
    Malformed(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedirHeader {
    pub packet_type: u32,
    pub length: u32,
    pub id: u64,
    pub wide_ids: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Inbound {
    pub header: RedirHeader,
    pub request: UsbRequest,
}

fn header(frame: &[u8], wide_ids: bool) -> Result<RedirHeader, UsbRedirError> {
    let header_len = if wide_ids && frame.get(0..4) != Some(&HELLO.to_le_bytes()) {
        HEADER64
    } else {
        HEADER32
    };
    if frame.len() < header_len {
        return Err(UsbRedirError::ShortFrame);
    }
    let packet_type = u32::from_le_bytes(frame[0..4].try_into().unwrap());
    let length = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    let id = if header_len == HEADER64 {
        u64::from_le_bytes(frame[8..16].try_into().unwrap())
    } else {
        u32::from_le_bytes(frame[8..12].try_into().unwrap()) as u64
    };
    if length as usize > MAX_PAYLOAD + 32 {
        return Err(UsbRedirError::TooLarge(length as usize));
    }
    if frame.len() != header_len + length as usize {
        return Err(UsbRedirError::Malformed(
            "header length does not match frame",
        ));
    }
    Ok(RedirHeader {
        packet_type,
        length,
        id,
        wide_ids: header_len == HEADER64,
    })
}

pub fn decode(
    frame: &[u8],
    attachment_id: &str,
    generation: u64,
    deadline_ms: u32,
) -> Result<Inbound, UsbRedirError> {
    decode_with_header(frame, attachment_id, generation, deadline_ms, false)
}

pub fn decode_with_header(
    frame: &[u8],
    attachment_id: &str,
    generation: u64,
    deadline_ms: u32,
    wide_ids: bool,
) -> Result<Inbound, UsbRedirError> {
    let header = header(frame, wide_ids)?;
    let header_len = if header.wide_ids { HEADER64 } else { HEADER32 };
    let body = &frame[header_len..];
    let (endpoint, direction_in, transfer_type, setup, payload, in_length) =
        match header.packet_type {
            CONTROL => {
                if body.len() < 10 {
                    return Err(UsbRedirError::Malformed("control header"));
                }
                let endpoint = body[0];
                let direction_in = body[2] & 0x80 != 0;
                let setup = [
                    body[2], body[1], body[4], body[5], body[6], body[7], body[8], body[9],
                ];
                let length = u16::from_le_bytes([body[8], body[9]]) as usize;
                let data = &body[10..];
                if direction_in && !data.is_empty() || !direction_in && data.len() != length {
                    return Err(UsbRedirError::Malformed("control data direction"));
                }
                if length > MAX_PAYLOAD {
                    return Err(UsbRedirError::TooLarge(length));
                }
                (
                    endpoint,
                    direction_in,
                    UsbTransferType::Control,
                    Some(setup),
                    data.to_vec(),
                    length as u32,
                )
            }
            BULK => {
                if body.len() < 10 {
                    return Err(UsbRedirError::Malformed("bulk header"));
                }
                let endpoint = body[0];
                let length = u16::from_le_bytes([body[2], body[3]]) as usize
                    | ((u16::from_le_bytes([body[8], body[9]]) as usize) << 16);
                if length > MAX_PAYLOAD {
                    return Err(UsbRedirError::TooLarge(length));
                }
                let data = &body[10..];
                let direction_in = endpoint & 0x80 != 0;
                if direction_in && !data.is_empty() || !direction_in && data.len() != length {
                    return Err(UsbRedirError::Malformed("bulk data direction"));
                }
                (
                    endpoint,
                    direction_in,
                    UsbTransferType::Bulk,
                    None,
                    data.to_vec(),
                    if direction_in { length as u32 } else { 0 },
                )
            }
            INTERRUPT => {
                if body.len() < 4 {
                    return Err(UsbRedirError::Malformed("interrupt header"));
                }
                let endpoint = body[0];
                let length = u16::from_le_bytes([body[2], body[3]]) as usize;
                let data = &body[4..];
                let direction_in = endpoint & 0x80 != 0;
                if direction_in && !data.is_empty() || !direction_in && data.len() != length {
                    return Err(UsbRedirError::Malformed("interrupt data direction"));
                }
                (
                    endpoint,
                    direction_in,
                    UsbTransferType::Interrupt,
                    None,
                    data.to_vec(),
                    if direction_in { length as u32 } else { 0 },
                )
            }
            other => return Err(UsbRedirError::Unsupported(other)),
        };
    let request = UsbRequest {
        attachment_id: attachment_id.to_owned(),
        generation,
        request_id: header.id,
        interface: 0,
        endpoint,
        direction_in,
        transfer_type,
        deadline_ms,
        setup,
        payload,
        in_length,
    };
    request
        .validate()
        .map_err(|_| UsbRedirError::Malformed("internal request bounds"))?;
    Ok(Inbound { header, request })
}

pub fn response(
    header: RedirHeader,
    request: &UsbRequest,
    status: UsbStatus,
    payload: &[u8],
) -> Result<Vec<u8>, UsbRedirError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(UsbRedirError::TooLarge(payload.len()));
    }
    let wire_status = match status {
        UsbStatus::Ok | UsbStatus::ShortTransfer => 0,
        UsbStatus::IndeterminateTimeout => 5,
        UsbStatus::Stall => 4,
        UsbStatus::DeviceRemoved => 3,
        UsbStatus::Unsupported | UsbStatus::ProtocolError => 2,
    };
    let mut body = match header.packet_type {
        CONTROL => {
            let setup = request
                .setup
                .ok_or(UsbRedirError::Malformed("control setup"))?;
            vec![
                request.endpoint,
                setup[1],
                setup[0],
                wire_status,
                setup[2],
                setup[3],
                setup[4],
                setup[5],
                0,
                0,
            ]
        }
        BULK => vec![request.endpoint, wire_status, 0, 0, 0, 0, 0, 0, 0, 0],
        INTERRUPT => vec![request.endpoint, wire_status, 0, 0],
        other => return Err(UsbRedirError::Unsupported(other)),
    };
    if header.packet_type == CONTROL {
        body[8..10].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    }
    if header.packet_type == BULK {
        body[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    }
    if header.packet_type == INTERRUPT {
        body[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    }
    body.extend_from_slice(payload);
    let header_len = if header.wide_ids { HEADER64 } else { HEADER32 };
    let mut frame = Vec::with_capacity(header_len + body.len());
    frame.extend_from_slice(&header.packet_type.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    if header.wide_ids {
        frame.extend_from_slice(&header.id.to_le_bytes());
    } else {
        frame.extend_from_slice(&(header.id as u32).to_le_bytes());
    }
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Return whether a peer hello advertises 64-bit packet IDs.
/// Hello packets always use the 32-bit header, even when the capability is
/// present; the wider header is legal only after both peers advertise it.
pub fn hello_supports_64bit_ids(frame: &[u8]) -> Result<bool, UsbRedirError> {
    let header = header(frame, false)?;
    if header.packet_type != HELLO || header.length < 64 {
        return Err(UsbRedirError::Malformed("hello packet"));
    }
    let body = &frame[HEADER32..];
    Ok(body[64..].chunks_exact(4).any(|cap| {
        u32::from_le_bytes(cap.try_into().expect("capability is four bytes")) == CAP_64BIT_IDS
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(packet_type: u32, id: u64, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&packet_type.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(id as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn decodes_bulk_in_without_accepting_payload() {
        let inbound = decode(
            &frame(BULK, 42, &[0x81, 0, 4, 0, 0, 0, 0, 0, 0, 0]),
            "00112233445566778899aabbccddeeff",
            3,
            100,
        )
        .unwrap();
        assert_eq!(inbound.request.request_id, 42);
        assert!(inbound.request.direction_in);
        assert_eq!(inbound.request.in_length, 4);
    }

    #[test]
    fn decodes_control_setup_and_echoes_it_in_response() {
        let body = [0, 0x09, 0x80, 0, 0x34, 0x12, 0x78, 0x56, 2, 0];
        let inbound = decode(&frame(CONTROL, 7, &body), "a", 1, 100).unwrap();
        let encoded = response(inbound.header, &inbound.request, UsbStatus::Ok, &[1, 2]).unwrap();
        assert_eq!(
            &encoded[12..22],
            &[0, 0x09, 0x80, 0, 0x34, 0x12, 0x78, 0x56, 2, 0]
        );
        assert_eq!(&encoded[22..], &[1, 2]);
    }

    #[test]
    fn rejects_iso_and_bad_lengths() {
        assert_eq!(
            decode(&frame(102, 1, &[]), "a", 1, 100),
            Err(UsbRedirError::Unsupported(102))
        );
        assert_eq!(
            decode(&frame(BULK, 1, &[1, 0, 4]), "a", 1, 100),
            Err(UsbRedirError::Malformed("bulk header"))
        );
    }

    #[test]
    fn hello_capability_uses_32_bit_header_before_wide_ids() {
        let mut body = vec![0; 68];
        body[64..68].copy_from_slice(&CAP_64BIT_IDS.to_le_bytes());
        let hello = frame(HELLO, 0, &body);
        assert!(hello_supports_64bit_ids(&hello).unwrap());
        assert_eq!(header(&hello, true).unwrap().wide_ids, false);
    }
}
