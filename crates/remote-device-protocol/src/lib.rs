//! The transport-independent contract shared by the remote-device bridge.
//! Payloads are deliberately opaque here: adapters own USB, CTAP, and
//! WebAuthn encoding and this crate owns bounds, correlation, and lifecycle.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL: &str = "remote-device.v1";
pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_DESCRIPTORS: usize = 128 * 1024;
pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;
pub const MAX_OUTSTANDING: usize = 16;
pub const BINARY_HEADER_BYTES: usize = 40;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Webauthn,
    Ctap,
    Usb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Local,
    Guest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbTransferType {
    Control,
    Bulk,
    Interrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbStatus {
    Ok,
    ShortTransfer,
    Stall,
    DeviceRemoved,
    Unsupported,
    ProtocolError,
    IndeterminateTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentState {
    Reserved,
    Connecting,
    Active,
    Draining,
    Closed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    UsbRequest = 1,
    UsbResponse = 2,
    Disconnect = 3,
    Cancel = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryHeader {
    pub kind: FrameKind,
    pub attachment_id: [u8; 16],
    pub generation: u64,
    pub request_id: u64,
    pub payload_length: u32,
}

impl BinaryHeader {
    /// Encode the fixed little-endian header. The attachment ID is the raw
    /// 16-byte value represented by the API's 32-character hex ID.
    pub fn encode(self) -> [u8; BINARY_HEADER_BYTES] {
        let mut out = [0; BINARY_HEADER_BYTES];
        out[0..2].copy_from_slice(&1u16.to_le_bytes());
        out[2] = self.kind as u8;
        out[4..20].copy_from_slice(&self.attachment_id);
        out[20..28].copy_from_slice(&self.generation.to_le_bytes());
        out[28..36].copy_from_slice(&self.request_id.to_le_bytes());
        out[36..40].copy_from_slice(&self.payload_length.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < BINARY_HEADER_BYTES {
            return Err(ProtocolError::InvalidRequest("short binary header"));
        }
        if u16::from_le_bytes([bytes[0], bytes[1]]) != 1 {
            return Err(ProtocolError::InvalidRequest("binary protocol version"));
        }
        let kind = match bytes[2] {
            1 => FrameKind::UsbRequest,
            2 => FrameKind::UsbResponse,
            3 => FrameKind::Disconnect,
            4 => FrameKind::Cancel,
            _ => return Err(ProtocolError::InvalidRequest("binary frame kind")),
        };
        let mut attachment_id = [0; 16];
        attachment_id.copy_from_slice(&bytes[4..20]);
        let mut generation = [0; 8];
        generation.copy_from_slice(&bytes[20..28]);
        let mut request_id = [0; 8];
        request_id.copy_from_slice(&bytes[28..36]);
        let mut payload_length = [0; 4];
        payload_length.copy_from_slice(&bytes[36..40]);
        let header = Self {
            kind,
            attachment_id,
            generation: u64::from_le_bytes(generation),
            request_id: u64::from_le_bytes(request_id),
            payload_length: u32::from_le_bytes(payload_length),
        };
        if header.generation == 0
            || header.request_id == 0
            || header.payload_length as usize > MAX_PAYLOAD
        {
            return Err(ProtocolError::InvalidRequest("binary frame bounds"));
        }
        Ok(header)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub protocol: String,
    pub mode: Mode,
    pub role: Role,
    pub attachment_id: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceMetadata {
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub descriptors: Vec<u8>,
    pub configuration: u8,
    pub interfaces: Vec<u8>,
    pub endpoints: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsbRequest {
    pub attachment_id: String,
    pub generation: u64,
    pub request_id: u64,
    pub interface: u8,
    pub endpoint: u8,
    pub direction_in: bool,
    pub transfer_type: UsbTransferType,
    pub deadline_ms: u32,
    pub setup: Option<[u8; 8]>,
    pub payload: Vec<u8>,
    pub in_length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UsbResponse {
    pub attachment_id: String,
    pub generation: u64,
    pub request_id: u64,
    pub status: UsbStatus,
    pub usb_error: Option<String>,
    pub transferred: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("unsupported protocol {0}")]
    UnsupportedProtocol(String),
    #[error("payload exceeds {limit} bytes")]
    PayloadTooLarge { limit: usize },
    #[error("descriptor tree exceeds {limit} bytes")]
    DescriptorsTooLarge { limit: usize },
    #[error("invalid USB request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: AttachmentState,
        to: AttachmentState,
    },
}

impl Hello {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != PROTOCOL {
            return Err(ProtocolError::UnsupportedProtocol(self.protocol.clone()));
        }
        if self.attachment_id.is_empty() || self.attachment_id.len() > 64 {
            return Err(ProtocolError::InvalidRequest("attachment id"));
        }
        if self.generation == 0 {
            return Err(ProtocolError::InvalidRequest("generation"));
        }
        Ok(())
    }
}

impl DeviceMetadata {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.descriptors.len() > MAX_DESCRIPTORS {
            return Err(ProtocolError::DescriptorsTooLarge {
                limit: MAX_DESCRIPTORS,
            });
        }
        if self.interfaces.is_empty() || self.endpoints.is_empty() {
            return Err(ProtocolError::InvalidRequest(
                "device has no claimed interface or endpoint",
            ));
        }
        Ok(())
    }
}

impl UsbRequest {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.attachment_id.is_empty() || self.generation == 0 || self.request_id == 0 {
            return Err(ProtocolError::InvalidRequest("correlation fields"));
        }
        if self.deadline_ms == 0 {
            return Err(ProtocolError::InvalidRequest("deadline"));
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge { limit: MAX_PAYLOAD });
        }
        if self.direction_in && self.in_length as usize > MAX_PAYLOAD {
            return Err(ProtocolError::PayloadTooLarge { limit: MAX_PAYLOAD });
        }
        if self.direction_in && !self.payload.is_empty() {
            return Err(ProtocolError::InvalidRequest("IN request has OUT payload"));
        }
        if !self.direction_in && self.in_length != 0 {
            return Err(ProtocolError::InvalidRequest("OUT request has IN length"));
        }
        if self.transfer_type == UsbTransferType::Control && self.setup.is_none() {
            return Err(ProtocolError::InvalidRequest("control setup"));
        }
        Ok(())
    }
}

pub fn transition(from: AttachmentState, to: AttachmentState) -> Result<(), ProtocolError> {
    let valid = matches!(
        (from, to),
        (
            AttachmentState::Reserved,
            AttachmentState::Connecting | AttachmentState::Closed
        ) | (
            AttachmentState::Connecting,
            AttachmentState::Active | AttachmentState::Draining
        ) | (AttachmentState::Active, AttachmentState::Draining)
            | (
                AttachmentState::Draining,
                AttachmentState::Closed | AttachmentState::Quarantined
            )
            | (AttachmentState::Quarantined, AttachmentState::Closed)
    );
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidTransition { from, to })
    }
}

pub fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_and_malformed_requests() {
        let mut request = UsbRequest {
            attachment_id: "a".into(),
            generation: 1,
            request_id: 1,
            interface: 0,
            endpoint: 1,
            direction_in: false,
            transfer_type: UsbTransferType::Bulk,
            deadline_ms: 1,
            setup: None,
            payload: vec![0; MAX_PAYLOAD + 1],
            in_length: 0,
        };
        assert!(matches!(
            request.validate(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
        request.payload.clear();
        request.direction_in = true;
        request.in_length = 1;
        request.payload.push(1);
        assert_eq!(
            request.validate(),
            Err(ProtocolError::InvalidRequest("IN request has OUT payload"))
        );
    }

    #[test]
    fn teardown_is_one_way() {
        assert!(transition(AttachmentState::Active, AttachmentState::Draining).is_ok());
        assert!(transition(AttachmentState::Draining, AttachmentState::Active).is_err());
    }

    #[test]
    fn binary_header_is_fixed_and_bounded() {
        let header = BinaryHeader {
            kind: FrameKind::UsbRequest,
            attachment_id: [7; 16],
            generation: 2,
            request_id: 9,
            payload_length: 12,
        };
        assert_eq!(BinaryHeader::decode(&header.encode()), Ok(header));
        let mut encoded = header.encode();
        encoded[36..40].copy_from_slice(&((MAX_PAYLOAD as u32) + 1).to_le_bytes());
        assert!(BinaryHeader::decode(&encoded).is_err());
    }
}
