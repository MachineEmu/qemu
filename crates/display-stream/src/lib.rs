//! Transport-independent framing for the QEMU display video path.
//!
//! The encoder and QEMU D-Bus listener are deliberately separate from this
//! module.  This keeps the browser contract testable on machines without a
//! guest, VA-API, or a graphical session.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod frame;
pub mod gpu_bridge;
pub mod listener;

pub const HEADER_LEN: usize = 16;
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Config = 0,
    Keyframe = 1,
    Delta = 2,
    Resize = 3,
    Control = 4,
    AudioConfig = 5,
    AudioData = 6,
}

impl TryFrom<u8> for RecordType {
    type Error = VideoError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Config),
            1 => Ok(Self::Keyframe),
            2 => Ok(Self::Delta),
            3 => Ok(Self::Resize),
            4 => Ok(Self::Control),
            5 => Ok(Self::AudioConfig),
            6 => Ok(Self::AudioData),
            _ => Err(VideoError::UnknownType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: RecordType,
    pub flags: u8,
    pub pts_us: u64,
    pub payload: Bytes,
}

impl Record {
    pub fn encode(&self, output: &mut BytesMut) -> Result<(), VideoError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(VideoError::PayloadTooLarge);
        }
        output.reserve(HEADER_LEN + self.payload.len());
        output.put_u8(self.kind as u8);
        output.put_u8(self.flags);
        output.put_u16(0);
        output.put_u32(self.payload.len() as u32);
        output.put_u64(self.pts_us);
        output.extend_from_slice(&self.payload);
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VideoError {
    #[error("unknown display record type {0}")]
    UnknownType(u8),
    #[error("display record payload is too large")]
    PayloadTooLarge,
    #[error("display record has a non-zero reserved field")]
    Reserved,
    #[error("display record is truncated")]
    Truncated,
}

pub fn decode(input: &mut BytesMut) -> Result<Option<Record>, VideoError> {
    if input.len() < HEADER_LEN {
        return Ok(None);
    }
    let mut header = &input[..HEADER_LEN];
    let kind = RecordType::try_from(header.get_u8())?;
    let flags = header.get_u8();
    if header.get_u16() != 0 {
        return Err(VideoError::Reserved);
    }
    let length = header.get_u32() as usize;
    let pts_us = header.get_u64();
    if length > MAX_PAYLOAD {
        return Err(VideoError::PayloadTooLarge);
    }
    if input.len() < HEADER_LEN + length {
        return Ok(None);
    }
    input.advance(HEADER_LEN);
    Ok(Some(Record {
        kind,
        flags,
        pts_us,
        payload: input.split_to(length).freeze(),
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoConfig {
    pub codec: String,
    #[serde(rename = "codedWidth")]
    pub coded_width: u32,
    #[serde(rename = "codedHeight")]
    pub coded_height: u32,
    /// AVCDecoderConfigurationRecord bytes for WebCodecs.
    pub description: Vec<u8>,
    /// Server-side source path, such as `dmabuf` or `cpu-readback`.
    pub capture: String,
    /// Server-side H.264 encoder implementation.
    pub encoder: String,
    /// Whether the server-side encoder is hardware accelerated.
    pub hardware: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_with_partial_input() {
        let record = Record {
            kind: RecordType::Keyframe,
            flags: 1,
            pts_us: 42,
            payload: Bytes::from_static(b"\x00\x00\x00\x01\x65"),
        };
        let mut encoded = BytesMut::new();
        record.encode(&mut encoded).unwrap();
        let split = encoded.split_off(7);
        let mut input = encoded;
        assert!(decode(&mut input).unwrap().is_none());
        input.extend_from_slice(&split);
        assert_eq!(decode(&mut input).unwrap(), Some(record));
        assert!(input.is_empty());
    }

    #[test]
    fn config_uses_browser_names() {
        let config = VideoConfig {
            codec: "avc1.640028".into(),
            coded_width: 1920,
            coded_height: 1080,
            description: Vec::new(),
            capture: "dmabuf".into(),
            encoder: "vaapi".into(),
            hardware: true,
        };
        assert_eq!(
            serde_json::to_string(&config).unwrap(),
            r#"{"codec":"avc1.640028","codedWidth":1920,"codedHeight":1080,"description":[],"capture":"dmabuf","encoder":"vaapi","hardware":true}"#
        );
    }

    #[test]
    fn audio_records_round_trip() {
        for kind in [RecordType::AudioConfig, RecordType::AudioData] {
            let record = Record {
                kind,
                flags: 0,
                pts_us: 1_234,
                payload: Bytes::from_static(b"audio"),
            };
            let mut encoded = BytesMut::new();
            record.encode(&mut encoded).unwrap();
            assert_eq!(decode(&mut encoded).unwrap(), Some(record));
            assert!(encoded.is_empty());
        }
    }
}
