//! Mini-header framing and the audio messages carried inside it.
//!
//! The codec negotiates `COMMON_CAP_MINI_HEADER` on every channel, so a
//! message is a six-byte header (`u16` type, `u32` size) followed by its
//! payload.  [`Framer`] turns an arbitrarily chunked byte stream into whole
//! messages without ever buffering more than one oversized message's worth.

use crate::error::SpiceError;
use crate::protocol::{self, AudioMode};

/// A whole channel message: its type and its payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    /// Message type, interpreted relative to the channel it arrived on.
    pub kind: u16,
    /// Message payload, excluding the mini header.
    pub payload: Vec<u8>,
}

impl Message {
    /// Serialize the message with its mini header.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(protocol::MINI_HEADER_BYTES + self.payload.len());
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.payload.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Reassembles mini-header messages from a byte stream.
#[derive(Debug, Default)]
pub struct Framer {
    buffer: Vec<u8>,
}

impl Framer {
    /// A framer with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `data` and return every message it completed.
    ///
    /// # Errors
    /// Returns [`SpiceError::TooLarge`] when a header declares a payload
    /// larger than [`protocol::MAX_MESSAGE_BYTES`], which is a protocol
    /// violation rather than a reason to grow the buffer.
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Message>, SpiceError> {
        self.buffer.extend_from_slice(data);
        let mut out = Vec::new();
        let mut offset = 0usize;
        while self.buffer.len() - offset >= protocol::MINI_HEADER_BYTES {
            let head = &self.buffer[offset..offset + protocol::MINI_HEADER_BYTES];
            let kind = u16::from_le_bytes(head[0..2].try_into().unwrap());
            let size = u32::from_le_bytes(head[2..6].try_into().unwrap()) as usize;
            if size > protocol::MAX_MESSAGE_BYTES {
                return Err(SpiceError::TooLarge(size));
            }
            let end = offset + protocol::MINI_HEADER_BYTES + size;
            if self.buffer.len() < end {
                break;
            }
            out.push(Message {
                kind,
                payload: self.buffer[offset + protocol::MINI_HEADER_BYTES..end].to_vec(),
            });
            offset = end;
        }
        if offset > 0 {
            self.buffer.drain(..offset);
        }
        Ok(out)
    }

    /// Bytes held for an incomplete message.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

/// `SpiceMsgMainInit`, of which only the connection id matters to an audio client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MainInit {
    /// The connection id every subsequent channel link must carry.
    pub connection_id: u32,
    /// The server's media clock at the moment the session was created.
    pub multi_media_time: u32,
}

impl MainInit {
    /// Parse `MSG_MAIN_INIT`.
    ///
    /// # Errors
    /// Returns [`SpiceError::Short`] when the payload is shorter than the
    /// eight `u32` fields the structure defines.
    pub fn parse(payload: &[u8]) -> Result<Self, SpiceError> {
        let head = payload.get(..32).ok_or(SpiceError::Short)?;
        let word = |index: usize| u32::from_le_bytes(head[index..index + 4].try_into().unwrap());
        Ok(Self {
            connection_id: word(0),
            multi_media_time: word(24),
        })
    }

    /// Serialize `MSG_MAIN_INIT` with plausible values for the unused fields.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        for word in [self.connection_id, 0, 1, 1, 0, 0, self.multi_media_time, 0] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// `SpiceMsgPlaybackStart`: the format of the stream that is about to play.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaybackStart {
    /// Interleaved channel count.
    pub channels: u32,
    /// Sample format; SPICE only defines [`protocol::AUDIO_FMT_S16`].
    pub format: u16,
    /// Sample rate in hertz.
    pub frequency: u32,
    /// The server's media clock at the first sample.
    pub time: u32,
}

impl PlaybackStart {
    /// Parse `MSG_PLAYBACK_START`.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the payload is short or the sample format
    /// is not one SPICE defines.
    pub fn parse(payload: &[u8]) -> Result<Self, SpiceError> {
        let head = payload.get(..14).ok_or(SpiceError::Short)?;
        let format = u16::from_le_bytes(head[4..6].try_into().unwrap());
        if format != protocol::AUDIO_FMT_S16 {
            return Err(SpiceError::Malformed("unsupported SPICE sample format"));
        }
        Ok(Self {
            channels: u32::from_le_bytes(head[0..4].try_into().unwrap()),
            format,
            frequency: u32::from_le_bytes(head[6..10].try_into().unwrap()),
            time: u32::from_le_bytes(head[10..14].try_into().unwrap()),
        })
    }

    /// Serialize `MSG_PLAYBACK_START`.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.frequency.to_le_bytes());
        out.extend_from_slice(&self.time.to_le_bytes());
        out
    }
}

/// `SpiceMsgRecordStart`: the format the guest has opened for capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordStart {
    /// Interleaved channel count.
    pub channels: u32,
    /// Sample format; SPICE only defines [`protocol::AUDIO_FMT_S16`].
    pub format: u16,
    /// Sample rate in hertz.
    pub frequency: u32,
}

impl RecordStart {
    /// Parse `MSG_RECORD_START`.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the payload is short or the sample format
    /// is not one SPICE defines.
    pub fn parse(payload: &[u8]) -> Result<Self, SpiceError> {
        let head = payload.get(..10).ok_or(SpiceError::Short)?;
        let format = u16::from_le_bytes(head[4..6].try_into().unwrap());
        if format != protocol::AUDIO_FMT_S16 {
            return Err(SpiceError::Malformed("unsupported SPICE sample format"));
        }
        Ok(Self {
            channels: u32::from_le_bytes(head[0..4].try_into().unwrap()),
            format,
            frequency: u32::from_le_bytes(head[6..10].try_into().unwrap()),
        })
    }

    /// Serialize `MSG_RECORD_START`.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10);
        out.extend_from_slice(&self.channels.to_le_bytes());
        out.extend_from_slice(&self.format.to_le_bytes());
        out.extend_from_slice(&self.frequency.to_le_bytes());
        out
    }
}

/// A timestamped audio payload: `MSG_PLAYBACK_DATA` or `MSGC_RECORD_DATA`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioData {
    /// The server's media clock for the first sample in `samples`.
    pub time: u32,
    /// Coded or raw audio, depending on the negotiated mode.
    pub samples: Vec<u8>,
}

impl AudioData {
    /// Parse a timestamped audio payload.
    ///
    /// # Errors
    /// Returns [`SpiceError::Short`] when the payload has no timestamp.
    pub fn parse(payload: &[u8]) -> Result<Self, SpiceError> {
        let head = payload.get(..4).ok_or(SpiceError::Short)?;
        Ok(Self {
            time: u32::from_le_bytes(head.try_into().unwrap()),
            samples: payload[4..].to_vec(),
        })
    }

    /// Serialize a timestamped audio payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.samples.len());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.samples);
        out
    }
}

/// A coding-mode announcement: `MSG_PLAYBACK_MODE` or `MSGC_RECORD_MODE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeMessage {
    /// The server's media clock at which the mode takes effect.
    pub time: u32,
    /// The coding mode of subsequent data messages.
    pub mode: AudioMode,
    /// Codec setup bytes, empty for raw and for Opus as QEMU sends it.
    pub data: Vec<u8>,
}

impl ModeMessage {
    /// Parse a coding-mode announcement.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the payload is short or names a coding
    /// mode this codec does not implement.
    pub fn parse(payload: &[u8]) -> Result<Self, SpiceError> {
        let head = payload.get(..6).ok_or(SpiceError::Short)?;
        let raw = u16::from_le_bytes(head[4..6].try_into().unwrap());
        Ok(Self {
            time: u32::from_le_bytes(head[0..4].try_into().unwrap()),
            mode: AudioMode::from_wire(raw)
                .ok_or(SpiceError::Malformed("unknown SPICE audio mode"))?,
            data: payload[6..].to_vec(),
        })
    }

    /// Serialize a coding-mode announcement.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.data.len());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&(self.mode as u16).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}
