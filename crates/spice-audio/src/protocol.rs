//! Wire constants taken from the permissively licensed `spice-protocol`
//! definitions.  Nothing here is derived from an LGPL client implementation.

/// Link header magic, `REDQ` in wire order.
pub const MAGIC: u32 = u32::from_le_bytes(*b"REDQ");
/// Protocol major version this codec speaks.
pub const VERSION_MAJOR: u32 = 2;
/// Protocol minor version this codec speaks.
pub const VERSION_MINOR: u32 = 2;

/// Bytes in a `SpiceLinkHeader`.
pub const LINK_HEADER_BYTES: usize = 16;
/// Bytes in a `SpiceLinkMess`, excluding its capability words.
pub const LINK_MESS_BYTES: usize = 18;
/// Bytes in a `SpiceLinkReply`, excluding its capability words.
pub const LINK_REPLY_BYTES: usize = 178;
/// Bytes in the server's RSA public key blob (a 1024-bit DER `SubjectPublicKeyInfo`).
pub const TICKET_PUBKEY_BYTES: usize = 162;
/// Bytes in the RSA-OAEP encrypted ticket the client sends back.
pub const TICKET_BYTES: usize = 128;
/// Longest password the server will accept, excluding the terminating NUL.
pub const MAX_PASSWORD_BYTES: usize = 60;
/// Bytes in a `SpiceMiniDataHeader`.
pub const MINI_HEADER_BYTES: usize = 6;

/// Largest link message this codec will accept, which bounds capability counts.
pub const MAX_LINK_BYTES: usize = 4096;
/// Largest channel message payload this codec will accept.
pub const MAX_MESSAGE_BYTES: usize = 512 * 1024;

/// SPICE channel types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChannelType {
    /// Session control; carries `MSG_MAIN_INIT` and the connection id.
    Main = 1,
    /// Guest-to-client audio.
    Playback = 5,
    /// Client-to-guest audio.
    Record = 6,
}

impl ChannelType {
    /// Parse a channel type, accepting only the three this codec speaks.
    #[must_use]
    pub fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Main),
            5 => Some(Self::Playback),
            6 => Some(Self::Record),
            _ => None,
        }
    }

    /// The channel's lowercase route name, as used by the console proxy.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Playback => "playback",
            Self::Record => "record",
        }
    }
}

/// Common capability: the client selects an authentication mechanism.
pub const COMMON_CAP_PROTOCOL_AUTH_SELECTION: u32 = 0;
/// Common capability: SPICE ticket authentication.
pub const COMMON_CAP_AUTH_SPICE: u32 = 1;
/// Common capability: SASL authentication, which this codec never offers.
pub const COMMON_CAP_AUTH_SASL: u32 = 2;
/// Common capability: six-byte message headers.
pub const COMMON_CAP_MINI_HEADER: u32 = 3;

/// Authentication mechanism selector sent when `PROTOCOL_AUTH_SELECTION` is agreed.
pub const AUTH_SELECTION_SPICE: u32 = 1;

/// Playback capability: Opus-coded frames.
pub const PLAYBACK_CAP_OPUS: u32 = 3;
/// Record capability: Opus-coded frames.
pub const RECORD_CAP_OPUS: u32 = 2;

/// Link succeeded.
pub const LINK_ERR_OK: u32 = 0;

/// Server-to-client message: the channel is disconnecting.
pub const MSG_DISCONNECTING: u16 = 6;
/// Server-to-client message: a human-readable notification.
pub const MSG_NOTIFY: u16 = 7;
/// Server-to-client message: request acknowledgement windows.
pub const MSG_SET_ACK: u16 = 3;
/// Server-to-client message: latency probe.
pub const MSG_PING: u16 = 4;
/// Client-to-server message: begin acknowledging at this serial.
pub const MSGC_ACK_SYNC: u16 = 1;
/// Client-to-server message: acknowledge one window.
pub const MSGC_ACK: u16 = 2;
/// Client-to-server message: reply to `MSG_PING`.
pub const MSGC_PONG: u16 = 3;

/// Main channel: session parameters, including the connection id.
pub const MSG_MAIN_INIT: u16 = 103;
/// Main channel: the channels this session offers.
pub const MSG_MAIN_CHANNELS_LIST: u16 = 104;
/// Main channel: the current and supported mouse modes.
pub const MSG_MAIN_MOUSE_MODE: u16 = 105;
/// Main channel: the server's media clock.
pub const MSG_MAIN_MULTI_MEDIA_TIME: u16 = 106;
/// Main channel, client-to-server: client identification.
pub const MSGC_MAIN_CLIENT_INFO: u16 = 101;
/// Main channel, client-to-server: request the channel list.
pub const MSGC_MAIN_ATTACH_CHANNELS: u16 = 104;

/// Playback channel: coded or raw audio.
pub const MSG_PLAYBACK_DATA: u16 = 101;
/// Playback channel: the coding mode of subsequent data.
pub const MSG_PLAYBACK_MODE: u16 = 102;
/// Playback channel: the stream is starting.
pub const MSG_PLAYBACK_START: u16 = 103;
/// Playback channel: the stream has stopped.
pub const MSG_PLAYBACK_STOP: u16 = 104;
/// Playback channel: per-channel volume.
pub const MSG_PLAYBACK_VOLUME: u16 = 105;
/// Playback channel: mute state.
pub const MSG_PLAYBACK_MUTE: u16 = 106;
/// Playback channel: the guest's requested latency.
pub const MSG_PLAYBACK_LATENCY: u16 = 107;

/// Record channel: the guest has opened the capture stream.
pub const MSG_RECORD_START: u16 = 101;
/// Record channel: the guest has closed the capture stream.
pub const MSG_RECORD_STOP: u16 = 102;
/// Record channel: per-channel volume.
pub const MSG_RECORD_VOLUME: u16 = 103;
/// Record channel: mute state.
pub const MSG_RECORD_MUTE: u16 = 104;
/// Record channel, client-to-server: captured audio.
pub const MSGC_RECORD_DATA: u16 = 101;
/// Record channel, client-to-server: the coding mode of subsequent data.
pub const MSGC_RECORD_MODE: u16 = 102;
/// Record channel, client-to-server: the first sample's server timestamp.
pub const MSGC_RECORD_START_MARK: u16 = 103;

/// Audio coding modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AudioMode {
    /// Uncompressed interleaved samples in the negotiated format.
    Raw = 1,
    /// CELT 0.5.1, which this codec never negotiates.
    Celt = 2,
    /// Opus frames.
    Opus = 3,
}

impl AudioMode {
    /// Parse a coding mode.
    #[must_use]
    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Raw),
            2 => Some(Self::Celt),
            3 => Some(Self::Opus),
            _ => None,
        }
    }
}

/// Signed 16-bit little-endian samples, the only sample format SPICE defines.
pub const AUDIO_FMT_S16: u16 = 1;
