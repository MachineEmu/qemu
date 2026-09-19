//! The single error type shared by the link, framing, and message codecs.

use thiserror::Error;

/// A SPICE codec failure.  Every variant is a reason to close the connection.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SpiceError {
    /// The frame ended before a fixed-size structure was complete.
    #[error("short SPICE frame")]
    Short,
    /// A declared length exceeded the codec's bound.
    #[error("SPICE frame of {0} bytes exceeds the size limit")]
    TooLarge(usize),
    /// The bytes parsed but described something the codec refuses.
    #[error("malformed SPICE frame: {0}")]
    Malformed(&'static str),
    /// The peer asked for a channel this codec will not carry.
    #[error("unsupported SPICE channel type {0}")]
    UnsupportedChannel(u8),
    /// The server rejected the link.
    #[error("SPICE link failed with error {0}")]
    LinkRejected(u32),
}
