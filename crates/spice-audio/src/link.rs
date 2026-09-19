//! The SPICE channel-link handshake: header, link message, reply, and ticket.
//!
//! Every length is checked against [`protocol::MAX_LINK_BYTES`] before an
//! allocation is made, and every capability offset is validated against the
//! frame actually received, so a hostile peer cannot steer a read past the
//! buffer or force an unbounded allocation.

use crate::error::SpiceError;
use crate::protocol::{self, ChannelType};

/// A parsed `SpiceLinkHeader`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkHeader {
    /// Protocol major version.
    pub major: u32,
    /// Protocol minor version.
    pub minor: u32,
    /// Bytes of link message that follow this header.
    pub size: u32,
}

impl LinkHeader {
    /// Parse a header, rejecting a foreign magic, version, or oversized body.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the frame is short, the magic or version
    /// does not match, or `size` exceeds [`protocol::MAX_LINK_BYTES`].
    pub fn parse(frame: &[u8]) -> Result<Self, SpiceError> {
        let bytes: [u8; protocol::LINK_HEADER_BYTES] = frame
            .get(..protocol::LINK_HEADER_BYTES)
            .ok_or(SpiceError::Short)?
            .try_into()
            .map_err(|_| SpiceError::Short)?;
        let word = |index: usize| u32::from_le_bytes(bytes[index..index + 4].try_into().unwrap());
        if word(0) != protocol::MAGIC {
            return Err(SpiceError::Malformed("link magic is not REDQ"));
        }
        let (major, minor, size) = (word(4), word(8), word(12));
        if major != protocol::VERSION_MAJOR {
            return Err(SpiceError::Malformed("unsupported SPICE major version"));
        }
        if size as usize > protocol::MAX_LINK_BYTES {
            return Err(SpiceError::TooLarge(size as usize));
        }
        Ok(Self { major, minor, size })
    }

    /// Serialize the header for a body of `size` bytes.
    #[must_use]
    pub fn encode(size: u32) -> [u8; protocol::LINK_HEADER_BYTES] {
        let mut out = [0u8; protocol::LINK_HEADER_BYTES];
        out[0..4].copy_from_slice(&protocol::MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&protocol::VERSION_MAJOR.to_le_bytes());
        out[8..12].copy_from_slice(&protocol::VERSION_MINOR.to_le_bytes());
        out[12..16].copy_from_slice(&size.to_le_bytes());
        out
    }
}

/// A parsed `SpiceLinkMess`: the client's request to link one channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkMess {
    /// Session connection id; zero on the first main link.
    pub connection_id: u32,
    /// Raw channel type, kept unparsed so a rejected type can be reported.
    pub channel_type: u8,
    /// Channel instance id.
    pub channel_id: u8,
    /// Capabilities common to every channel.
    pub common_caps: Vec<u32>,
    /// Capabilities specific to this channel type.
    pub channel_caps: Vec<u32>,
}

fn capabilities(body: &[u8], offset: u32, count: u32, total: u32) -> Result<Vec<u32>, SpiceError> {
    let start = offset as usize;
    let words = count as usize;
    if words > protocol::MAX_LINK_BYTES / 4 || total as usize > protocol::MAX_LINK_BYTES / 4 {
        return Err(SpiceError::TooLarge(words * 4));
    }
    let end = start
        .checked_add(words * 4)
        .ok_or(SpiceError::Malformed("capability offset overflows"))?;
    let slice = body.get(start..end).ok_or(SpiceError::Malformed(
        "capabilities fall outside the link message",
    ))?;
    Ok(slice
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect())
}

impl LinkMess {
    /// Parse a link message body, which excludes the preceding header.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the body is short, a capability count is
    /// implausible, or a capability offset does not lie inside the body.
    pub fn parse(body: &[u8]) -> Result<Self, SpiceError> {
        if body.len() > protocol::MAX_LINK_BYTES {
            return Err(SpiceError::TooLarge(body.len()));
        }
        let head = body
            .get(..protocol::LINK_MESS_BYTES)
            .ok_or(SpiceError::Short)?;
        let word = |index: usize| u32::from_le_bytes(head[index..index + 4].try_into().unwrap());
        let (num_common, num_channel, caps_offset) = (word(6), word(10), word(14));
        let total = num_common
            .checked_add(num_channel)
            .ok_or(SpiceError::Malformed("capability count overflows"))?;
        let common_caps = capabilities(body, caps_offset, num_common, total)?;
        let channel_caps = capabilities(body, caps_offset + num_common * 4, num_channel, total)?;
        Ok(Self {
            connection_id: word(0),
            channel_type: head[4],
            channel_id: head[5],
            common_caps,
            channel_caps,
        })
    }

    /// Serialize this link message, capabilities packed directly after the fields.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let offset = u32::try_from(protocol::LINK_MESS_BYTES).unwrap();
        let mut out = Vec::with_capacity(
            protocol::LINK_MESS_BYTES + (self.common_caps.len() + self.channel_caps.len()) * 4,
        );
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        out.push(self.channel_type);
        out.push(self.channel_id);
        out.extend_from_slice(&u32::try_from(self.common_caps.len()).unwrap().to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(self.channel_caps.len())
                .unwrap()
                .to_le_bytes(),
        );
        out.extend_from_slice(&offset.to_le_bytes());
        for cap in self.common_caps.iter().chain(&self.channel_caps) {
            out.extend_from_slice(&cap.to_le_bytes());
        }
        out
    }

    /// The channel type, when it is one this codec is willing to speak.
    #[must_use]
    pub fn channel(&self) -> Option<ChannelType> {
        ChannelType::from_wire(self.channel_type)
    }

    /// Whether a common capability bit is set.
    #[must_use]
    pub fn has_common_cap(&self, bit: u32) -> bool {
        has_cap(&self.common_caps, bit)
    }

    /// Whether a channel capability bit is set.
    #[must_use]
    pub fn has_channel_cap(&self, bit: u32) -> bool {
        has_cap(&self.channel_caps, bit)
    }

    /// Build the link message a client sends for `channel`.
    #[must_use]
    pub fn client(channel: ChannelType, connection_id: u32, opus: bool) -> Self {
        let mut channel_caps = Vec::new();
        if opus {
            match channel {
                ChannelType::Playback => channel_caps.push(cap_word(protocol::PLAYBACK_CAP_OPUS)),
                ChannelType::Record => channel_caps.push(cap_word(protocol::RECORD_CAP_OPUS)),
                ChannelType::Main => {}
            }
        }
        Self {
            connection_id,
            channel_type: channel as u8,
            channel_id: 0,
            common_caps: vec![
                cap_word(protocol::COMMON_CAP_PROTOCOL_AUTH_SELECTION)
                    | cap_word(protocol::COMMON_CAP_AUTH_SPICE)
                    | cap_word(protocol::COMMON_CAP_MINI_HEADER),
            ],
            channel_caps,
        }
    }
}

/// A capability word with a single bit set, for capabilities below 32.
#[must_use]
pub fn cap_word(bit: u32) -> u32 {
    1 << (bit % 32)
}

fn has_cap(words: &[u32], bit: u32) -> bool {
    words
        .get(bit as usize / 32)
        .is_some_and(|word| word & (1 << (bit % 32)) != 0)
}

/// A parsed `SpiceLinkReply`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkReply {
    /// Link error code; zero means the handshake may continue.
    pub error: u32,
    /// The server's RSA public key, DER-encoded.
    pub pub_key: Vec<u8>,
    /// Capabilities common to every channel.
    pub common_caps: Vec<u32>,
    /// Capabilities specific to this channel type.
    pub channel_caps: Vec<u32>,
}

impl LinkReply {
    /// Parse a link reply body, which excludes the preceding header.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the body is short or its capability
    /// offsets do not lie inside the body.
    pub fn parse(body: &[u8]) -> Result<Self, SpiceError> {
        if body.len() > protocol::MAX_LINK_BYTES {
            return Err(SpiceError::TooLarge(body.len()));
        }
        let head = body
            .get(..protocol::LINK_REPLY_BYTES)
            .ok_or(SpiceError::Short)?;
        let word = |index: usize| u32::from_le_bytes(head[index..index + 4].try_into().unwrap());
        let (num_common, num_channel, caps_offset) = (word(166), word(170), word(174));
        let total = num_common
            .checked_add(num_channel)
            .ok_or(SpiceError::Malformed("capability count overflows"))?;
        Ok(Self {
            error: word(0),
            pub_key: head[4..4 + protocol::TICKET_PUBKEY_BYTES].to_vec(),
            common_caps: capabilities(body, caps_offset, num_common, total)?,
            channel_caps: capabilities(body, caps_offset + num_common * 4, num_channel, total)?,
        })
    }

    /// Serialize this reply.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let offset = u32::try_from(protocol::LINK_REPLY_BYTES).unwrap();
        let mut out = Vec::with_capacity(protocol::LINK_REPLY_BYTES);
        out.extend_from_slice(&self.error.to_le_bytes());
        let mut key = self.pub_key.clone();
        key.resize(protocol::TICKET_PUBKEY_BYTES, 0);
        out.extend_from_slice(&key);
        out.extend_from_slice(&u32::try_from(self.common_caps.len()).unwrap().to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(self.channel_caps.len())
                .unwrap()
                .to_le_bytes(),
        );
        out.extend_from_slice(&offset.to_le_bytes());
        for cap in self.common_caps.iter().chain(&self.channel_caps) {
            out.extend_from_slice(&cap.to_le_bytes());
        }
        out
    }

    /// Whether a common capability bit is set.
    #[must_use]
    pub fn has_common_cap(&self, bit: u32) -> bool {
        has_cap(&self.common_caps, bit)
    }

    /// Whether a channel capability bit is set.
    #[must_use]
    pub fn has_channel_cap(&self, bit: u32) -> bool {
        has_cap(&self.channel_caps, bit)
    }
}

/// Encrypt the ticket the server expects after its link reply.
///
/// The server requires the 128-byte RSA-OAEP-SHA1 blob even when it was
/// started with `disable-ticketing=on`, in which case any password is
/// accepted and the empty one is conventional.
///
/// # Errors
/// Returns [`SpiceError`] when the password is too long, the public key does
/// not parse, or encryption fails.
pub fn encrypt_ticket(pub_key: &[u8], password: &str) -> Result<Vec<u8>, SpiceError> {
    use rsa::RsaPublicKey;
    use rsa::oaep::Oaep;
    use rsa::pkcs8::DecodePublicKey;

    if password.len() > protocol::MAX_PASSWORD_BYTES {
        return Err(SpiceError::Malformed("SPICE password exceeds 60 bytes"));
    }
    let key = RsaPublicKey::from_public_key_der(pub_key)
        .map_err(|_| SpiceError::Malformed("server public key is not a DER RSA key"))?;
    let mut plain = password.as_bytes().to_vec();
    plain.push(0);
    let cipher = key
        .encrypt(
            &mut rsa::rand_core::OsRng,
            Oaep::new::<sha1::Sha1>(),
            &plain,
        )
        .map_err(|_| SpiceError::Malformed("ticket encryption failed"))?;
    if cipher.len() != protocol::TICKET_BYTES {
        return Err(SpiceError::Malformed("ticket is not 128 bytes"));
    }
    Ok(cipher)
}
