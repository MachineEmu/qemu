//! An async SPICE client for the three channels this crate speaks.
//!
//! The transport is a Unix stream because that is what QEMU's
//! `-spice unix=on,addr=...` exposes and what the console proxy connects to.
//! Each channel is its own connection: SPICE does not multiplex channels onto
//! one byte stream, and neither does the browser client.

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::SpiceError;
use crate::link::{LinkHeader, LinkMess, LinkReply, encrypt_ticket};
use crate::message::{Framer, MainInit, Message};
use crate::protocol::{self, ChannelType};

/// One linked SPICE channel.
#[derive(Debug)]
pub struct Channel {
    stream: UnixStream,
    framer: Framer,
    kind: ChannelType,
    opus: bool,
}

/// Read exactly `len` bytes, mapping a short read to [`SpiceError::Short`].
async fn read_exact(stream: &mut UnixStream, len: usize) -> Result<Vec<u8>, SpiceError> {
    let mut buffer = vec![0u8; len];
    stream
        .read_exact(&mut buffer)
        .await
        .map_err(|_| SpiceError::Short)?;
    Ok(buffer)
}

impl Channel {
    /// Link one channel on a fresh connection to `socket`.
    ///
    /// `connection_id` is zero for the first main channel and the id from
    /// [`MainInit`] for every channel after it.  The ticket is sent even when
    /// the server disabled ticketing, because the server still reads it.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the socket cannot be opened, the server's
    /// reply does not parse, the server refuses the link, or the server
    /// declines the mini-header capability this codec requires.
    pub async fn link(
        socket: &Path,
        kind: ChannelType,
        connection_id: u32,
        password: &str,
        opus: bool,
    ) -> Result<Self, SpiceError> {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| SpiceError::Malformed("SPICE socket could not be opened"))?;
        let mess = LinkMess::client(kind, connection_id, opus).encode();
        let header = LinkHeader::encode(u32::try_from(mess.len()).unwrap());
        stream
            .write_all(&header)
            .await
            .map_err(|_| SpiceError::Short)?;
        stream
            .write_all(&mess)
            .await
            .map_err(|_| SpiceError::Short)?;

        let head = LinkHeader::parse(&read_exact(&mut stream, protocol::LINK_HEADER_BYTES).await?)?;
        let body = read_exact(&mut stream, head.size as usize).await?;
        let reply = LinkReply::parse(&body)?;
        if reply.error != protocol::LINK_ERR_OK {
            return Err(SpiceError::LinkRejected(reply.error));
        }
        if !reply.has_common_cap(protocol::COMMON_CAP_MINI_HEADER) {
            return Err(SpiceError::Malformed("server declined mini headers"));
        }
        if reply.has_common_cap(protocol::COMMON_CAP_PROTOCOL_AUTH_SELECTION) {
            stream
                .write_all(&protocol::AUTH_SELECTION_SPICE.to_le_bytes())
                .await
                .map_err(|_| SpiceError::Short)?;
        }
        let ticket = encrypt_ticket(&reply.pub_key, password)?;
        stream
            .write_all(&ticket)
            .await
            .map_err(|_| SpiceError::Short)?;
        let result = read_exact(&mut stream, 4).await?;
        let code = u32::from_le_bytes(result[..4].try_into().unwrap());
        if code != protocol::LINK_ERR_OK {
            return Err(SpiceError::LinkRejected(code));
        }
        let negotiated_opus = match kind {
            ChannelType::Playback => reply.has_channel_cap(protocol::PLAYBACK_CAP_OPUS),
            ChannelType::Record => reply.has_channel_cap(protocol::RECORD_CAP_OPUS),
            ChannelType::Main => false,
        };
        Ok(Self {
            stream,
            framer: Framer::new(),
            kind,
            opus: opus && negotiated_opus,
        })
    }

    /// The channel type this connection linked.
    #[must_use]
    pub fn kind(&self) -> ChannelType {
        self.kind
    }

    /// Whether Opus was agreed for this channel.
    #[must_use]
    pub fn opus(&self) -> bool {
        self.opus
    }

    /// Read the next batch of whole messages, or `None` at end of stream.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when the peer sends an oversized message.
    pub async fn receive(&mut self) -> Result<Option<Vec<Message>>, SpiceError> {
        let mut chunk = [0u8; 16 * 1024];
        let read = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|_| SpiceError::Short)?;
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(self.framer.feed(&chunk[..read])?))
    }

    /// Send one message.
    ///
    /// # Errors
    /// Returns [`SpiceError::Short`] when the connection is gone.
    pub async fn send(&mut self, message: &Message) -> Result<(), SpiceError> {
        self.stream
            .write_all(&message.encode())
            .await
            .map_err(|_| SpiceError::Short)
    }

    /// Answer the server's flow-control and latency messages.
    ///
    /// Returns true when `message` was one of them and needs no further
    /// handling by the caller.
    ///
    /// # Errors
    /// Returns [`SpiceError`] when a reply cannot be written.
    pub async fn handle_common(&mut self, message: &Message) -> Result<bool, SpiceError> {
        match message.kind {
            protocol::MSG_SET_ACK => {
                let generation = message.payload.get(..4).ok_or(SpiceError::Short)?.to_vec();
                self.send(&Message {
                    kind: protocol::MSGC_ACK_SYNC,
                    payload: generation,
                })
                .await?;
                Ok(true)
            }
            protocol::MSG_PING => {
                self.send(&Message {
                    kind: protocol::MSGC_PONG,
                    payload: message.payload.clone(),
                })
                .await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Link main and read its `MSG_MAIN_INIT`, returning the session connection id.
///
/// # Errors
/// Returns [`SpiceError`] when the link fails or the server closes the main
/// channel before sending `MSG_MAIN_INIT`.
pub async fn open_main(socket: &Path, password: &str) -> Result<(Channel, MainInit), SpiceError> {
    let mut main = Channel::link(socket, ChannelType::Main, 0, password, false).await?;
    loop {
        let Some(messages) = main.receive().await? else {
            return Err(SpiceError::Malformed("main closed before MSG_MAIN_INIT"));
        };
        for message in messages {
            if main.handle_common(&message).await? {
                continue;
            }
            if message.kind == protocol::MSG_MAIN_INIT {
                let init = MainInit::parse(&message.payload)?;
                main.send(&Message {
                    kind: protocol::MSGC_MAIN_ATTACH_CHANNELS,
                    payload: Vec::new(),
                })
                .await?;
                return Ok((main, init));
            }
        }
    }
}
