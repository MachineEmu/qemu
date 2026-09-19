//! A transport-independent SPICE codec for the three channels an audio-only
//! client needs: main, playback, and record.
//!
//! The codec is written from the permissively licensed `spice-protocol`
//! definitions rather than from any LGPL client, so it can be shared with a
//! build that has no copyleft story.  It carries no display, cursor, inputs,
//! or guest-agent support: those channels are refused, not merely unused.
//!
//! Three binaries ship with it.  `spice-audio-probe` answers the question
//! this crate exists for -- whether a SPICE server streams playback, and
//! accepts record data, for a client that never links a display channel --
//! against a live `spice.sock`.  `spice-audio-fake-server` replays a canned
//! session for the console's proxy tests.  `spice-audio-fixtures` writes the
//! golden byte vectors the TypeScript codec is tested against, so both
//! implementations are checked against the same bytes.

pub mod client;
pub mod error;
pub mod link;
pub mod message;
pub mod protocol;
pub mod server;

pub use error::SpiceError;
pub use protocol::ChannelType;
