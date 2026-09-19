//! Round-trip and rejection tests for the SPICE audio codec.

use spice_audio::link::{LinkHeader, LinkMess, LinkReply, cap_word};
use spice_audio::message::{AudioData, Framer, MainInit, Message, ModeMessage, PlaybackStart};
use spice_audio::protocol::{self, AudioMode, ChannelType};
use spice_audio::{ChannelType as Exported, SpiceError};

#[test]
fn link_messages_round_trip_with_their_capabilities() {
    let mess = LinkMess::client(Exported::Playback, 0x1234_5678, true);
    let encoded = mess.encode();
    let header =
        LinkHeader::parse(&LinkHeader::encode(u32::try_from(encoded.len()).unwrap())).unwrap();
    assert_eq!(header.size as usize, encoded.len());
    let parsed = LinkMess::parse(&encoded).unwrap();
    assert_eq!(parsed, mess);
    assert_eq!(parsed.channel(), Some(ChannelType::Playback));
    assert!(parsed.has_common_cap(protocol::COMMON_CAP_MINI_HEADER));
    assert!(parsed.has_channel_cap(protocol::PLAYBACK_CAP_OPUS));
    assert!(!parsed.has_common_cap(protocol::COMMON_CAP_AUTH_SASL));
}

#[test]
fn link_replies_round_trip_and_short_bodies_are_rejected() {
    let reply = LinkReply {
        error: protocol::LINK_ERR_OK,
        pub_key: vec![7; protocol::TICKET_PUBKEY_BYTES],
        common_caps: vec![cap_word(protocol::COMMON_CAP_MINI_HEADER)],
        channel_caps: vec![cap_word(protocol::PLAYBACK_CAP_OPUS)],
    };
    let encoded = reply.encode();
    assert_eq!(LinkReply::parse(&encoded).unwrap(), reply);
    assert_eq!(
        LinkReply::parse(&encoded[..encoded.len() - 1]).unwrap_err(),
        SpiceError::Malformed("capabilities fall outside the link message"),
    );
    assert_eq!(LinkReply::parse(&[]).unwrap_err(), SpiceError::Short);
}

#[test]
fn display_and_agent_channels_are_not_representable() {
    for channel_type in [2u8, 3, 4, 8, 9, 10, 11, 0, 255] {
        assert!(ChannelType::from_wire(channel_type).is_none());
    }
    let mut mess = LinkMess::client(ChannelType::Main, 0, false);
    mess.channel_type = 2; // display
    assert!(LinkMess::parse(&mess.encode()).unwrap().channel().is_none());
}

#[test]
fn a_capability_offset_outside_the_body_is_refused() {
    let mut body = LinkMess::client(ChannelType::Main, 0, false).encode();
    // Point caps_offset far past the end of the message.
    body[14..18].copy_from_slice(&4000u32.to_le_bytes());
    assert_eq!(
        LinkMess::parse(&body).unwrap_err(),
        SpiceError::Malformed("capabilities fall outside the link message"),
    );
}

#[test]
fn an_implausible_capability_count_is_refused_before_allocation() {
    let mut body = LinkMess::client(ChannelType::Main, 0, false).encode();
    body[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        LinkMess::parse(&body).unwrap_err(),
        SpiceError::TooLarge(_) | SpiceError::Malformed(_),
    ));
}

#[test]
fn an_oversized_link_header_is_refused() {
    let mut header = LinkHeader::encode(0);
    header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        LinkHeader::parse(&header).unwrap_err(),
        SpiceError::TooLarge(_)
    ));
    let mut foreign = LinkHeader::encode(8);
    foreign[0..4].copy_from_slice(b"XXXX");
    assert_eq!(
        LinkHeader::parse(&foreign).unwrap_err(),
        SpiceError::Malformed("link magic is not REDQ"),
    );
}

#[test]
fn framing_reassembles_across_arbitrary_chunk_boundaries() {
    let messages = vec![
        Message {
            kind: protocol::MSG_PLAYBACK_MODE,
            payload: ModeMessage {
                time: 0,
                mode: AudioMode::Raw,
                data: Vec::new(),
            }
            .encode(),
        },
        Message {
            kind: protocol::MSG_PLAYBACK_START,
            payload: PlaybackStart {
                channels: 2,
                format: protocol::AUDIO_FMT_S16,
                frequency: 48_000,
                time: 0,
            }
            .encode(),
        },
        Message {
            kind: protocol::MSG_PLAYBACK_DATA,
            payload: AudioData {
                time: 10,
                samples: vec![1, 2, 3, 4],
            }
            .encode(),
        },
    ];
    let stream: Vec<u8> = messages.iter().flat_map(Message::encode).collect();
    for split in 1..stream.len() {
        let mut framer = Framer::new();
        let mut out = framer.feed(&stream[..split]).unwrap();
        out.extend(framer.feed(&stream[split..]).unwrap());
        assert_eq!(out, messages, "split at {split}");
        assert_eq!(framer.pending(), 0);
    }
}

#[test]
fn an_oversized_message_header_is_refused_rather_than_buffered() {
    let mut framer = Framer::new();
    let mut frame = protocol::MSG_PLAYBACK_DATA.to_le_bytes().to_vec();
    frame.extend_from_slice(
        &u32::try_from(protocol::MAX_MESSAGE_BYTES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    assert!(matches!(
        framer.feed(&frame).unwrap_err(),
        SpiceError::TooLarge(_)
    ));
}

#[test]
fn audio_payloads_round_trip() {
    let init = MainInit {
        connection_id: 0xdead_beef,
        multi_media_time: 42,
    };
    assert_eq!(MainInit::parse(&init.encode()).unwrap(), init);

    let data = AudioData {
        time: 1234,
        samples: vec![9; 64],
    };
    assert_eq!(AudioData::parse(&data.encode()).unwrap(), data);

    let mode = ModeMessage {
        time: 7,
        mode: AudioMode::Opus,
        data: vec![1, 2],
    };
    assert_eq!(ModeMessage::parse(&mode.encode()).unwrap(), mode);
    assert_eq!(AudioData::parse(&[1, 2]).unwrap_err(), SpiceError::Short);
}

#[test]
fn an_unknown_sample_format_is_refused() {
    let mut payload = PlaybackStart {
        channels: 2,
        format: protocol::AUDIO_FMT_S16,
        frequency: 48_000,
        time: 0,
    }
    .encode();
    payload[4..6].copy_from_slice(&9u16.to_le_bytes());
    assert_eq!(
        PlaybackStart::parse(&payload).unwrap_err(),
        SpiceError::Malformed("unsupported SPICE sample format"),
    );
}
