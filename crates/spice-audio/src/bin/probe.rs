//! Phase 0 gate: does a live SPICE server serve an audio-only client?
//!
//! Links main, then playback, then record against a running session's
//! `spice.sock`, reports what arrives, and optionally feeds a generated sine
//! wave into the guest so an operator can confirm it in a guest recorder.
//! A browser cannot run this unattended, because the record direction needs a
//! human to grant microphone permission and make noise; this binary needs
//! neither.
//!
//! ```text
//! spice-audio-probe --socket runtime/<session>/spice.sock --seconds 5 --tone
//! ```
//!
//! Exit status is zero only when playback data arrived, which is the gate.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use spice_audio::client::{Channel, open_main};
use spice_audio::message::{AudioData, Message, ModeMessage, PlaybackStart, RecordStart};
use spice_audio::protocol::{self, AudioMode, ChannelType};
use spice_audio::server::{FAKE_CHANNELS, FAKE_FREQUENCY, tone_frame};

struct Options {
    socket: PathBuf,
    password: String,
    seconds: u64,
    tone: bool,
    opus: bool,
}

fn parse() -> Result<Options, String> {
    let mut options = Options {
        socket: PathBuf::new(),
        password: String::new(),
        seconds: 5,
        tone: false,
        opus: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => {
                options.socket = PathBuf::from(args.next().ok_or("--socket needs a path")?)
            }
            "--password" => options.password = args.next().ok_or("--password needs a value")?,
            "--seconds" => {
                options.seconds = args
                    .next()
                    .ok_or("--seconds needs a value")?
                    .parse()
                    .map_err(|_| "--seconds must be a whole number")?;
            }
            "--tone" => options.tone = true,
            "--opus" => options.opus = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if options.socket.as_os_str().is_empty() {
        return Err("--socket is required".into());
    }
    Ok(options)
}

/// Report what the playback channel delivered within the probe window.
#[derive(Default)]
struct Playback {
    started: Option<PlaybackStart>,
    mode: Option<AudioMode>,
    frames: u32,
    bytes: usize,
}

async fn watch_playback(channel: &mut Channel, seconds: u64) -> Playback {
    let mut report = Playback::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return report;
        }
        let Ok(Ok(Some(messages))) = tokio::time::timeout(remaining, channel.receive()).await
        else {
            return report;
        };
        for message in messages {
            if channel.handle_common(&message).await.unwrap_or(false) {
                continue;
            }
            match message.kind {
                protocol::MSG_PLAYBACK_MODE => {
                    if let Ok(mode) = ModeMessage::parse(&message.payload) {
                        report.mode = Some(mode.mode);
                    }
                }
                protocol::MSG_PLAYBACK_START => {
                    report.started = PlaybackStart::parse(&message.payload).ok();
                }
                protocol::MSG_PLAYBACK_DATA => {
                    if let Ok(data) = AudioData::parse(&message.payload) {
                        report.frames += 1;
                        report.bytes += data.samples.len();
                    }
                }
                _ => {}
            }
        }
    }
}

async fn feed_tone(channel: &mut Channel, seconds: u64) -> Result<u32, String> {
    // Negotiate raw S16 rather than Opus for the record direction: generating
    // samples needs no encoder, and `unsafe_code = "forbid"` rules out FFI Opus.
    channel
        .send(&Message {
            kind: protocol::MSGC_RECORD_MODE,
            payload: ModeMessage {
                time: 0,
                mode: AudioMode::Raw,
                data: Vec::new(),
            }
            .encode(),
        })
        .await
        .map_err(|error| error.to_string())?;
    channel
        .send(&Message {
            kind: protocol::MSGC_RECORD_START_MARK,
            payload: 0u32.to_le_bytes().to_vec(),
        })
        .await
        .map_err(|error| error.to_string())?;
    let frames = u32::try_from(seconds * 100).unwrap_or(u32::MAX);
    for index in 0..frames {
        channel
            .send(&Message {
                kind: protocol::MSGC_RECORD_DATA,
                payload: AudioData {
                    time: index * 10,
                    samples: tone_frame(index),
                }
                .encode(),
            })
            .await
            .map_err(|error| error.to_string())?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(frames)
}

#[tokio::main]
async fn main() -> ExitCode {
    let options = match parse() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("spice-audio-probe: {error}");
            return ExitCode::from(2);
        }
    };
    let (main, init) = match open_main(&options.socket, &options.password).await {
        Ok(value) => value,
        Err(error) => {
            eprintln!("main channel: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("main linked, connection id {:#x}", init.connection_id);
    // The main channel must stay linked: the server ties every other channel
    // of the session to it, and so does the console proxy.
    let _main = main;

    let mut playback = match Channel::link(
        &options.socket,
        ChannelType::Playback,
        init.connection_id,
        &options.password,
        options.opus,
    )
    .await
    {
        Ok(channel) => channel,
        Err(error) => {
            eprintln!("playback channel: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("playback linked, opus {}", playback.opus());

    let record = Channel::link(
        &options.socket,
        ChannelType::Record,
        init.connection_id,
        &options.password,
        false,
    )
    .await;
    match &record {
        Ok(channel) => println!("record linked, opus {}", channel.opus()),
        Err(error) => println!("record channel refused: {error}"),
    }

    let tone = async {
        match (options.tone, record) {
            (true, Ok(mut channel)) => {
                // Wait for the guest to open the capture stream before
                // sending; a guest that never opens it is itself a result.
                if let Ok(Ok(Some(messages))) =
                    tokio::time::timeout(Duration::from_secs(options.seconds), channel.receive())
                        .await
                {
                    for message in messages {
                        if message.kind == protocol::MSG_RECORD_START {
                            match RecordStart::parse(&message.payload) {
                                Ok(start) => println!(
                                    "guest opened capture: {} ch, {} Hz",
                                    start.channels, start.frequency
                                ),
                                Err(error) => println!("record start unparsed: {error}"),
                            }
                        }
                    }
                }
                match feed_tone(&mut channel, options.seconds).await {
                    Ok(frames) => println!(
                        "sent {frames} raw frames of a 440 Hz tone ({FAKE_CHANNELS} ch, {FAKE_FREQUENCY} Hz); \
                         confirm it in a guest recorder"
                    ),
                    Err(error) => println!("record send failed: {error}"),
                }
            }
            (true, Err(_)) => println!("record direction skipped: the channel did not link"),
            (false, _) => {}
        }
    };

    let (report, ()) = tokio::join!(watch_playback(&mut playback, options.seconds), tone);
    match report.started {
        Some(start) => println!(
            "playback start: {} ch, {} Hz, mode {:?}",
            start.channels, start.frequency, report.mode
        ),
        None => println!("playback never started; mode {:?}", report.mode),
    }
    println!(
        "playback delivered {} messages, {} bytes in {}s",
        report.frames, report.bytes, options.seconds
    );
    if report.frames == 0 {
        eprintln!(
            "GATE FAILED: no playback data reached an audio-only client. \
             Re-plan items 4-6 around -audiodev dbus."
        );
        return ExitCode::FAILURE;
    }
    println!("GATE PASSED: an audio-only SPICE client is served.");
    ExitCode::SUCCESS
}
