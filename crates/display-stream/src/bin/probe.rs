//! Read framed display records from stdin and print their metadata.
//!
//! The probe is useful for validating a streamer or a captured socket without
//! requiring a browser. Input is the network-order record format from
//! `display_stream::Record`.
use anyhow::Result;
use bytes::BytesMut;
use display_stream::decode;
use std::io::{self, Read};

#[cfg(unix)]
async fn run_bus(fd: i32) -> Result<()> {
    use display_stream::listener::{CaptureState, attach};
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::sync::{Arc, Mutex};
    use tokio::net::UnixStream;
    use zbus::connection::Builder;

    // The descriptor is inherited from QMP. Converting it is the one
    // ownership transfer at the process boundary; the resulting stream owns
    // the duplicated descriptor and closes it on exit.
    #[allow(unsafe_code)]
    let stream = unsafe { StdUnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    eprintln!("display-stream-probe: connecting to QEMU D-Bus");
    let connection = Builder::unix_stream(tokio::net::UnixStream::from_std(stream)?)
        .p2p()
        .build()
        .await?;
    eprintln!("display-stream-probe: D-Bus connected");
    let (listener, peer) = StdUnixStream::pair()?;
    listener.set_nonblocking(true)?;
    let state = Arc::new(Mutex::new(CaptureState::new()));
    eprintln!("display-stream-probe: registering listener");
    let _listener_connection = attach(
        &connection,
        UnixStream::from_std(listener)?,
        #[allow(unsafe_code)]
        unsafe {
            OwnedFd::from_raw_fd(peer.into_raw_fd())
        },
        state.clone(),
    )
    .await?;
    eprintln!("display-stream-probe: listener attached");
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let mut state = state.lock().expect("capture lock poisoned");
        if state.refresh {
            if let Some(frame) = state.frame.as_mut() {
                eprintln!(
                    "frame {:?}x{:?} damage={:?}",
                    frame.dimensions().0,
                    frame.dimensions().1,
                    frame.take_damage()
                );
            }
            state.refresh = false;
        }
    }
}

fn main() -> Result<()> {
    if let Some(fd) = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .windows(2)
        .find(|args| args[0] == "--bus-fd")
        .and_then(|args| args[1].parse::<i32>().ok())
    {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(run_bus(fd));
    }
    let mut raw = Vec::new();
    io::stdin().read_to_end(&mut raw)?;
    let mut input = BytesMut::from(raw.as_slice());
    let mut count = 0;
    while let Some(record) = decode(&mut input)? {
        println!(
            "{} pts={} bytes={}",
            format!("{:?}", record.kind).to_lowercase(),
            record.pts_us,
            record.payload.len()
        );
        count += 1;
    }
    if !input.is_empty() {
        anyhow::bail!("truncated display record");
    }
    eprintln!("records={count}");
    Ok(())
}
