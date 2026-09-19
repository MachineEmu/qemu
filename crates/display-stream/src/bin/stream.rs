//! Supervised per-session QEMU display streamer.

use anyhow::{Context, Result, bail};
use bytes::BytesMut;
use display_stream::frame::Frame;
use display_stream::gpu_bridge::{BridgedFrame, GpuBridge};
use display_stream::listener::{
    AudioEvent, CaptureFrame, CaptureState, ClipboardEvent, ClipboardState, DmaBufFrame,
    MAX_CLIPBOARD_BYTES, attach, attach_audio, attach_clipboard, input, request_clipboard,
    set_clipboard,
};
use display_stream::{Record, RecordType, VideoConfig};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_allocators::{DmaBufAllocator, DmaBufAllocatorExtManual};
use gstreamer_app as gst_app;
use gstreamer_video::{VideoFormat, VideoFrameFlags, VideoMeta};
use std::collections::VecDeque;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
#[cfg(test)]
use tokio::process::Command;
use tokio::sync::{Notify, broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use zbus::connection::Builder;

const MAX_VIEWER_QUEUE: usize = 64;
const TARGET_FPS: u64 = 60;

#[derive(Clone)]
enum EncoderInput {
    Cpu(Arc<Frame>),
    DmaBuf(Arc<DmaBufFrame>),
}

impl EncoderInput {
    fn dimensions(&self) -> (u32, u32) {
        match self {
            Self::Cpu(frame) => frame.dimensions(),
            Self::DmaBuf(frame) => (frame.width, frame.height),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncoderMode {
    Cpu,
    DmaBuf,
}

impl EncoderMode {
    fn label(self) -> &'static str {
        match self {
            Self::Cpu => "cpu-readback",
            Self::DmaBuf => "dmabuf",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum EncoderBackend {
    Vaapi,
    OpenH264,
}

impl EncoderBackend {
    fn label(self) -> &'static str {
        match self {
            Self::Vaapi => "vaapi",
            Self::OpenH264 => "openh264",
        }
    }

    fn hardware(self) -> bool {
        matches!(self, Self::Vaapi)
    }
}

type DmaSignature = (u32, u32, u32, u64, bool);

fn dma_signature(frame: &DmaBufFrame) -> DmaSignature {
    (
        frame.width,
        frame.height,
        frame.fourcc,
        frame.modifier,
        frame.y0_top,
    )
}

#[derive(Clone)]
struct Options {
    bus_fd: i32,
    output: PathBuf,
    record: PathBuf,
}

fn options() -> Result<Options> {
    let mut bus_fd = None;
    let mut output = None;
    let mut record = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bus-fd" => bus_fd = Some(args.next().context("--bus-fd needs a value")?.parse()?),
            "--output" => {
                output = Some(PathBuf::from(args.next().context("--output needs a path")?))
            }
            "--record" => {
                record = Some(PathBuf::from(args.next().context("--record needs a path")?))
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(Options {
        bus_fd: bus_fd.context("--bus-fd is required")?,
        output: output.context("--output is required")?,
        record: record.context("--record is required")?,
    })
}

#[allow(unsafe_code)]
fn inherited_stream(fd: i32) -> Result<StdUnixStream> {
    // The broker passes this descriptor through QMP; this process owns it.
    let stream = unsafe { StdUnixStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;
    Ok(stream)
}

fn record_bytes(record: &Record) -> Result<Vec<u8>> {
    let mut output = BytesMut::new();
    record
        .encode(&mut output)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(output.to_vec())
}

fn contains_idr(payload: &[u8]) -> bool {
    let mut index = 0;
    while index + 3 <= payload.len() {
        let prefix = if payload[index..].starts_with(&[0, 0, 1]) {
            3
        } else if index + 4 <= payload.len() && payload[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        let nal_start = index + prefix;
        if nal_start < payload.len() && payload[nal_start] & 0x1f == 5 {
            return true;
        }
        index = nal_start;
    }
    false
}

fn codec_from_sps(payload: &[u8]) -> Option<String> {
    let mut index = 0;
    while index + 4 <= payload.len() {
        let prefix = if payload[index..].starts_with(&[0, 0, 1]) {
            3
        } else if payload[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        let start = index + prefix;
        let end = (start..payload.len())
            .find(|position| {
                payload[*position..].starts_with(&[0, 0, 1])
                    || payload[*position..].starts_with(&[0, 0, 0, 1])
            })
            .unwrap_or(payload.len());
        if start + 4 <= end && payload[start] & 0x1f == 7 {
            return Some(format!(
                "avc1.{:02x}{:02x}{:02x}",
                payload[start + 1],
                payload[start + 2],
                payload[start + 3]
            ));
        }
        index = end;
    }
    None
}

fn parameter_sets(payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 <= payload.len() {
        let prefix = if payload[index..].starts_with(&[0, 0, 1]) {
            3
        } else if index + 4 <= payload.len() && payload[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        starts.push((index, prefix));
        index += prefix;
    }
    for (position, prefix) in starts.iter().copied() {
        let nal_start = position + prefix;
        let nal_type = payload.get(nal_start).copied().unwrap_or_default() & 0x1f;
        if nal_type != 7 && nal_type != 8 {
            continue;
        }
        let end = starts
            .iter()
            .map(|(next, _)| *next)
            .find(|next| *next > position)
            .unwrap_or(payload.len());
        result.extend_from_slice(&payload[position..end]);
    }
    result
}

fn avcc_description(payload: &[u8]) -> Option<Vec<u8>> {
    let mut nals = Vec::new();
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 <= payload.len() {
        let prefix = if payload[index..].starts_with(&[0, 0, 1]) {
            3
        } else if index + 4 <= payload.len() && payload[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            index += 1;
            continue;
        };
        starts.push((index, prefix));
        index += prefix;
    }
    for (position, prefix) in starts.iter().copied() {
        let start = position + prefix;
        let end = starts
            .iter()
            .map(|(next, _)| *next)
            .find(|next| *next > position)
            .unwrap_or(payload.len());
        let nal = &payload[start..end];
        if matches!(nal.first().map(|byte| byte & 0x1f), Some(7 | 8)) {
            nals.push(nal);
        }
    }
    let sps = nals.iter().find(|nal| nal[0] & 0x1f == 7)?;
    let pps = nals.iter().find(|nal| nal[0] & 0x1f == 8)?;
    if sps.len() < 4 || sps.len() > u16::MAX as usize || pps.len() > u16::MAX as usize {
        return None;
    }
    let mut description = Vec::with_capacity(11 + sps.len() + pps.len());
    description.extend_from_slice(&[1, sps[1], sps[2], sps[3], 0xff, 0xe1]);
    description.extend_from_slice(&u16::try_from(sps.len()).ok()?.to_be_bytes());
    description.extend_from_slice(sps);
    description.push(1);
    description.extend_from_slice(&u16::try_from(pps.len()).ok()?.to_be_bytes());
    description.extend_from_slice(pps);
    Some(description)
}

fn gst_pipeline_encoder(
    width: u32,
    height: u32,
    record: &std::path::Path,
    encoder: &[&str],
    va: bool,
    dma: Option<(u32, u64)>,
) -> Result<(gst::Pipeline, gst_app::AppSrc, gst_app::AppSink)> {
    std::fs::create_dir_all(record.parent().unwrap_or_else(|| std::path::Path::new(".")))?;
    gst::init()?;
    let encoder = encoder.join(" ");
    let input = match dma {
        Some(_) => format!(
            "appsrc name=source is-live=true format=time block=false max-buffers=1 leaky-type=downstream \
             ! vapostproc ! video/x-raw(memory:VAMemory),format=NV12"
        ),
        None => {
            let postprocess = if va { " ! vapostproc" } else { "" };
            format!(
                "appsrc name=source is-live=true format=time block=false max-buffers=1 leaky-type=downstream \
                 ! videoconvert{postprocess}"
            )
        }
    };
    let location = record
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let description = format!(
        "{input} ! {encoder} \
         ! h264parse config-interval=-1 \
         ! video/x-h264,stream-format=byte-stream,alignment=au \
         ! tee name=t \
         t. ! queue ! appsink name=stream sync=false max-buffers=8 \
         t. ! queue ! h264parse ! video/x-h264,stream-format=avc,alignment=au \
         ! mp4mux fragment-duration=1000 ! filesink location=\"{location}\""
    );
    let pipeline = gst::parse::launch(&description)?
        .downcast::<gst::Pipeline>()
        .map_err(|_| anyhow::anyhow!("GStreamer description did not create a pipeline"))?;
    let source = pipeline
        .by_name("source")
        .context("GStreamer appsrc unavailable")?
        .downcast::<gst_app::AppSrc>()
        .map_err(|_| anyhow::anyhow!("GStreamer source is not appsrc"))?;
    let caps: gst::Caps = match dma {
        Some((fourcc, modifier)) => format!(
            "video/x-raw(memory:DMABuf),format=DMA_DRM,drm-format={}:{:#018x},width={width},height={height},framerate={TARGET_FPS}/1",
            drm_fourcc_name(fourcc)?, modifier
        )
        .parse()?,
        None => format!(
            "video/x-raw,format=BGRA,width={width},height={height},framerate={TARGET_FPS}/1"
        )
        .parse()?,
    };
    source.set_caps(Some(&caps));
    let sink = pipeline
        .by_name("stream")
        .context("GStreamer appsink unavailable")?
        .downcast::<gst_app::AppSink>()
        .map_err(|_| anyhow::anyhow!("GStreamer stream is not appsink"))?;
    Ok((pipeline, source, sink))
}

fn drm_fourcc_name(fourcc: u32) -> Result<&'static str> {
    match fourcc {
        0x3432_4258 => Ok("XB24"),
        0x3432_4241 => Ok("AB24"),
        0x3432_5258 => Ok("XR24"),
        0x3432_5241 => Ok("AR24"),
        _ => bail!("unsupported GStreamer DRM fourcc 0x{fourcc:08x}"),
    }
}

fn input_buffer(
    input: &EncoderInput,
    bridge: Option<&mut GpuBridge>,
    pts: gst::ClockTime,
    duration: gst::ClockTime,
) -> Result<gst::Buffer> {
    let mut buffer = match input {
        EncoderInput::Cpu(frame) => gst::Buffer::from_mut_slice(frame.pixels().to_vec()),
        EncoderInput::DmaBuf(frame) => {
            let output = bridge
                .context("DMABUF encoder has no EGL bridge")?
                .convert(frame)?;
            bridged_buffer(&output)?
        }
    };
    let writable = buffer
        .get_mut()
        .context("new GStreamer input buffer is shared")?;
    writable.set_pts(pts);
    writable.set_duration(duration);
    Ok(buffer)
}

fn bridged_buffer(frame: &BridgedFrame) -> Result<gst::Buffer> {
    let length = (frame.stride as usize)
        .checked_mul(frame.height as usize)
        .context("DMABUF size overflow")?;
    let allocator = DmaBufAllocator::new();
    let file = frame.file.try_clone().context("duplicating DMABUF")?;
    #[allow(unsafe_code)]
    let memory =
        unsafe { allocator.alloc_dmabuf(file, length) }.context("wrapping DMABUF for GStreamer")?;
    let mut buffer = gst::Buffer::new();
    let writable = buffer
        .get_mut()
        .context("new GStreamer DMABUF buffer is shared")?;
    writable.append_memory(memory);
    VideoMeta::add_full(
        writable,
        VideoFrameFlags::empty(),
        VideoFormat::DmaDrm,
        frame.width,
        frame.height,
        &[frame.offset as usize],
        &[i32::try_from(frame.stride).context("DMABUF stride overflow")?],
    )?;
    Ok(buffer)
}

// One lock protects bootstrap publication and subscription. The receiver starts
// strictly after the cached GOP, so no live frames are skipped or replayed twice.
const MAX_GOP_BYTES: usize = 32 * 1024 * 1024;
type Packet = Arc<Vec<u8>>;
struct Hub {
    sender: broadcast::Sender<Packet>,
    bootstrap: Vec<Packet>,
    audio_config: Option<Packet>,
    clipboard: Option<Packet>,
    bytes: usize,
}
impl Hub {
    fn new() -> Self {
        Self {
            sender: broadcast::channel(MAX_VIEWER_QUEUE).0,
            bootstrap: Vec::new(),
            audio_config: None,
            clipboard: None,
            bytes: 0,
        }
    }
    fn reset(&mut self) {
        self.bootstrap.clear();
        self.bytes = 0;
    }
    fn publish(&mut self, packet: Vec<u8>, key: bool) {
        if key {
            self.reset();
        }
        let packet = Arc::new(packet);
        if key || !self.bootstrap.is_empty() {
            self.bytes += packet.len();
            if self.bytes > MAX_GOP_BYTES {
                self.reset();
            } else {
                self.bootstrap.push(packet.clone());
            }
        }
        let _ = self.sender.send(packet);
    }
    fn subscribe(&self) -> (Vec<Packet>, broadcast::Receiver<Packet>) {
        let mut initial = self.bootstrap.clone();
        if let Some(config) = &self.audio_config {
            initial.push(config.clone());
        }
        if let Some(clipboard) = &self.clipboard {
            initial.push(clipboard.clone());
        }
        (initial, self.sender.subscribe())
    }
    fn publish_audio_config(&mut self, packet: Vec<u8>) {
        let packet = Arc::new(packet);
        self.audio_config = Some(packet.clone());
        let _ = self.sender.send(packet);
    }
    fn publish_audio(&self, packet: Vec<u8>) {
        let _ = self.sender.send(Arc::new(packet));
    }
    fn publish_clipboard(&mut self, packet: Vec<u8>) {
        let packet = Arc::new(packet);
        self.clipboard = Some(packet.clone());
        let _ = self.sender.send(packet);
    }
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AudioConfig {
    id: u64,
    bits: u8,
    signed: bool,
    float: bool,
    frequency: u32,
    channels: u8,
    bytes_per_frame: u32,
    big_endian: bool,
    enabled: bool,
    muted: bool,
    volume: Vec<u8>,
}

fn unix_time_us() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_micros(),
    )
    .context("system timestamp overflow")
}

#[derive(Default)]
struct Inputs {
    queue: Mutex<VecDeque<serde_json::Value>>,
    ready: Notify,
}
impl Inputs {
    fn push(&self, value: serde_json::Value) -> Result<()> {
        let mut queue = self.queue.lock().expect("input lock poisoned");
        // Only adjacent absolute motions may be replaced; never cross a click
        // or key event, and never discard relative movement deltas.
        if value["type"] == "mouse_abs"
            && queue.back().is_some_and(|last| last["type"] == "mouse_abs")
        {
            queue.pop_back();
        }
        if queue.len() >= 256 {
            bail!("input queue full");
        }
        queue.push_back(value);
        drop(queue);
        self.ready.notify_one();
        Ok(())
    }
}

async fn serve_viewer(stream: UnixStream, hub: Arc<Mutex<Hub>>, inputs: Arc<Inputs>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let (initial, mut receiver) = hub.lock().expect("hub lock poisoned").subscribe();
    let mut ready = initial
        .iter()
        .any(|packet| packet.first() == Some(&(RecordType::Config as u8)));
    for packet in initial {
        tokio::time::timeout(Duration::from_secs(3), write.write_all(&packet)).await??;
    }
    let mut reader = BufReader::new(read);
    // A bounded line reader prevents local clients from growing an unlimited line.
    let mut line = Vec::new();
    loop {
        tokio::select! {
            byte = reader.read_u8() => {
                let byte = byte?;
                if byte != b'\n' {
                    if line.len() >= MAX_CLIPBOARD_BYTES * 6 + 1024 {
                        bail!("input message too large");
                    }
                    line.push(byte);
                    continue;
                }
                let value: serde_json::Value = serde_json::from_slice(&line)?;
                line.clear();
                if value["type"] == "request_idr" {
                    // Recovery replays the complete GOP, not a lone stale IDR.
                    let (bootstrap, next) = hub.lock().expect("hub lock poisoned").subscribe();
                    receiver = next;
                    ready = bootstrap
                        .iter()
                        .any(|packet| packet.first() == Some(&(RecordType::Config as u8)));
                    for packet in bootstrap {
                        tokio::time::timeout(Duration::from_secs(3), write.write_all(&packet)).await??;
                    }
                } else {
                    match value["type"].as_str() {
                        Some("mouse_abs" | "mouse_move" | "mouse_down" | "mouse_up" | "mouse_wheel" | "key_down" | "key_up" | "resize" | "clipboard_set" | "clipboard_request") => inputs.push(value)?,
                        _ => bail!("unsupported input message"),
                    }
                }
            }
            packet = receiver.recv() => {
                match packet {
                    Ok(packet) => {
                        let kind = packet.first().copied();
                        if matches!(kind, Some(value) if value == RecordType::Config as u8 || value == RecordType::Resize as u8) {
                            ready = true;
                        }
                        let independent = matches!(kind, Some(value)
                            if value == RecordType::Control as u8
                                || value == RecordType::AudioConfig as u8
                                || value == RecordType::AudioData as u8);
                        if ready || independent {
                            tokio::time::timeout(Duration::from_secs(3), write.write_all(&packet)).await??;
                        }
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let (bootstrap, next) = hub.lock().expect("hub lock poisoned").subscribe();
                        receiver = next;
                        ready = bootstrap
                            .iter()
                            .any(|packet| packet.first() == Some(&(RecordType::Config as u8)));
                        for packet in bootstrap {
                            tokio::time::timeout(Duration::from_secs(3), write.write_all(&packet)).await??;
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

struct Encoder {
    pipeline: gst::Pipeline,
    source: gst_app::AppSrc,
    frames: watch::Sender<Option<EncoderInput>>,
    output: mpsc::Receiver<Result<EncodedFrame>>,
    writer: JoinHandle<Result<()>>,
    bus: JoinHandle<Result<()>>,
    dimensions: (u32, u32),
    mode: EncoderMode,
    backend: EncoderBackend,
    dma_signature: Option<DmaSignature>,
}

struct EncodedFrame {
    payload: Vec<u8>,
    captured_at_us: u64,
}

impl Encoder {
    fn start_cpu(frame: Frame, record: &std::path::Path) -> Result<Self> {
        let dimensions = frame.dimensions();
        let va_pipeline = gst_pipeline_encoder(
            dimensions.0,
            dimensions.1,
            record,
            &[
                "vah264enc",
                "b-frames=0",
                "rate-control=cbr",
                "key-int-max=20",
            ],
            true,
            None,
        );
        let (pipeline, backend) = match va_pipeline {
            Ok(pipeline) => (pipeline, EncoderBackend::Vaapi),
            Err(va_error) => {
                eprintln!("VAAPI encoder unavailable, using OpenH264: {va_error:#}");
                (
                    gst_pipeline_encoder(
                        dimensions.0,
                        dimensions.1,
                        record,
                        &[
                            "openh264enc",
                            "gop-size=20",
                            "bitrate=20000000",
                            "enable-frame-skip=false",
                        ],
                        false,
                        None,
                    )?,
                    EncoderBackend::OpenH264,
                )
            }
        };
        let (pipeline, source, sink) = pipeline;
        Self::from_pipeline(
            EncoderInput::Cpu(Arc::new(frame)),
            pipeline,
            source,
            sink,
            EncoderMode::Cpu,
            backend,
            None,
        )
    }
    fn start_dmabuf(frame: DmaBufFrame, record: &std::path::Path) -> Result<Self> {
        let dimensions = (frame.width, frame.height);
        let bridge = GpuBridge::new(frame.width, frame.height)?;
        let (pipeline, source, sink) = gst_pipeline_encoder(
            dimensions.0,
            dimensions.1,
            record,
            &[
                "vah264enc",
                "b-frames=0",
                "rate-control=cbr",
                "key-int-max=20",
            ],
            true,
            Some((0x3432_4241, 0x0100_0000_0000_0002)),
        )?;
        Self::from_pipeline(
            EncoderInput::DmaBuf(Arc::new(frame)),
            pipeline,
            source,
            sink,
            EncoderMode::DmaBuf,
            EncoderBackend::Vaapi,
            Some(bridge),
        )
    }
    fn from_pipeline(
        input: EncoderInput,
        pipeline: gst::Pipeline,
        source: gst_app::AppSrc,
        sink: gst_app::AppSink,
        mode: EncoderMode,
        backend: EncoderBackend,
        mut bridge: Option<GpuBridge>,
    ) -> Result<Self> {
        let dimensions = input.dimensions();
        let stream_started = Instant::now();
        let epoch_base_us = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before the Unix epoch")?
                .as_micros(),
        )
        .context("system timestamp overflow")?;
        let (sender, output) = mpsc::channel(8);
        let sample_sender = sender.clone();
        sink.set_callbacks(
            gst_app::AppSinkCallbacks::builder()
                .new_sample(move |sink| {
                    let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                    let buffer = sample.buffer().ok_or(gst::FlowError::Error)?;
                    let mapped = buffer.map_readable().map_err(|_| gst::FlowError::Error)?;
                    let captured_at_us = epoch_base_us.saturating_add(
                        buffer.pts().unwrap_or(gst::ClockTime::ZERO).nseconds() / 1_000,
                    );
                    sample_sender
                        .blocking_send(Ok(EncodedFrame {
                            payload: mapped.as_slice().to_vec(),
                            captured_at_us,
                        }))
                        .map_err(|_| gst::FlowError::Flushing)?;
                    Ok(gst::FlowSuccess::Ok)
                })
                .build(),
        );
        let dma_signature = match &input {
            EncoderInput::DmaBuf(frame) => Some(dma_signature(frame)),
            EncoderInput::Cpu(_) => None,
        };
        let (frames, mut updates) = watch::channel(Some(input));
        let writer_source = source.clone();
        let writer = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / TARGET_FPS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let duration = gst::ClockTime::from_nseconds(1_000_000_000 / TARGET_FPS);
            loop {
                tick.tick().await;
                let input = updates.borrow_and_update().clone();
                let Some(input) = input else {
                    break;
                };
                let elapsed_ns =
                    u64::try_from(stream_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                let pts = gst::ClockTime::from_nseconds(elapsed_ns);
                let buffer = input_buffer(&input, bridge.as_mut(), pts, duration)?;
                writer_source
                    .push_buffer(buffer)
                    .map_err(|error| anyhow::anyhow!("GStreamer input stopped: {error:?}"))?;
            }
            writer_source
                .end_of_stream()
                .map_err(|error| anyhow::anyhow!("GStreamer EOS failed: {error:?}"))?;
            Ok(())
        });
        let bus = pipeline.bus().context("GStreamer pipeline has no bus")?;
        let bus = tokio::task::spawn_blocking(move || {
            loop {
                match bus.timed_pop(gst::ClockTime::NONE) {
                    Some(message) => match message.view() {
                        gst::MessageView::Eos(..) => return Ok(()),
                        gst::MessageView::Error(error) => {
                            let detail = format!(
                                "GStreamer error from {}: {} ({:?})",
                                error.src().map(|src| src.path_string()).unwrap_or_default(),
                                error.error(),
                                error.debug()
                            );
                            let _ = sender.blocking_send(Err(anyhow::anyhow!(detail.clone())));
                            bail!(detail);
                        }
                        _ => {}
                    },
                    None => bail!("GStreamer bus closed before EOS"),
                }
            }
        });
        pipeline
            .set_state(gst::State::Playing)
            .context("starting GStreamer pipeline")?;
        Ok(Self {
            pipeline,
            source,
            frames,
            output,
            writer,
            bus,
            dimensions,
            mode,
            backend,
            dma_signature,
        })
    }
    async fn stop(mut self) -> Result<()> {
        self.output.close();
        let _ = self.frames.send(None);
        let writer_result =
            match tokio::time::timeout(Duration::from_secs(3), &mut self.writer).await {
                Ok(result) => result
                    .context("encoder writer task failed")
                    .and_then(|result| result),
                Err(_) => {
                    self.writer.abort();
                    let _ = (&mut self.writer).await;
                    Err(anyhow::anyhow!("encoder writer shutdown timed out"))
                }
            };
        let bus_result = match tokio::time::timeout(Duration::from_secs(5), &mut self.bus).await {
            Ok(result) => result
                .context("GStreamer bus task failed")
                .and_then(|result| result),
            Err(_) => {
                self.bus.abort();
                let _ = (&mut self.bus).await;
                Err(anyhow::anyhow!("GStreamer EOS timed out"))
            }
        };
        self.pipeline
            .set_state(gst::State::Null)
            .context("stopping GStreamer pipeline")?;
        drop(self.source);
        writer_result.and(bus_result)
    }
}

fn segment_path(path: &std::path::Path, segment: usize) -> PathBuf {
    if segment == 0 {
        return path.to_owned();
    }
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{stem}-{segment:04}.mp4"))
}

async fn run(options: Options) -> Result<()> {
    if options.output.exists() {
        tokio::fs::remove_file(&options.output).await?;
    }
    let listener = UnixListener::bind(&options.output)?;
    let hub = Arc::new(Mutex::new(Hub::new()));
    let inputs = Arc::new(Inputs::default());
    let accept_hub = hub.clone();
    let accept_inputs = inputs.clone();
    let accept = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;
            let hub = accept_hub.clone();
            let inputs = accept_inputs.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_viewer(stream, hub, inputs).await {
                    eprintln!("display viewer disconnected: {error}");
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });
    let bus = Builder::unix_stream(UnixStream::from_std(inherited_stream(options.bus_fd)?)?)
        .p2p()
        .build()
        .await?;
    let (local, peer) = StdUnixStream::pair()?;
    local.set_nonblocking(true)?;
    let state = Arc::new(Mutex::new(CaptureState::new()));
    let (_connection, path) = attach(
        &bus,
        UnixStream::from_std(local)?,
        peer.into(),
        state.clone(),
    )
    .await?;
    let (audio_sender, mut audio_events) = mpsc::unbounded_channel();
    let (audio_local, audio_peer) = StdUnixStream::pair()?;
    audio_local.set_nonblocking(true)?;
    let _audio_connection = match attach_audio(
        &bus,
        UnixStream::from_std(audio_local)?,
        audio_peer.into(),
        audio_sender,
    )
    .await
    {
        Ok(connection) => Some(connection),
        Err(error) => {
            eprintln!("QEMU D-Bus audio unavailable: {error}");
            None
        }
    };
    let clipboard_state = Arc::new(ClipboardState::default());
    let (clipboard_sender, mut clipboard_events) = mpsc::unbounded_channel();
    // QEMU creates a proxy back to this object while Register is in flight.
    // Keep that optional handshake off the display startup path: a broken or
    // incompatible clipboard peer must never prevent the first scanout from
    // reaching the encoder.
    let (clipboard_ready_sender, mut clipboard_ready) = mpsc::channel(1);
    let clipboard_bus = bus.clone();
    let clipboard_attach_state = clipboard_state.clone();
    tokio::spawn(async move {
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            attach_clipboard(&clipboard_bus, clipboard_attach_state, clipboard_sender),
        )
        .await
        .map_err(|_| anyhow::anyhow!("clipboard registration timed out"))
        .and_then(|result| result.map_err(anyhow::Error::from));
        let _ = clipboard_ready_sender.send(result).await;
    });
    let mut clipboard_available = false;
    let mut clipboard_registration_done = false;
    let clipboard_status = record_bytes(&Record {
        kind: RecordType::Control,
        flags: 0,
        pts_us: unix_time_us()?,
        payload: bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({
            "type": "clipboard",
            "available": clipboard_available,
        }))?),
    })?;
    hub.lock()
        .expect("hub lock poisoned")
        .publish_clipboard(clipboard_status);
    let input_bus = bus.clone();
    let input_hub = hub.clone();
    let input_clipboard = clipboard_state.clone();
    let input_worker = tokio::spawn(async move {
        loop {
            inputs.ready.notified().await;
            loop {
                let message = inputs
                    .queue
                    .lock()
                    .expect("input lock poisoned")
                    .pop_front();
                let Some(message) = message else {
                    break;
                };
                let kind = message["type"].as_str().unwrap_or_default();
                if kind == "clipboard_set" {
                    let result = message["text"]
                        .as_str()
                        .filter(|text| text.len() <= MAX_CLIPBOARD_BYTES)
                        .context("invalid clipboard text");
                    match result {
                        Ok(text) => {
                            if let Err(error) =
                                set_clipboard(&input_bus, &input_clipboard, text).await
                            {
                                eprintln!("setting guest clipboard failed: {error}");
                            }
                        }
                        Err(error) => eprintln!("setting guest clipboard failed: {error}"),
                    }
                } else if kind == "clipboard_request" {
                    match tokio::time::timeout(
                        Duration::from_secs(6),
                        request_clipboard(&input_bus),
                    )
                    .await
                    {
                        Ok(Ok(text)) => {
                            match record_bytes(&Record {
                                kind: RecordType::Control,
                                flags: 0,
                                pts_us: unix_time_us().unwrap_or_default(),
                                payload: bytes::Bytes::from(
                                    serde_json::to_vec(&serde_json::json!({
                                        "type": "clipboard",
                                        "available": true,
                                        "text": text,
                                    }))
                                    .unwrap_or_default(),
                                ),
                            }) {
                                Ok(packet) => input_hub
                                    .lock()
                                    .expect("hub lock poisoned")
                                    .publish_clipboard(packet),
                                Err(error) => {
                                    eprintln!("encoding guest clipboard failed: {error}");
                                }
                            }
                        }
                        result => eprintln!("requesting guest clipboard failed: {result:?}"),
                    }
                } else {
                    match tokio::time::timeout(
                        Duration::from_secs(2),
                        input(&input_bus, &path, &message.to_string()),
                    )
                    .await
                    {
                        Ok(Ok(true)) => {}
                        result => eprintln!("display input forwarding failed: {result:?}"),
                    }
                }
            }
        }
    });
    let mut encoder: Option<Encoder> = None;
    let mut native_failed: Option<DmaSignature> = None;
    let mut segment = 0;
    let mut parameters = Vec::new();
    let mut audio_config: Option<AudioConfig> = None;
    let mut tick = tokio::time::interval(Duration::from_nanos(1_000_000_000 / TARGET_FPS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = tick.tick() => {
                    if accept.is_finished() { bail!("display listener stopped"); }
                    if let Some(current) = encoder.as_ref() {
                        if current.writer.is_finished() { bail!("encoder input writer stopped"); }
                    }
                    let capture = state.lock().expect("capture lock poisoned").snapshot(false);
                    if let Some(CaptureFrame { cpu, dma }) = capture {
                        let dimensions = cpu.dimensions();
                        let candidate = dma
                            .as_ref()
                            .filter(|frame| Some(dma_signature(frame)) != native_failed);
                        let desired_mode = if candidate.is_some() {
                            EncoderMode::DmaBuf
                        } else {
                            EncoderMode::Cpu
                        };
                        let restart = encoder.as_ref().is_none_or(|current| {
                            current.dimensions != dimensions || current.mode != desired_mode
                                || (desired_mode == EncoderMode::DmaBuf
                                    && current.dma_signature
                                        != candidate.map(|frame| dma_signature(frame)))
                        });
                        if restart {
                            hub.lock().expect("hub lock poisoned").reset();
                            if let Some(old) = encoder.take() { old.stop().await?; segment += 1; }
                            parameters.clear();
                            let record = segment_path(&options.record, segment);
                            if let Some(dma) = dma.filter(|frame| Some(dma_signature(frame)) != native_failed) {
                                let signature = dma_signature(&dma);
                                match Encoder::start_dmabuf(dma, &record) {
                                    Ok(current) => {
                                        eprintln!(
                                            "display encoder using EGL/GBM/VAAPI GPU path"
                                        );
                                        state.lock().expect("capture lock poisoned").set_native(true);
                                        encoder = Some(current);
                                    }
                                    Err(error) => {
                                        eprintln!("DMABUF encoder unavailable, using CPU capture: {error:#}");
                                        native_failed = Some(signature);
                                        state.lock().expect("capture lock poisoned").set_native(false);
                                        encoder = Some(Encoder::start_cpu(cpu, &record)?);
                                    }
                                }
                            } else {
                                state.lock().expect("capture lock poisoned").set_native(false);
                                encoder = Some(Encoder::start_cpu(cpu, &record)?);
                            }
                        } else if let Some(current) = encoder.as_ref() {
                            let input = match (current.mode, dma) {
                                (EncoderMode::DmaBuf, Some(frame)) => EncoderInput::DmaBuf(Arc::new(frame)),
                                _ => EncoderInput::Cpu(Arc::new(cpu)),
                            };
                            current.frames.send(Some(input))?;
                        }
                    }
                }
                event = audio_events.recv(), if _audio_connection.is_some() => {
                    let event = event.context("D-Bus audio listener stopped")?;
                    match event {
                        AudioEvent::Init { id, bits, signed, float, frequency, channels,
                            bytes_per_frame, big_endian } => {
                            audio_config = Some(AudioConfig { id, bits, signed, float, frequency,
                                channels, bytes_per_frame, big_endian, enabled: false,
                                muted: false, volume: vec![255; channels as usize] });
                        }
                        AudioEvent::Enabled { id, enabled } => {
                            if let Some(config) = audio_config.as_mut().filter(|config| config.id == id) {
                                config.enabled = enabled;
                            }
                        }
                        AudioEvent::Volume { id, muted, channels } => {
                            if let Some(config) = audio_config.as_mut().filter(|config| config.id == id) {
                                config.muted = muted;
                                config.volume = channels;
                            }
                        }
                        AudioEvent::Fini { id } => {
                            if let Some(config) = audio_config.as_mut().filter(|config| config.id == id) {
                                config.enabled = false;
                            }
                        }
                        AudioEvent::Data { id, data } => {
                            if audio_config.as_ref().is_some_and(|config| config.id == id && config.enabled) {
                                let packet = record_bytes(&Record { kind: RecordType::AudioData,
                                    flags: 0, pts_us: unix_time_us()?, payload: bytes::Bytes::from(data) })?;
                                hub.lock().expect("hub lock poisoned").publish_audio(packet);
                            }
                            continue;
                        }
                    }
                    if let Some(config) = &audio_config {
                        let packet = record_bytes(&Record { kind: RecordType::AudioConfig,
                            flags: 0, pts_us: unix_time_us()?,
                            payload: bytes::Bytes::from(serde_json::to_vec(config)?) })?;
                        hub.lock().expect("hub lock poisoned").publish_audio_config(packet);
                    }
                }
                registration = clipboard_ready.recv(), if !clipboard_registration_done => {
                    clipboard_registration_done = true;
                    match registration {
                        Some(Ok(())) => {
                            clipboard_available = true;
                            let packet = record_bytes(&Record {
                                kind: RecordType::Control,
                                flags: 0,
                                pts_us: unix_time_us()?,
                                payload: bytes::Bytes::from(serde_json::to_vec(
                                    &serde_json::json!({
                                        "type": "clipboard",
                                        "available": true,
                                    }),
                                )?),
                            })?;
                            hub.lock()
                                .expect("hub lock poisoned")
                                .publish_clipboard(packet);
                        }
                        Some(Err(error)) => {
                            eprintln!("QEMU D-Bus clipboard unavailable: {error:#}");
                        }
                        None => eprintln!("QEMU D-Bus clipboard registration task stopped"),
                    }
                }
                event = clipboard_events.recv(), if clipboard_available => {
                    let event = event.context("D-Bus clipboard listener stopped")?;
                    match event {
                        ClipboardEvent::Grab { selection: 0, mimes, .. }
                            if mimes.iter().any(|mime| mime == display_stream::listener::CLIPBOARD_MIME) =>
                        {
                            match tokio::time::timeout(
                                Duration::from_secs(6),
                                request_clipboard(&bus),
                            )
                            .await
                            {
                                Ok(Ok(text)) => {
                                    let packet = record_bytes(&Record {
                                        kind: RecordType::Control,
                                        flags: 0,
                                        pts_us: unix_time_us()?,
                                        payload: bytes::Bytes::from(serde_json::to_vec(
                                            &serde_json::json!({
                                                "type": "clipboard",
                                                "available": true,
                                                "text": text,
                                            }),
                                        )?),
                                    })?;
                                    hub.lock()
                                        .expect("hub lock poisoned")
                                        .publish_clipboard(packet);
                                }
                                result => {
                                    eprintln!("reading guest clipboard failed: {result:?}");
                                }
                            }
                        }
                        ClipboardEvent::Release { selection: 0 } => {
                            let packet = record_bytes(&Record {
                                kind: RecordType::Control,
                                flags: 0,
                                pts_us: unix_time_us()?,
                                payload: bytes::Bytes::from(serde_json::to_vec(
                                    &serde_json::json!({
                                        "type": "clipboard",
                                        "available": true,
                                        "text": null,
                                    }),
                                )?),
                            })?;
                            hub.lock()
                                .expect("hub lock poisoned")
                                .publish_clipboard(packet);
                        }
                        _ => {}
                    }
                }
                payload = async {
                    match encoder.as_mut() {
                        Some(current) => current.output.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let encoded = match payload.context("encoder output closed")? {
                        Ok(encoded) => encoded,
                        Err(error) if encoder.as_ref().is_some_and(|current| current.mode == EncoderMode::DmaBuf) => {
                            eprintln!("DMABUF encoder failed, reverting to CPU capture: {error:#}");
                            native_failed = encoder.as_ref().and_then(|current| current.dma_signature);
                            state.lock().expect("capture lock poisoned").set_native(false);
                            if let Some(current) = encoder.take() {
                                if let Err(stop_error) = current.stop().await {
                                    eprintln!("failed to stop DMABUF encoder after fallback: {stop_error:#}");
                                }
                                segment += 1;
                            }
                            hub.lock().expect("hub lock poisoned").reset();
                            parameters.clear();
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    let payload = encoded.payload;
                    let key = contains_idr(&payload);
                    let new_parameters = parameter_sets(&payload);
                    if !new_parameters.is_empty() { parameters = new_parameters; }
                    let pts = encoded.captured_at_us;
                    let mut packet = Vec::new();
                    if key {
                        let (width, height) = encoder.as_ref().context("missing encoder")?.dimensions;
                        let current = encoder.as_ref().context("missing encoder")?;
                        let config = VideoConfig {
                            codec: codec_from_sps(&parameters).context("keyframe missing SPS")?,
                            coded_width: width, coded_height: height,
                            description: avcc_description(&parameters).context("keyframe missing SPS/PPS")?,
                            capture: current.mode.label().into(),
                            encoder: current.backend.label().into(),
                            hardware: current.backend.hardware(),
                        };
                        packet.extend(record_bytes(&Record { kind: RecordType::Config, flags: 0, pts_us: pts,
                            payload: bytes::Bytes::from(serde_json::to_vec(&config)?) })?);
                    }
                    packet.extend(record_bytes(&Record { kind: if key { RecordType::Keyframe } else { RecordType::Delta },
                        flags: 0, pts_us: pts, payload: bytes::Bytes::from(payload) })?);
                    hub.lock().expect("hub lock poisoned").publish(packet, key);
                }
            }
        }
        Ok(())
    }.await;
    accept.abort();
    input_worker.abort();
    let shutdown = match encoder {
        Some(current) => current.stop().await,
        None => Ok(()),
    };
    let _ = tokio::fs::remove_file(&options.output).await;
    result.and(shutdown)
}

fn main() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(options()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn late_viewer_gets_all_references_then_exactly_the_next_live_record() {
        let mut hub = Hub::new();
        hub.publish(vec![0, 1], true);
        hub.publish(vec![2, 10], false);
        hub.publish(vec![2, 11], false);
        let (bootstrap, mut live) = hub.subscribe();
        assert_eq!(
            bootstrap.iter().map(|p| p.as_slice()).collect::<Vec<_>>(),
            vec![&[0, 1][..], &[2, 10], &[2, 11]]
        );
        hub.publish(vec![2, 12], false);
        assert_eq!(&**live.try_recv().unwrap(), &[2, 12]);
        assert!(live.try_recv().is_err());
        hub.publish(vec![0, 20], true);
        assert_eq!(hub.subscribe().0.len(), 1);
        hub.reset();
        assert!(hub.subscribe().0.is_empty());
    }

    #[test]
    fn bootstrap_memory_is_bounded_and_recovers_at_next_keyframe() {
        let mut hub = Hub::new();
        hub.publish(vec![0, 1], true);
        hub.publish(vec![2; MAX_GOP_BYTES], false);
        assert!(hub.subscribe().0.is_empty());
        hub.publish(vec![2, 3], false);
        assert!(hub.subscribe().0.is_empty());
        hub.publish(vec![0, 4], true);
        assert_eq!(hub.subscribe().0.len(), 1);
    }

    #[tokio::test]
    async fn existing_viewer_recovery_replays_config_and_complete_gop() {
        let hub = Arc::new(Mutex::new(Hub::new()));
        hub.lock().unwrap().publish(vec![0, 1], true);
        hub.lock().unwrap().publish(vec![2, 3], false);
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_viewer(server, hub, Arc::new(Inputs::default())));
        let mut initial = [0; 4];
        client.read_exact(&mut initial).await.unwrap();
        client
            .write_all(b"{ \"type\" : \"request_idr\" }\n")
            .await
            .unwrap();
        let mut replay = [0; 4];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut replay))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(initial, [0, 1, 2, 3]);
        assert_eq!(initial, replay);
        drop(client);
        assert!(task.await.unwrap().is_err());
    }

    #[test]
    fn motion_coalescing_preserves_click_order_and_has_a_hard_limit() {
        let inputs = Inputs::default();
        inputs.push(json!({"type":"mouse_abs","x":1})).unwrap();
        inputs.push(json!({"type":"mouse_abs","x":2})).unwrap();
        inputs
            .push(json!({"type":"mouse_down","button":0}))
            .unwrap();
        inputs.push(json!({"type":"mouse_abs","x":3})).unwrap();
        let queue = inputs.queue.lock().unwrap();
        assert_eq!(queue.len(), 3);
        assert_eq!(queue[0]["x"], 2);
        assert_eq!(queue[1]["type"], "mouse_down");
        assert_eq!(queue[2]["x"], 3);
        drop(queue);
        for _ in 3..256 {
            inputs.push(json!({"type":"key_up","keycode":30})).unwrap();
        }
        assert!(
            inputs
                .push(json!({"type":"key_down","keycode":30}))
                .is_err()
        );
    }

    #[test]
    fn recording_segments_have_distinct_names() {
        let path = PathBuf::from("/tmp/screen.mp4");
        assert_eq!(segment_path(&path, 0), path);
        assert_eq!(
            segment_path(&path, 1),
            PathBuf::from("/tmp/screen-0001.mp4")
        );
        assert_ne!(segment_path(&path, 1), segment_path(&path, 2));
    }
    #[tokio::test]
    #[ignore = "requires GStreamer openh264enc/h264parse/mp4mux and ffmpeg"]
    async fn real_encoder_static_frames_backpressure_and_recording_shutdown() {
        let root =
            std::env::temp_dir().join(format!("display-stream-integration-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let record = root.join("screen.mp4");
        let mut first_size = 0;
        for (segment, width, height) in [(0, 640, 480), (1, 320, 240)] {
            let mut seed = 1u32;
            let pixels: Vec<u8> = (0..width * height * 4)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let frame = Frame::scanout(width, height, width * 4, 0x2002_8840, &pixels).unwrap();
            let path = segment_path(&record, segment);
            let (pipeline, source, sink) = gst_pipeline_encoder(
                width,
                height,
                &path,
                &["openh264enc", "gop-size=10", "bitrate=20000000"],
                false,
                None,
            )
            .unwrap();
            let mut encoder = Encoder::from_pipeline(
                EncoderInput::Cpu(Arc::new(frame)),
                pipeline,
                source,
                sink,
                EncoderMode::Cpu,
                EncoderBackend::OpenH264,
                None,
            )
            .unwrap();
            let mut count = 0;
            let mut keys = 0;
            let mut compressed = Vec::new();
            tokio::time::timeout(Duration::from_secs(15), async {
                while count < 35 {
                    let encoded = encoder.output.recv().await.unwrap().unwrap();
                    keys += usize::from(contains_idr(&encoded.payload));
                    compressed.extend(encoded.payload);
                    count += 1;
                }
            })
            .await
            .expect("encoder stalled on pipes or idle screen");
            assert!(keys >= 3, "static screen did not produce periodic IDRs");
            encoder.stop().await.unwrap();
            let h264 = root.join(format!("segment-{segment}.h264"));
            std::fs::write(&h264, compressed).unwrap();
            for input in [&h264, &path] {
                let decoded = Command::new("ffmpeg")
                    .args(["-v", "error", "-xerror", "-i"])
                    .arg(input)
                    .args(["-f", "null", "-"])
                    .output()
                    .await
                    .unwrap();
                assert!(
                    decoded.status.success(),
                    "{}",
                    String::from_utf8_lossy(&decoded.stderr)
                );
                assert!(
                    decoded.stderr.is_empty(),
                    "{}",
                    String::from_utf8_lossy(&decoded.stderr)
                );
            }
            if segment == 0 {
                first_size = std::fs::metadata(&record).unwrap().len();
            } else {
                assert_eq!(std::fs::metadata(&record).unwrap().len(), first_size);
            }
        }
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn viewer_without_bootstrap_waits_for_keyframe() {
        let hub = Arc::new(Mutex::new(Hub::new()));
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_viewer(
            server,
            hub.clone(),
            Arc::new(Inputs::default()),
        ));
        tokio::task::yield_now().await;
        hub.lock().unwrap().publish(vec![2, 99], false);
        let mut bytes = [0; 2];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read_exact(&mut bytes))
                .await
                .is_err()
        );
        hub.lock().unwrap().publish(vec![0, 1], true);
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, [0, 1]);
        drop(client);
        let _ = task.await;
    }

    #[test]
    fn lagged_subscription_can_resynchronize_without_missing_references() {
        let mut hub = Hub::new();
        let (_, mut old) = hub.subscribe();
        hub.publish(vec![0, 1], true);
        for i in 0..MAX_VIEWER_QUEUE + 1 {
            hub.publish(vec![2, u8::try_from(i).unwrap()], false);
        }
        assert!(matches!(
            old.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        let (bootstrap, mut live) = hub.subscribe();
        assert_eq!(bootstrap.len(), MAX_VIEWER_QUEUE + 2);
        assert_eq!(&**bootstrap.first().unwrap(), &[0, 1]);
        hub.publish(vec![2, 100], false);
        assert_eq!(&**live.try_recv().unwrap(), &[2, 100]);
    }
}
