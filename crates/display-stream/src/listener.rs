//! QEMU D-Bus display listener.

use crate::frame::{Frame, FrameError, pixman_from_fourcc};
use memmap2::MmapOptions;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use zbus::zvariant::ObjectPath;
use zbus::{Connection, interface, proxy};

/// MIME type supported by QEMU's current D-Bus clipboard implementation.
pub const CLIPBOARD_MIME: &str = "text/plain;charset=utf-8";
/// Maximum clipboard payload accepted from either side.
pub const MAX_CLIPBOARD_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct CaptureState {
    pub frame: Option<Frame>,
    pub refresh: bool,
    dma: Option<DmaBufFrame>,
    native: bool,
}

/// A platform-native capture surface. The encoder duplicates the descriptor
/// when it wraps a frame, so QEMU and GStreamer retain independent ownership.
#[derive(Clone, Debug)]
pub struct DmaBufFrame {
    pub file: Arc<File>,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub fourcc: u32,
    pub modifier: u64,
    pub y0_top: bool,
    pixman_format: u32,
}

#[derive(Clone, Debug)]
pub struct CaptureFrame {
    pub cpu: Frame,
    pub dma: Option<DmaBufFrame>,
}

const I915_FORMAT_MOD_X_TILED: u64 = 0x0100_0000_0000_0001;

fn copy_x_tiled_row(
    mapped: &[u8],
    stride: usize,
    source_y: usize,
    source_x: usize,
    width: usize,
    target: &mut [u8],
) -> Result<(), FrameError> {
    let tiles_per_row = stride / 512;
    let mut source_byte_x = source_x.checked_mul(4).ok_or(FrameError::Geometry)?;
    let mut target_offset = 0;
    let end = source_byte_x
        .checked_add(width.checked_mul(4).ok_or(FrameError::Geometry)?)
        .ok_or(FrameError::Geometry)?;
    while source_byte_x < end {
        let in_tile_x = source_byte_x % 512;
        let bytes = (512 - in_tile_x).min(end - source_byte_x);
        let source = (source_y / 8 * tiles_per_row + source_byte_x / 512) * 4096
            + source_y % 8 * 512
            + in_tile_x;
        if source + bytes > mapped.len() || target_offset + bytes > target.len() {
            return Err(FrameError::ShortData);
        }
        target[target_offset..target_offset + bytes]
            .copy_from_slice(&mapped[source..source + bytes]);
        source_byte_x += bytes;
        target_offset += bytes;
    }
    Ok(())
}

fn linearize_x_tiled(
    mapped: &[u8],
    width: u32,
    height: u32,
    stride: u32,
    y0_top: bool,
) -> Result<Vec<u8>, FrameError> {
    if stride < width.saturating_mul(4) || !stride.is_multiple_of(512) {
        return Err(FrameError::Geometry);
    }
    let required = (stride as usize)
        .checked_mul(height as usize)
        .ok_or(FrameError::Geometry)?;
    if mapped.len() < required {
        return Err(FrameError::ShortData);
    }
    let mut output = vec![0; required];
    for y in 0..height as usize {
        // The firmware scanout is top-down (`y0_top=false`), while the Windows
        // virtio GPU driver switches to a bottom-up surface (`y0_top=true`).
        let source_y = if y0_top { height as usize - 1 - y } else { y };
        let target = y * stride as usize;
        copy_x_tiled_row(
            mapped,
            stride as usize,
            source_y,
            0,
            width as usize,
            &mut output[target..target + width as usize * 4],
        )?;
    }
    Ok(output)
}

fn flip_linear(mapped: &[u8], height: u32, stride: u32) -> Result<Vec<u8>, FrameError> {
    let length = (height as usize)
        .checked_mul(stride as usize)
        .ok_or(FrameError::Geometry)?;
    if mapped.len() < length {
        return Err(FrameError::ShortData);
    }
    let mut output = vec![0; length];
    for row in 0..height as usize {
        let source = (height as usize - 1 - row) * stride as usize;
        let target = row * stride as usize;
        output[target..target + stride as usize]
            .copy_from_slice(&mapped[source..source + stride as usize]);
    }
    Ok(output)
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            frame: None,
            refresh: false,
            dma: None,
            native: false,
        }
    }
    fn scanout(
        &mut self,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
        data: &[u8],
    ) -> Result<(), FrameError> {
        self.frame = Some(Frame::scanout(width, height, stride, format, data)?);
        self.refresh = true;
        Ok(())
    }
    fn update(
        &mut self,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        stride: u32,
        format: u32,
        data: &[u8],
    ) -> Result<(), FrameError> {
        let frame = self.frame.as_mut().ok_or(FrameError::Outside)?;
        frame.update(x, y, width, height, stride, format, data)?;
        self.refresh = true;
        Ok(())
    }

    fn scanout_dmabuf(
        &mut self,
        dmabuf: zbus::zvariant::OwnedFd,
        width: u32,
        height: u32,
        stride: u32,
        fourcc: u32,
        modifier: u64,
        y0_top: bool,
    ) -> Result<(), FrameError> {
        eprintln!(
            "ScanoutDMABUF width={width} height={height} stride={stride} fourcc=0x{fourcc:08x} modifier={modifier} y0_top={y0_top}"
        );
        if modifier != 0 && modifier != I915_FORMAT_MOD_X_TILED {
            eprintln!("ScanoutDMABUF rejected: unsupported modifier={modifier}");
            return Err(FrameError::Format(fourcc));
        }
        let pixman_format = match pixman_from_fourcc(fourcc) {
            Some(format) => format,
            None => {
                eprintln!("ScanoutDMABUF rejected: unsupported fourcc=0x{fourcc:08x}");
                return Err(FrameError::Format(fourcc));
            }
        };
        let file = Arc::new(File::from(std::os::fd::OwnedFd::from(dmabuf)));
        let length = (stride as usize)
            .checked_mul(height as usize)
            .ok_or(FrameError::Geometry)?;
        // QEMU's linear DMABUF is a read-only snapshot source for this
        // process. The mapped bytes are copied into the owned framebuffer.
        #[allow(unsafe_code)]
        let mapped = match unsafe { MmapOptions::new().len(length).map(&file) } {
            Ok(mapped) => mapped,
            Err(error) => {
                eprintln!("ScanoutDMABUF mmap failed for {length} bytes: {error}");
                return Err(FrameError::ShortData);
            }
        };
        let linear = if modifier == I915_FORMAT_MOD_X_TILED {
            linearize_x_tiled(&mapped, width, height, stride, y0_top)?
        } else if y0_top {
            mapped.to_vec()
        } else {
            flip_linear(&mapped, height, stride)?
        };
        self.frame = Some(Frame::scanout(
            width,
            height,
            stride,
            pixman_format,
            &linear,
        )?);
        self.dma = Some(DmaBufFrame {
            file,
            width,
            height,
            stride,
            fourcc,
            pixman_format,
            modifier,
            y0_top,
        });
        self.refresh = true;
        Ok(())
    }

    fn update_dmabuf(&mut self, x: i32, y: i32, width: i32, height: i32) -> Result<(), FrameError> {
        let source = match self.dma.as_ref() {
            Some(source) => source,
            None => {
                eprintln!(
                    "UpdateDMABUF without an accepted scanout: x={x} y={y} width={width} height={height}"
                );
                return Err(FrameError::Outside);
            }
        };
        let x = u32::try_from(x).map_err(|_| FrameError::Outside)?;
        let y = u32::try_from(y).map_err(|_| FrameError::Outside)?;
        let width = u32::try_from(width).map_err(|_| FrameError::Outside)?;
        let height = u32::try_from(height).map_err(|_| FrameError::Outside)?;
        if x.checked_add(width)
            .filter(|right| *right <= source.width)
            .is_none()
            || y.checked_add(height)
                .filter(|bottom| *bottom <= source.height)
                .is_none()
        {
            return Err(FrameError::Outside);
        }
        if self.native {
            self.refresh = true;
            return Ok(());
        }
        let length = (source.stride as usize)
            .checked_mul(source.height as usize)
            .ok_or(FrameError::Geometry)?;
        #[allow(unsafe_code)]
        let mapped = match unsafe { MmapOptions::new().len(length).map(&source.file) } {
            Ok(mapped) => mapped,
            Err(error) => {
                eprintln!("UpdateDMABUF mmap failed for {length} bytes: {error}");
                return Err(FrameError::ShortData);
            }
        };
        let linear = if source.modifier == I915_FORMAT_MOD_X_TILED {
            linearize_x_tiled(
                &mapped,
                source.width,
                source.height,
                source.stride,
                source.y0_top,
            )?
        } else if source.y0_top {
            mapped.to_vec()
        } else {
            flip_linear(&mapped, source.height, source.stride)?
        };
        // We already reconstructed the complete scanout above. Publishing that
        // complete image avoids applying QEMU's top-left damage coordinates a
        // second time to the bottom-up tiled source and prevents stale blocks
        // when the producer's damage region is smaller than its actual update.
        self.frame = Some(Frame::scanout(
            source.width,
            source.height,
            source.stride,
            source.pixman_format,
            &linear,
        )?);
        self.refresh = true;
        Ok(())
    }

    fn scanout_dmabuf2(
        &mut self,
        dmabufs: Vec<zbus::zvariant::OwnedFd>,
        offsets: Vec<u32>,
        strides: Vec<u32>,
        width: u32,
        height: u32,
        fourcc: u32,
        backing_width: u32,
        backing_height: u32,
        modifier: u64,
        y0_top: bool,
    ) -> Result<(), FrameError> {
        eprintln!(
            "ScanoutDMABUF2 planes={} width={width} height={height} backing={backing_width}x{backing_height} fourcc=0x{fourcc:08x} modifier={modifier} y0_top={y0_top}",
            dmabufs.len()
        );
        if dmabufs.len() != 1 || offsets.first().copied().unwrap_or(0) != 0 {
            eprintln!("ScanoutDMABUF2 rejected: expected one plane with offset zero");
            return Err(FrameError::Format(fourcc));
        }
        let stride = strides.first().copied().ok_or(FrameError::Geometry)?;
        self.scanout_dmabuf(
            dmabufs.into_iter().next().expect("one DMABUF plane"),
            backing_width.max(width),
            backing_height.max(height),
            stride,
            fourcc,
            modifier,
            y0_top,
        )
    }

    pub fn snapshot(&mut self, force: bool) -> Option<CaptureFrame> {
        if !self.refresh && !force {
            return None;
        }
        self.refresh = false;
        Some(CaptureFrame {
            cpu: self.frame.clone()?,
            dma: self.dma.clone(),
        })
    }

    pub fn set_native(&mut self, native: bool) {
        self.native = native;
        if !native {
            self.refresh = true;
        }
    }
}

pub struct DmaBuf2Listener {
    pub state: Arc<Mutex<CaptureState>>,
}

#[interface(name = "org.qemu.Display1.Listener.Unix.ScanoutDMABUF2")]
impl DmaBuf2Listener {
    #[zbus(name = "ScanoutDMABUF2")]
    async fn scanout_dmabuf2(
        &self,
        dmabufs: Vec<zbus::zvariant::OwnedFd>,
        _x: u32,
        _y: u32,
        width: u32,
        height: u32,
        offsets: Vec<u32>,
        strides: Vec<u32>,
        _num_planes: u32,
        fourcc: u32,
        backing_width: u32,
        backing_height: u32,
        modifier: u64,
        y0_top: bool,
    ) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .expect("capture lock poisoned")
            .scanout_dmabuf2(
                dmabufs,
                offsets,
                strides,
                width,
                height,
                fourcc,
                backing_width,
                backing_height,
                modifier,
                y0_top,
            )
            .map_err(|error| zbus::fdo::Error::NotSupported(error.to_string()))
    }
}

pub struct Listener {
    pub state: Arc<Mutex<CaptureState>>,
}

#[interface(name = "org.qemu.Display1.Listener")]
impl Listener {
    async fn scanout(
        &self,
        width: u32,
        height: u32,
        stride: u32,
        pixman_format: u32,
        data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .expect("capture lock poisoned")
            .scanout(width, height, stride, pixman_format, &data)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }
    async fn update(
        &self,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        stride: u32,
        pixman_format: u32,
        data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .expect("capture lock poisoned")
            .update(x, y, width, height, stride, pixman_format, &data)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }
    #[zbus(name = "ScanoutDMABUF")]
    async fn scanout_dmabuf(
        &self,
        dmabuf: zbus::zvariant::OwnedFd,
        width: u32,
        height: u32,
        stride: u32,
        fourcc: u32,
        modifier: u64,
        y0_top: bool,
    ) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .expect("capture lock poisoned")
            .scanout_dmabuf(dmabuf, width, height, stride, fourcc, modifier, y0_top)
            .map_err(|error| zbus::fdo::Error::NotSupported(error.to_string()))
    }
    #[zbus(name = "UpdateDMABUF")]
    async fn update_dmabuf(
        &self,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
    ) -> zbus::fdo::Result<()> {
        self.state
            .lock()
            .expect("capture lock poisoned")
            .update_dmabuf(x, y, width, height)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))
    }
    async fn disable(&self) -> zbus::fdo::Result<()> {
        Ok(())
    }
    async fn mouse_set(&self, _x: i32, _y: i32, _on: i32) -> zbus::fdo::Result<()> {
        Ok(())
    }
    async fn cursor_define(
        &self,
        _width: i32,
        _height: i32,
        _hot_x: i32,
        _hot_y: i32,
        _data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        Ok(())
    }
    async fn cursor_move(&self, _x: i32, _y: i32) -> zbus::fdo::Result<()> {
        Ok(())
    }
    async fn cursor_update(
        &self,
        _x: i32,
        _y: i32,
        _width: i32,
        _height: i32,
        _data: Vec<u8>,
    ) -> zbus::fdo::Result<()> {
        Ok(())
    }
}

#[proxy(interface = "org.qemu.Display1.VM", default_service = "org.qemu")]
trait VmProxy {
    #[zbus(property, name = "ConsoleIDs")]
    fn console_ids(&self) -> zbus::Result<Vec<u32>>;
}

#[proxy(interface = "org.qemu.Display1.Console", default_service = "org.qemu")]
trait ConsoleProxy {
    async fn register_listener(&self, listener: zbus::zvariant::OwnedFd) -> zbus::Result<()>;
    #[zbus(name = "SetUIInfo")]
    async fn set_ui_info(
        &self,
        width_mm: u16,
        height_mm: u16,
        xoff: i32,
        yoff: i32,
        width: u32,
        height: u32,
    ) -> zbus::Result<()>;
    #[zbus(property, name = "Type")]
    fn type_(&self) -> zbus::Result<String>;
}

/// Attach a listener to the first graphic QEMU console on a p2p connection.
pub async fn attach(
    connection: &Connection,
    listener_stream: UnixStream,
    listener_fd: OwnedFd,
    state: Arc<Mutex<CaptureState>>,
) -> zbus::Result<(Connection, ObjectPath<'static>)> {
    let vm = VmProxyProxy::builder(connection)
        .path("/org/qemu/Display1/VM")?
        .build()
        .await?;
    let consoles = vm.console_ids().await?;
    let id = consoles
        .into_iter()
        .next()
        .ok_or_else(|| zbus::Error::Failure("QEMU exposed no display console".into()))?;
    let path: ObjectPath<'static> = format!("/org/qemu/Display1/Console_{id}")
        .try_into()
        .map_err(|_| zbus::Error::Failure("invalid QEMU console path".into()))?;
    let console = ConsoleProxyProxy::builder(connection)
        .path(path.clone())?
        .build()
        .await?;
    if console.type_().await? != "Graphic" {
        return Err(zbus::Error::Failure("QEMU console is not graphical".into()));
    }
    let listener_task = tokio::spawn(async move {
        // QEMU is the D-Bus server for registered listeners; this end is the
        // client that exports the Listener object.
        let listener_connection = zbus::connection::Builder::unix_stream(listener_stream)
            .p2p()
            .build()
            .await?;
        listener_connection
            .object_server()
            .at(
                "/org/qemu/Display1/Listener",
                Listener {
                    state: state.clone(),
                },
            )
            .await?;
        listener_connection
            .object_server()
            .at("/org/qemu/Display1/Listener", DmaBuf2Listener { state })
            .await?;
        zbus::Result::Ok(listener_connection)
    });
    console
        .register_listener(zbus::zvariant::OwnedFd::from(listener_fd))
        .await?;
    let listener_connection = listener_task
        .await
        .map_err(|error| zbus::Error::Failure(error.to_string()))??;
    Ok((listener_connection, path))
}

#[proxy(interface = "org.qemu.Display1.Keyboard", default_service = "org.qemu")]
trait Keyboard {
    async fn press(&self, keycode: u32) -> zbus::Result<()>;
    async fn release(&self, keycode: u32) -> zbus::Result<()>;
}

#[proxy(interface = "org.qemu.Display1.Mouse", default_service = "org.qemu")]
trait Mouse {
    async fn press(&self, button: u32) -> zbus::Result<()>;
    async fn release(&self, button: u32) -> zbus::Result<()>;
    #[zbus(name = "SetAbsPosition")]
    async fn set_abs_position(&self, x: u32, y: u32) -> zbus::Result<()>;
    #[zbus(name = "RelMotion")]
    async fn rel_motion(&self, dx: i32, dy: i32) -> zbus::Result<()>;
}

/// Forward one validated browser input control message to QEMU.
pub async fn input(
    connection: &Connection,
    path: &ObjectPath<'static>,
    message: &str,
) -> zbus::Result<bool> {
    let value: serde_json::Value =
        serde_json::from_str(message).map_err(|error| zbus::Error::Failure(error.to_string()))?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if kind == "resize" {
        let width = value
            .get("width")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (320..=7680).contains(value))
            .ok_or_else(|| zbus::Error::Failure("invalid display width".into()))?;
        let height = value
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (200..=4320).contains(value))
            .ok_or_else(|| zbus::Error::Failure("invalid display height".into()))?;
        let console = ConsoleProxyProxy::builder(connection)
            .path(path)?
            .build()
            .await?;
        let width_mm = u16::try_from(width.saturating_mul(254) / 960).unwrap_or(u16::MAX);
        let height_mm = u16::try_from(height.saturating_mul(254) / 960).unwrap_or(u16::MAX);
        console
            .set_ui_info(width_mm, height_mm, 0, 0, width, height)
            .await?;
        return Ok(true);
    }
    if let Some(keycode) = value.get("keycode").and_then(serde_json::Value::as_u64) {
        let keyboard = KeyboardProxy::builder(connection)
            .path(path)?
            .build()
            .await?;
        match kind {
            "key_down" => keyboard.press(keycode as u32).await?,
            "key_up" => keyboard.release(keycode as u32).await?,
            _ => return Ok(false),
        }
        return Ok(true);
    }
    let mouse = MouseProxy::builder(connection).path(path)?.build().await?;
    match kind {
        "mouse_move" => {
            mouse
                .rel_motion(
                    value
                        .get("dx")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0) as i32,
                    value
                        .get("dy")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0) as i32,
                )
                .await?
        }
        "mouse_abs" => {
            mouse
                .set_abs_position(
                    value
                        .get("x")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0) as u32,
                    value
                        .get("y")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0) as u32,
                )
                .await?
        }
        "mouse_down" => {
            mouse
                .press(
                    value
                        .get("button")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0) as u32,
                )
                .await?
        }
        "mouse_up" => {
            mouse
                .release(
                    value
                        .get("button")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0) as u32,
                )
                .await?
        }
        "mouse_wheel" => {
            let steps = value
                .get("steps")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
                .clamp(-10, 10);
            let button = if steps < 0 { 3 } else { 4 };
            for _ in 0..steps.unsigned_abs() {
                mouse.press(button).await?;
                mouse.release(button).await?;
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Clipboard ownership changes sent by QEMU after the guest agent updates the
/// guest clipboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardEvent {
    Grab {
        selection: u32,
        serial: u32,
        mimes: Vec<String>,
    },
    Release {
        selection: u32,
    },
}

#[derive(Default)]
struct ClipboardData {
    serial: u32,
    host_text: Option<Vec<u8>>,
}

/// Shared state used both by browser-initiated grabs and by QEMU callbacks.
#[derive(Default)]
pub struct ClipboardState {
    data: Mutex<ClipboardData>,
}

impl ClipboardState {
    fn reset(&self) {
        let mut data = self.data.lock().expect("clipboard lock poisoned");
        data.serial = 0;
        data.host_text = None;
    }

    fn accept_guest_serial(&self, serial: u32) -> bool {
        let mut data = self.data.lock().expect("clipboard lock poisoned");
        // The D-Bus client wins a tie, so an incoming server grab must be
        // strictly newer than the local serial.
        if serial <= data.serial {
            return false;
        }
        data.serial = serial;
        data.host_text = None;
        true
    }

    fn set_host_text(&self, text: Vec<u8>) -> u32 {
        let mut data = self.data.lock().expect("clipboard lock poisoned");
        data.serial = data.serial.wrapping_add(1).max(1);
        data.host_text = Some(text);
        data.serial
    }

    fn host_text(&self) -> Option<Vec<u8>> {
        self.data
            .lock()
            .expect("clipboard lock poisoned")
            .host_text
            .clone()
    }
}

struct ClipboardPeer {
    state: Arc<ClipboardState>,
    events: mpsc::UnboundedSender<ClipboardEvent>,
}

#[interface(name = "org.qemu.Display1.Clipboard")]
impl ClipboardPeer {
    async fn register(&self) {
        self.state.reset();
    }

    async fn unregister(&self) {
        self.state.reset();
    }

    async fn grab(&self, selection: u32, serial: u32, mimes: Vec<String>) -> zbus::fdo::Result<()> {
        if selection > 2 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "invalid clipboard selection".into(),
            ));
        }
        if self.state.accept_guest_serial(serial) {
            let _ = self.events.send(ClipboardEvent::Grab {
                selection,
                serial,
                mimes,
            });
        }
        Ok(())
    }

    async fn release(&self, selection: u32) -> zbus::fdo::Result<()> {
        if selection > 2 {
            return Err(zbus::fdo::Error::InvalidArgs(
                "invalid clipboard selection".into(),
            ));
        }
        let _ = self.events.send(ClipboardEvent::Release { selection });
        Ok(())
    }

    async fn request(
        &self,
        selection: u32,
        mimes: Vec<String>,
    ) -> zbus::fdo::Result<(String, Vec<u8>)> {
        if selection != 0 || !mimes.iter().any(|mime| mime == CLIPBOARD_MIME) {
            return Err(zbus::fdo::Error::Failed(
                "requested clipboard format is unavailable".into(),
            ));
        }
        let text = self
            .state
            .host_text()
            .ok_or_else(|| zbus::fdo::Error::Failed("host clipboard is unavailable".into()))?;
        Ok((CLIPBOARD_MIME.into(), text))
    }

    #[zbus(property, name = "Interfaces")]
    fn interfaces(&self) -> Vec<String> {
        Vec::new()
    }
}

#[proxy(
    interface = "org.qemu.Display1.Clipboard",
    default_service = "org.qemu"
)]
trait Clipboard {
    async fn register(&self) -> zbus::Result<()>;
    async fn unregister(&self) -> zbus::Result<()>;
    async fn grab(&self, selection: u32, serial: u32, mimes: Vec<&str>) -> zbus::Result<()>;
    async fn release(&self, selection: u32) -> zbus::Result<()>;
    async fn request(&self, selection: u32, mimes: Vec<&str>) -> zbus::Result<(String, Vec<u8>)>;
}

/// Export the client half of QEMU's bidirectional clipboard interface and
/// register this display connection as the exclusive clipboard peer.
pub async fn attach_clipboard(
    connection: &Connection,
    state: Arc<ClipboardState>,
    events: mpsc::UnboundedSender<ClipboardEvent>,
) -> zbus::Result<()> {
    connection
        .object_server()
        .at(
            "/org/qemu/Display1/Clipboard",
            ClipboardPeer { state, events },
        )
        .await?;
    ClipboardProxy::builder(connection)
        .path("/org/qemu/Display1/Clipboard")?
        .build()
        .await?
        .register()
        .await
}

/// Advertise browser text as the current guest clipboard contents.
pub async fn set_clipboard(
    connection: &Connection,
    state: &ClipboardState,
    text: &str,
) -> zbus::Result<()> {
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(zbus::Error::Failure("clipboard text exceeds 64 KiB".into()));
    }
    let serial = state.set_host_text(text.as_bytes().to_vec());
    ClipboardProxy::builder(connection)
        .path("/org/qemu/Display1/Clipboard")?
        .build()
        .await?
        .grab(0, serial, vec![CLIPBOARD_MIME])
        .await
}

/// Fetch text currently owned by the guest clipboard.
pub async fn request_clipboard(connection: &Connection) -> zbus::Result<String> {
    let (mime, data) = ClipboardProxy::builder(connection)
        .path("/org/qemu/Display1/Clipboard")?
        .build()
        .await?
        .request(0, vec![CLIPBOARD_MIME])
        .await?;
    if mime != CLIPBOARD_MIME || data.len() > MAX_CLIPBOARD_BYTES {
        return Err(zbus::Error::Failure(
            "guest returned an unsupported clipboard payload".into(),
        ));
    }
    String::from_utf8(data)
        .map_err(|_| zbus::Error::Failure("guest clipboard is not valid UTF-8".into()))
}

/// PCM format and lifecycle events emitted by QEMU's D-Bus audio backend.
#[derive(Clone, Debug)]
pub enum AudioEvent {
    Init {
        id: u64,
        bits: u8,
        signed: bool,
        float: bool,
        frequency: u32,
        channels: u8,
        bytes_per_frame: u32,
        big_endian: bool,
    },
    Fini {
        id: u64,
    },
    Enabled {
        id: u64,
        enabled: bool,
    },
    Volume {
        id: u64,
        muted: bool,
        channels: Vec<u8>,
    },
    Data {
        id: u64,
        data: Vec<u8>,
    },
}

struct AudioOutListener {
    events: mpsc::UnboundedSender<AudioEvent>,
}

#[interface(name = "org.qemu.Display1.AudioOutListener")]
impl AudioOutListener {
    async fn init(
        &self,
        id: u64,
        bits: u8,
        is_signed: bool,
        is_float: bool,
        freq: u32,
        nchannels: u8,
        bytes_per_frame: u32,
        _bytes_per_second: u32,
        be: bool,
    ) {
        let _ = self.events.send(AudioEvent::Init {
            id,
            bits,
            signed: is_signed,
            float: is_float,
            frequency: freq,
            channels: nchannels,
            bytes_per_frame,
            big_endian: be,
        });
    }

    async fn fini(&self, id: u64) {
        let _ = self.events.send(AudioEvent::Fini { id });
    }

    async fn set_enabled(&self, id: u64, enabled: bool) {
        let _ = self.events.send(AudioEvent::Enabled { id, enabled });
    }

    async fn set_volume(&self, id: u64, mute: bool, volume: Vec<u8>) {
        let _ = self.events.send(AudioEvent::Volume {
            id,
            muted: mute,
            channels: volume,
        });
    }

    async fn write(&self, id: u64, data: Vec<u8>) {
        let _ = self.events.send(AudioEvent::Data { id, data });
    }
}

#[proxy(interface = "org.qemu.Display1.Audio", default_service = "org.qemu")]
trait Audio {
    #[zbus(name = "RegisterOutListener")]
    async fn register_out_listener(&self, listener: zbus::zvariant::OwnedFd) -> zbus::Result<()>;
}

/// Attach a playback listener to QEMU's D-Bus audio backend.
pub async fn attach_audio(
    connection: &Connection,
    listener_stream: UnixStream,
    listener_fd: OwnedFd,
    events: mpsc::UnboundedSender<AudioEvent>,
) -> zbus::Result<Connection> {
    let listener_task = tokio::spawn(async move {
        let listener_connection = zbus::connection::Builder::unix_stream(listener_stream)
            .p2p()
            .build()
            .await?;
        listener_connection
            .object_server()
            .at(
                "/org/qemu/Display1/AudioOutListener",
                AudioOutListener { events },
            )
            .await?;
        zbus::Result::Ok(listener_connection)
    });
    let audio = AudioProxy::builder(connection)
        .path("/org/qemu/Display1/Audio")?
        .build()
        .await?;
    audio
        .register_out_listener(zbus::zvariant::OwnedFd::from(listener_fd))
        .await?;
    listener_task
        .await
        .map_err(|error| zbus::Error::Failure(error.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiled_source(width: usize, height: usize, bottom_up: bool) -> Vec<u8> {
        let stride = (width * 4).div_ceil(512) * 512;
        let mut mapped = vec![0; stride * height];
        for y in 0..height {
            for x in 0..width {
                let source_x = x;
                let source_y = if bottom_up { height - 1 - y } else { y };
                let source = (source_y / 8) * 4096
                    + (source_x * 4 / 512) * 4096
                    + (source_y % 8) * 512
                    + source_x * 4 % 512;
                mapped[source..source + 4].copy_from_slice(&[x as u8, y as u8, 0xaa, 0xff]);
            }
        }
        mapped
    }

    #[test]
    fn x_tiled_scanout_preserves_top_down_rows_and_columns() {
        for y0_top in [false, true] {
            let width = 4;
            let height = 8;
            let linear = linearize_x_tiled(
                &tiled_source(width, height, y0_top),
                width as u32,
                height as u32,
                512,
                y0_top,
            )
            .unwrap();
            for y in 0..height {
                for x in 0..width {
                    let offset = y * 512 + x * 4;
                    assert_eq!(&linear[offset..offset + 4], &[x as u8, y as u8, 0xaa, 0xff]);
                }
            }
        }
    }

    #[test]
    fn x_tiled_damage_reads_only_requested_tile_runs() {
        let width = 132;
        let height = 8;
        let mapped = tiled_source(width, height, false);
        let mut damage = vec![0; 8 * 4];
        copy_x_tiled_row(&mapped, 1024, 5, 124, 8, &mut damage).unwrap();
        for (pixel, x) in damage.chunks_exact(4).zip(124u8..132) {
            assert_eq!(pixel, &[x, 5, 0xaa, 0xff]);
        }
    }
}
