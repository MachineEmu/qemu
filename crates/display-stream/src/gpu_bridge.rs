//! GPU-only conversion from QEMU scanout DMABUFs to VA-API-compatible DMABUFs.

#![allow(unsafe_code)]

use crate::listener::DmaBufFrame;
use anyhow::{Context, Result, bail};
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::fs::{File, OpenOptions};
use std::os::fd::{FromRawFd, RawFd};
use std::ptr;
use std::sync::Arc;

const OUTPUT_FOURCC: u32 = 0x3432_4241; // DRM_FORMAT_ABGR8888 (AB24)
const INTEL_Y_TILED: u64 = 0x0100_0000_0000_0002;
const TARGET_COUNT: usize = 3;

const EGL_NONE: isize = 0x3038;
const EGL_RENDERABLE_TYPE: c_int = 0x3040;
const EGL_OPENGL_ES2_BIT: c_int = 0x0004;
const EGL_CONTEXT_CLIENT_VERSION: c_int = 0x3098;
const EGL_OPENGL_ES_API: c_uint = 0x30a0;
const EGL_PLATFORM_GBM_KHR: c_uint = 0x31d7;
const EGL_LINUX_DMA_BUF_EXT: c_uint = 0x3270;
const EGL_WIDTH: isize = 0x3057;
const EGL_HEIGHT: isize = 0x3056;
const EGL_LINUX_DRM_FOURCC_EXT: isize = 0x3271;
const EGL_DMA_BUF_PLANE0_FD_EXT: isize = 0x3272;
const EGL_DMA_BUF_PLANE0_OFFSET_EXT: isize = 0x3273;
const EGL_DMA_BUF_PLANE0_PITCH_EXT: isize = 0x3274;
const EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT: isize = 0x3443;
const EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT: isize = 0x3444;

const GL_TEXTURE_2D: c_uint = 0x0de1;
const GL_TEXTURE_MIN_FILTER: c_uint = 0x2801;
const GL_TEXTURE_MAG_FILTER: c_uint = 0x2800;
const GL_TEXTURE_WRAP_S: c_uint = 0x2802;
const GL_TEXTURE_WRAP_T: c_uint = 0x2803;
const GL_NEAREST: c_int = 0x2600;
const GL_CLAMP_TO_EDGE: c_int = 0x812f;
const GL_FRAMEBUFFER: c_uint = 0x8d40;
const GL_COLOR_ATTACHMENT0: c_uint = 0x8ce0;
const GL_FRAMEBUFFER_COMPLETE: c_uint = 0x8cd5;
const GL_ARRAY_BUFFER: c_uint = 0x8892;
const GL_STATIC_DRAW: c_uint = 0x88e4;
const GL_FLOAT: c_uint = 0x1406;
const GL_TRIANGLE_STRIP: c_uint = 0x0005;
const GL_VERTEX_SHADER: c_uint = 0x8b31;
const GL_FRAGMENT_SHADER: c_uint = 0x8b30;
const GL_COMPILE_STATUS: c_uint = 0x8b81;
const GL_LINK_STATUS: c_uint = 0x8b82;

#[repr(C)]
struct GbmDevice(c_void);
#[repr(C)]
struct GbmBo(c_void);

type EglDisplay = *mut c_void;
type EglConfig = *mut c_void;
type EglContext = *mut c_void;
type EglImage = *mut c_void;
type ImageTargetTexture = unsafe extern "C" fn(c_uint, EglImage);

#[link(name = "gbm")]
unsafe extern "C" {
    fn gbm_create_device(fd: c_int) -> *mut GbmDevice;
    fn gbm_device_destroy(device: *mut GbmDevice);
    fn gbm_bo_create_with_modifiers2(
        device: *mut GbmDevice,
        width: c_uint,
        height: c_uint,
        format: c_uint,
        modifiers: *const u64,
        count: c_uint,
        flags: c_uint,
    ) -> *mut GbmBo;
    fn gbm_bo_get_stride(bo: *mut GbmBo) -> c_uint;
    fn gbm_bo_get_offset(bo: *mut GbmBo, plane: c_int) -> c_uint;
    fn gbm_bo_get_fd(bo: *mut GbmBo) -> c_int;
    fn gbm_bo_get_modifier(bo: *mut GbmBo) -> u64;
    fn gbm_bo_get_plane_count(bo: *mut GbmBo) -> c_int;
    fn gbm_bo_destroy(bo: *mut GbmBo);
}

#[link(name = "EGL")]
unsafe extern "C" {
    fn eglGetPlatformDisplay(
        platform: c_uint,
        native_display: *mut c_void,
        attributes: *const isize,
    ) -> EglDisplay;
    fn eglInitialize(display: EglDisplay, major: *mut c_int, minor: *mut c_int) -> c_uint;
    fn eglTerminate(display: EglDisplay) -> c_uint;
    fn eglBindAPI(api: c_uint) -> c_uint;
    fn eglChooseConfig(
        display: EglDisplay,
        attributes: *const c_int,
        configs: *mut EglConfig,
        size: c_int,
        count: *mut c_int,
    ) -> c_uint;
    fn eglCreateContext(
        display: EglDisplay,
        config: EglConfig,
        share: EglContext,
        attributes: *const c_int,
    ) -> EglContext;
    fn eglDestroyContext(display: EglDisplay, context: EglContext) -> c_uint;
    fn eglMakeCurrent(
        display: EglDisplay,
        draw: *mut c_void,
        read: *mut c_void,
        context: EglContext,
    ) -> c_uint;
    fn eglCreateImage(
        display: EglDisplay,
        context: EglContext,
        target: c_uint,
        buffer: *mut c_void,
        attributes: *const isize,
    ) -> EglImage;
    fn eglDestroyImage(display: EglDisplay, image: EglImage) -> c_uint;
    fn eglGetProcAddress(name: *const c_char) -> *const c_void;
    fn eglGetError() -> c_int;
}

#[link(name = "GLESv2")]
unsafe extern "C" {
    fn glGenTextures(count: c_int, textures: *mut c_uint);
    fn glDeleteTextures(count: c_int, textures: *const c_uint);
    fn glBindTexture(target: c_uint, texture: c_uint);
    fn glTexParameteri(target: c_uint, name: c_uint, value: c_int);
    fn glGenFramebuffers(count: c_int, framebuffers: *mut c_uint);
    fn glDeleteFramebuffers(count: c_int, framebuffers: *const c_uint);
    fn glBindFramebuffer(target: c_uint, framebuffer: c_uint);
    fn glFramebufferTexture2D(
        target: c_uint,
        attachment: c_uint,
        texture_target: c_uint,
        texture: c_uint,
        level: c_int,
    );
    fn glCheckFramebufferStatus(target: c_uint) -> c_uint;
    fn glViewport(x: c_int, y: c_int, width: c_int, height: c_int);
    fn glCreateShader(kind: c_uint) -> c_uint;
    fn glShaderSource(
        shader: c_uint,
        count: c_int,
        source: *const *const c_char,
        length: *const c_int,
    );
    fn glCompileShader(shader: c_uint);
    fn glGetShaderiv(shader: c_uint, name: c_uint, value: *mut c_int);
    fn glGetShaderInfoLog(shader: c_uint, size: c_int, length: *mut c_int, log: *mut c_char);
    fn glDeleteShader(shader: c_uint);
    fn glCreateProgram() -> c_uint;
    fn glAttachShader(program: c_uint, shader: c_uint);
    fn glBindAttribLocation(program: c_uint, index: c_uint, name: *const c_char);
    fn glLinkProgram(program: c_uint);
    fn glGetProgramiv(program: c_uint, name: c_uint, value: *mut c_int);
    fn glGetProgramInfoLog(program: c_uint, size: c_int, length: *mut c_int, log: *mut c_char);
    fn glDeleteProgram(program: c_uint);
    fn glUseProgram(program: c_uint);
    fn glGenBuffers(count: c_int, buffers: *mut c_uint);
    fn glDeleteBuffers(count: c_int, buffers: *const c_uint);
    fn glBindBuffer(target: c_uint, buffer: c_uint);
    fn glBufferData(target: c_uint, size: isize, data: *const c_void, usage: c_uint);
    fn glEnableVertexAttribArray(index: c_uint);
    fn glVertexAttribPointer(
        index: c_uint,
        size: c_int,
        kind: c_uint,
        normalized: u8,
        stride: c_int,
        pointer: *const c_void,
    );
    fn glDrawArrays(mode: c_uint, first: c_int, count: c_int);
    fn glFinish();
}

/// A Y-tiled RGB DMABUF produced entirely on the GPU.
pub struct BridgedFrame {
    pub file: Arc<File>,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub offset: u32,
    pub fourcc: u32,
    pub modifier: u64,
}

struct Target {
    bo: *mut GbmBo,
    image: EglImage,
    texture: c_uint,
    framebuffer: c_uint,
    file: Arc<File>,
    stride: u32,
    offset: u32,
}

/// Converts modifier-bearing QEMU scanout buffers into Intel Y-tiled RGB.
pub struct GpuBridge {
    _drm: File,
    device: *mut GbmDevice,
    display: EglDisplay,
    context: EglContext,
    image_target_texture: ImageTargetTexture,
    program: c_uint,
    vertex_buffer: c_uint,
    targets: Vec<Target>,
    next_target: usize,
    width: u32,
    height: u32,
}

// The EGL context is detached after construction and the bridge is moved to and
// used by exactly one writer task. No pointer is shared between threads.
unsafe impl Send for GpuBridge {}

impl GpuBridge {
    /// Creates a bridge and a small output ring on the default render node.
    pub fn new(width: u32, height: u32) -> Result<Self> {
        let drm = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/dri/renderD128")
            .context("opening /dev/dri/renderD128 for EGL/GBM bridge")?;
        let device = unsafe { gbm_create_device(std::os::fd::AsRawFd::as_raw_fd(&drm)) };
        if device.is_null() {
            bail!("gbm_create_device failed");
        }
        let display =
            unsafe { eglGetPlatformDisplay(EGL_PLATFORM_GBM_KHR, device.cast(), ptr::null()) };
        if display.is_null() {
            unsafe { gbm_device_destroy(device) };
            bail!("eglGetPlatformDisplay(GBM) failed");
        }
        let mut major = 0;
        let mut minor = 0;
        if unsafe { eglInitialize(display, &mut major, &mut minor) } == 0 {
            let error = unsafe { eglGetError() };
            unsafe { gbm_device_destroy(device) };
            bail!("eglInitialize failed with 0x{error:x}");
        }
        if unsafe { eglBindAPI(EGL_OPENGL_ES_API) } == 0 {
            bail!("eglBindAPI(OpenGL ES) failed");
        }
        let config_attributes = [EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE as c_int];
        let mut config = ptr::null_mut();
        let mut config_count = 0;
        if unsafe {
            eglChooseConfig(
                display,
                config_attributes.as_ptr(),
                &mut config,
                1,
                &mut config_count,
            )
        } == 0
            || config_count == 0
        {
            bail!("no EGL OpenGL ES 2 config is available");
        }
        let context_attributes = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE as c_int];
        let context = unsafe {
            eglCreateContext(
                display,
                config,
                ptr::null_mut(),
                context_attributes.as_ptr(),
            )
        };
        if context.is_null() {
            bail!("eglCreateContext failed");
        }
        if unsafe { eglMakeCurrent(display, ptr::null_mut(), ptr::null_mut(), context) } == 0 {
            bail!("making the EGL context current failed");
        }
        let symbol = CString::new("glEGLImageTargetTexture2DOES")?;
        let image_target = unsafe { eglGetProcAddress(symbol.as_ptr()) };
        if image_target.is_null() {
            bail!("GL_OES_EGL_image is unavailable");
        }
        let image_target_texture: ImageTargetTexture = unsafe { std::mem::transmute(image_target) };
        let program = build_program()?;
        let mut vertex_buffer = 0;
        unsafe { glGenBuffers(1, &mut vertex_buffer) };

        let mut bridge = Self {
            _drm: drm,
            device,
            display,
            context,
            image_target_texture,
            program,
            vertex_buffer,
            targets: Vec::with_capacity(TARGET_COUNT),
            next_target: 0,
            width,
            height,
        };
        for _ in 0..TARGET_COUNT {
            bridge.targets.push(bridge.create_target()?);
        }
        if unsafe { eglMakeCurrent(display, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) }
            == 0
        {
            bail!("detaching the EGL context failed");
        }
        Ok(bridge)
    }

    /// Renders one source scanout into the next VA-API-compatible target.
    pub fn convert(&mut self, source: &DmaBufFrame) -> Result<BridgedFrame> {
        if (source.width, source.height) != (self.width, self.height) {
            bail!("GPU bridge dimensions changed");
        }
        if unsafe { eglMakeCurrent(self.display, ptr::null_mut(), ptr::null_mut(), self.context) }
            == 0
        {
            bail!("making the GPU bridge EGL context current failed");
        }
        let fd = std::os::fd::AsRawFd::as_raw_fd(source.file.as_ref());
        let attrs = dma_attributes(
            source.width,
            source.height,
            source.fourcc,
            fd,
            source.stride,
            0,
            source.modifier,
        );
        let image = unsafe {
            eglCreateImage(
                self.display,
                ptr::null_mut(),
                EGL_LINUX_DMA_BUF_EXT,
                ptr::null_mut(),
                attrs.as_ptr(),
            )
        };
        if image.is_null() {
            bail!(
                "importing QEMU DMABUF into EGL failed with 0x{:x}",
                unsafe { eglGetError() }
            );
        }
        let mut texture = 0;
        unsafe {
            glGenTextures(1, &mut texture);
            bind_image_texture(texture, image, self.image_target_texture);
        }
        let target = &self.targets[self.next_target];
        self.next_target = (self.next_target + 1) % self.targets.len();
        // EGL's imported image origin is opposite the framebuffer origin.
        // QEMU's y0_top flag therefore selects the inverse texture mapping.
        let top = if source.y0_top { 0.0 } else { 1.0 };
        let bottom = if source.y0_top { 1.0 } else { 0.0 };
        let vertices: [f32; 16] = [
            -1.0, -1.0, 0.0, bottom, 1.0, -1.0, 1.0, bottom, -1.0, 1.0, 0.0, top, 1.0, 1.0, 1.0,
            top,
        ];
        unsafe {
            glBindFramebuffer(GL_FRAMEBUFFER, target.framebuffer);
            glViewport(0, 0, self.width as c_int, self.height as c_int);
            glUseProgram(self.program);
            glBindTexture(GL_TEXTURE_2D, texture);
            glBindBuffer(GL_ARRAY_BUFFER, self.vertex_buffer);
            glBufferData(
                GL_ARRAY_BUFFER,
                std::mem::size_of_val(&vertices) as isize,
                vertices.as_ptr().cast(),
                GL_STATIC_DRAW,
            );
            glEnableVertexAttribArray(0);
            glEnableVertexAttribArray(1);
            glVertexAttribPointer(0, 2, GL_FLOAT, 0, 16, ptr::null());
            glVertexAttribPointer(1, 2, GL_FLOAT, 0, 16, 8usize as *const c_void);
            glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
            glFinish();
            glDeleteTextures(1, &texture);
            eglDestroyImage(self.display, image);
        }
        Ok(BridgedFrame {
            file: target.file.clone(),
            width: self.width,
            height: self.height,
            stride: target.stride,
            offset: target.offset,
            fourcc: OUTPUT_FOURCC,
            modifier: INTEL_Y_TILED,
        })
    }

    fn create_target(&self) -> Result<Target> {
        const GBM_BO_USE_RENDERING: u32 = 1 << 2;
        let bo = unsafe {
            gbm_bo_create_with_modifiers2(
                self.device,
                self.width,
                self.height,
                OUTPUT_FOURCC,
                &INTEL_Y_TILED,
                1,
                GBM_BO_USE_RENDERING,
            )
        };
        if bo.is_null() {
            bail!("allocating Y-tiled GBM output failed");
        }
        if unsafe { gbm_bo_get_plane_count(bo) } != 1
            || unsafe { gbm_bo_get_modifier(bo) } != INTEL_Y_TILED
        {
            unsafe { gbm_bo_destroy(bo) };
            bail!("GBM did not allocate the requested single-plane Y-tiled buffer");
        }
        let stride = unsafe { gbm_bo_get_stride(bo) };
        let offset = unsafe { gbm_bo_get_offset(bo, 0) };
        let fd = unsafe { gbm_bo_get_fd(bo) };
        if fd < 0 {
            unsafe { gbm_bo_destroy(bo) };
            bail!("exporting the Y-tiled GBM buffer failed");
        }
        let file = Arc::new(unsafe { File::from_raw_fd(fd as RawFd) });
        let attrs = dma_attributes(
            self.width,
            self.height,
            OUTPUT_FOURCC,
            fd,
            stride,
            offset,
            INTEL_Y_TILED,
        );
        let image = unsafe {
            eglCreateImage(
                self.display,
                ptr::null_mut(),
                EGL_LINUX_DMA_BUF_EXT,
                ptr::null_mut(),
                attrs.as_ptr(),
            )
        };
        if image.is_null() {
            unsafe { gbm_bo_destroy(bo) };
            bail!(
                "importing Y-tiled GBM output into EGL failed with 0x{:x}",
                unsafe { eglGetError() }
            );
        }
        let mut texture = 0;
        let mut framebuffer = 0;
        unsafe {
            glGenTextures(1, &mut texture);
            bind_image_texture(texture, image, self.image_target_texture);
            glGenFramebuffers(1, &mut framebuffer);
            glBindFramebuffer(GL_FRAMEBUFFER, framebuffer);
            glFramebufferTexture2D(
                GL_FRAMEBUFFER,
                GL_COLOR_ATTACHMENT0,
                GL_TEXTURE_2D,
                texture,
                0,
            );
        }
        if unsafe { glCheckFramebufferStatus(GL_FRAMEBUFFER) } != GL_FRAMEBUFFER_COMPLETE {
            bail!("Y-tiled EGL output is not framebuffer-renderable");
        }
        Ok(Target {
            bo,
            image,
            texture,
            framebuffer,
            file,
            stride,
            offset,
        })
    }
}

impl Drop for GpuBridge {
    fn drop(&mut self) {
        unsafe {
            let _ = eglMakeCurrent(self.display, ptr::null_mut(), ptr::null_mut(), self.context);
            for target in self.targets.drain(..) {
                glDeleteFramebuffers(1, &target.framebuffer);
                glDeleteTextures(1, &target.texture);
                eglDestroyImage(self.display, target.image);
                gbm_bo_destroy(target.bo);
            }
            glDeleteBuffers(1, &self.vertex_buffer);
            glDeleteProgram(self.program);
            let _ = eglMakeCurrent(
                self.display,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            eglDestroyContext(self.display, self.context);
            eglTerminate(self.display);
            gbm_device_destroy(self.device);
        }
    }
}

fn dma_attributes(
    width: u32,
    height: u32,
    fourcc: u32,
    fd: RawFd,
    stride: u32,
    offset: u32,
    modifier: u64,
) -> [isize; 19] {
    [
        EGL_WIDTH,
        width as isize,
        EGL_HEIGHT,
        height as isize,
        EGL_LINUX_DRM_FOURCC_EXT,
        fourcc as isize,
        EGL_DMA_BUF_PLANE0_FD_EXT,
        fd as isize,
        EGL_DMA_BUF_PLANE0_OFFSET_EXT,
        offset as isize,
        EGL_DMA_BUF_PLANE0_PITCH_EXT,
        stride as isize,
        EGL_DMA_BUF_PLANE0_MODIFIER_LO_EXT,
        (modifier as u32) as isize,
        EGL_DMA_BUF_PLANE0_MODIFIER_HI_EXT,
        (modifier >> 32) as isize,
        EGL_NONE,
        0,
        0,
    ]
}

unsafe fn bind_image_texture(texture: c_uint, image: EglImage, target: ImageTargetTexture) {
    unsafe {
        glBindTexture(GL_TEXTURE_2D, texture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        target(GL_TEXTURE_2D, image);
    }
}

fn compile_shader(kind: c_uint, source: &str) -> Result<c_uint> {
    let source = CString::new(source)?;
    let shader = unsafe { glCreateShader(kind) };
    unsafe {
        let pointer = source.as_ptr();
        glShaderSource(shader, 1, &pointer, ptr::null());
        glCompileShader(shader);
    }
    let mut status = 0;
    unsafe { glGetShaderiv(shader, GL_COMPILE_STATUS, &mut status) };
    if status == 0 {
        let mut log = vec![0i8; 1024];
        unsafe { glGetShaderInfoLog(shader, 1024, ptr::null_mut(), log.as_mut_ptr()) };
        bail!(
            "GL shader compilation failed: {}",
            unsafe { std::ffi::CStr::from_ptr(log.as_ptr()) }.to_string_lossy()
        );
    }
    Ok(shader)
}

fn build_program() -> Result<c_uint> {
    let vertex = compile_shader(
        GL_VERTEX_SHADER,
        "attribute vec2 position; attribute vec2 texcoord; varying vec2 uv; void main() { gl_Position = vec4(position, 0.0, 1.0); uv = texcoord; }",
    )?;
    let fragment = compile_shader(
        GL_FRAGMENT_SHADER,
        "precision mediump float; uniform sampler2D source; varying vec2 uv; void main() { gl_FragColor = texture2D(source, uv); }",
    )?;
    let program = unsafe { glCreateProgram() };
    let position = CString::new("position")?;
    let texcoord = CString::new("texcoord")?;
    unsafe {
        glAttachShader(program, vertex);
        glAttachShader(program, fragment);
        glBindAttribLocation(program, 0, position.as_ptr());
        glBindAttribLocation(program, 1, texcoord.as_ptr());
        glLinkProgram(program);
        glDeleteShader(vertex);
        glDeleteShader(fragment);
    }
    let mut status = 0;
    unsafe { glGetProgramiv(program, GL_LINK_STATUS, &mut status) };
    if status == 0 {
        let mut log = vec![0i8; 1024];
        unsafe { glGetProgramInfoLog(program, 1024, ptr::null_mut(), log.as_mut_ptr()) };
        bail!(
            "GL program link failed: {}",
            unsafe { std::ffi::CStr::from_ptr(log.as_ptr()) }.to_string_lossy()
        );
    }
    Ok(program)
}
