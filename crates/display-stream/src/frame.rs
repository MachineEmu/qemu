//! Safe reconstruction of the inline QEMU display callbacks.

use thiserror::Error;

/// Canonical pixel formats emitted by the QEMU D-Bus display interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    /// Little-endian B,G,R,X bytes.
    X8R8G8B8,
    /// Little-endian B,G,R,A bytes.
    A8R8G8B8,
    /// Little-endian R,G,B,X bytes.
    X8B8G8R8,
    /// Little-endian R,G,B,A bytes.
    A8B8G8R8,
}

impl PixelFormat {
    /// Convert the numeric pixman format value used by QEMU.
    pub fn from_pixman(value: u32) -> Option<Self> {
        // These are the format constants used by pixman_format_code(). The
        // explicit values avoid depending on QEMU headers in this crate.
        match value {
            0x2002_8820 => Some(Self::X8R8G8B8),
            0x2002_8840 => Some(Self::A8R8G8B8),
            0x2002_4820 => Some(Self::X8B8G8R8),
            0x2002_4840 => Some(Self::A8B8G8R8),
            _ => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("unsupported pixman format 0x{0:08x}")]
    Format(u32),
    #[error("frame dimensions or stride are invalid")]
    Geometry,
    #[error("display update is outside the current scanout")]
    Outside,
    #[error("display callback did not provide enough bytes")]
    ShortData,
}

/// Translate the linear DRM formats used by QEMU's GL display path.
pub fn pixman_from_fourcc(fourcc: u32) -> Option<u32> {
    match fourcc {
        // DRM_FORMAT_XRGB8888 / ARGB8888, little-endian BGRA bytes.
        0x3432_5258 => Some(0x2002_8820),
        0x3432_5241 => Some(0x2002_8840),
        // DRM_FORMAT_XBGR8888 / ABGR8888, little-endian RGBA bytes.
        0x3432_4258 => Some(0x2002_4820),
        0x3432_4241 => Some(0x2002_4840),
        _ => None,
    }
}

/// A BGRA framebuffer reconstructed from Scanout/Update callbacks.
#[derive(Debug, Clone)]
pub struct Frame {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
    damage: Option<(u32, u32, u32, u32)>,
}

impl Frame {
    /// Create a framebuffer from a complete inline Scanout callback.
    pub fn scanout(
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
        data: &[u8],
    ) -> Result<Self, FrameError> {
        let mut frame = Self::empty(width, height)?;
        frame.copy_rect(0, 0, width, height, stride, format, data)?;
        frame.damage = Some((0, 0, width, height));
        Ok(frame)
    }

    fn empty(width: u32, height: u32) -> Result<Self, FrameError> {
        let bytes = (width as usize)
            .checked_mul(height as usize)
            .and_then(|n| n.checked_mul(4))
            .ok_or(FrameError::Geometry)?;
        Ok(Self {
            width,
            height,
            pixels: vec![0; bytes],
            damage: None,
        })
    }

    /// Apply an inline Update callback and merge its damage rectangle.
    pub fn update(
        &mut self,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        stride: u32,
        format: u32,
        data: &[u8],
    ) -> Result<(), FrameError> {
        if x < 0 || y < 0 || width <= 0 || height <= 0 {
            return Err(FrameError::Outside);
        }
        let (x, y, width, height) = (x as u32, y as u32, width as u32, height as u32);
        if x.checked_add(width).filter(|v| *v <= self.width).is_none()
            || y.checked_add(height)
                .filter(|v| *v <= self.height)
                .is_none()
        {
            return Err(FrameError::Outside);
        }
        self.copy_rect(x, y, width, height, stride, format, data)?;
        self.damage = Some(match self.damage {
            None => (x, y, width, height),
            Some((dx, dy, dw, dh)) => {
                let right = (dx + dw).max(x + width);
                let bottom = (dy + dh).max(y + height);
                (dx.min(x), dy.min(y), right - dx.min(x), bottom - dy.min(y))
            }
        });
        Ok(())
    }

    fn copy_rect(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        stride: u32,
        raw_format: u32,
        data: &[u8],
    ) -> Result<(), FrameError> {
        let format = PixelFormat::from_pixman(raw_format).ok_or(FrameError::Format(raw_format))?;
        if stride < width * 4 || data.len() < stride as usize * height as usize {
            return Err(FrameError::ShortData);
        }
        for row in 0..height as usize {
            let source = &data[row * stride as usize..row * stride as usize + width as usize * 4];
            let target_start = ((y as usize + row) * self.width as usize + x as usize) * 4;
            let target = &mut self.pixels[target_start..target_start + width as usize * 4];
            match format {
                PixelFormat::X8R8G8B8 | PixelFormat::A8R8G8B8 => {
                    target.copy_from_slice(source);
                }
                PixelFormat::X8B8G8R8 | PixelFormat::A8B8G8R8 => {
                    for (src, dst) in source.chunks_exact(4).zip(target.chunks_exact_mut(4)) {
                        dst.copy_from_slice(&[src[2], src[1], src[0], src[3]])
                    }
                }
            }
        }
        Ok(())
    }

    /// Return and clear the accumulated damage rectangle.
    pub fn take_damage(&mut self) -> Option<(u32, u32, u32, u32)> {
        self.damage.take()
    }
    /// Return the framebuffer in tightly packed BGRA order.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
    /// Return the current dimensions.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BGRA: u32 = 0x2002_8840;

    #[test]
    fn scanout_and_update_merge_damage() {
        let mut frame = Frame::scanout(
            2,
            2,
            8,
            BGRA,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        )
        .unwrap();
        assert_eq!(frame.take_damage(), Some((0, 0, 2, 2)));
        frame
            .update(1, 0, 1, 1, 4, BGRA, &[20, 21, 22, 23])
            .unwrap();
        assert_eq!(frame.take_damage(), Some((1, 0, 1, 1)));
        assert_eq!(&frame.pixels()[4..8], &[20, 21, 22, 23]);
    }
}
