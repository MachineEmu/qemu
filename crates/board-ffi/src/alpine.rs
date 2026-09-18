//! PCI-independent FFI for the Alpine Rust DMA engine.
use crate::UnifiHost;
use board_core::dma::{DmaBus, TransferStatus};
use net_offload::Request;
use std::ffi::c_void;
use udmpro_machine::ethernet::{AlpineEthernet, Effects};

type Emit = unsafe extern "C" fn(*mut c_void, u32, *const Request, *const u8, usize);
struct Bus<'a>(&'a UnifiHost);
impl DmaBus for Bus<'_> {
    fn read(&mut self, at: u64, out: &mut [u8]) -> TransferStatus {
        if self
            .0
            .dma_read
            .is_some_and(|read| read(self.0.context, at, out.as_mut_ptr(), out.len()) == 0)
        {
            TransferStatus::Complete
        } else {
            TransferStatus::Failed
        }
    }
    fn write(&mut self, at: u64, bytes: &[u8]) -> TransferStatus {
        if self
            .0
            .dma_write
            .is_some_and(|write| write(self.0.context, at, bytes.as_ptr(), bytes.len()) == 0)
        {
            TransferStatus::Complete
        } else {
            TransferStatus::Failed
        }
    }
}
/// Allocate an independent Alpine Ethernet function.
/// # Safety
/// MAC must point to six readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_new(mac: *const u8) -> *mut AlpineEthernet {
    if mac.is_null() {
        return std::ptr::null_mut();
    }
    Box::into_raw(Box::new(AlpineEthernet::new(unsafe {
        *mac.cast::<[u8; 6]>()
    })))
}
/// Release a function.
/// # Safety
/// Pointer must be null or returned by `unifi_alpine_new`, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_free(s: *mut AlpineEthernet) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}
/// Reset a live function.
/// # Safety
/// Pointer must reference an exclusively borrowed live model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_reset(s: *mut AlpineEthernet) {
    if let Some(s) = unsafe { s.as_mut() } {
        s.reset();
    }
}
/// Read an aligned register.
/// # Safety
/// Pointer must reference a live model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_read(s: *const AlpineEthernet, at: u64) -> u32 {
    unsafe { s.as_ref() }.map_or(0, |s| s.read(at))
}
/// Query RX readiness.
/// # Safety
/// Pointer must reference a live model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_can_receive(s: *const AlpineEthernet) -> bool {
    unsafe { s.as_ref() }.is_some_and(AlpineEthernet::can_receive)
}
fn deliver(result: Effects, emit: Option<Emit>, opaque: *mut c_void) -> u32 {
    if let Some(emit) = emit {
        for p in result.packets {
            unsafe {
                emit(opaque, p.queue, &p.request, p.bytes.as_ptr(), p.bytes.len());
            }
        }
    }
    result.interrupts | if result.failed { 1 << 31 } else { 0 }
}
/// Execute a register write; result bits 0..30 are interrupt vectors, 31 failure.
/// # Safety
/// Exclusive model/host references and valid DMA callbacks are required.
/// Emit must copy bytes and must not reenter the model during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_write(
    s: *mut AlpineEthernet,
    host: *const UnifiHost,
    at: u64,
    value: u32,
    emit: Option<Emit>,
    opaque: *mut c_void,
) -> u32 {
    let (Some(s), Some(host)) = (unsafe { s.as_mut() }, unsafe { host.as_ref() }) else {
        return 1 << 31;
    };
    deliver(s.write(&mut Bus(host), at, value), emit, opaque)
}
/// DMA one normalized RX frame; return interrupt bitset, bit 31 failure.
/// # Safety
/// Model/host must be live, exclusively borrowed; bytes must be valid for len.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_alpine_receive(
    s: *mut AlpineEthernet,
    host: *const UnifiHost,
    bytes: *const u8,
    len: usize,
) -> u32 {
    let (Some(s), Some(host)) = (unsafe { s.as_mut() }, unsafe { host.as_ref() }) else {
        return 1 << 31;
    };
    if bytes.is_null() || len > net_offload::MAX_PACKET {
        return 1 << 31;
    }
    deliver(
        s.receive(&mut Bus(host), unsafe {
            std::slice::from_raw_parts(bytes, len)
        }),
        None,
        std::ptr::null_mut(),
    )
}
