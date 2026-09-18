//! Board-independent packet preparation ABI; output is borrowed during callback.
use crate::{Board, UnifiBoard};
use net_offload::Request;
use std::ffi::c_void;

type Emit = unsafe extern "C" fn(*mut c_void, *const u8, *const u8, usize);

/// Prepare owned output packets. Returns 0, 1 for software fallback, or -1.
///
/// # Safety
/// Input and request pointers must be valid for their indicated lengths.
/// The callback must not retain output pointers after returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_net_prepare(
    request: *const Request,
    bytes: *const u8,
    len: usize,
    capabilities: u32,
    emit: Option<Emit>,
    opaque: *mut c_void,
) -> i32 {
    if request.is_null() || bytes.is_null() || len > net_offload::MAX_PACKET {
        return -1;
    }
    let Some(emit) = emit else {
        return -1;
    };
    let request = unsafe { *request };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec();
    let Ok(batch) = net_offload::prepare(request, bytes, capabilities) else {
        return -1;
    };
    for packet in batch.packets {
        unsafe {
            emit(
                opaque,
                packet.header.as_ptr(),
                packet.bytes.as_ptr(),
                packet.bytes.len(),
            );
        }
    }
    i32::from(batch.fallback)
}

/// Normalize RX into caller storage. Returns length, or -1 for malformed input.
///
/// # Safety
/// Header points to ten bytes; input/output have len readable/writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_net_receive(
    header: *const u8,
    bytes: *const u8,
    len: usize,
    output: *mut u8,
) -> isize {
    if header.is_null() || bytes.is_null() || output.is_null() || len > net_offload::MAX_PACKET {
        return -1;
    }
    let header = unsafe { *header.cast::<[u8; 10]>() };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec();
    let Ok(bytes) = net_offload::receive(&header, bytes) else {
        return -1;
    };
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
    }
    isize::try_from(bytes.len()).unwrap_or(-1)
}

/// Normalize RX and emit one or more ordinary Ethernet frames. Returns the
/// number of frames, or -1 for malformed input.
///
/// # Safety
/// Header points to ten bytes; input has len readable bytes. The callback must
/// not retain output pointers after returning.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_net_receive_batch(
    header: *const u8,
    bytes: *const u8,
    len: usize,
    emit: Option<Emit>,
    opaque: *mut c_void,
) -> isize {
    if header.is_null() || bytes.is_null() || len > net_offload::MAX_PACKET {
        return -1;
    }
    let Some(emit) = emit else {
        return -1;
    };
    let header = unsafe { *header.cast::<[u8; 10]>() };
    let bytes = unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec();
    let Ok(frames) = net_offload::receive_batch(&header, bytes) else {
        return -1;
    };
    let count = isize::try_from(frames.len()).unwrap_or(-1);
    if count < 0 {
        return -1;
    }
    let empty_header = [0; 10];
    for frame in frames {
        unsafe { emit(opaque, empty_header.as_ptr(), frame.as_ptr(), frame.len()) };
    }
    count
}

/// Select backend preparation on supported boards. Capture/replay currently
/// supports software mode only, so reject enabling acceleration during capture.
///
/// # Safety
/// Board must be a live exclusively borrowed board handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_board_set_host_offload(
    board: *mut UnifiBoard,
    enabled: bool,
) -> bool {
    let Some(board) = (unsafe { board.as_mut() }) else {
        return false;
    };
    if enabled && board.capture.is_some() {
        return false;
    }
    match &mut board.board {
        Board::Mt7981(b) => {
            b.set_host_offload(enabled);
            true
        }
        // BCM5616x packet DMA emits wire-ready frames. The shared transport
        // can prepend an empty virtio header without descriptor adaptation.
        Board::Bcm5616x(_) => true,
        _ => !enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UnifiBoardKind, unifi_board_free, unifi_board_new};

    #[test]
    fn bcm5616x_accepts_host_offload_transport() {
        let board = unsafe { unifi_board_new(UnifiBoardKind::Bcm5616x as u32, std::ptr::null()) };
        assert!(unsafe { unifi_board_set_host_offload(board, true) });
        unsafe { unifi_board_free(board) };
    }
}
