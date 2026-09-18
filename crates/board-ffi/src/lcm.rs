//! Opaque, single-threaded display endpoint ABI. QEMU owns each handle.
use bcm5616x_machine::lcm::{Lcm, MAX_TRANSFER};

/// Inject one bounded display action.
/// # Safety
/// Handle is live/exclusive; input points to len readable, nonaliasing bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_lcm_input(handle: *mut Lcm, input: *const u8, len: usize) -> bool {
    if input.is_null() || len > 1024 {
        return false;
    }
    let Some(lcm) = (unsafe { handle.as_mut() }) else {
        return false;
    };
    lcm.input(unsafe { std::slice::from_raw_parts(input, len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn unifi_lcm_new() -> *mut Lcm {
    Box::into_raw(Box::new(Lcm::default()))
}
/// Construct the UDM-Pro GD display application profile.
#[unsafe(no_mangle)]
pub extern "C" fn unifi_lcm_new_udmpro() -> *mut Lcm {
    Box::into_raw(Box::new(Lcm::udm_pro()))
}

/// # Safety
/// Handle must come from new, be exclusively owned, and be freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_lcm_free(handle: *mut Lcm) {
    if !handle.is_null() {
        unsafe {
            drop(Box::from_raw(handle));
        }
    }
}
/// # Safety
/// Handle must be live and exclusively borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_lcm_reset(handle: *mut Lcm) {
    if let Some(lcm) = unsafe { handle.as_mut() } {
        lcm.reset();
    }
}
/// # Safety
/// Handle is live/exclusive; input points to len readable, nonaliasing bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_lcm_feed(handle: *mut Lcm, input: *const u8, len: usize) -> bool {
    if input.is_null() || len > MAX_TRANSFER {
        return false;
    }
    let Some(lcm) = (unsafe { handle.as_mut() }) else {
        return false;
    };
    lcm.feed(unsafe { std::slice::from_raw_parts(input, len) })
}
/// # Safety
/// Handle is live/exclusive; output points to cap writable, nonaliasing bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unifi_lcm_read(
    handle: *mut Lcm,
    output: *mut u8,
    cap: usize,
    snapshot: bool,
) -> usize {
    if output.is_null() || cap > 65536 {
        return 0;
    }
    let Some(lcm) = (unsafe { handle.as_mut() }) else {
        return 0;
    };
    let out = unsafe { std::slice::from_raw_parts_mut(output, cap) };
    if snapshot {
        lcm.take_snapshot(out)
    } else {
        lcm.read(out)
    }
}
