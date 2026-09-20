// SPDX-License-Identifier: GPL-2.0

//! Rust measurement policy for the unifi-qemu KVM analysis guard.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

#[repr(C)]
/// Snapshot copied to the C debugfs shim for read-only observability.
pub struct AnalysisKvmStats {
    /// Whether lab-only controls are armed.
    pub lab_enable: bool,
    /// Selected qemu-system process TGID.
    pub target_tgid: i32,
    /// Whether the target is expected to use Hyper-V enlightenments.
    pub hyperv_fast_mode: bool,
    /// Reserved timing floor in nanoseconds.
    pub tsc_floor_ns: u32,
    /// Total target KVM exits observed by the Rust policy.
    pub exits_observed: u64,
    /// Target KVM exits that included a duration measurement.
    pub exit_timing_observed: u64,
    /// Saturating sum of measured target exit durations.
    pub exit_ns_total: u64,
    /// Maximum measured target exit duration.
    pub exit_ns_max: u64,
    /// Exponentially weighted moving average of target exit duration.
    pub exit_ns_ewma: u64,
    /// Target RDTSC/RDTSCP observations passed through the policy.
    pub rdtsc_observed: u64,
    /// Target RDTSC/RDTSCP values adjusted by the policy.
    pub rdtsc_adjusted: u64,
    /// Last guest TSC value returned by the policy.
    pub last_guest_tsc: u64,
    /// Last host TSC value passed to the policy.
    pub last_host_tsc: u64,
}

static LAB_ENABLE: AtomicBool = AtomicBool::new(false);
static TARGET_TGID: AtomicI32 = AtomicI32::new(-1);
static HYPERV_FAST_MODE: AtomicBool = AtomicBool::new(false);
static TSC_FLOOR_NS: AtomicU32 = AtomicU32::new(0);

static EXITS_OBSERVED: AtomicU64 = AtomicU64::new(0);
static EXIT_TIMING_OBSERVED: AtomicU64 = AtomicU64::new(0);
static EXIT_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
static EXIT_NS_MAX: AtomicU64 = AtomicU64::new(0);
static EXIT_NS_EWMA: AtomicU64 = AtomicU64::new(0);
static RDTSC_OBSERVED: AtomicU64 = AtomicU64::new(0);
static RDTSC_ADJUSTED: AtomicU64 = AtomicU64::new(0);
static LAST_GUEST_TSC: AtomicU64 = AtomicU64::new(0);
static LAST_HOST_TSC: AtomicU64 = AtomicU64::new(0);

fn enabled_for(tgid: i32) -> bool {
    LAB_ENABLE.load(Ordering::Relaxed)
        && tgid > 0
        && TARGET_TGID.load(Ordering::Relaxed) == tgid
}

fn atomic_saturating_add(value: &AtomicU64, delta: u64) {
    let mut current = value.load(Ordering::Relaxed);

    loop {
        let next = current.saturating_add(delta);
        match value.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn atomic_max(value: &AtomicU64, candidate: u64) {
    let mut current = value.load(Ordering::Relaxed);

    while candidate > current {
        match value.compare_exchange_weak(
            current,
            candidate,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn update_exit_ewma(delta_ns: u64) {
    let mut current = EXIT_NS_EWMA.load(Ordering::Relaxed);

    loop {
        let next = if current == 0 {
            delta_ns
        } else {
            current.saturating_mul(7).saturating_add(delta_ns) / 8
        };

        match EXIT_NS_EWMA.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[no_mangle]
/// Configures the Rust policy state from C module parameters.
pub extern "C" fn analysis_kvm_policy_configure(
    enable: bool,
    target_tgid: i32,
    hyperv_fast_mode: bool,
    tsc_floor_ns: u32,
) {
    LAB_ENABLE.store(enable, Ordering::Relaxed);
    TARGET_TGID.store(target_tgid, Ordering::Relaxed);
    HYPERV_FAST_MODE.store(hyperv_fast_mode, Ordering::Relaxed);
    TSC_FLOOR_NS.store(tsc_floor_ns, Ordering::Relaxed);
    EXITS_OBSERVED.store(0, Ordering::Relaxed);
    EXIT_TIMING_OBSERVED.store(0, Ordering::Relaxed);
    EXIT_NS_TOTAL.store(0, Ordering::Relaxed);
    EXIT_NS_MAX.store(0, Ordering::Relaxed);
    EXIT_NS_EWMA.store(0, Ordering::Relaxed);
    RDTSC_OBSERVED.store(0, Ordering::Relaxed);
    RDTSC_ADJUSTED.store(0, Ordering::Relaxed);
    LAST_GUEST_TSC.store(0, Ordering::Relaxed);
    LAST_HOST_TSC.store(0, Ordering::Relaxed);
}

#[no_mangle]
/// Clears all policy state and disarms the selected target.
pub extern "C" fn analysis_kvm_policy_reset() {
    analysis_kvm_policy_configure(false, -1, false, 0);
}

#[no_mangle]
/// Returns whether `tgid` is the currently armed analysis target.
pub extern "C" fn analysis_kvm_target_enabled(tgid: i32) -> bool {
    enabled_for(tgid)
}

#[no_mangle]
/// Returns the guest TSC value after applying the current policy model.
pub extern "C" fn analysis_kvm_adjust_tsc(tgid: i32, raw_tsc: u64, host_tsc: u64) -> u64 {
    if !enabled_for(tgid) {
        return raw_tsc;
    }

    RDTSC_OBSERVED.fetch_add(1, Ordering::Relaxed);
    LAST_HOST_TSC.store(host_tsc, Ordering::Relaxed);

    /*
     * Inert floor model for now: keep TSC monotonic for the selected target,
     * but do not attempt wall-clock smoothing until a real hook backend can
     * provide calibrated cycles-per-ns.
     */
    let last = LAST_GUEST_TSC.load(Ordering::Relaxed);
    let adjusted = raw_tsc.max(last);
    LAST_GUEST_TSC.store(adjusted, Ordering::Relaxed);
    if adjusted != raw_tsc {
        RDTSC_ADJUSTED.fetch_add(1, Ordering::Relaxed);
    }
    adjusted
}

#[no_mangle]
/// Records a KVM exit for the currently selected target.
pub extern "C" fn analysis_kvm_record_exit(tgid: i32, _reason: u32) {
    if enabled_for(tgid) {
        EXITS_OBSERVED.fetch_add(1, Ordering::Relaxed);
    }
}

#[no_mangle]
/// Records a measured KVM exit duration for the selected target.
pub extern "C" fn analysis_kvm_record_exit_timing(tgid: i32, _reason: u32, delta_ns: u64) {
    if !enabled_for(tgid) {
        return;
    }

    EXITS_OBSERVED.fetch_add(1, Ordering::Relaxed);
    EXIT_TIMING_OBSERVED.fetch_add(1, Ordering::Relaxed);
    atomic_saturating_add(&EXIT_NS_TOTAL, delta_ns);
    atomic_max(&EXIT_NS_MAX, delta_ns);
    update_exit_ewma(delta_ns);
}

#[no_mangle]
/// Copies the current policy and measurement state into a C-owned buffer.
pub extern "C" fn analysis_kvm_snapshot_stats(out: *mut AnalysisKvmStats) {
    if out.is_null() {
        return;
    }

    // The C side provides a valid, writable struct for this synchronous copy.
    unsafe {
        *out = AnalysisKvmStats {
            lab_enable: LAB_ENABLE.load(Ordering::Relaxed),
            target_tgid: TARGET_TGID.load(Ordering::Relaxed),
            hyperv_fast_mode: HYPERV_FAST_MODE.load(Ordering::Relaxed),
            tsc_floor_ns: TSC_FLOOR_NS.load(Ordering::Relaxed),
            exits_observed: EXITS_OBSERVED.load(Ordering::Relaxed),
            exit_timing_observed: EXIT_TIMING_OBSERVED.load(Ordering::Relaxed),
            exit_ns_total: EXIT_NS_TOTAL.load(Ordering::Relaxed),
            exit_ns_max: EXIT_NS_MAX.load(Ordering::Relaxed),
            exit_ns_ewma: EXIT_NS_EWMA.load(Ordering::Relaxed),
            rdtsc_observed: RDTSC_OBSERVED.load(Ordering::Relaxed),
            rdtsc_adjusted: RDTSC_ADJUSTED.load(Ordering::Relaxed),
            last_guest_tsc: LAST_GUEST_TSC.load(Ordering::Relaxed),
            last_host_tsc: LAST_HOST_TSC.load(Ordering::Relaxed),
        };
    }
}
