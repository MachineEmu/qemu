# unifi-qemu analysis KVM guard

This directory is a DKMS-ready scaffold for host-kernel-side malware-analysis
VM compatibility work.

It is intentionally inactive by default. QEMU/device identity belongs in the
analysis QEMU patch series. This module is only for the remaining host-KVM
class of signals, especially timing and interception behavior.

## Why this exists

The HikaruChang Proxmox approach is mostly a DKMS-like QEMU rebuild wrapper:
it patches device strings, SMBIOS, ACPI, EDID, USB defaults, and VMGENID at
QEMU source level. Its own compatibility notes call timing side channels out as
requiring a host kernel patch. Our repo already handles the QEMU side with
`tracks/analysis-10.2`; this directory is the matching place for the host
kernel side.

## Current state

`kvm_analysis_guard.ko` currently:

- loads only as an inert guard unless `lab_enable=1` is set;
- requires a `target_tgid` before any future active backend may arm;
- records whether the VM is running the fast Hyper-V profile;
- can register target-gated `vmx_handle_exit` / `svm_handle_exit` kretprobes
  with `hook_exits=1`;
- can register a target-gated `kvm_read_l1_tsc` kretprobe with `hook_tsc=1`,
  passing KVM TSC helper reads through the Rust adjustment model;
- measures per-target VM-exit handler duration and keeps Rust-owned timing
  totals, max, and EWMA calibration state;
- validates basic x86 TSC capabilities;
- does not change KVM timing or register state yet.

That gives us a safe packaging and deployment shape before adding fragile
kernel-version-specific hooks.

See `rust-design.md` for the Rust-first measurement backend plan. The module is
now a single mixed C/Rust `kvm_analysis_guard.ko`: C owns module parameters and
kernel hook registration, while Rust owns target policy, timing calibration
state, and counters.

## Build

For repeatable development, use the pinned Nix kernel shell:

```sh
nix develop path:nix#kernel
scripts/build-analysis-kvm-module.sh
```

The shell exports `KDIR` to the Nix kernel build tree and `KERNELRELEASE` to
the matching module directory version.

There is also a stable-channel kernel shell:

```sh
nix develop path:nix#kernel-stable
scripts/build-analysis-kvm-module.sh
```

Use `#kernel` for latest-kernel iteration and `#kernel-stable` when you want
to track the current stable NixOS kernel line.

For host-kernel builds outside Nix, the host needs matching kernel headers:

```sh
make -C kernel/analysis-kvm check
make -C kernel/analysis-kvm
```

This workspace currently does not have `/lib/modules/$(uname -r)/build`, so
local compilation will fail until headers are installed or a kernel build tree
is provided with `KDIR=/path/to/kernel/build`.

## Manual load

```sh
python -m console.cli --config config/malware-analysis-x64.yaml analysis kvm-guard-load-command <session-id>
insmod kernel/analysis-kvm/kvm_analysis_guard.ko
insmod kernel/analysis-kvm/kvm_analysis_guard.ko lab_enable=1 target_tgid=<qemu-tgid> hyperv_fast_mode=1 hook_exits=1 hook_tsc=1
python -m console.cli --config config/malware-analysis-x64.yaml analysis kvm-guard-status <session-id>
python -m console.cli --config config/malware-analysis-x64.yaml analysis kvm-guard-snapshot <session-id>
cat /sys/kernel/debug/kvm_analysis_guard/stats
rmmod kvm_analysis_guard
```

New sessions record QEMU's TGID in `qemu.pid` and in both session manifests.
If an older live session lacks that field, the console tries the broker status
endpoint once and backfills the metadata before generating the load command.

## DKMS install shape

```sh
cp -a kernel/analysis-kvm /usr/src/unifi-qemu-analysis-kvm-0.1.0
dkms add -m unifi-qemu-analysis-kvm -v 0.1.0
dkms build -m unifi-qemu-analysis-kvm -v 0.1.0
dkms install -m unifi-qemu-analysis-kvm -v 0.1.0
```

## Next backend

The active VMX backend now starts as a kernel source patch:

```text
kernel/patches/0001-kvm-vmx-analysis-rdtsc-exit.patch
nix/kernel-patches/0001-kvm-vmx-analysis-rdtsc-exit.patch
```

The Nix flake exposes a patched stable-kernel development shell:

```sh
nix develop path:nix#kernel-analysis-stable
```

That shell realizes the patched kernel package, which is useful for final
integration but too slow for patch debugging. For iteration, use the source-tree
debug shell instead:

```sh
nix develop path:nix#kernel-debug-stable --command scripts/build-analysis-kvm-intel-debug.sh rebuild
```

The first run extracts a writable Linux source tree under
`runtime/kernel-worktrees/`, applies the VMX patch, prepares modules, and builds
only `arch/x86/kvm`. Later edits can use:

```sh
nix develop path:nix#kernel-debug-stable --command scripts/build-analysis-kvm-intel-debug.sh build
```

This debug path is for compile testing and producing patched KVM module objects.
Boot integration still needs the patched kernel/KVM modules to be installed and
loaded for the running kernel.

For quick iteration against the booted NixOS kernel, use the host debug shell.
It avoids the flake's pinned-kernel `uname` wrapper, auto-detects the current
kernel dev tree/source tarball, and keeps the writable source/object cache under
`runtime/kernel-worktrees/linux-<host-release>-analysis`:

```sh
nix develop path:nix#kernel-debug-host --command scripts/build-analysis-kvm-intel-debug.sh rebuild
```

After the first `rebuild`, source/tool prep is cached. For normal edit/compile
loops, rebuild only the KVM module objects:

```sh
nix develop path:nix#kernel-debug-host --command scripts/build-analysis-kvm-intel-debug.sh build
```

That patched kernel adds `kvm_intel` parameters:

```text
analysis_rdtsc_exit=1
analysis_target_tgid=<qemu-tgid>
analysis_rdtsc_subtract_cycles=<cycles>
analysis_rdtsc_observed
analysis_rdtsc_adjusted
analysis_filter_user_cpuid=1
analysis_vmcall_ud=1
analysis_cpuid_filtered
analysis_vmcall_ud_injected
analysis_cpuid_db_merged
```

`analysis_rdtsc_exit` should be enabled before creating the VM's vCPUs when
RDTSC/RDTSCP compensation is needed. CPUID and hypercall-instruction filtering
only require `analysis_target_tgid` plus their own enable flags. The target TGID
can be written after QEMU starts:

```sh
echo 1 | sudo tee /sys/module/kvm_intel/parameters/analysis_rdtsc_exit
echo <qemu-tgid> | sudo tee /sys/module/kvm_intel/parameters/analysis_target_tgid
```

Keep `analysis_rdtsc_subtract_cycles=0` for normal boot/login and for all
non-timing checks. With zero subtraction the VMX backend is observe-only for
RDTSC/RDTSCP; it increments counters but returns the guest TSC unchanged. Set a
nonzero subtraction only for the short VMAware timer experiment, then restore it
to zero immediately afterwards:

```sh
echo 0 | sudo tee /sys/module/kvm_intel/parameters/analysis_rdtsc_subtract_cycles
echo <qemu-tgid> | sudo tee /sys/module/kvm_intel/parameters/analysis_target_tgid
```

When `analysis_filter_user_cpuid=1`, CPL3 CPUID reads for the targeted QEMU
TGID hide the hypervisor-present bit and return empty `0x40000000..0x400000ff`
hypervisor leaves. Kernel-mode CPUID remains unchanged so Windows Hyper-V/VBS
paths can still use the exposed enlightenments. When `analysis_vmcall_ud=1`,
targeted CPL3 `VMCALL` exits inject `#UD` instead of taking KVM's hypercall
path. Targeted CPL3 `VMMCALL` invalid-opcode exits are also reinjected directly
as `#UD`, which avoids KVM's hypercall-instruction patching path. The
`analysis_vmcall_ud_injected` counter includes both cases.

`analysis_cpuid_db_merged` increments when a targeted CPL3 CPUID skip also
matches an enabled guest code breakpoint at the post-CPUID RIP, and the pending
single-step `#DB` payload is replaced with Intel bare-metal-style `DR6_BS|B0`.

Do not pause peer vCPUs from inside `vmx_vcpu_run()` to mask the
CPUID-vs-counter-thread timer check. That experiment can wedge the host when a
vCPU is held behind a global spin gate. Keep the VM running with normal CPU
affinity and use only targeted CPUID filtering/RDTSC observation unless a safer
timer backend is added.

Build note: realizing the patched kernel needs substantially more temporary
space than the out-of-tree module. A validation build on this host reached
kernel compilation but failed because `/build` ran out of space with about 9 GiB
free on `/`.

The remaining active-backend work:

- use the debugfs calibration counters to compare fast Hyper-V and stealth CPU
  profiles under the same workload;
- boot the patched kernel and load `kvm_intel` with `analysis_rdtsc_exit=1`;
- run the analysis VM with `analysis_target_tgid` set to its QEMU TGID;
- tune `analysis_rdtsc_subtract_cycles` from the measured VM-exit timing data;
- compensate guest `RDTSC/RDTSCP` and related VM-exit timing only for the
  analysis VM;
- expose counters so every adjustment is observable from the host.

Do not enable global host-wide timing hooks. They are fragile and can degrade
or destabilize unrelated VMs.
