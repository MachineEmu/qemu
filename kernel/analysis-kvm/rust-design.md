# Rust measurement backend plan

The stable Nix kernel dev shell currently reports:

- `CONFIG_RUST=y`
- `CONFIG_RUST_IS_AVAILABLE=y`
- `CONFIG_HAVE_RUST=y`

So the target kernel line can host Rust code. The safest architecture is still
hybrid:

- C owns tiny KVM/ftrace/kprobe glue because those ABIs and callback signatures
  are kernel-C-first and version-sensitive.
- Rust owns measurement policy, target allowlisting, calibration state,
  saturating arithmetic, counters, and debugfs/sysfs formatting.

## Rust-owned model

The Rust side should own a per-target state machine:

```text
AnalysisTarget
  tgid
  fast_hyperv_mode
  tsc_floor_cycles
  exits_observed
  exit_timing_observed
  exit_ns_total
  exit_ns_max
  exit_ns_ewma
  rdtsc_observed
  rdtsc_adjusted
  last_guest_tsc
  last_host_tsc
```

All mutation should use checked/saturating arithmetic. Policy must be explicit:
if no target tgid is selected, no adjustment happens.

## Kernel ABI boundary

The C shim should expose a very small ABI:

```c
bool analysis_kvm_target_enabled(pid_t tgid);
u64 analysis_kvm_adjust_tsc(pid_t tgid, u64 raw_tsc, u64 host_tsc);
void analysis_kvm_record_exit(pid_t tgid, u32 reason);
void analysis_kvm_record_exit_timing(pid_t tgid, u32 reason, u64 delta_ns);
```

The Rust object implements the policy behind those calls. It is linked into the
same `kvm_analysis_guard.ko` module as the C hook shim, so these functions are
internal ABI rather than exported inter-module symbols.

## Nix workflow

Latest kernel:

```sh
nix develop path:nix#kernel
scripts/build-analysis-kvm-module.sh
```

Stable kernel:

```sh
nix develop path:nix#kernel-stable
scripts/build-analysis-kvm-module.sh
```

Use the stable shell for the current 6.18 kernel family. It currently builds
against `6.18.52`.

## Proof status

`kvm_analysis_measure.rs` is a Rust out-of-tree object linked into the mixed
`kvm_analysis_guard.ko` module with:

```sh
nix develop path:nix#kernel-stable --command scripts/build-analysis-kvm-module.sh
```

It is verified against stable Nix kernel `6.18.52`. The target policy state is
now in Rust. The C side has an optional `hook_exits=1` kretprobe backend for
target-gated `vmx_handle_exit` / `svm_handle_exit` duration measurement. Rust
stores total, max, and EWMA timing calibration state, and the C shim exposes a
read-only debugfs stats file. The C side also has an optional `hook_tsc=1`
kretprobe on `kvm_read_l1_tsc`, which wires KVM TSC helper reads through
`analysis_kvm_adjust_tsc()`. Guest VMX `RDTSC/RDTSCP` instruction interception
still requires a KVM source patch because stock VMX clears
`CPU_BASED_RDTSC_EXITING` and has no `EXIT_REASON_RDTSC` handler in the exit
dispatch table.
