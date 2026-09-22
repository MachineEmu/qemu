# MachineEmu QEMU

This repository owns pinned QEMU sources, engine tracks, ordered patches,
custom machines, QEMU-side helpers, and engine-build provenance.

MachineEmu-owned code is currently licensed under AGPL-3.0-or-later. Imported
QEMU and third-party components retain their upstream licenses and notices.

The first Rust migration slice contains `board-core`, `net-offload`, the three
board model crates, `board-ffi`, and `board-tools`. The deterministic
`analysis-profile` validation/identity crate, the dedicated QEMU analysis patch
series, and the opt-in host-kernel guard scaffold are now migrated; a clean
analysis-engine build and privileged kernel validation remain milestone work.

## Build environment

`flake.nix` pins the toolchain and every library QEMU's `configure`
auto-detects. Detection is silent: a missing dependency drops the device or
backend that needs it instead of failing the build, so builds run inside the
development shell rather than against host packages.

```sh
nix develop .#qemu
```

Shells, all on `x86_64-linux` unless noted (`aarch64-linux` provides `.#qemu`):

- `.#qemu` (also `.#default`): compiler, meson/ninja, the Rust toolchain for
  `board-ffi` and `analysis-profile`, and QEMU's library dependencies. Exports
  `QEMU_SOURCE_VERSION` and `QEMU_SOURCE_COMMIT` from the track pin.
- `.#qemu-xen`: the same, plus Xen with `QEMU_ENABLE_XEN=1`.
- `.#kernel`, `.#kernel-stable`, `.#kernel-analysis-stable`: `KDIR` and
  `KERNELRELEASE` for `scripts/build-analysis-kvm-module.sh`. The last applies
  `kernel/patches/0001-kvm-vmx-analysis-rdtsc-exit-nix.patch`.

The built binary resolves its libraries through the shell environment, so run
it from inside the shell; an installed bundle needs its own library paths.

## Tracks

Patches are split by what they are for, one track each:

- `tracks/unifi-10.2`: emulates UniFi hardware (machines, Alpine NIC, AHCI,
  PCIe topology), built for `aarch64-softmmu`.
- `tracks/analysis-10.2`: removes the emulator's fingerprints so the guest
  reads as a physical machine (ACPI/SMBIOS/EDID/PCI/USB identity, no VMPort),
  built for `x86_64-softmmu`. It declares `unifi-10.2` as its `[base]` because
  it links through that series' meson hooks, so both series are applied in
  order and both are recorded in the manifest.

## Building a track

The `unifi-10.2` fetch and build scripts work from this checkout: the preflight
fetches QEMU 10.2.4, applies all 11 patches, compiles `board-ffi`, and produces
`qemu-system-aarch64`. Build outputs stay under ignored `.cache/` and `target/`
directories.

```sh
nix develop .#qemu --command scripts/fetch-unifi-10.2.sh
nix develop .#qemu --command scripts/build-unifi-10.2.sh
```

The analysis engine is built separately, into its own source and build
directory; the ordinary fetch/build path never applies that series:

```sh
nix develop .#qemu --command scripts/build-analysis-10.2.sh
```

The build directory records the source tree and target list it was configured
with. After switching between the board and analysis tracks, pass
`--reconfigure` or remove the build directory; otherwise Ninja reports the
requested binary as an unknown target.

After a build, validate the installed bundle before handing it to the runtime:

```sh
python3 scripts/validate_engine_bundle.py .cache/qemu-build-10.2.4-unifi/engine-build.json
```

Validation rejects incomplete or dirty manifests, path escapes, missing
executables, symlinks, and executable digest mismatches.

## Tasks

`Taskfile.yml` wraps the same scripts for [go-task](https://taskfile.dev), so
the ordinary paths are one command and each already runs inside the right
development shell. `task` alone lists everything.

```sh
task release            # fetch, build and validate the board track
task release:analysis   # the same for the analysis track
task kernel:build       # analysis KVM guard module, against .#kernel
task check              # track inputs, clippy, workspace tests, tooling tests
```

`task build` passes arguments after `--` to the build script, so a
reconfigure is `task build -- --reconfigure`, or simply `task reconfigure`.
`KERNEL_SHELL` selects the kernel the
module builds against; `task kernel:build:stable` and
`task kernel:build:analysis` are the pinned stable and patched-stable shells.
Set `MACHINEEMU_NO_NIX=1` to drop the `nix develop` wrapper when the shell is
already entered.

## Independent checkout

An engine build must be reproducible from this checkout and its declared inputs.
The runtime consumes an installed immutable engine bundle; it never imports
source files through a sibling path.

Initial directories:

- `tracks`: source descriptors and ordered patch series
- `integration`: QEMU C integration and adapters
- `crates`: board models and QEMU helper crates
- `kernel`: optional analysis host-kernel components
- `scripts`, `tests`: build and verification tooling
- `Taskfile.yml`: task entry points over those scripts
- `flake.nix`, `nix`: pinned build environment

The first commit is a repository boundary only. The source tree is ported after
the reviewed M0 ledger and baseline are accepted.
