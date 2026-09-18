# MachineEmu QEMU

This repository owns pinned QEMU sources, engine tracks, ordered patches,
custom machines, QEMU-side helpers, and engine-build provenance.

MachineEmu-owned code is currently licensed under AGPL-3.0-or-later. Imported
QEMU and third-party components retain their upstream licenses and notices.

The first Rust migration slice contains `board-core`, `net-offload`, the three
board model crates, `board-ffi`, and `board-tools`. Display, audio, remote
device, and analysis crates remain in the source repository until their own
milestones.

The `unifi-10.2` fetch and build scripts now work from this checkout: the
preflight fetched QEMU 10.2.4, applied all 11 patches, compiled `board-ffi`,
and produced `qemu-system-aarch64`. Build outputs stay under ignored `.cache/`
and `target/` directories.

After a build, validate the installed bundle before handing it to the runtime:

```sh
python3 scripts/validate_engine_bundle.py .cache/qemu-build-10.2.4/engine-build.json
```

Validation rejects incomplete or dirty manifests, path escapes, missing
executables, symlinks, and executable digest mismatches.

## Independent checkout

An engine build must be reproducible from this checkout and its declared inputs.
The runtime consumes an installed immutable engine bundle; it never imports
source files through a sibling path.

Initial directories:

- `tracks`: source descriptors and ordered patch series
- `integration`: QEMU C integration and adapters
- `crates`: board models and QEMU helper crates
- `kernel`: optional analysis host-kernel components
- `scripts`, `tests`, `nix`: build and verification tooling

The first commit is a repository boundary only. The source tree is ported after
the reviewed M0 ledger and baseline are accepted.
