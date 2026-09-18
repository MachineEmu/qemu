# MachineEmu QEMU

This repository owns pinned QEMU sources, engine tracks, ordered patches,
custom machines, QEMU-side helpers, and engine-build provenance.

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
