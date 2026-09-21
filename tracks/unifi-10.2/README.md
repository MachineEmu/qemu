# `unifi-10.2` engine track

This is the first migrated track descriptor. Its source revision comes from
the current `unifi-qemu/scripts/fetch.sh`; the ordered patch list comes from
`qemu/patches`.

The patch files now live under `patches/` and the QEMU integration source under
`integration/hw/unifi/`. Use `scripts/fetch-unifi-10.2.sh` to materialize the
pinned upstream checkout and apply the ordered series, then
`scripts/build-unifi-10.2.sh` to build it. The copied helpers under
`scripts/legacy/` remain as source provenance. The track remains `experimental`
until privileged and hardware-backed validation passes.

`dirty_source: false` in the generated manifest means the pinned upstream
checkout was clean before the declared patch series was applied. QEMU's version
string may still include `-dirty` because the applied series changes that
checkout; `patches_applied: true` records this expected state.

This track's patches emulate UniFi hardware. The patches that hide the
emulator from the guest are a separate track, `../analysis-10.2`, applied onto
this series by `scripts/build-analysis-10.2.sh` to produce the x86_64 analysis
engine. That series is opt-in and is never included by the common fetch/build
path:

```sh
nix develop .#qemu --command scripts/build-analysis-10.2.sh
```

The output is `.cache/qemu-build-10.2.4-analysis/engine-build.json`; validate
it with `scripts/validate_engine_bundle.py` before installing the bundle.
