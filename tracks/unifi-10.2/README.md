# `unifi-10.2` engine track

This is the first migrated track descriptor. Its source revision comes from
the current `unifi-qemu/scripts/fetch.sh`; the ordered patch list comes from
`qemu/patches`.

The patch files now live under `patches/` and the QEMU integration source under
`integration/hw/unifi/`. Use `scripts/fetch-unifi-10.2.sh` to materialize the
pinned upstream checkout and apply the ordered series, then
`scripts/build-unifi-10.2.sh` to build it. The copied helpers under
`scripts/legacy/` remain as source provenance. The track remains `experimental`
until a clean QEMU build and smoke test pass.

`dirty_source: false` in the generated manifest means the pinned upstream
checkout was clean before the declared patch series was applied. QEMU's version
string may still include `-dirty` because the applied series changes that
checkout; `patches_applied: true` records this expected state.

The dedicated `analysis-patches/` series and
`scripts/build-analysis-unifi-10.2.sh` materialize the x86_64 analysis engine
separately from the ordinary aarch64 engine. The analysis series is opt-in and
is never included by the common fetch/build path.
