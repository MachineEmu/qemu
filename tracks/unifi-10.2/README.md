# `unifi-10.2` engine track

This is the first migrated track descriptor. Its source revision comes from
the current `unifi-qemu/scripts/fetch.sh`; the ordered patch list comes from
`qemu/patches`.

The patch files now live under `patches/` and the QEMU integration source under
`integration/hw/unifi/`. The copied build helpers remain under
`scripts/legacy/`; they still expect the board crates and generated QEMU source
layout to be migrated, so this track remains `experimental` and is not a
release artifact yet.
