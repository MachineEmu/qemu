# QEMU integration sources

Integration sources are kept separate from the upstream QEMU checkout. The
`unifi-10.2` track currently contains the migrated UniFi device sources under
`hw/unifi/` and the MT7981 device-tree overlays under `mt7981/`.

The Meson hook and Rust FFI wiring are still coupled to the source repository's
board-crate layout. Port those dependencies before enabling a clean engine
build; the copied sources are intentionally not treated as release-ready.
