# UniFi QEMU integration

This directory is the repository-owned QEMU boundary. The adapter owns QOM,
`MemoryRegion`, and host lifetime; board state is an opaque `board-ffi`
allocation. `scripts/fetch.sh` links this directory into the pinned QEMU
checkout so edits are reproducible.
