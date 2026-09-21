# Engine tracks

Each track declares an immutable source digest, ordered patches, build
options, target architectures, toolchain inputs, and required helper binaries.
Do not add a track until a baseline profile needs it.

Patches fall into two kinds, and each kind gets its own track so a build can
take one without the other:

- Board tracks emulate hardware the host does not have. `unifi-10.2` adds the
  UniFi machines, their Alpine NIC, AHCI and PCIe topology.
- Analysis tracks remove the emulator's own fingerprints so the guest reads as
  a physical machine. `analysis-10.2` rewrites ACPI, SMBIOS, EDID, PCI and USB
  identity and drops interfaces such as VMPort that only a hypervisor exposes.

A track that is applied onto another declares it under `[base]`; both series
are then applied in order and recorded in the engine manifest.
