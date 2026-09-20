# Analysis QEMU series

This directory is the opt-in patch series for the malware-analysis binary. It
is intentionally separate from `qemu/patches/`: `scripts/fetch.sh` applies the
common board series to the pinned QEMU `3e0bcba1ca7d6607ca49a988d165f052a3a53323`
checkout, while `scripts/build-analysis.sh` applies this series in a dedicated
source and build directory.

The first profile revision uses QEMU's existing PC, Q35, SMBIOS, ACPI, UUID,
and MAC options through the validated launch plan, and adds an explicit
`analysis-profile=on` Q35 property. That property disables the optional VMPort
compatibility interface for the analysis guest while leaving ordinary PC and
Q35 machines unchanged. The series also adds opt-in ACPI header identity
properties for OEM revision and creator identity. Firmware-owned tables and
functional ACPI interfaces remain unchanged until a named guest check justifies
a separate patch.

Storage inquiry identity is driven by Rust-validated descriptor data in the
launch plan. SCSI devices use existing `vendor`, `product`, and `serial`
properties. IDE devices already expose `model` and `serial`; this series adds
the missing `vendor` property and wires ATAPI inquiry strings to the resolved
per-device values while preserving upstream defaults when the property is not
set.

The analysis machine property also gates a small static ACPI sensor surface:
`\_TZ.TZ00` reports the configured temperature and thresholds, and `\_SB.FAN0`
reports a configured fan speed through ACPI fan methods. These are profile-owned
values, not host sensor passthrough, and ordinary `q35` launches do not emit
them.

Display identity is provided through QEMU's existing EDID generator. The series
exposes the generator's vendor, monitor name, serial, and physical-size fields
as ordinary qdev properties; the console passes them only for the active
analysis VGA device. The analysis VGA device also accepts opt-in PCI
vendor/device and subsystem IDs so guest PCI enumeration can move away from
QEMU's default `1234:1111` adapter identity. The `pci-identity-delay-ms`
property lets the profile keep stdvga's normal firmware/display initialization
path and mutate PCI config-space IDs later. Ordinary VGA devices keep QEMU's
default EDID and PCI values.

virtio-gpu does not use that EDID property macro: it defines its own
`xres`/`yres` properties with non-zero defaults, so appending the full macro
would collide on those names.  The series therefore splits the identity fields
into `DEFINE_EDID_IDENTITY_PROPERTIES` and gives virtio-gpu that half only, so
a virtio display can carry the same profile-owned monitor identity.  The PCI
identity properties stay VGA-only on purpose: forging vendor/device IDs onto a
device that still advertises virtio capability structures in PCI config space,
and that the guest drives through a virtio GPU driver, makes the device more
anomalous rather than less.  virtio video is for boards with no stealth
requirement; the analysis board stays on `vga`.

USB descriptor identity is profile-owned for the devices the analysis launch
path creates directly. `usb-tablet` and `usb-storage` expose opt-in
`usb-manufacturer`, `usb-product`, `vendorid`, `productid`, and `bcd-device`
properties, while the existing USB `serial` property is reused. The console
passes those values only for analysis USB devices and leaves ordinary USB
launches at QEMU defaults.

PCI subsystem defaults are profile-owned for `q35,analysis-profile=on`.
Ordinary Q35 devices keep QEMU's Red Hat/QEMU fallback, while analysis launches
replace that fallback with the Rust-validated `analysis.pci` values before PCI
devices are realized. This covers chipset, SATA, USB, and NIC devices whose
classes do not already define explicit subsystem IDs.

VMAware 2.8.2's `CLOCK` technique checks for a present `PNP0100`/AT timer
hardware ID.  The analysis profile emits a small `_SB.TIMR` ACPI node for the
already-present PIT resources (`0x40-0x43`, IRQ 0); ordinary Q35 launches are
unchanged.

The Rust profile crate also exposes a minimal C ABI in
`crates/analysis-profile/include/analysis_profile.h` for future QEMU-side
consumers that need to validate a resolved profile or derive clone identity
without shelling out. The ABI returns owned JSON strings and uses NULL on
validation failure so callers can abort before applying partial identity.

Future QEMU C hooks are added here with a numbered patch and a test result in
`docs/qemu/malware-analysis-integration-plan.md`.

The source commit and profile revision are recorded in each session's
`environment.json`; this directory must never be added to the common fetch
glob.
