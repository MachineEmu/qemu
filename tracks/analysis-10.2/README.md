# `analysis-10.2` engine track

This track holds the patches that keep the guest from recognizing the
emulator. They are deliberately separate from the board track: `unifi-10.2`
under `../unifi-10.2` emulates UniFi hardware that does not otherwise exist,
while this series removes the evidence that any emulator is present at all.
A patch belongs here when it exists because a guest looks for a hypervisor,
and there when it exists because a board has a device.

The two series share one pinned QEMU checkout,
`3e0bcba1ca7d6607ca49a988d165f052a3a53323`. This one is not standalone: it
links through the meson hooks the board series adds, so `track.toml` declares
`unifi-10.2` as its base and `scripts/build-analysis-10.2.sh` applies that
series first, into a dedicated source and build directory. Both series are
recorded in the engine manifest, in apply order.

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

`analysis-profile host-clone <seed>` builds a profile from the machine it runs
on, so a guest reports the hardware model of a real host instead of a
hand-written identity. It reads the DMI attributes and the raw SMBIOS table,
`/proc/cpuinfo`, the DSDT (or FACP) ACPI header, PCI and USB device IDs, block
device vendor/model, the display EDID, network interfaces, and thermal and fan
readings.

Two of those sources are root-only: the ACPI tables and the raw SMBIOS table
at `/sys/firmware/dmi/tables/DMI`. The raw table is where the memory modules,
the processor's socket and speed ceiling, and the chassis asset tag live --
`/sys/class/dmi/id` publishes none of them -- so an unprivileged run produces a
thinner profile and says so.

Identifiers are written the way `lspci` and `lsusb` write them: the inventory
carries `"vendor_id": "0x8086"`, while `analysis.pci` keeps the numeric form
that QEMU's properties take.

The command has two modes. With a seed, the identity that is unique to one
machine -- the system UUID, MAC and every serial -- is derived from that seed
rather than copied, so the clone can run beside the host it was taken from. A
derived value keeps the shape of the one it stands in for: a drive serial of
`S7DPNU0X909340K` becomes another fifteen characters with digits where digits
were, because a serial replaced by `AN-03AC6742` announces itself to anything
that knows what a real one looks like.

With no seed, the clone is literal: the host's own UUID, MAC and serials go in
as a resolved identity, and `identity_source` records that they came from the
machine. That guest is an exact twin, which also means it collides with the
host on the same network and reports the host's real identifiers if it phones
home, so nothing produces it by default.

The inventory always records what was observed, including the serials the
seeded profile does not use. Either mode's output is an ordinary profile
input, so `validate` accepts it directly.

The output carries two layers. `inventory` is everything the host reported:
every display with its decoded EDID, every block device, PCI function, USB
device, network interface, thermal zone and fan. `analysis` is the profile
itself, which picks from that inventory what a single emulated machine can
carry -- the connected monitor, a fixed disk over removable media, the host
bridge's subsystem IDs, the CPU package thermal zone -- and records which one
it took in `source_device`, `source_connector`, `source_slot` and
`source_zone`. Keeping both means the choice can be revisited without going
back to the machine, and that a second look can tell a host with one monitor
from a capture that only looked at the first.

Every source is optional and the command never fails on a missing one; the
`source.unavailable` list names the sections that came back empty. ACPI tables
are root-readable only on most distributions, so an unprivileged run reports
`acpi` there and the profile keeps QEMU's ACPI identity unless the command is
re-run with privileges.

The `analysis-profile acpi-dump` command captures Linux ACPI sysfs metadata,
checksums, and SHA-256 digests, with `--metadata-only` and `--output-dir`
modes for keeping raw tables outside the repository. Permission-limited or
missing host ACPI trees produce a valid empty report rather than weakening the
profile validation path.

The QEMU C hooks are applied by the numbered patch series and are covered by
the clean x86_64 build plus a runtime smoke that enables the machine property
and rejects an invalid resolved network mode before startup.

The source commit and profile revision are recorded in each session's
`environment.json`; this directory must never be added to the common fetch
glob.
