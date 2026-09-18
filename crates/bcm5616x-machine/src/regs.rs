/// Base of the chip peripheral window (`map_desc` virtual `0xfec0_0000`).
pub const PERIPH_BASE: u64 = 0x1800_0000;
/// Length of the chip peripheral window.
pub const PERIPH_SIZE: u64 = 0x0020_0000;
/// Base of the Cortex-A9 `MPCore` window (`map_desc` virtual `0xfee0_0000`).
pub const MPCORE_WINDOW_BASE: u64 = 0x1900_0000;
/// Length of the Cortex-A9 `MPCore` window.
pub const MPCORE_WINDOW_SIZE: u64 = 0x0010_0000;
/// Cortex-A9 private peripheral base, from the SCU and GIC pools.
pub const PERIPHBASE: u64 = 0x1902_0000;
/// GIC CPU interface, `PERIPHBASE + 0x100`.
pub const GIC_CPU_BASE: u64 = PERIPHBASE + 0x100;
/// Cortex-A9 private timer and watchdog, `PERIPHBASE + 0x600`.
pub const TWD_BASE: u64 = PERIPHBASE + 0x600;
/// GIC distributor, `PERIPHBASE + 0x1000`.
pub const GIC_DIST_BASE: u64 = PERIPHBASE + 0x1000;
/// `ChipcommonA` base.
pub const CHIPCOMMON_BASE: u64 = 0x1800_0000;
/// Broadcom SI chip identification register, `ChipCommon` offset 0.
///
/// The kernel dispatches on the low 16 bits at `0xc001ab3c`: `0xb160` selects
/// `"Broadcom BCM5616x"`, against `0x8416` for `BCM5340x` and `0xdb56` for
/// `BCM5615x`. The upper nibble is the backplane type; this `SoC` uses the AI
/// backplane, matching the `si_doattach` and `ai_addrspace` code in the image.
pub const CHIPCOMMON_CHIPID: u64 = CHIPCOMMON_BASE;
/// Boot console. Taken from the kernel's `plat_serial8250_port` table at
/// `0xc14a57f8`: `mapbase` `0x1802_0000`, `membase` `0xfec2_0000`, IRQ 93,
/// `regshift` 2, `iotype` `UPIO_MEM32`, type 16550A.
pub const UART0_BASE: u64 = 0x1802_0000;
/// Second port from the same table: `mapbase` `0x1802_1000`, IRQ 94.
pub const UART1_BASE: u64 = 0x1802_1000;
/// Console interrupt line from the same table.
pub const UART0_IRQ: u32 = 93;
/// Clock and reset unit base.
pub const CRU_BASE: u64 = 0x1800_e000;
/// QSPI register window. The board builds seven resources for `qspi_iproc.1`
/// at `0xc035fad4`, and the driver's `platform_get_resource(MEM, n)` order at
/// `0xc0016850` gives each one a role. The first four are contiguous here.
pub const QSPI_BASE: u64 = 0x1804_7000;
/// MSPI registers, resource MEM 0 (`0x18047200-0x18047387`).
///
/// The offsets the driver writes match `spi-bcm-qspi.c` upstream exactly:
/// `+0x08`/`+0x0c` SPCR1, `+0x10` NEWQP, `+0x14` ENDQP, `+0x18` SPCR2,
/// `+0x20` status, `+0x40` TXRAM, `+0xc0` RXRAM, `+0x140` CDRAM,
/// `+0x180` write lock.
pub const MSPI_BASE: u64 = 0x1804_7200;
/// BSPI registers, resource MEM 1 (`0x18047000-0x1804704f`). `+0x08` is
/// `MAST_N_BOOT_CTRL` and `+0x0c` is `BUSY_STATUS`, per the MSPI-mode
/// function at `0xc0015a1c`.
pub const BSPI_BASE: u64 = 0x1804_7000;
/// BSPI RAF registers, resource MEM 2 (`0x18047100-0x18047123`).
pub const BSPI_RAF_BASE: u64 = 0x1804_7100;
/// QSPI interrupt block, resource MEM 3 (`0x180473a0-0x180473bb`): seven
/// registers, one per interrupt source, which `0xc00156f4` clears by writing
/// 1 to each.
pub const QSPI_INTR_BASE: u64 = 0x1804_73a0;
/// QSPI IDM control, resource MEM 4 (`0x1811f408-0x1811f40b`).
pub const QSPI_IDM_BASE: u64 = 0x1811_f408;
/// QSPI CRU control, resource MEM 5 (`0x1800e000-0x1800e003`).
pub const QSPI_CRU_BASE: u64 = 0x1800_e000;
/// QSPI interrupt line, from the board's IRQ resource.
pub const QSPI_IRQ: u32 = 90;
/// CRU register block. The kernel declares it as the `cru_regs` resource at
/// virtual `0xfee00000`, which the static `map_desc` translates to this
/// physical base. The A9 PLL lives inside it.
///
/// `a9pll_chan_status()` reads `+0x008`, `+0xa10`, `+0xc20`, `+0xe00` and
/// `+0xec0` off this base; `+0xe00` bit 4 selects a mode and its low nibble
/// indexes a divider. The encodings are not modelled yet, so reads are
/// defined-zero rather than aborting the guest.
pub const CRU_REGS_BASE: u64 = 0x1900_0000;
/// GENPLL control block, located at `0x1800_fc00` by tracing which addresses
/// the console clock chain touches outside the modelled windows.
///
/// The vendor kernel derives the console clock from it:
///
/// ```text
/// GENPLL:      locked = *(base + 0x18) & 1
///              ctrl   = *(base + 0x04)
///              rate   = (parent 25 MHz / ((ctrl >> 10) & 0xf)) * (ctrl & 0x3ff)
/// genpll_ch5:  mdiv   = ((*(base + 0x08) >> 8) << 2), or 256 when zero
///              rate   = GENPLL rate / mdiv
/// ```
pub const GENPLL_BASE: u64 = 0x1800_fc00;
/// DMU register block, the kernel's `dmu_regs` resource at virtual
/// `0xfec0f000`. GENPLL sits at `+0xc00` inside it.
pub const DMU_REGS_BASE: u64 = 0x1800_f000;

/// `CMICd` switch management block. `cmicd_mdiobus_probe` at `0xc027a9b0`
/// ioremaps this address directly — `ioremap(0x3233000, 0x1000, 0)` — rather
/// than taking it from a platform resource. It sits outside the peripheral
/// window, so an unmodelled access aborts instead of being absorbed.
///
/// `cmicd_miim_op` at `0xc0014de0` uses five registers off this base:
/// `+0x80` parameter, `+0x84` read data, `+0x88` address, `+0x8c` control
/// (bit 0 write, bit 1 read) and `+0x90` status (bit 0 done).
pub const CMICD_BASE: u64 = 0x0323_3000;
/// Switch register block containing `CMICd`. `ubnthal`'s `system_init` ioremaps
/// `0x03200000`+256 KiB and `bcm5334x_get_cputype` reads `+0x10224` from it.
pub const CMIC_BLOCK_BASE: u64 = 0x0320_0000;
pub(super) const CMIC_BLOCK_BASE_U32: u32 = 0x0320_0000;
/// Length of that block, from the module's own ioremap length.
pub const CMIC_BLOCK_SIZE: u64 = 0x0004_0000;
pub(super) const CMIC_BLOCK_SIZE_U32: u32 = 0x0004_0000;
/// Switch device identification.
///
/// `bcm5334x_get_cputype` accepts the BCM56166 variant within the `BCM5616x`
/// family. US24PRO requires the exact device ID `0xb166` here, while
/// `CHIPCOMMON_CHIPID` retains family ID `0xb160`; see
/// `docs/us24pro/sdk-board-identity.md` for the SDK board-table evidence.
///
/// The helper at `0x1480c` in `ubnthal.ko` ioremaps `0x3200000`+256 KiB and reads
///
/// ```text
/// add   r0, r4, #0x10000
/// ldr   r4, [r0, #0x224]
/// uxth  r4, r4
/// ```
///
/// so it is a 32-bit read whose low half is the comparison, one 64 KiB page
/// into the window.
pub const CMIC_DEVICE_ID: u64 = CMIC_BLOCK_BASE + 0x10224;

/// `ChipCommon` `EROMPTR`, the physical address of the enumeration ROM.
///
/// `_init` in `linux-kernel-bde.ko` (at `_init+0xf70` in the module's own
/// image) does `ioremap(0x180000fc, 0x100)`, reads this one word, unmaps it,
/// then `ioremap`s 4 KiB of whatever it read and walks that as an EROM. The
/// chip id this model reports already sets `CHIPID_TYPE_AI`, which is what
/// tells that class of driver an EROM exists, so the pointer has to be real.
pub const CHIPCOMMON_EROM_PTR: u64 = CHIPCOMMON_BASE + 0xfc;

/// Where this model places the enumeration ROM.
///
/// The cores of an AI-type chip are enumerated in 4 KiB slots from
/// [`CHIPCOMMON_BASE`], `ChipCommon` itself occupying the first, so the EROM
/// goes in the second. No US24PRO was read out to confirm the vendor's own
/// choice; what matters to the guest is that `EROMPTR` and the table agree.
pub const EROM_BASE: u64 = 0x1800_1000;
pub(super) const EROM_BASE_U32: u32 = 0x1800_1000;
/// Length the BDE maps, and so the least this window may be.
pub const EROM_SIZE: u64 = 0x1000;

/// Manufacturer field of a `CoreInfo` entry: Broadcom.
pub(super) const EROM_MANUF_BROADCOM: u32 = 0x4bf;
/// Core id the BDE looks for. It compares bits 8..19 of the first `CoreInfo`
/// word against this and takes the next address descriptor it sees.
pub(super) const EROM_CORE_CMICD: u32 = 0x14;
/// Tag of a `CoreInfo` entry, in the low three bits of the word.
pub(super) const EROM_TAG_CORE_INFO: u32 = 1;
/// Tag of an address descriptor.
pub(super) const EROM_TAG_ADDRESS: u32 = 5;
/// Size type meaning "the size is in the following word" rather than
/// `0x1000 << type`, which tops out at 0x4000 and so cannot express the
/// 256 KiB CMIC block.
pub(super) const EROM_SIZE_TYPE_WORD: u32 = 3;
/// End of the table. The BDE stops when a word's low nibble is all ones.
pub(super) const EROM_END: u32 = 0xf;

/// The enumeration ROM, one 32-bit word per entry.
///
/// The BDE walks this looking for the `CMICd` core and writes the address
/// descriptor that follows it into its platform device's memory resource.
/// Its own compiled-in fallback names `0x48000000`+256 KiB, which this model
/// does not implement; the table below redirects it to [`CMIC_BLOCK_BASE`],
/// the window `ubnthal` and the MDIO driver already use.
pub const EROM_TABLE: [u32; 5] = [
    // CoreInfo, first word: manufacturer and core id.
    (EROM_MANUF_BROADCOM << 20) | (EROM_CORE_CMICD << 8) | EROM_TAG_CORE_INFO,
    // CoreInfo, second word. The BDE reads nothing out of it and only
    // uses it to step over the pair, so it carries no port counts.
    EROM_TAG_CORE_INFO,
    // Address descriptor: the base is the top 20 bits of the word.
    CMIC_BLOCK_BASE_U32 | (EROM_SIZE_TYPE_WORD << 4) | EROM_TAG_ADDRESS,
    // The size, likewise masked to its top 20 bits. Bit 3 clear ends the
    // descriptor, which ends the walk.
    CMIC_BLOCK_SIZE_U32,
    EROM_END,
];
