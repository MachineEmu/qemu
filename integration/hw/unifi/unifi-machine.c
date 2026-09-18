/* Small standalone ARM machines for the Rust-backed board models. */
#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qapi/error.h"
#include "hw/boards.h"
#include "chardev/char.h"
#include "hw/char/serial-mm.h"
#include "hw/arm/machines-qom.h"
#include "hw/arm/bsa.h"
#include "hw/arm/boot.h"
#include "hw/arm/fdt.h"
#include "hw/intc/arm_gicv3_common.h"
#include "hw/intc/arm_gic.h"
#include "hw/pci-host/gpex.h"
#include "hw/pci/pci.h"
#include "hw/sysbus.h"
#include "hw/misc/unimp.h"
#include "hw/or-irq.h"
#include "hw/usb/hcd-ehci.h"
#include "hw/qdev-core.h"
#include "hw/qdev-properties.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/block-backend-global-state.h"
#include "system/block-backend-io.h"
#include "system/system.h"
#include "system/device_tree.h"
#include "target/arm/cpu-qom.h"
#include "target/arm/cpu.h"
#include "target/arm/gtimer.h"
#include "qobject/qlist.h"
#include "net/net.h"
#include "qemu/error-report.h"
#include "alpine-dw-spi.h"
#include "unifi_board.h"

#define UNIFI_RAM_BASE UINT64_C(0x40000000)
#define TYPE_UNIFI_MT7981 MACHINE_TYPE_NAME("mt7981")
#define TYPE_UNIFI_UDMPRO MACHINE_TYPE_NAME("udm-pro")
#define TYPE_UNIFI_US24PRO MACHINE_TYPE_NAME("us24pro")
/* BCM5616x/iProc switch board.  Every address below is read out of the vendor
 * Linux 3.6.5 image, not taken from upstream Broadcom support; see
 * docs/us24pro/firmware-container.md and crates/bcm5616x-machine. */
#define UNIFI_US24PRO_RAM_BASE UINT64_C(0x61000000)
#define UNIFI_US24PRO_PERIPH_BASE UINT64_C(0x18000000)
#define UNIFI_US24PRO_PERIPH_SIZE UINT64_C(0x00200000)
#define UNIFI_US24PRO_PERIPHBASE UINT64_C(0x19020000)
/* 0x19022000 is the PL310 L2 cache controller, not a second GIC: early boot
 * writes 0 to its control register (offset 0x100) before enabling the MMU,
 * and Linux later writes AUX_CTRL 0x0a120000 at offset 0x104. */
#define UNIFI_US24PRO_L2CC_BASE UINT64_C(0x19022000)
/* From the kernel's plat_serial8250_port table at 0xc14a57f8:
 * mapbase 0x18020000, IRQ 93, regshift 2, iotype UPIO_MEM32. */
#define UNIFI_US24PRO_UART_BASE UINT64_C(0x18020000)
/* The second port from the same table, which the guest confirms:
 * "serial8250.0: ttyS1 at MMIO 0x18021000 (irq = 94) is a 16550A". */
#define UNIFI_US24PRO_UART1_BASE UINT64_C(0x18021000)
/* Linux reports GIC INTIDs; a9mpcore's GPIO inputs are SPIs, so the input
 * index is INTID - 32. */
#define UNIFI_US24PRO_UART_IRQ 93
#define UNIFI_US24PRO_UART1_IRQ 94
#define UNIFI_US24PRO_QSPI_IRQ 90
/* /proc/interrupts in the guest: "113: ... GIC eth0". */
#define UNIFI_US24PRO_GMAC_IRQ 113
#define UNIFI_US24PRO_SPI_IN(intid) ((intid) - 32)
/* CMIC uses GIC INTID 184. GPIO child IRQ 266 is not a GIC INTID. */
#define UNIFI_US24PRO_NUM_IRQS 256
/* The SPI-NOR is memory-mapped here: u-boot links at 0xf0000000 and
 * nvram_env_init maps NVRAM at 0xf0200000, which is exactly past
 * 1920k(u-boot)+64k(u-boot-env)+64k(shmoo) in the mtdparts layout.  The part
 * is an MX66L51235F, 64 MiB. */
#define UNIFI_US24PRO_FLASH_BASE UINT64_C(0xf0000000)
#define UNIFI_US24PRO_FLASH_SIZE (64 * MiB)
/* The same part is also visible at 0x1c000000: the firmware container's PART
 * records carry baseaddr 0x1c000000 (u-boot) and 0x1c200000 (kernel0), and
 * ubnthal reads board data from 0x1fff0000 and requests an iomem region at
 * 0x1fffe000 -- the last 64 KiB, which mtdparts names EEPROM. */
#define UNIFI_US24PRO_FLASH_XIP_BASE UINT64_C(0x1c000000)
#define UNIFI_GIC_DIST_BASE UINT64_C(0x0c000000)
#define UNIFI_GIC_REDIST_BASE UINT64_C(0x0c080000)
#define UNIFI_NUM_IRQS 256

typedef struct UnifiMachineState {
    MachineState parent_obj;
    struct arm_boot_info bootinfo;
    DeviceState *gic;
    DeviceState *pcie[2];
    MemoryRegion *pcie_ecam[2];
    MemoryRegion *pcie_mmio[2];
    MemoryRegion pcie_dbi;
} UnifiMachineState;

static void *unifi_get_dtb(const struct arm_boot_info *info, int *size)
{
    const UnifiMachineState *ums = container_of(info, UnifiMachineState, bootinfo);
    const bool udm_pro = g_str_equal(MACHINE_GET_CLASS(ums)->name, "udm-pro");
    const UnifiUdmProLayout *layout = unifi_udmpro_layout();
    const hwaddr uart_base = udm_pro ? layout->uart_base :
                                       UINT64_C(0x11002000);
    void *fdt = create_device_tree(size);
    uint32_t gic_phandle;
    char *node;

    if (fdt == NULL) {
        return NULL;
    }
    qemu_fdt_setprop_string(fdt, "/", "compatible",
                            udm_pro ? "annapurna-labs,alpine" : "unifi,board");
    if (udm_pro) {
        qemu_fdt_setprop_string(fdt, "/", "model",
                                "Annapurna Labs Alpine V2 UBNT");
        qemu_fdt_setprop_string(fdt, "/", "version", "1.1");
    }
    qemu_fdt_setprop_cell(fdt, "/", "#address-cells", 2);
    qemu_fdt_setprop_cell(fdt, "/", "#size-cells", 2);
    qemu_fdt_add_subnode(fdt, "/chosen");
    node = g_strdup_printf("/uart@%" PRIx64, uart_base);
    qemu_fdt_setprop_string(fdt, "/chosen", "stdout-path", node);
    qemu_fdt_add_subnode(fdt, "/aliases");
    qemu_fdt_setprop_string(fdt, "/aliases", "serial0", node);
    g_free(node);
    qemu_fdt_add_subnode(fdt, "/memory@40000000");
    qemu_fdt_setprop_string(fdt, "/memory@40000000", "device_type", "memory");
    qemu_fdt_setprop_sized_cells(fdt, "/memory@40000000", "reg",
                                 2, UNIFI_RAM_BASE, 2, info->ram_size);
    qemu_fdt_add_subnode(fdt, "/cpus");
    qemu_fdt_setprop_cell(fdt, "/cpus", "#address-cells", 1);
    qemu_fdt_setprop_cell(fdt, "/cpus", "#size-cells", 0);
    for (unsigned int n = 0; n < MACHINE(ums)->smp.cpus; n++) {
        node = g_strdup_printf("/cpus/cpu@%x", n);
        qemu_fdt_add_subnode(fdt, node);
        qemu_fdt_setprop_string(fdt, node, "device_type", "cpu");
        qemu_fdt_setprop_string(fdt, node, "compatible",
                               udm_pro ? "arm,cortex-a57" : "arm,cortex-a53");
        qemu_fdt_setprop_cell(fdt, node, "reg", n);
        qemu_fdt_setprop_string(fdt, node, "enable-method", "psci");
        g_free(node);
    }
    qemu_fdt_add_subnode(fdt, "/intc@c000000");
    gic_phandle = qemu_fdt_alloc_phandle(fdt);
    qemu_fdt_setprop_string(fdt, "/intc@c000000", "compatible",
                           udm_pro ? "arm,cortex-a15-gic" : "arm,gic-v3");
    qemu_fdt_setprop(fdt, "/intc@c000000", "interrupt-controller", NULL, 0);
    qemu_fdt_setprop_cell(fdt, "/intc@c000000", "#interrupt-cells", 3);
    qemu_fdt_setprop_cell(fdt, "/intc@c000000", "#address-cells", 2);
    qemu_fdt_setprop_cell(fdt, "/intc@c000000", "#size-cells", 2);
    qemu_fdt_setprop(fdt, "/intc@c000000", "ranges", NULL, 0);
    qemu_fdt_setprop_cell(fdt, "/intc@c000000", "phandle", gic_phandle);
    qemu_fdt_setprop_sized_cells(fdt, "/intc@c000000", "reg",
                                 2, UNIFI_GIC_DIST_BASE, 2, 0x10000,
                                 2, UNIFI_GIC_REDIST_BASE, 2,
                                 udm_pro ? 0x2000 : 0x400000);
    qemu_fdt_setprop_cell(fdt, "/", "interrupt-parent", gic_phandle);
    uint32_t msi_phandle = 0;
    if (udm_pro) {
        msi_phandle = qemu_fdt_alloc_phandle(fdt);
        qemu_fdt_add_subnode(fdt, "/intc@c000000/v2m@8020000");
        qemu_fdt_setprop_string(fdt, "/intc@c000000/v2m@8020000", "compatible",
                                "arm,gic-v2m-frame");
        qemu_fdt_setprop(fdt, "/intc@c000000/v2m@8020000", "msi-controller", NULL, 0);
        qemu_fdt_setprop_cell(fdt, "/intc@c000000/v2m@8020000", "phandle", msi_phandle);
        qemu_fdt_setprop_sized_cells(fdt, "/intc@c000000/v2m@8020000", "reg",
                                    2, 0x08020000, 2, 0x1000);
    }
    qemu_fdt_add_subnode(fdt, "/timer");
    qemu_fdt_setprop_string(fdt, "/timer", "compatible", "arm,armv8-timer");
    qemu_fdt_setprop_cells(fdt, "/timer", "interrupts",
                           GIC_FDT_IRQ_TYPE_PPI, 13, GIC_FDT_IRQ_FLAGS_LEVEL_HI,
                           GIC_FDT_IRQ_TYPE_PPI, 14, GIC_FDT_IRQ_FLAGS_LEVEL_HI,
                           GIC_FDT_IRQ_TYPE_PPI, 11, GIC_FDT_IRQ_FLAGS_LEVEL_HI,
                           GIC_FDT_IRQ_TYPE_PPI, 10, GIC_FDT_IRQ_FLAGS_LEVEL_HI);
    qemu_fdt_setprop(fdt, "/timer", "always-on", NULL, 0);
    node = g_strdup_printf("/uart@%" PRIx64, uart_base);
    qemu_fdt_add_subnode(fdt, node);
    qemu_fdt_setprop_string(fdt, node, "compatible", "ns16550a");
    qemu_fdt_setprop_cell(fdt, node, "reg-shift", 2);
    qemu_fdt_setprop_cell(fdt, node, "reg-io-width", 4);
    qemu_fdt_setprop_sized_cells(fdt, node, "reg", 2, uart_base,
                                 2, 0x1000);
    qemu_fdt_setprop_cell(fdt, node, "clock-frequency", udm_pro ?
                           1843200 : 26000000);
    qemu_fdt_setprop_cell(fdt, node, "current-speed", 115200);
    qemu_fdt_setprop_cells(fdt, node, "interrupts", GIC_FDT_IRQ_TYPE_SPI,
                           udm_pro ? layout->uart_irq : 33,
                           GIC_FDT_IRQ_FLAGS_LEVEL_HI);
    g_free(node);
    if (udm_pro) {
        /* Alpine uart1: the port /usr/sbin/hci-device-up attaches the
         * CSR8811 Bluetooth controller to on an `ea15` board, as /dev/ttyS1.
         * The node is emitted only when a second -serial backend exists,
         * because a 16550 without a chardev fails to realize; an absent node
         * is also the honest description of an unpopulated BT header. */
        if (serial_hd(1) != NULL) {
            node = g_strdup_printf("/uart@%" PRIx64, layout->bt_uart_base);
            qemu_fdt_add_subnode(fdt, node);
            qemu_fdt_setprop_string(fdt, node, "compatible", "ns16550a");
            qemu_fdt_setprop_cell(fdt, node, "reg-shift", 2);
            qemu_fdt_setprop_cell(fdt, node, "reg-io-width", 4);
            qemu_fdt_setprop_sized_cells(fdt, node, "reg", 2, layout->bt_uart_base,
                                         2, 0x1000);
            qemu_fdt_setprop_cell(fdt, node, "clock-frequency", 1843200);
            qemu_fdt_setprop_cell(fdt, node, "current-speed", 115200);
            qemu_fdt_setprop_cells(fdt, node, "interrupts", GIC_FDT_IRQ_TYPE_SPI,
                                   layout->bt_uart_irq,
                                   GIC_FDT_IRQ_FLAGS_LEVEL_HI);
            qemu_fdt_setprop_string(fdt, "/aliases", "serial1", node);
            g_free(node);
        }
        qemu_fdt_add_subnode(fdt, "/soc");
        qemu_fdt_setprop_string(fdt, "/soc", "compatible", "simple-bus");
        qemu_fdt_setprop_cell(fdt, "/soc", "#address-cells", 2);
        qemu_fdt_setprop_cell(fdt, "/soc", "#size-cells", 2);
        qemu_fdt_setprop(fdt, "/soc", "ranges", NULL, 0);

        /* The vendor Ethernet driver does not derive port policy from the
         * PCI function alone.  It looks up board-cfg/ethernet/portN while
         * binding each Alpine Ethernet function.  Keep these nodes aligned
         * with the production UDM Pro DT so the driver sees the same port
         * topology (copper LAN, SGMII switch uplink, and two SFP ports). */
        qemu_fdt_add_subnode(fdt, "/soc/board-cfg");
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "id",
                                "alpine_v2_ubnt udm-pro v5.0");
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "board-id",
                                layout->board_id);
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "vendor-id",
                                layout->vendor_id);
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "system-id",
                                layout->system_id);
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "serial-number",
                                layout->serial_number);
        qemu_fdt_setprop_string(fdt, "/soc/board-cfg", "model",
                                layout->model);
        qemu_fdt_add_subnode(fdt, "/soc/board-cfg/ethernet");
        const char *port_modes[] = {
            "auto-detect-auto-speed", "rgmii", "auto-detect-auto-speed",
            "sgmii-2.5g"
        };
        const char *port_status[] = { "enabled", "enabled", "enabled", "enabled" };
        const unsigned int port_i2c[] = { 2, 0, 3, 0 };
        const unsigned int port_serdes_group[] = { 3, 0, 3, 2 };
        const unsigned int port_serdes_lane[] = { 2, 0, 0, 3 };
        const unsigned int port_phy_addr[] = { 0, 4, 0, 17 };
        for (unsigned int port = 0; port < 4; port++) {
            char *port_node = g_strdup_printf("/soc/board-cfg/ethernet/port%u",
                                              port);
            qemu_fdt_add_subnode(fdt, port_node);
            qemu_fdt_setprop_string(fdt, port_node, "status", port_status[port]);
            qemu_fdt_setprop_string(fdt, port_node, "mode", port_modes[port]);
            qemu_fdt_setprop_cell(fdt, port_node, "i2c-id", port_i2c[port]);
            qemu_fdt_setprop_cell(fdt, port_node, "serdes-grp",
                                  port_serdes_group[port]);
            qemu_fdt_setprop_cell(fdt, port_node, "serdes-lane",
                                  port_serdes_lane[port]);
            qemu_fdt_setprop_cell(fdt, port_node, "phy-addr", port_phy_addr[port]);
            char *leds = g_strdup_printf("%s/leds", port_node);
            qemu_fdt_add_subnode(fdt, leds);
            if (port == 0 || port == 2) {
                char *serial = g_strdup_printf(
                    "/soc/board-cfg/ethernet/port%u/10g-serial", port);
                qemu_fdt_add_subnode(fdt, serial);
                g_free(serial);
                char *sfp_led = g_strdup_printf("%s/sfp_1g", leds);
                qemu_fdt_add_subnode(fdt, sfp_led);
                qemu_fdt_setprop_string(fdt, sfp_led, "label", "sfp_1g");
                qemu_fdt_setprop_cell(fdt, sfp_led, "led-index", port == 0 ? 2 : 0);
                g_free(sfp_led);
            }
            g_free(leds);
            g_free(port_node);
        }
        for (unsigned int i = 0; i < 4; i++) {
            char *eth = g_strdup_printf("/soc/eth%u", i);
            qemu_fdt_add_subnode(fdt, eth);
            qemu_fdt_setprop_sized_cells(fdt, eth, "reg",
                                        2, layout->ethernet_bases[i],
                                        2, 0x1000);
            qemu_fdt_setprop_cells(fdt, eth, "interrupts",
                                    GIC_FDT_IRQ_TYPE_SPI, 0x3d + i,
                                    GIC_FDT_IRQ_FLAGS_LEVEL_HI);
            g_free(eth);
        }
        qemu_fdt_add_subnode(fdt, "/soc/serdes");
        qemu_fdt_setprop_string(fdt, "/soc/serdes", "compatible",
                                "annapurna-labs,al-serdes");
        qemu_fdt_setprop_sized_cells(fdt, "/soc/serdes", "reg",
                                    2, 0xfd8c0000, 2, 0x2400);

        qemu_fdt_add_subnode(fdt, "/soc/pbs@fd8a8000");
        qemu_fdt_setprop_string(fdt, "/soc/pbs@fd8a8000", "compatible",
                                "annapurna-labs,al-pbs");
        qemu_fdt_setprop_sized_cells(fdt, "/soc/pbs@fd8a8000", "reg",
                                     2, UINT64_C(0xfd8a8000), 2, 0x1000);

        uint32_t clock = qemu_fdt_alloc_phandle(fdt);
        uint32_t gpio_phandles[6] = { 0 };
        qemu_fdt_add_subnode(fdt, "/soc/clocks");
        qemu_fdt_setprop_cell(fdt, "/soc/clocks", "#address-cells", 1);
        qemu_fdt_setprop_cell(fdt, "/soc/clocks", "#size-cells", 0);
        qemu_fdt_add_subnode(fdt, "/soc/clocks/sbclk");
        qemu_fdt_setprop_string(fdt, "/soc/clocks/sbclk", "compatible",
                                "fixed-clock");
        qemu_fdt_setprop_cell(fdt, "/soc/clocks/sbclk", "#clock-cells", 0);
        qemu_fdt_setprop_cell(fdt, "/soc/clocks/sbclk", "clock-frequency",
                              1000000);
        qemu_fdt_setprop_cell(fdt, "/soc/clocks/sbclk", "phandle", clock);

        /* Alpine GPIO banks drive board LEDs, keys, and SATA indicators. */
        for (unsigned int i = 0; i < ARRAY_SIZE(layout->gpio_bases); i++) {
            const hwaddr gpio_base = layout->gpio_bases[i];
            char *gpio = g_strdup_printf("/soc/gpio%u@%lx", i,
                                         (unsigned long)gpio_base);
            qemu_fdt_add_subnode(fdt, gpio);
            {
                static const char compat[] = "arm,pl061\0arm,primecell";
                qemu_fdt_setprop(fdt, gpio, "compatible", compat,
                                 sizeof(compat));
            }
            qemu_fdt_setprop(fdt, gpio, "gpio-controller", NULL, 0);
            qemu_fdt_setprop_cell(fdt, gpio, "#gpio-cells", 2);
            qemu_fdt_setprop_sized_cells(fdt, gpio, "reg", 2,
                                         gpio_base, 2, 0x1000);
            qemu_fdt_setprop_cells(fdt, gpio, "interrupts",
                                   GIC_FDT_IRQ_TYPE_SPI, 2 + i,
                                   GIC_FDT_IRQ_FLAGS_LEVEL_HI);
            qemu_fdt_setprop_cell(fdt, gpio, "baseidx",
                                  layout->gpio_base_indices[i]);
            if (i == 2 || i == 3) {
                gpio_phandles[i] = qemu_fdt_alloc_phandle(fdt);
                qemu_fdt_setprop_cell(fdt, gpio, "phandle", gpio_phandles[i]);
            }
            qemu_fdt_setprop_cell(fdt, gpio, "clocks", clock);
            qemu_fdt_setprop_string(fdt, gpio, "clock-names", "apb_pclk");
            g_free(gpio);
        }

        qemu_fdt_add_subnode(fdt, "/soc/spi@fd882000");
        {
            static const char compat[] =
                "amazon,alpine-dw-apb-ssi\0snps,dw-spi-mmio\0snps,dw-apb-ssi";
            qemu_fdt_setprop(fdt, "/soc/spi@fd882000", "compatible",
                            compat, sizeof(compat));
        }
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000", "clocks", clock);
        qemu_fdt_setprop_string(fdt, "/soc/spi@fd882000", "clock-names", "sbclk");
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000", "num-chipselect", 4);
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000", "bus-num", 0);
        qemu_fdt_setprop_sized_cells(fdt, "/soc/spi@fd882000", "reg",
                                     2, UINT64_C(0xfd882000), 2, 0x1000);
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000", "#address-cells", 1);
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000", "#size-cells", 0);
        qemu_fdt_setprop_cells(fdt, "/soc/spi@fd882000", "interrupts",
                               GIC_FDT_IRQ_TYPE_SPI, 23,
                               GIC_FDT_IRQ_FLAGS_LEVEL_HI);
        qemu_fdt_add_subnode(fdt, "/soc/spi@fd882000/flash@0");
        qemu_fdt_setprop_string(fdt, "/soc/spi@fd882000/flash@0", "compatible",
                                "spi_flash_jedec_detection");
        qemu_fdt_setprop_cell(fdt, "/soc/spi@fd882000/flash@0", "reg", 0);
        const char *flash = "/soc/spi@fd882000/flash@0";
        qemu_fdt_setprop_cell(fdt, flash, "spi-max-frequency", 37500000);
        qemu_fdt_setprop_cell(fdt, flash, "#address-cells", 1);
        qemu_fdt_setprop_cell(fdt, flash, "#size-cells", 1);
        /* Emit these highest-offset-first.  libfdt inserts a new subnode
         * ahead of the parent's existing subnodes, so the order the tree ends
         * up in is the reverse of the order they are added, and Linux's
         * ofpart parser numbers mtdN by tree order.  Adding them ascending
         * produced mtd0="config" ... mtd5="u-boot", the exact reverse of the
         * vendor DT.  Everything indexed by partition number then landed on
         * the wrong partition: `ubnt-tools id` reads /dev/mtdblock0 expecting
         * `u-boot` and got `config`, so it found no board record and fell
         * back to sysid 0 / ARMv8, and the vendor initramfs wrote the config
         * partition through /dev/mtdblock5 straight over the real `u-boot`
         * partition -- including the Alpine board record at 0x8000. */
        for (unsigned int n = 0; n < 6; n++) {
            unsigned int i = 5 - n;
            static const uint32_t offsets[] = {
                0, 0x1c0000, 0x1d0000, 0x1e0000, 0x1f0000, 0x200000
            };
            static const uint32_t sizes[] = {
                0x1c0000, 0x10000, 0x10000, 0x10000, 0x10000, 0x600000
            };
            static const char *labels[] = {
                "u-boot", "u-boot env", "u-boot env redundant",
                "Factory", "EEPROM", "config"
            };
            char *part = g_strdup_printf("%s/partition@%x", flash, offsets[i]);
            qemu_fdt_add_subnode(fdt, part);
            qemu_fdt_setprop_cells(fdt, part, "reg", offsets[i], sizes[i]);
            qemu_fdt_setprop_string(fdt, part, "label", labels[i]);
            if (i == 3 || i == 4) {
                qemu_fdt_setprop(fdt, part, "read-only", NULL, 0);
            }
            g_free(part);
        }

        /* ubnthal requires the write-policy tree even when the emulated
         * flash is intentionally writable for development. */
        qemu_fdt_add_subnode(fdt, "/ubnthal-wp");
        qemu_fdt_setprop_string(fdt, "/ubnthal-wp", "compatible",
                                "ubnthal,write-protect");
        qemu_fdt_setprop_string(fdt, "/ubnthal-wp", "default-write-policy",
                                "rw");
        qemu_fdt_add_subnode(fdt, "/ubnthal-wp/bus");
        qemu_fdt_add_subnode(fdt, "/ubnthal-wp/bus/spi@0");
        qemu_fdt_setprop_string(fdt, "/ubnthal-wp/bus/spi@0", "bus", "*.spi");
        qemu_fdt_setprop_string(fdt, "/ubnthal-wp/bus/spi@0",
                                "default-write-policy", "rw");
        qemu_fdt_add_subnode(fdt, "/ubnthal-wp/explicit-write-policy");
        qemu_fdt_add_subnode(fdt, "/ubnthal-wp/explicit-write-policy/mtd");
        for (unsigned int i = 0; i < 2; i++) {
            const char *label = i == 0 ? "Factory" : "EEPROM";
            char *policy = g_strdup_printf(
                "/ubnthal-wp/explicit-write-policy/mtd/partition@%u", i);
            qemu_fdt_add_subnode(fdt, policy);
            qemu_fdt_setprop_string(fdt, policy, "label", label);
            qemu_fdt_setprop_string(fdt, policy, "write-policy", "ro");
            g_free(policy);
        }

        /* Alpine V2 exposes SP805 watchdog 0 to the vendor watchdog driver.
         * Keep the APB clock and interrupt wiring from the production DT so
         * the guest sees the same platform device during early boot. */
        char *wdt = g_strdup_printf("/soc/wdt@%lx",
                                    (unsigned long)layout->watchdog_base);
        qemu_fdt_add_subnode(fdt, wdt);
        {
            static const char compat[] = "arm,sp805\0arm,primecell";
            qemu_fdt_setprop(fdt, wdt, "compatible",
                             compat, sizeof(compat));
        }
        qemu_fdt_setprop_sized_cells(fdt, wdt, "reg",
                                     2, layout->watchdog_base, 2, 0x1000);
        qemu_fdt_setprop_cells(fdt, wdt, "interrupts",
                               GIC_FDT_IRQ_TYPE_SPI, layout->watchdog_irq,
                               GIC_FDT_IRQ_FLAGS_LEVEL_HI);
        qemu_fdt_setprop_cell(fdt, wdt, "clocks", clock);
        qemu_fdt_setprop_string(fdt, wdt, "clock-names",
                                "apb_pclk");
        uint32_t wdt_phandle = qemu_fdt_alloc_phandle(fdt);
        qemu_fdt_setprop_cell(fdt, wdt, "phandle",
                              wdt_phandle);
        qemu_fdt_setprop_string(fdt, wdt, "status", "okay");
        g_free(wdt);

        qemu_fdt_add_subnode(fdt, "/soc/gpio_keys");
        qemu_fdt_setprop_string(fdt, "/soc/gpio_keys", "compatible", "gpio-keys");
        qemu_fdt_add_subnode(fdt, "/soc/gpio_keys/reset_button");
        qemu_fdt_setprop_string(fdt, "/soc/gpio_keys/reset_button", "label",
                                "Reset Button");
        qemu_fdt_setprop_cell(fdt, "/soc/gpio_keys/reset_button", "linux,code",
                              0x198);
        qemu_fdt_setprop_cell(fdt, "/soc/gpio_keys/reset_button",
                              "debounce-interval", 200);
        qemu_fdt_setprop_cells(fdt, "/soc/gpio_keys/reset_button", "gpios",
                               gpio_phandles[2], 7, 1);

        qemu_fdt_add_subnode(fdt, "/soc/reboot");
        qemu_fdt_setprop_string(fdt, "/soc/reboot", "compatible",
                                "annapurna-labs,alpine-reboot");
        qemu_fdt_setprop_cell(fdt, "/soc/reboot", "wdt-parent", wdt_phandle);

        qemu_fdt_add_subnode(fdt, "/soc/pcie-external0");
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "msi-parent", msi_phandle);
        const char *ethnode = "/soc/pcie-external0/ethernet@0,0";
        qemu_fdt_add_subnode(fdt, ethnode);
        qemu_fdt_setprop_string(fdt, ethnode, "compatible",
                                "annapurna-labs,al-eth");
        qemu_fdt_setprop_cells(fdt, ethnode, "reg", 0, 0, 0, 0, 0);
        qemu_fdt_setprop_string(fdt, ethnode, "status", "okay");
        qemu_fdt_setprop_cell(fdt, ethnode, "phy-addr", 1);
        qemu_fdt_setprop_string(fdt, ethnode, "phy-mode", "rgmii");
        qemu_fdt_setprop_string(fdt, "/soc/pcie-external0", "compatible",
                                "annapurna-labs,alpine-external-pcie");
        /* The vendor udev rules identify the management Ethernet functions
         * by domain 0000 and slot (00..03). */
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "linux,pci-domain",
                              1);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "pcie-port-num", 0);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "max-link-speed", 2);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "num-lanes", 4);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "cfg-space-offset",
                              0x10000);
        qemu_fdt_setprop_string(fdt, "/soc/pcie-external0", "device_type", "pci");
        qemu_fdt_setprop_string(fdt, "/soc/pcie-external0", "reg-names", "ecam");
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "#address-cells", 3);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "#size-cells", 2);
        qemu_fdt_setprop_cell(fdt, "/soc/pcie-external0", "#interrupt-cells", 1);
        qemu_fdt_setprop_cells(fdt, "/soc/pcie-external0", "bus-range", 0, 0xff);
        qemu_fdt_setprop_sized_cells(fdt, "/soc/pcie-external0", "reg",
                                     2, UINT64_C(0xfd800000), 2, 0x20000);
        qemu_fdt_setprop_cells(fdt, "/soc/pcie-external0", "ranges",
                               0, 0, 0xfb600000, 0, 0xfb600000, 0, 0x100000,
                               0x01000000, 0, 0x10000,
                               0, 0xc0000000, 0, 0x10000,
                               0x02000000, 0, 0xc0010000,
                               0, 0xc0010000, 0, 0x01000000);

        qemu_fdt_add_subnode(fdt, "/soc/pci@fbc00000");
        qemu_fdt_setprop_cell(fdt, "/soc/pci@fbc00000", "msi-parent", msi_phandle);
        qemu_fdt_setprop_string(fdt, "/soc/pci@fbc00000", "compatible",
                                "annapurna-labs,alpine-internal-pcie");
        qemu_fdt_setprop_cell(fdt, "/soc/pci@fbc00000", "linux,pci-domain",
                              0);
        qemu_fdt_setprop(fdt, "/soc/pci@fbc00000", "dma-coherent", NULL, 0);
        qemu_fdt_setprop_string(fdt, "/soc/pci@fbc00000", "device_type", "pci");
        qemu_fdt_setprop_string(fdt, "/soc/pci@fbc00000", "reg-names", "ecam");
        qemu_fdt_setprop_cell(fdt, "/soc/pci@fbc00000", "#address-cells", 3);
        qemu_fdt_setprop_cell(fdt, "/soc/pci@fbc00000", "#size-cells", 2);
        qemu_fdt_setprop_cell(fdt, "/soc/pci@fbc00000", "#interrupt-cells", 1);
        qemu_fdt_setprop_cells(fdt, "/soc/pci@fbc00000", "bus-range", 0, 0);
        qemu_fdt_setprop_cells(fdt, "/soc/pci@fbc00000", "interrupt-parent",
                               gic_phandle);
        qemu_fdt_setprop_cells(fdt, "/soc/pci@fbc00000", "interrupt-map-mask",
                               0xf800, 0, 0, 7);
        qemu_fdt_setprop_cells(fdt, "/soc/pci@fbc00000", "interrupt-map",
                               0x4000, 0, 0, 1, gic_phandle, 0, 0,
                               GIC_FDT_IRQ_TYPE_SPI, 53,
                               GIC_FDT_IRQ_FLAGS_LEVEL_HI,
                               0x4800, 0, 0, 1, gic_phandle, 0, 0,
                               GIC_FDT_IRQ_TYPE_SPI, 54,
                               GIC_FDT_IRQ_FLAGS_LEVEL_HI);
        qemu_fdt_setprop_sized_cells(fdt, "/soc/pci@fbc00000", "reg",
                                     2, UINT64_C(0xfbc00000), 2, 0x100000);
        qemu_fdt_setprop_cells(fdt, "/soc/pci@fbc00000", "ranges",
                               0x02000000, 0, 0xfe000000,
                               0, 0xfe000000, 0, 0x01000000);
        for (unsigned int slot = 0; slot < 4; slot++) {
            char *node = g_strdup_printf("/soc/pci@fbc00000/ethernet@%x,0",
                                         slot);
            qemu_fdt_add_subnode(fdt, node);
            qemu_fdt_setprop_string(fdt, node, "compatible",
                                    "annapurna-labs,al-eth");
            qemu_fdt_setprop_cells(fdt, node, "reg", slot << 11, 0, 0, 0, 0);
            qemu_fdt_setprop_string(fdt, node, "status", "okay");
            qemu_fdt_setprop_cell(fdt, node, "phy-addr", 17);
            qemu_fdt_setprop_string(fdt, node, "phy-mode", "rgmii");
            g_free(node);
        }

        /* The gateway switch driver expects the RTL8370 description in the
         * board DT, in addition to the PCI function used as switch0. */
        qemu_fdt_add_subnode(fdt, "/soc/switch-chip");
        qemu_fdt_add_subnode(fdt, "/soc/switch-chip/rtl8370mb@11");
        qemu_fdt_setprop_string(fdt, "/soc/switch-chip/rtl8370mb@11",
                                "compatible", "realtek,rtl8370mb");
        qemu_fdt_setprop_cell(fdt, "/soc/switch-chip/rtl8370mb@11", "reg", 0x11);
        qemu_fdt_setprop_cell(fdt, "/soc/switch-chip/rtl8370mb@11",
                              "led-profile", 1);
        qemu_fdt_add_subnode(fdt, "/soc/switch-chip/rtl8370mb@11/gmac");
        qemu_fdt_add_subnode(fdt,
                             "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@0");
        qemu_fdt_setprop_cell(fdt,
                              "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@0",
                              "reg", 0);
        qemu_fdt_setprop_string(fdt,
                                "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@0",
                                "mode", "disabled");
        qemu_fdt_add_subnode(fdt,
                             "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@1");
        qemu_fdt_setprop_cell(fdt,
                              "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@1",
                              "reg", 1);
        qemu_fdt_setprop_string(fdt,
                                "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@1",
                                "mode", "sgmii-2.5g");
        qemu_fdt_setprop(fdt,
                         "/soc/switch-chip/rtl8370mb@11/gmac/cpu_port@1",
                         "nway_enable", NULL, 0);
    }
    return fdt;
}


static bool unifi_get_secure(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;
    return false;
}

static void unifi_set_secure(Object *obj, bool value, Error **errp)
{
    (void)obj;
    (void)value;
    (void)errp;
}

static char *unifi_get_gic_version(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;
    return g_strdup("3");
}

static void unifi_set_gic_version(Object *obj, const char *value, Error **errp)
{
    (void)obj;
    (void)value;
    (void)errp;
}

/* The board table id `ubnt-tools` resolves the console model from.  Held per
 * process rather than per machine because the SPI seeding below runs from
 * machine init, before any board device exists to carry it. */
static uint16_t unifi_udmpro_system_id;

static uint16_t unifi_udmpro_selected_system_id(void)
{
    return unifi_udmpro_system_id ? unifi_udmpro_system_id
                                  : unifi_udmpro_default_system_id();
}

static char *unifi_get_system_id(Object *obj, Error **errp)
{
    (void)obj;
    (void)errp;
    return g_strdup_printf("0x%04x", unifi_udmpro_selected_system_id());
}

static void unifi_set_system_id(Object *obj, const char *value, Error **errp)
{
    uint64_t parsed;

    (void)obj;
    if (qemu_strtou64(value, NULL, 0, &parsed) != 0 || parsed > UINT16_MAX) {
        error_setg(errp, "system-id must be a 16-bit value, e.g. 0xea15");
        return;
    }
    /* Zero is the unset marker above, and no board table entry uses it. */
    if (parsed == 0) {
        error_setg(errp, "system-id must not be zero");
        return;
    }
    unifi_udmpro_system_id = (uint16_t)parsed;
}

static void unifi_create_cpu(MachineState *machine)
{
    MachineClass *mc = MACHINE_GET_CLASS(machine);

    /* The U6+ DTB declares both MT7981 A53 cores with a PSCI enable method.
     * Creating only one made Linux report `psci: failed to boot CPU1 (-22)`
     * because the secondary MPIDR did not exist. */
    /* machine->cpu_type carries -cpu and falls back to mc->default_cpu_type,
     * so using the class default directly discarded -cpu silently.  That
     * matters here: ubnt-tools branches on the MIDR, and a Cortex-A53's
     * 0x410fd034 selects an Alpine board path that a real UDM Pro (A57,
     * 0x411fd070) never takes. */
    const char *cpu_type = machine->cpu_type ?: mc->default_cpu_type;

    for (unsigned int n = 0; n < machine->smp.cpus; n++) {
        Object *cpu = object_new(cpu_type);

        if (g_str_equal(mc->name, "udm-pro")) {
            object_property_set_bool(cpu, "has_el3", false, &error_fatal);
            /* The Alpine AL324 is a Cortex-A57 r1p3, MIDR 0x411fd073, and
             * `ubnt-tools` keys its whole platform table on that string as
             * read from /proc/cpumidr.  QEMU's cortex-a57 is r1p0, 0x411fd070,
             * which matches no entry; detection then falls through to a
             * /proc/cpuinfo branch that yields a platform code the board
             * dispatcher does not handle, so every board lookup ended in the
             * generic `ARMv8` profile.  Correct only the revision nibble, and
             * only for QEMU's A57, so an explicitly selected -cpu is never
             * misreported. */
            if (ARM_CPU(cpu)->midr == 0x411fd070) {
                ARM_CPU(cpu)->midr = 0x411fd073;
            }
        }
        object_property_set_link(cpu, "memory", OBJECT(get_system_memory()),
                                 &error_fatal);
        object_property_set_int(cpu, "mp-affinity",
                                arm_build_mp_affinity(n,
                                    ARM_DEFAULT_CPUS_PER_CLUSTER),
                                &error_fatal);
        if (n > 0) {
            object_property_set_bool(cpu, "start-powered-off", true,
                                     &error_fatal);
        }
        qdev_realize(DEVICE(cpu), NULL, &error_fatal);
        object_unref(cpu);
    }
}

static void unifi_create_gic(UnifiMachineState *ums)
{
    MachineState *machine = MACHINE(ums);
    SysBusDevice *gicbusdev;
    QList *redist_region_count;
    DeviceState *cpu;

    if (g_str_equal(MACHINE_GET_CLASS(machine)->name, "udm-pro")) {
        ums->gic = qdev_new(gic_class_name());
        qdev_prop_set_uint32(ums->gic, "revision", 2);
        qdev_prop_set_uint32(ums->gic, "num-cpu", machine->smp.cpus);
        qdev_prop_set_uint32(ums->gic, "num-irq", UNIFI_NUM_IRQS + 32);
        qdev_prop_set_bit(ums->gic, "has-security-extensions", false);
        gicbusdev = SYS_BUS_DEVICE(ums->gic);
        sysbus_realize_and_unref(gicbusdev, &error_fatal);
        sysbus_mmio_map(gicbusdev, 0, UNIFI_GIC_DIST_BASE);
        sysbus_mmio_map(gicbusdev, 1, UNIFI_GIC_REDIST_BASE);
        const int irqs[] = {
            ARCH_TIMER_NS_EL1_IRQ, ARCH_TIMER_VIRT_IRQ,
            ARCH_TIMER_NS_EL2_IRQ, ARCH_TIMER_S_EL1_IRQ
        };
        for (unsigned int n = 0; n < machine->smp.cpus; n++) {
            cpu = DEVICE(qemu_get_cpu(n));
            for (unsigned int i = 0; i < ARRAY_SIZE(irqs); i++) {
                qdev_connect_gpio_out(cpu, i,
                    qdev_get_gpio_in(ums->gic,
                                    UNIFI_NUM_IRQS + n * GIC_INTERNAL + irqs[i]));
            }
            sysbus_connect_irq(gicbusdev, n,
                               qdev_get_gpio_in(cpu, ARM_CPU_IRQ));
            sysbus_connect_irq(gicbusdev, n + machine->smp.cpus,
                               qdev_get_gpio_in(cpu, ARM_CPU_FIQ));
        }
        DeviceState *v2m = qdev_new("arm-gicv2m");
        qdev_prop_set_uint32(v2m, "base-spi", 128);
        qdev_prop_set_uint32(v2m, "num-spi", 64);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(v2m), &error_fatal);
        sysbus_mmio_map(SYS_BUS_DEVICE(v2m), 0, 0x08020000);
        for (unsigned int i = 0; i < 64; i++) {
            sysbus_connect_irq(SYS_BUS_DEVICE(v2m), i,
                               qdev_get_gpio_in(ums->gic, 128 + i));
        }
        return;
    }
    ums->gic = qdev_new(gicv3_class_name());
    qdev_prop_set_uint32(ums->gic, "revision", 3);
    qdev_prop_set_uint32(ums->gic, "num-cpu", machine->smp.cpus);
    qdev_prop_set_uint32(ums->gic, "num-irq", UNIFI_NUM_IRQS + 32);
    qdev_prop_set_bit(ums->gic, "has-security-extensions", true);
    redist_region_count = qlist_new();
    qlist_append_int(redist_region_count, machine->smp.cpus);
    qdev_prop_set_array(ums->gic, "redist-region-count", redist_region_count);
    object_property_set_link(OBJECT(ums->gic), "sysmem",
                             OBJECT(get_system_memory()), &error_fatal);
    gicbusdev = SYS_BUS_DEVICE(ums->gic);
    sysbus_realize_and_unref(gicbusdev, &error_fatal);
    sysbus_mmio_map(gicbusdev, 0, UNIFI_GIC_DIST_BASE);
    sysbus_mmio_map(gicbusdev, 1, UNIFI_GIC_REDIST_BASE);

    /* Every core owns a private set of PPI and CPU interface lines; wiring
     * only CPU 0 leaves a secondary core without timer or SPI delivery. */
    for (unsigned int n = 0; n < machine->smp.cpus; n++) {
        const unsigned int num_cpu = machine->smp.cpus;
        const int timer_irq[] = {
            [GTIMER_PHYS] = ARCH_TIMER_NS_EL1_IRQ,
            [GTIMER_VIRT] = ARCH_TIMER_VIRT_IRQ,
            [GTIMER_HYP] = ARCH_TIMER_NS_EL2_IRQ,
            [GTIMER_SEC] = ARCH_TIMER_S_EL1_IRQ,
            [GTIMER_HYPVIRT] = ARCH_TIMER_NS_EL2_VIRT_IRQ,
            [GTIMER_S_EL2_PHYS] = ARCH_TIMER_S_EL2_IRQ,
            [GTIMER_S_EL2_VIRT] = ARCH_TIMER_S_EL2_VIRT_IRQ,
        };

        cpu = DEVICE(qemu_get_cpu(n));
        for (unsigned int irq = 0; irq < ARRAY_SIZE(timer_irq); irq++) {
            qdev_connect_gpio_out(cpu, irq,
                                  qdev_get_gpio_in(ums->gic,
                                      UNIFI_NUM_IRQS + n * GIC_INTERNAL
                                      + timer_irq[irq]));
        }
        qdev_connect_gpio_out_named(cpu, "gicv3-maintenance-interrupt", 0,
                                    qdev_get_gpio_in(ums->gic,
                                        UNIFI_NUM_IRQS + n * GIC_INTERNAL
                                        + ARCH_GIC_MAINT_IRQ));
        qdev_connect_gpio_out_named(cpu, "pmu-interrupt", 0,
                                    qdev_get_gpio_in(ums->gic,
                                        UNIFI_NUM_IRQS + n * GIC_INTERNAL
                                        + VIRTUAL_PMU_IRQ));
        sysbus_connect_irq(gicbusdev, n,
                           qdev_get_gpio_in(cpu, ARM_CPU_IRQ));
        sysbus_connect_irq(gicbusdev, num_cpu + n,
                           qdev_get_gpio_in(cpu, ARM_CPU_FIQ));
        sysbus_connect_irq(gicbusdev, 2 * num_cpu + n,
                           qdev_get_gpio_in(cpu, ARM_CPU_VIRQ));
        sysbus_connect_irq(gicbusdev, 3 * num_cpu + n,
                           qdev_get_gpio_in(cpu, ARM_CPU_VFIQ));
    }
}

static void unifi_create_uart(UnifiMachineState *ums)
{
    const UnifiUdmProLayout *layout = unifi_udmpro_layout();
    serial_mm_init(get_system_memory(), layout->uart_base, 2,
                   qdev_get_gpio_in(ums->gic, layout->uart_irq), 115200,
                   serial_hd(0), DEVICE_LITTLE_ENDIAN);
    /* uart1 carries the Bluetooth controller.  A 16550 with no chardev fails
     * to realize, so create it only when the run supplies a second -serial
     * backend; unifi_get_dtb() gates its DT node on the same condition. */
    if (serial_hd(1) != NULL) {
        serial_mm_init(get_system_memory(), layout->bt_uart_base, 2,
                       qdev_get_gpio_in(ums->gic, layout->bt_uart_irq), 115200,
                       serial_hd(1), DEVICE_LITTLE_ENDIAN);
    }
}

static void unifi_create_board(UnifiMachineState *ums, uint32_t kind)
{
    DeviceState *dev = qdev_new("unifi-board");
    SysBusDevice *sysbus = SYS_BUS_DEVICE(dev);

    qdev_prop_set_uint32(dev, "kind", kind);
    qdev_prop_set_bit(dev, "has-nic", kind == 1);
    /* UDM Pro's UART is provided by the native QEMU 16550 below.  Sharing
     * serial_hd(0) with the Rust board adapter would reserve the same
     * chardev twice when run.sh uses -serial stdio. */
    sysbus_realize_and_unref(sysbus, &error_fatal);
    sysbus_connect_irq(sysbus, 74, qdev_get_gpio_in(ums->gic, 74));
    if (kind == 1) {
        // MT7981/U6+ DT uses SPI 142 for the SPI-NOR controller and SPI 143
        // for MSDC. The Rust board emits those lines by their architectural
        // GIC numbers, so keep the QEMU output indices identical.
        sysbus_connect_irq(sysbus, 142, qdev_get_gpio_in(ums->gic, 142));
        sysbus_connect_irq(sysbus, 143, qdev_get_gpio_in(ums->gic, 143));
        /* U6+ frame-engine SPIs, not Linux's dynamically assigned IRQs. */
        for (unsigned int irq = 196; irq <= 199; irq++) {
            sysbus_connect_irq(sysbus, irq, qdev_get_gpio_in(ums->gic, irq));
        }
        /* WFDMA WM event completion: DT SPI 213, GIC INTID 245. */
        sysbus_connect_irq(sysbus, 213, qdev_get_gpio_in(ums->gic, 213));
    }
}

/* The Alpine host driver accesses function zero through the DBI aperture.
 * Forward it to the Ethernet endpoint at slot 0 on our external GPEX bus. */
static uint64_t unifi_dbi_read(void *opaque, hwaddr offset, unsigned size)
{
    UnifiMachineState *ums = opaque;
    PCIBus *bus = PCI_HOST_BRIDGE(ums->pcie[0])->bus;
    PCIDevice *dev = pci_find_device(bus, 0, PCI_DEVFN(0, 0));

    if (offset == 0x220 && size == 4) {
        return 0x3ff;
    }
    if (dev && offset + size <= PCI_CONFIG_SPACE_SIZE) {
        return pci_default_read_config(dev, offset, size);
    }
    if (offset == 0x728 || offset == 0x72c) {
        return 0x10;
    }
    return 0;
}

static void unifi_dbi_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    UnifiMachineState *ums = opaque;
    PCIBus *bus = PCI_HOST_BRIDGE(ums->pcie[0])->bus;
    PCIDevice *dev = pci_find_device(bus, 0, PCI_DEVFN(0, 0));

    if (dev && offset + size <= PCI_CONFIG_SPACE_SIZE) {
        dev->config_write(dev, offset, value, size);
    }
}

static const MemoryRegionOps unifi_dbi_ops = {
    .read = unifi_dbi_read,
    .write = unifi_dbi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void unifi_create_gpex(UnifiMachineState *ums, unsigned int index)
{
    const hwaddr ecam_base = index == 0 ? UINT64_C(0xfb600000) :
                                          UINT64_C(0xfbc00000);
    const hwaddr mmio_base = index == 0 ? UINT64_C(0xc0010000) :
                                          UINT64_C(0xfe000000);
    const hwaddr pio_base = UINT64_C(0x28000000) + index * UINT64_C(0x00010000);
    SysBusDevice *host;
    PCIHostState *pci;
    MemoryRegion *ecam;
    MemoryRegion *mmio;

    ums->pcie[index] = qdev_new(TYPE_GPEX_HOST);
    /* Alpine treats slot zero as the Ethernet PF; leave it for the NIC. */
    qdev_prop_set_uint8(ums->pcie[index], "root-slot", 31);
    /* The firmware names the management PCI bus pcie-external even though
     * the four management functions are on Alpine's internal controller. */
    qdev_prop_set_string(ums->pcie[index], "bus-name",
                         index == 0 ? "pcie-controller" : "pcie-external");
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_ECAM_BASE, ecam_base);
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_ECAM_SIZE, 0x00100000);
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_BELOW_4G_MMIO_BASE,
                         mmio_base);
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_BELOW_4G_MMIO_SIZE,
                         0x01000000);
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_PIO_BASE, pio_base);
    qdev_prop_set_uint64(ums->pcie[index], PCI_HOST_PIO_SIZE, 0x00010000);
    host = SYS_BUS_DEVICE(ums->pcie[index]);
    sysbus_realize_and_unref(host, &error_fatal);
    ecam = sysbus_mmio_get_region(host, 0);
    mmio = sysbus_mmio_get_region(host, 1);
    ums->pcie_ecam[index] = g_new0(MemoryRegion, 1);
    ums->pcie_mmio[index] = g_new0(MemoryRegion, 1);
    memory_region_init_alias(ums->pcie_ecam[index], OBJECT(ums->pcie[index]),
                             "unifi-pcie-ecam", ecam, 0, 0x00100000);
    memory_region_init_alias(ums->pcie_mmio[index], OBJECT(ums->pcie[index]),
                             "unifi-pcie-mmio", mmio, mmio_base, 0x01000000);
    memory_region_add_subregion(get_system_memory(), ecam_base,
                                ums->pcie_ecam[index]);
    memory_region_add_subregion(get_system_memory(), mmio_base,
                                ums->pcie_mmio[index]);
    sysbus_mmio_map(host, 2, pio_base);
    for (unsigned int pin = 0; pin < PCI_NUM_PINS; pin++) {
        const int irq = index == 1 ? 66 + (int)pin :
                                     80 + (int)pin;
        sysbus_connect_irq(host, pin, qdev_get_gpio_in(ums->gic, irq));
        gpex_set_irq_num(GPEX_HOST(ums->pcie[index]), pin, irq);
    }
    pci = PCI_HOST_BRIDGE(ums->pcie[index]);
    pci->bypass_iommu = true;
}

static DeviceState *unifi_attach_pci_device(PCIBus *bus, const char *type,
                                            unsigned int slot, bool msi_off,
                                            bool configure_nic)
{
    DeviceState *dev = qdev_new(type);
    qdev_prop_set_int32(dev, "addr", PCI_DEVFN(slot, 0));
    if (msi_off) {
        qdev_prop_set_bit(dev, "msi-off", true);
    }
    if (configure_nic) {
        qemu_configure_nic_device(dev, false, NULL);
    }
    qdev_realize(dev, BUS(bus), &error_fatal);
    return dev;
}

static void unifi_attach_boot_disk(DeviceState *ahci)
{
    BlockBackend *blk = blk_by_name("udm-boot");
    DeviceState *disk;
    BusState *bus;

    if (blk == NULL) {
        return;
    }
    bus = qdev_get_child_bus(ahci, "ide.0");
    disk = qdev_new("ide-hd");
    qdev_prop_set_uint32(disk, "unit", 0);
    qdev_prop_set_drive(disk, "drive", blk);
    qdev_realize_and_unref(disk, bus, &error_fatal);
}

static uint32_t unifi_eeprom_crc32(const uint8_t *bytes, size_t length)
{
    uint32_t crc = 0;
    for (size_t i = 0; i < length; i++) {
        crc ^= bytes[i];
        for (unsigned int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
        }
    }
    return crc;
}

static bool unifi_alpine_record_valid(const uint8_t *flash, size_t offset)
{
    const uint8_t *record = flash + offset;
    uint32_t crc = unifi_eeprom_crc32(&record[0x0c], 0x65);

    return record[0x00] == 'U' && record[0x01] == 'B' &&
           record[0x02] == 'N' && record[0x03] == 'T' &&
           record[0x08] == 0x00 && record[0x09] == 0x00 &&
           record[0x0a] == 0x00 && record[0x0b] == 0x65 &&
           record[0x0c] == 0x00 && record[0x0d] == 0x02 &&
           record[0x0e] == 0x00 && record[0x0f] == 0x02 &&
           record[0x04] == (crc & 0xff) &&
           record[0x05] == ((crc >> 8) & 0xff) &&
           record[0x06] == ((crc >> 16) & 0xff) &&
           record[0x07] == (crc >> 24) && record[0x70] == 0x01;
}

static bool unifi_flash_region_blank(const uint8_t *flash, size_t offset,
                                     size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (flash[offset + i] != 0 && flash[offset + i] != 0xff) {
            return false;
        }
    }
    return true;
}

static void unifi_create_spi(UnifiMachineState *ums)
{
    const UnifiUdmProLayout *layout = unifi_udmpro_layout();
    DeviceState *dev = qdev_new(TYPE_ALPINE_DW_SPI);
    SysBusDevice *spi = SYS_BUS_DEVICE(dev);
    const char *drive_id = "udm-config";

    if (blk_by_name(drive_id) != NULL) {
        qdev_prop_set_string(dev, "drive-id", drive_id);
        BlockBackend *blk = blk_by_name(drive_id);
        size_t eeprom_size = 0;
        const uint8_t *eeprom =
            unifi_udmpro_eeprom_for(unifi_udmpro_selected_system_id(), &eeprom_size);
        const int64_t eeprom_offset = 0x1f0000;
        /* Binary Ninja trace of vendor ubnt-tools shows the Alpine UDM Pro
         * selector opening /dev/mtdblock0 and validating this same record at
         * partition offset 0x8000.  The DT's named EEPROM partition is also
         * used by other firmware paths, so both locations are intentional. */
        const size_t alpine_record_offset = 0x8000;
        const size_t alpine_record_size = 0x71;
        /* Two MAC addresses then the big-endian system and vendor ids. */
        const size_t UDM_PRO_LEGACY_HEADER_SIZE = 0x10;
        uint8_t *existing = g_malloc(eeprom_size);

        if (blk_pread(blk, eeprom_offset, eeprom_size, existing, 0) < 0) {
            error_report("unable to read UDM Pro EEPROM partition");
        } else {
            bool blank = unifi_flash_region_blank(existing, alpine_record_offset,
                                                  eeprom_size - alpine_record_offset);
            bool valid_alpine_record =
                unifi_alpine_record_valid(existing, alpine_record_offset);
            /* An image seeded by an older build carries a valid UBNT record
             * but no legacy identity header at the base of the region -- and
             * that header, not the record, is what `ubnt-tools` reads to
             * resolve the board.  Without this check such an image is left
             * alone forever and the guest stays on the generic ARMv8 profile,
             * which is what makes unifi-core exit with
             * `Unsupported console model`. */
            bool legacy_header_current =
                memcmp(existing, eeprom, UDM_PRO_LEGACY_HEADER_SIZE) == 0 &&
                /* The identity record at 0xa000 is seeded too, and an image
                 * written before it existed still matches the header above. */
                existing[0xa000] == eeprom[0xa000] &&
                memcmp(&existing[0xa020], &eeprom[0xa020], 8) == 0;
            if (blank || !valid_alpine_record || !legacy_header_current) {
                /* The flash device claims its backend permissions during
                 * realization.  Grant the seed write explicitly now; the
                 * subsequent flash realization will retain the same access
                 * and load the seeded bytes into its private storage. */
                blk_set_perm(blk, BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                             BLK_PERM_ALL, &error_abort);
                if (blk_pwrite(blk, eeprom_offset, eeprom_size, eeprom, 0) < 0) {
                    error_report("unable to seed UDM Pro EEPROM partition");
                }
            } else if (unifi_flash_region_blank(existing, 0x10, 4)) {
                /* Migrate only the missing revision in our synthetic identity;
                 * preserve every other byte of an existing valid EEPROM. */
                blk_set_perm(blk, BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                             BLK_PERM_ALL, &error_abort);
                if (blk_pwrite(blk, eeprom_offset + 0x10, 4,
                               &eeprom[0x10], 0) < 0) {
                    error_report("unable to seed UDM Pro hardware revision");
                }
            }
        }
        g_free(existing);

        /* ubnt-tools does not discover the named EEPROM MTD partition for
         * this CPU.  Its board-profile path opens mtdblock0 directly, so
         * place the same record in the first MTD partition as well.  Only
         * seed an erased region; never overwrite a supplied bootloader. */
        uint8_t *mtd0 = g_malloc(eeprom_size);
        if (blk_pread(blk, 0, eeprom_size, mtd0, 0) < 0) {
            error_report("unable to read UDM Pro mtd0 board-data region");
        } else if (unifi_flash_region_blank(mtd0, alpine_record_offset,
                                             alpine_record_size) &&
                   !unifi_alpine_record_valid(mtd0, alpine_record_offset)) {
            blk_set_perm(blk, BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE,
                         BLK_PERM_ALL, &error_abort);
            if (blk_pwrite(blk, alpine_record_offset, alpine_record_size,
                           &eeprom[alpine_record_offset], 0) < 0) {
                error_report("unable to seed UDM Pro mtd0 board-data region");
            }
        }
        g_free(mtd0);
    }
    sysbus_realize_and_unref(spi, &error_fatal);
    memory_region_add_subregion_overlap(get_system_memory(), layout->spi_base,
                                        sysbus_mmio_get_region(spi, 0), 10);
    sysbus_connect_irq(spi, 0, qdev_get_gpio_in(ums->gic, layout->spi_irq));
}

/* The switch board is a 32-bit Cortex-A9 MPCore: the SCU, GIC and private
 * timers all live in one block at PERIPHBASE, so this machine uses
 * a9mpcore_priv instead of the standalone GIC the other two machines build. */
static void unifi_us24pro_init(MachineState *machine)
{
    UnifiMachineState *ums = (UnifiMachineState *)machine;
    Object *cpuobj;
    DeviceState *mpcore;
    SysBusDevice *mpcorebusdev;
    DeviceState *board;

    memory_region_add_subregion(get_system_memory(), UNIFI_US24PRO_RAM_BASE,
                                machine->ram);

    cpuobj = object_new(MACHINE_GET_CLASS(machine)->default_cpu_type);
    object_property_set_link(cpuobj, "memory", OBJECT(get_system_memory()),
                             &error_fatal);
    /* A9 reads its private peripheral base out of CBAR. */
    object_property_set_int(cpuobj, "reset-cbar", UNIFI_US24PRO_PERIPHBASE,
                            &error_fatal);
    qdev_realize(DEVICE(cpuobj), NULL, &error_fatal);
    object_unref(cpuobj);

    mpcore = qdev_new("a9mpcore_priv");
    object_property_add_child(OBJECT(machine), "us24-mpcore", OBJECT(mpcore));
    qdev_prop_set_uint32(mpcore, "num-cpu", machine->smp.cpus);
    qdev_prop_set_uint32(mpcore, "num-irq", UNIFI_US24PRO_NUM_IRQS);
    mpcorebusdev = SYS_BUS_DEVICE(mpcore);
    sysbus_realize_and_unref(mpcorebusdev, &error_fatal);
    sysbus_mmio_map(mpcorebusdev, 0, UNIFI_US24PRO_PERIPHBASE);
    sysbus_connect_irq(mpcorebusdev, 0,
                       qdev_get_gpio_in(DEVICE(first_cpu), ARM_CPU_IRQ));
    sysbus_connect_irq(mpcorebusdev, 1,
                       qdev_get_gpio_in(DEVICE(first_cpu), ARM_CPU_FIQ));
    ums->gic = mpcore;

    /* Vendor platform resources: EHCI at 0x18048000, OHCI at
     * 0x18048800, both on GIC INTID 92. Preserve a shared level when
     * either controller acknowledges its own interrupt. */
    DeviceState *usb_irq = qdev_new(TYPE_OR_IRQ);
    object_property_add_child(OBJECT(machine), "us24-usb-irq", OBJECT(usb_irq));
    qdev_prop_set_uint16(usb_irq, "num-lines", 2);
    qdev_realize_and_unref(usb_irq, NULL, &error_fatal);
    qdev_connect_gpio_out(usb_irq, 0,
                         qdev_get_gpio_in(mpcore, UNIFI_US24PRO_SPI_IN(92)));
    DeviceState *ehci = qdev_new(TYPE_PLATFORM_EHCI);
    ehci->id = g_strdup("us24-usb");
    qdev_prop_set_bit(ehci, "companion-enable", true);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(ehci), &error_fatal);
    /* Clip the generic controller's aperture to the vendor resource. */
    MemoryRegion *ehci_window = g_new0(MemoryRegion, 1);
    memory_region_init_alias(ehci_window, OBJECT(machine), "us24-ehci",
                            sysbus_mmio_get_region(SYS_BUS_DEVICE(ehci), 0),
                            0, 0x800);
    memory_region_add_subregion(get_system_memory(), 0x18048000, ehci_window);
    sysbus_connect_irq(SYS_BUS_DEVICE(ehci), 0, qdev_get_gpio_in(usb_irq, 0));
    DeviceState *ohci = qdev_new("sysbus-ohci");
    qdev_prop_set_string(ohci, "masterbus", "us24-usb.0");
    qdev_prop_set_uint32(ohci, "num-ports", EHCI_PORTS);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(ohci), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(ohci), 0, 0x18048800);
    sysbus_connect_irq(SYS_BUS_DEVICE(ohci), 0, qdev_get_gpio_in(usb_irq, 1));

    /* Board-local registers come from the Rust model, which maps its own
     * windows.  Its interrupt lines are the shared QSPI source -- the board
     * code at 0xc035fad4 gives qspi_iproc.1 IRQ 90 -- and the GMAC's. */
    board = qdev_new("unifi-board");
    qdev_prop_set_uint32(board, "kind", 3);
    qdev_prop_set_bit(board, "has-nic", true);
    /* Give the host-side NIC the same address the guest will read out of
     * NVRAM, so both ends of the link agree about who eth0 is. */
    size_t record_len = 0;
    const uint8_t *record = unifi_bcm5616x_board_data(&record_len);
    if (record != NULL && record_len >= sizeof(((MACAddr *)0)->a)) {
        MACAddr mac;
        memcpy(mac.a, record, sizeof(mac.a));
        qdev_prop_set_macaddr(board, "mac", mac.a);
    }
    sysbus_realize_and_unref(SYS_BUS_DEVICE(board), &error_fatal);
    sysbus_connect_irq(SYS_BUS_DEVICE(board), UNIFI_US24PRO_QSPI_IRQ,
                       qdev_get_gpio_in(mpcore,
                           UNIFI_US24PRO_SPI_IN(UNIFI_US24PRO_QSPI_IRQ)));
    sysbus_connect_irq(SYS_BUS_DEVICE(board), UNIFI_US24PRO_GMAC_IRQ,
                       qdev_get_gpio_in(mpcore,
                           UNIFI_US24PRO_SPI_IN(UNIFI_US24PRO_GMAC_IRQ)));
    sysbus_connect_irq(SYS_BUS_DEVICE(board), 96,
                       qdev_get_gpio_in(mpcore, UNIFI_US24PRO_SPI_IN(96)));
    sysbus_connect_irq(SYS_BUS_DEVICE(board), 97,
                       qdev_get_gpio_in(mpcore, UNIFI_US24PRO_SPI_IN(97)));
    sysbus_connect_irq(SYS_BUS_DEVICE(board), 184,
                       qdev_get_gpio_in(mpcore, UNIFI_US24PRO_SPI_IN(184)));

    /* As on UDM Pro, the console is a native 16550 overlaid on the Rust
     * board's window so RX, FIFO and interrupt state are real. */
    DeviceState *uart = qdev_new(TYPE_SERIAL_MM);
    qdev_prop_set_uint8(uart, "regshift", 2);
    qdev_prop_set_uint32(uart, "baudbase", 115200 * 16);
    qdev_prop_set_chr(uart, "chardev", serial_hd(0));
    qdev_prop_set_uint8(uart, "endianness", DEVICE_LITTLE_ENDIAN);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(uart), &error_fatal);
    sysbus_connect_irq(SYS_BUS_DEVICE(uart), 0,
                       qdev_get_gpio_in(mpcore,
                                   UNIFI_US24PRO_SPI_IN(UNIFI_US24PRO_UART_IRQ)));
    /* Overlay above the Rust board's UART window, which maps at priority 0. */
    memory_region_add_subregion_overlap(get_system_memory(),
                                        UNIFI_US24PRO_UART_BASE,
                                        sysbus_mmio_get_region(
                                            SYS_BUS_DEVICE(uart), 0), 20);

    /* The kernel's port table declares two 16550s and registers both, and
     * 8250 verifies every LCR write by reading it back.  With nothing at
     * ttyS1 the read returns zero and the port fails that check --
     * "serial8250.0: Couldn't set LCR to 3" -- so the second port has to be
     * a real device whether or not anything is attached to it.  The vendor
     * root filesystem carries usw-lcm-fw images, which is the likely
     * consumer; a run that wants to talk to it supplies a second -serial,
     * and otherwise the port discards what the guest writes.  Nothing else
     * claims this address, so no overlay is needed. */
    Chardev *uart1_chr = serial_hd(1);
    if (uart1_chr == NULL) {
        uart1_chr = qemu_chr_new("us24pro-uart1", "null", NULL);
    }
    serial_mm_init(get_system_memory(), UNIFI_US24PRO_UART1_BASE, 2,
                   qdev_get_gpio_in(mpcore,
                       UNIFI_US24PRO_SPI_IN(UNIFI_US24PRO_UART1_IRQ)),
                   115200, uart1_chr, DEVICE_LITTLE_ENDIAN);

    /* Report, rather than abort on, the parts of the 2 MiB peripheral window
     * that are not modelled yet.  The first boot trace names what to add. */
    create_unimplemented_device("bcm5616x-periph", UNIFI_US24PRO_PERIPH_BASE,
                                UNIFI_US24PRO_PERIPH_SIZE);
    DeviceState *l2cc = qdev_new("l2x0");
    sysbus_realize_and_unref(SYS_BUS_DEVICE(l2cc), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(l2cc), 0, UNIFI_US24PRO_L2CC_BASE);

    /* Erased flash, with the vendor board-data record seeded where ubnthal's
     * bcm5334x_scan_eeprom looks for it.  Without it the HAL finds no
     * vendor id and the unit has no board id, MAC or model. */
    MemoryRegion *flash = g_new0(MemoryRegion, 1);
    memory_region_init_ram(flash, NULL, "bcm5616x.flash",
                           UNIFI_US24PRO_FLASH_SIZE, &error_fatal);
    uint8_t *flash_image = memory_region_get_ram_ptr(flash);
    size_t board_data_len = 0;
    const uint8_t *board_data = unifi_bcm5616x_board_data(&board_data_len);
    uint64_t board_data_offset = unifi_bcm5616x_board_data_offset();

    memset(flash_image, 0xff, UNIFI_US24PRO_FLASH_SIZE);
    if (board_data_offset + board_data_len <= UNIFI_US24PRO_FLASH_SIZE) {
        memcpy(flash_image + board_data_offset, board_data, board_data_len);
    } else {
        error_report("board data does not fit the modelled flash");
    }

    /* The kernel's NVRAM layer ioremaps physical 0xf0200000 and parses a
     * u-boot environment out of it.  Without an `ethaddr` there, the GMAC
     * probe logs "et0: ethaddr not found, ignore it" and returns -ENODEV, so
     * the guest comes up with no network interface at all. */
    size_t nvram_env_len = 0;
    const uint8_t *nvram_env = unifi_bcm5616x_nvram_env(&nvram_env_len);
    uint64_t nvram_env_offset = unifi_bcm5616x_nvram_env_offset();

    if (nvram_env_offset + nvram_env_len <= UNIFI_US24PRO_FLASH_SIZE) {
        memcpy(flash_image + nvram_env_offset, nvram_env, nvram_env_len);
    } else {
        error_report("u-boot environment does not fit the modelled flash");
    }
    memory_region_add_subregion(get_system_memory(), UNIFI_US24PRO_FLASH_BASE,
                                flash);
    MemoryRegion *flash_xip = g_new0(MemoryRegion, 1);
    memory_region_init_alias(flash_xip, NULL, "bcm5616x.flash-xip", flash, 0,
                             UNIFI_US24PRO_FLASH_SIZE);
    memory_region_add_subregion(get_system_memory(),
                                UNIFI_US24PRO_FLASH_XIP_BASE, flash_xip);

    ums->bootinfo.ram_size = machine->ram_size;
    ums->bootinfo.loader_start = UNIFI_US24PRO_RAM_BASE;
    ums->bootinfo.primary_cpu = ARM_CPU(first_cpu);
    /* The vendor kernel is a mach-iproc board-file build, so it may want an
     * ATAG boot with its own machine number rather than the generated DT.
     * -1 selects the DT path until that number is read out of the kernel's
     * __arch_info section. */
    ums->bootinfo.board_id = -1;
    arm_load_kernel(ARM_CPU(first_cpu), machine, &ums->bootinfo);
}

static void unifi_machine_init(MachineState *machine)
{
    UnifiMachineState *ums = (UnifiMachineState *)machine;
    memory_region_add_subregion(get_system_memory(), UNIFI_RAM_BASE,
                                machine->ram);
    unifi_create_cpu(machine);
    unifi_create_gic(ums);

    if (g_str_equal(MACHINE_GET_CLASS(machine)->name, "mt7981")) {
        unifi_create_board((UnifiMachineState *)machine, 1);
        /* UART0's 16550 register bank must own RX, FIFO and interrupt state.
         * The Rust placeholder only supported early-console writes. */
        DeviceState *uart = qdev_new(TYPE_SERIAL_MM);
        qdev_prop_set_uint8(uart, "regshift", 2);
        qdev_prop_set_uint32(uart, "baudbase", 26000000 / 16);
        qdev_prop_set_chr(uart, "chardev", serial_hd(0));
        qdev_prop_set_uint8(uart, "endianness", DEVICE_LITTLE_ENDIAN);
        sysbus_realize_and_unref(SYS_BUS_DEVICE(uart), &error_fatal);
        sysbus_connect_irq(SYS_BUS_DEVICE(uart), 0,
                            qdev_get_gpio_in(ums->gic, 123));
        memory_region_add_subregion_overlap(get_system_memory(), 0x11002000,
            sysbus_mmio_get_region(SYS_BUS_DEVICE(uart), 0), 20);
    } else {
        unifi_create_gpex(ums, 0);
        unifi_create_gpex(ums, 1);
        DeviceState *ahci = unifi_attach_pci_device(
            PCI_HOST_BRIDGE(ums->pcie[1])->bus, "ich9-ahci", 8, false, false);
        unifi_attach_boot_disk(ahci);
        unifi_create_spi(ums);
        unifi_create_board(ums, 2);
        /* The four Alpine functions are physically present. Let QEMU's
         * -nic entries configure the first matching functions in slot order;
         * unconfigured functions remain present so udev can create eth8,
         * eth10, and the switch parent switch0 at slot 3. */
        PCIBus *external_bus = PCI_HOST_BRIDGE(ums->pcie[1])->bus;
        for (unsigned int slot = 0; slot <= 3; slot++) {
            unifi_attach_pci_device(external_bus, "alpine-eth-pci", slot,
                                    false, true);
        }
        /* Unit-adapter status windows used by the integrated MAC driver. */
        const UnifiUdmProLayout *layout = unifi_udmpro_layout();
        for (unsigned int i = 0; i < 4; i++) {
            create_unimplemented_device("alpine-eth-unit",
                                         layout->ethernet_bases[i], 0x1000);
        }
        unifi_create_uart(ums);
        memory_region_init_io(&ums->pcie_dbi, OBJECT(ums), &unifi_dbi_ops,
                              ums, "alpine-pcie-dbi", 0x10000);
        memory_region_add_subregion_overlap(get_system_memory(), 0xfd810000,
                                            &ums->pcie_dbi, 10);
    }
    ums->bootinfo.ram_size = machine->ram_size;
    ums->bootinfo.board_id = -1;
    ums->bootinfo.loader_start = UNIFI_RAM_BASE;
    ums->bootinfo.primary_cpu = ARM_CPU(first_cpu);
    /* The vendor U6+ DTB declares PSCI over SMC.  The old virt-based
     * launcher enabled this implicitly; standalone machines must request it
     * explicitly or Linux stalls while probing PSCI. */
    ums->bootinfo.psci_conduit = QEMU_PSCI_CONDUIT_SMC;
    /* UDM boots Linux at EL2. HVC would target that same EL, causing
     * arm_load_kernel() to disable PSCI and leave secondary CPUs offline.
     * QEMU handles the SMC conduit above the guest's boot exception level. */
    ums->bootinfo.get_dtb = unifi_get_dtb;
    arm_load_kernel(ARM_CPU(first_cpu), machine, &ums->bootinfo);
}

static void unifi_machine_options(MachineClass *mc)
{
    mc->desc = "UniFi Rust board model (standalone scaffold)";
    mc->init = unifi_machine_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a53");
    mc->default_ram_size = 1 * GiB;
    mc->default_ram_id = "unifi.ram";
    mc->max_cpus = 1;
    mc->default_cpus = 1;
    object_class_property_add_bool(OBJECT_CLASS(mc), "secure",
                                   unifi_get_secure, unifi_set_secure);
    object_class_property_add_str(OBJECT_CLASS(mc), "gic-version",
                                  unifi_get_gic_version,
                                  unifi_set_gic_version);
}

static void unifi_mt7981_options(MachineClass *mc)
{
    unifi_machine_options(mc);
    /* MT7981 is a dual-core Cortex-A53 and the U6+ DTB lists both cores. */
    mc->max_cpus = 2;
    mc->default_cpus = 2;
}

static void unifi_udmpro_options(MachineClass *mc)
{
    unifi_machine_options(mc);
    object_class_property_add_str(OBJECT_CLASS(mc), "system-id",
                                  unifi_get_system_id, unifi_set_system_id);
    mc->max_cpus = 4;
    /* The UDM Pro's AL324 is a Cortex-A57; the A53 default sent `ubnt-tools`
     * down an Alpine path meant for other boards entirely. */
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a57");
}

static void unifi_us24pro_options(MachineClass *mc)
{
    mc->desc = "UniFi BCM5616x switch board (US24PRO class)";
    mc->init = unifi_us24pro_init;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a9");
    /* The vendor command line is `mem=128M`. */
    mc->default_ram_size = 128 * MiB;
    mc->default_ram_id = "unifi.ram";
    /* `maxcpus=1` on the vendor command line. */
    mc->max_cpus = 1;
    mc->default_cpus = 1;
}

static void unifi_mt7981_class_init(ObjectClass *oc, const void *data)
{
    unifi_mt7981_options(MACHINE_CLASS(oc));
}

static void unifi_udmpro_class_init(ObjectClass *oc, const void *data)
{
    unifi_udmpro_options(MACHINE_CLASS(oc));
}

static void unifi_us24pro_class_init(ObjectClass *oc, const void *data)
{
    unifi_us24pro_options(MACHINE_CLASS(oc));
}

static const TypeInfo unifi_mt7981_info = {
    .name = TYPE_UNIFI_MT7981,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(UnifiMachineState),
    .class_init = unifi_mt7981_class_init,
    .interfaces = arm_aarch64_machine_interfaces,
};

static const TypeInfo unifi_udmpro_info = {
    .name = TYPE_UNIFI_UDMPRO,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(UnifiMachineState),
    .class_init = unifi_udmpro_class_init,
    .interfaces = arm_aarch64_machine_interfaces,
};

/* A 32-bit Cortex-A9 board: arm_machine_interfaces publishes it in both
 * qemu-system-arm and qemu-system-aarch64.  Declaring no interface at all
 * would publish it in neither. */
static const TypeInfo unifi_us24pro_info = {
    .name = TYPE_UNIFI_US24PRO,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(UnifiMachineState),
    .class_init = unifi_us24pro_class_init,
    .interfaces = arm_machine_interfaces,
};

static void unifi_machine_register_types(void)
{
    type_register_static(&unifi_mt7981_info);
    type_register_static(&unifi_udmpro_info);
    type_register_static(&unifi_us24pro_info);
}

type_init(unifi_machine_register_types)
