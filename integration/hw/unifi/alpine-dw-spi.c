#include "qemu/osdep.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/sysbus.h"
#include "hw/ssi/ssi.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "alpine-dw-spi.h"
#include "system/block-backend-global-state.h"

#define DW_CTRLR0 0x00
#define DW_CTRLR1 0x04
#define DW_SSIENR 0x08
#define DW_SER    0x10
#define DW_BAUDR  0x14
#define DW_TXFTLR 0x18
#define DW_RXFTLR 0x1c
#define DW_TXFLR  0x20
#define DW_RXFLR  0x24
#define DW_SR     0x28
#define DW_IMR    0x2c
#define DW_ISR    0x30
#define DW_RISR   0x34
#define DW_TXOICR 0x38
#define DW_RXOICR 0x3c
#define DW_RXUICR 0x40
#define DW_ICR    0x48
#define DW_DR     0x60

#define SR_BUSY   (1U << 0)
#define SR_TFNF   (1U << 1)
#define SR_TFE    (1U << 2)
#define SR_RFNE   (1U << 3)
#define SR_RFF    (1U << 4)
#define INT_TXEI  (1U << 0)
#define INT_TXOI  (1U << 1)
#define INT_RXUI  (1U << 2)
#define INT_RXOI  (1U << 3)
#define INT_RXFI  (1U << 4)

/* The Alpine board-profile record `ubnt-tools id` validates, at mtd0 + 0x8000.
 * mtd0 is the `u-boot` partition (0x0-0x1c0000 in the vendor DT), so this is
 * flash offset 0x8000.  unifi_create_spi() seeds it, but the guest writes a
 * small counter structure straight over it during boot, after which
 * `ubnt-tools id` falls back to sysid 0 / ARMv8 and unifi-core refuses to
 * start with `Unsupported console model`.  On real hardware this window sits
 * inside the U-Boot image and nothing rewrites it in normal operation. */
#define BOARD_RECORD_OFFSET 0x8000
#define BOARD_RECORD_SIZE   0x71

/* SPI NOR opcodes the controller has to understand to police the window. */
#define SPI_PAGE_PROGRAM    0x02
#define SPI_ERASE_4K        0x20
#define SPI_ERASE_32K       0x52
#define SPI_ERASE_64K       0xd8
#define SPI_ERASE_CHIP_60   0x60
#define SPI_ERASE_CHIP_C7   0xc7

static bool alpine_dw_spi_has_address(uint8_t opcode)
{
    switch (opcode) {
    case SPI_PAGE_PROGRAM:
    case SPI_ERASE_4K:
    case SPI_ERASE_32K:
    case SPI_ERASE_64K:
        return true;
    default:
        return false;
    }
}

static uint32_t alpine_dw_spi_erase_size(uint8_t opcode)
{
    switch (opcode) {
    case SPI_ERASE_4K:
        return 4 * 1024;
    case SPI_ERASE_32K:
        return 32 * 1024;
    case SPI_ERASE_64K:
        return 64 * 1024;
    default:
        return 0;
    }
}

static bool alpine_dw_spi_hits_record(uint32_t start, uint32_t length)
{
    return start < BOARD_RECORD_OFFSET + BOARD_RECORD_SIZE &&
           BOARD_RECORD_OFFSET < start + length;
}

static void alpine_dw_spi_irq(AlpineDWSPIState *s);

static bool alpine_dw_spi_debug_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("UDM_SPI_DEBUG");
        enabled = value && (!strcmp(value, "1") || !strcmp(value, "yes"));
    }
    return enabled;
}

#define SPI_DEBUG(s, fmt, ...) \
    do { \
        if (alpine_dw_spi_debug_enabled()) { \
            fprintf(stderr, "[udm-spi] txn=%" PRIu64 " " fmt "\n", \
                    (s)->transaction_id, ##__VA_ARGS__); \
        } \
    } while (0)

/* MMIO callbacks run under the BQL, as do the SSI flash callbacks. IRQs
 * describe controller state, not elapsed host scheduling time. In particular,
 * Linux configures IMR and its transfer handler while SSIENR is clear. */
static uint32_t alpine_dw_spi_raw_irq(AlpineDWSPIState *s)
{
    uint32_t status = INT_TXEI | s->errors;

    if (!(s->regs[DW_SSIENR / 4] & 1)) {
        return 0;
    }
    if (s->rx_count > s->regs[DW_RXFTLR / 4]) {
        status |= INT_RXFI;
    }
    return status;
}

static void alpine_dw_spi_irq(AlpineDWSPIState *s)
{
    uint32_t raw = alpine_dw_spi_raw_irq(s);
    s->regs[DW_RISR / 4] = raw;
    s->regs[DW_ISR / 4] = raw & s->regs[DW_IMR / 4];
    qemu_set_irq(s->irq, s->regs[DW_ISR / 4] != 0);
}

static void alpine_dw_spi_select(AlpineDWSPIState *s)
{
    /* SSI_GPIO_CS is active-low for ordinary SPI peripherals. */
    /* The Alpine driver toggles SSIENR between FIFO bursts while retaining
     * SER; preserve the peripheral transaction until SER is cleared. */
    qemu_set_irq(s->cs, !(s->regs[DW_SER / 4] & 1));
}

static uint64_t alpine_dw_spi_read(void *opaque, hwaddr addr, unsigned size)
{
    AlpineDWSPIState *s = opaque;
    uint32_t value = 0;

    switch (addr) {
    case DW_TXFLR:
        value = 0;
        break;
    case DW_RXFLR:
        value = s->rx_count;
        break;
    case DW_SR:
        value = SR_TFNF | SR_TFE;
        /* Transfers complete synchronously; selected CS alone is not BUSY. */
        if (s->rx_count == ARRAY_SIZE(s->rx)) {
            value |= SR_RFF;
        }
        if (s->rx_count) {
            value |= SR_RFNE;
        }
        break;
    case DW_DR:
        if (s->rx_count) {
            value = s->rx[0];
            s->rx_count--;
            memmove(s->rx, s->rx + 1, s->rx_count);
        } else {
            s->errors |= INT_RXUI;
        }
        alpine_dw_spi_irq(s);
        break;
    case DW_ICR:
        value = s->errors != 0;
        s->errors = 0;
        alpine_dw_spi_irq(s);
        break;
    case DW_TXOICR:
    case DW_RXOICR:
    case DW_RXUICR:
        {
            uint32_t bit = addr == DW_TXOICR ? INT_TXOI :
                           addr == DW_RXOICR ? INT_RXOI : INT_RXUI;
            value = (s->errors & bit) != 0;
            s->errors &= ~bit;
            alpine_dw_spi_irq(s);
            break;
        }
    case DW_ISR:
    case DW_RISR:
        value = addr == DW_RISR ? alpine_dw_spi_raw_irq(s) :
                alpine_dw_spi_raw_irq(s) & s->regs[DW_IMR / 4];
        SPI_DEBUG(s, "read %s=0x%08x rx=%u tx=%u", addr == DW_ISR ? "isr" : "risr",
                  value, s->rx_count, s->tx_count);
        break;
    default:
        if (addr < sizeof(s->regs)) {
            value = s->regs[addr / 4];
        }
        break;
    }
    return value;
}

static void alpine_dw_spi_write(void *opaque, hwaddr addr,
                                uint64_t value64, unsigned size)
{
    AlpineDWSPIState *s = opaque;
    uint32_t value = value64;

    switch (addr) {
    case DW_SSIENR:
        s->regs[addr / 4] = value & 1;
        if (!(value & 1)) {
            s->rx_count = 0;
            s->errors = 0;
        }
        SPI_DEBUG(s, "ssienr=0x%08x", value);
        alpine_dw_spi_select(s);
        alpine_dw_spi_irq(s);
        break;
    case DW_SER:
        {
        uint32_t old_ser = s->regs[addr / 4];
        s->regs[addr / 4] = value;
        if ((value & 1) && !(old_ser & 1)) {
            s->transaction_id++;
            s->tx_count = 0;
            s->cmd_index = 0;
            s->cmd_opcode = 0;
            s->cmd_addr = 0;
            s->cmd_vetoed = false;
            SPI_DEBUG(s, "begin ser=0x%08x", value);
        }
        if (!(value & 1)) {
            s->rx_count = 0;
            SPI_DEBUG(s, "end ser=0x%08x rx=%u tx=%u", value,
                      s->rx_count, s->tx_count);
        }
        alpine_dw_spi_select(s);
        alpine_dw_spi_irq(s);
        break;
        }
    case DW_IMR:
        s->regs[addr / 4] = value & 0x3f;
        alpine_dw_spi_irq(s);
        break;
    case DW_TXFTLR:
    case DW_RXFTLR:
        s->regs[addr / 4] = MIN(value, ARRAY_SIZE(s->rx) - 1);
        alpine_dw_spi_irq(s);
        break;
    case DW_DR:
        if (s->regs[DW_SSIENR / 4] && (s->regs[DW_SER / 4] & 1)) {
            uint8_t byte = value;

            /* Decode the command as it goes out: byte 0 is the opcode and,
             * for programs and erases, bytes 1-3 are a big-endian 24-bit
             * address.  Page-program data starts at byte 4. */
            if (s->cmd_index == 0) {
                s->cmd_opcode = byte;
                s->cmd_addr = 0;
            } else if (s->cmd_index <= 3 &&
                       alpine_dw_spi_has_address(s->cmd_opcode)) {
                s->cmd_addr = (s->cmd_addr << 8) | byte;
            } else if (s->cmd_index == 4 && s->trace_flash_writes &&
                       s->cmd_opcode == SPI_PAGE_PROGRAM) {
                qemu_log("alpine-dw-spi: page program at 0x%06x\n",
                         s->cmd_addr);
            }
            if (s->cmd_index == 3) {
                uint32_t erase = alpine_dw_spi_erase_size(s->cmd_opcode);

                if (erase) {
                    /* This byte was already folded into cmd_addr by the
                     * accumulator above, so the address is complete here.
                     * Shifting it in again produced addresses 256x too large,
                     * which silently disabled the veto below. */
                    uint32_t full = s->cmd_addr;
                    uint32_t base = full & ~(erase - 1);

                    if (s->trace_flash_writes) {
                        qemu_log("alpine-dw-spi: erase 0x%02x at 0x%06x "
                                 "(sector 0x%06x+0x%x)\n", s->cmd_opcode,
                                 full, base, erase);
                    }
                    if (s->protect_board_record &&
                        alpine_dw_spi_hits_record(base, erase)) {
                        /* m25p80 erases as soon as the third address byte
                         * arrives, not on CS deassert, so the only way to
                         * veto it is to withhold that byte.  Dropping CS
                         * resets the flash's command state machine, leaving
                         * the erase unissued.  Rewriting the address byte
                         * instead would redirect the erase to some other
                         * sector, which is far worse than allowing it. */
                        qemu_log("alpine-dw-spi: refusing erase of sector "
                                 "0x%06x over the board record at 0x%06x\n",
                                 base, BOARD_RECORD_OFFSET);
                        s->protected_writes++;
                        s->cmd_vetoed = true;
                        qemu_set_irq(s->cs, 1);
                    }
                }
            }
            /* A NOR program can only clear bits, so substituting 0xff for a
             * data byte is exactly a no-op on the cell.  That vetoes a write
             * without having to abort a transaction already in flight. */
            if (s->protect_board_record &&
                s->cmd_opcode == SPI_PAGE_PROGRAM && s->cmd_index >= 4) {
                uint32_t offset = s->cmd_addr + (s->cmd_index - 4);

                if (alpine_dw_spi_hits_record(offset, 1)) {
                    if (!s->protected_writes) {
                        qemu_log("alpine-dw-spi: refusing program over the "
                                 "board record at 0x%06x\n", offset);
                    }
                    s->protected_writes++;
                    byte = 0xff;
                }
            }
            s->cmd_index++;
            s->tx_count++;
            /* A vetoed command is dead for the rest of the transaction: the
             * flash has been deselected and must not see its tail. */
            uint8_t received = s->cmd_vetoed ? 0xff : ssi_transfer(s->spi, byte);
            if (s->rx_count < ARRAY_SIZE(s->rx)) {
                s->rx[s->rx_count++] = received;
            } else {
                s->errors |= INT_RXOI;
            }
            if (s->tx_count <= 8 || (s->tx_count % 1024) == 0) {
                SPI_DEBUG(s, "dr write=0x%08x rx=%u tx=%u", value,
                          s->rx_count, s->tx_count);
            }
            alpine_dw_spi_irq(s);
        }
        break;
    case DW_ICR:
        /* RXFI is a level condition in the DesignWare block and remains
         * asserted until the FIFO is drained; ICR only clears latched
         * error conditions. */
        alpine_dw_spi_irq(s);
        break;
    case DW_ISR:
    case DW_RISR:
    case DW_TXFLR:
    case DW_RXFLR:
    case DW_SR:
        break;
    default:
        if (addr < sizeof(s->regs)) {
            s->regs[addr / 4] = value;
            if (addr == DW_CTRLR0 || addr == DW_CTRLR1 ||
                addr == DW_TXFTLR || addr == DW_RXFTLR) {
                SPI_DEBUG(s, "write 0x%02x=0x%08x", (unsigned)addr, value);
            }
        }
        break;
    }
}

static const MemoryRegionOps alpine_dw_spi_ops = {
    .read = alpine_dw_spi_read,
    .write = alpine_dw_spi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
};

static const Property alpine_dw_spi_properties[] = {
    DEFINE_PROP_STRING("drive-id", AlpineDWSPIState, drive_id),
    DEFINE_PROP_BOOL("protect-board-record", AlpineDWSPIState,
                     protect_board_record, true),
    /* Off by default: this logs every page program, which for a config
     * partition write is hundreds of lines per boot into QEMU's -D log. */
    DEFINE_PROP_BOOL("trace-flash-writes", AlpineDWSPIState,
                     trace_flash_writes, false),
};

static void alpine_dw_spi_reset(DeviceState *dev)
{
    AlpineDWSPIState *s = ALPINE_DW_SPI(dev);
    memset(s->regs, 0, sizeof(s->regs));
    s->rx_count = 0;
    s->tx_count = 0;
    s->transaction_id = 0;
    s->errors = 0;
    qemu_set_irq(s->cs, 1);
    qemu_set_irq(s->irq, 0);
}

static void alpine_dw_spi_realize(DeviceState *dev, Error **errp)
{
    AlpineDWSPIState *s = ALPINE_DW_SPI(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    DeviceState *flash;

    s->spi = ssi_create_bus(dev, "spi");
    sysbus_init_irq(sbd, &s->irq);
    qdev_init_gpio_out_named(dev, &s->cs, "cs", 1);
    memory_region_init_io(&s->mmio, OBJECT(dev), &alpine_dw_spi_ops, s,
                          TYPE_ALPINE_DW_SPI, 0x1000);
    sysbus_init_mmio(sbd, &s->mmio);

    flash = qdev_new("w25q64");
    qdev_prop_set_uint8(flash, "cs", 0);
    if (s->drive_id) {
        BlockBackend *blk = blk_by_name(s->drive_id);
        if (!blk) {
            error_setg(errp, "SPI flash drive '%s' was not found", s->drive_id);
            return;
        }
        qdev_prop_set_drive(flash, "drive", blk);
    }
    if (!ssi_realize_and_unref(flash, s->spi, errp)) {
        return;
    }
    qdev_connect_gpio_out_named(dev, "cs", 0,
                                qdev_get_gpio_in_named(flash,
                                                       SSI_GPIO_CS, 0));
}

static void alpine_dw_spi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = alpine_dw_spi_realize;
    device_class_set_props(dc, alpine_dw_spi_properties);
    device_class_set_legacy_reset(dc, alpine_dw_spi_reset);
}

static const TypeInfo alpine_dw_spi_info = {
    .name = TYPE_ALPINE_DW_SPI,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AlpineDWSPIState),
    .class_init = alpine_dw_spi_class_init,
};

static void alpine_dw_spi_register_types(void)
{
    type_register_static(&alpine_dw_spi_info);
}

type_init(alpine_dw_spi_register_types)
