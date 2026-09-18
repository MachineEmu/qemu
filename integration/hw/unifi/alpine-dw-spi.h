#ifndef HW_SSI_ALPINE_DW_SPI_H
#define HW_SSI_ALPINE_DW_SPI_H

#include "hw/sysbus.h"
#include "hw/ssi/ssi.h"

#define TYPE_ALPINE_DW_SPI "alpine.dw-spi"
OBJECT_DECLARE_SIMPLE_TYPE(AlpineDWSPIState, ALPINE_DW_SPI)

typedef struct AlpineDWSPIState {
    SysBusDevice parent_obj;
    MemoryRegion mmio;
    qemu_irq irq;
    qemu_irq cs;
    SSIBus *spi;
    uint32_t regs[0x100 / 4];
    /* DW SSI FIFO depth is probed through the threshold registers. */
    uint8_t rx[64];
    uint32_t rx_count;
    uint32_t tx_count;
    uint64_t transaction_id;
    uint32_t errors;
    char *drive_id;
    /* Decoded state for the SPI command currently on the wire.  The
     * controller sees every opcode, address and data byte, which is the only
     * place we can watch or veto flash writes: the flash itself is QEMU's
     * stock w25q64. */
    uint8_t cmd_opcode;
    uint32_t cmd_addr;
    uint32_t cmd_index;
    /* Refuse programs and erases that touch the Alpine board record at
     * mtd0 + 0x8000.  See docs/udm-pro/qemu-emulation.md. */
    bool protect_board_record;
    bool trace_flash_writes;
    uint32_t protected_writes;
    bool cmd_vetoed;
} AlpineDWSPIState;

#endif
