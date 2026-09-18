/* Generic Phase 1 sysbus adapter for the repository-owned board ABI. */
#include "qemu/osdep.h"
#include <fcntl.h>
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "chardev/char-fe.h"
#include "hw/sysbus.h"
#include "hw/irq.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "net/net.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/runstate.h"
#include "qapi/error.h"
#include "unifi_board.h"
#include "unifi-net.h"


#define TYPE_UNIFI_BOARD "unifi-board"
OBJECT_DECLARE_SIMPLE_TYPE(UnifiBoardState, UNIFI_BOARD)
typedef struct UnifiWindowRegion UnifiWindowRegion;
struct UnifiWindowRegion {
    UnifiBoardState *state;
    MemoryRegion mmio;
    uint64_t base;
};
typedef struct UnifiBoardState {
    SysBusDevice parent_obj;
    UnifiBoard *board;
    uint32_t kind;
    uint32_t nic_port;
    CharFrontend chr;
    CharFrontend frontpanel_chr;
    QEMUTimer *timer;
    QEMUTimer *wifi_timer;
    UnifiWifi *wifi;
    char *wifi_socket;
    UnifiNet *net;
    char *ethernet_mode;
    bool rx_gso;
    qemu_irq irqs[256];
    NICConf nic_conf;
    NICState *nic;
    char *eeprom_path;
    char *emmc_path;
    int emmc_fd;
    bool has_nic;
    bool rx_blocked;
    GQueue rx_packets;
    size_t window_count;
    UnifiWindowRegion windows[16];
} UnifiBoardState;

static ssize_t unifi_nic_receive(NetClientState *nc, const uint8_t *buf,
                                 size_t size);
static bool unifi_nic_can_receive(NetClientState *nc);

static NetClientInfo unifi_net_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = unifi_nic_can_receive,
    .receive = unifi_nic_receive,
};

static void unifi_packet_sent(NetClientState *nc, ssize_t len)
{
    UnifiBoardState *s = qemu_get_nic_opaque(nc);
    unifi_net_sent(s->net);
}

static void unifi_consume_events(UnifiBoardState *s,
                                 const UnifiExecutionResult *result)
{
    for (size_t i = 0; i < result->event_count; i++) {
        const UnifiEvent *event = &result->events[i];
        if (event->kind == 1) {
            if (event->line_or_port < ARRAY_SIZE(s->irqs)) {
                qemu_set_irq(s->irqs[event->line_or_port], event->value != 0);
            }
        } else if ((event->kind == 4 || event->kind == 5) && s->net &&
                   event->payload && event->line_or_port == s->nic_port) {
            unifi_net_submit(s->net, event->kind == 5 ? event->value : 0,
                             &event->net_request, event->payload, event->payload_len);
        } else if (event->kind == 2 && event->value <= UINT8_MAX &&
            qemu_chr_fe_backend_connected(&s->chr)) {
            uint8_t byte = (uint8_t)event->value;
            qemu_chr_fe_write_all(&s->chr, &byte, sizeof(byte));
        } else if (event->kind == 3) {
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
        } else if (event->kind == 6 && event->payload && event->payload_len &&
                   qemu_chr_fe_backend_connected(&s->frontpanel_chr)) {
            qemu_chr_fe_write_all(&s->frontpanel_chr, event->payload,
                                  event->payload_len);
        }
    }
}

static uint32_t unifi_dma_read(void *context, uint64_t address,
                               uint8_t *buffer, size_t length);
static uint32_t unifi_dma_write(void *context, uint64_t address,
                                const uint8_t *buffer, size_t length);
static void unifi_arm_timer(UnifiBoardState *s,
                            const UnifiExecutionResult *result);

typedef struct UnifiRxContext {
    UnifiBoardState *state;
} UnifiRxContext;

static void unifi_queue_wire(void *opaque, const uint8_t *buf, size_t size)
{
    UnifiRxContext *context = opaque;
    g_queue_push_tail(&context->state->rx_packets, g_bytes_new(buf, size));
}

static void unifi_arm_timer(UnifiBoardState *s,
                            const UnifiExecutionResult *result)
{
    if (result->next_deadline_ns == 0) {
        timer_del(s->timer);
    } else {
        timer_mod_ns(s->timer, result->next_deadline_ns);
    }
}

static void unifi_timer_cb(void *opaque)
{
    UnifiBoardState *s = opaque;
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiExecutionResult result = { 0 };

    unifi_advance_to(s->board, &host, &result);
    unifi_consume_events(s, &result);
    unifi_arm_timer(s, &result);
}

static void unifi_wifi_timer_cb(void *opaque)
{
    UnifiBoardState *s = opaque;
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiExecutionResult result = { 0 };
    bool alive = unifi_wifi_poll(s->wifi, s->board, &host, &result);
    unifi_consume_events(s, &result);
    unifi_arm_timer(s, &result);
    if (alive) {
        timer_mod_ns(s->wifi_timer,
                     qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + 10000000);
    } else {
        unifi_wifi_free(s->wifi);
        s->wifi = NULL;
    }
}

static uint32_t unifi_dma_read(void *context, uint64_t address,
                               uint8_t *buffer, size_t length)
{
    (void)context;
    /* Model-owned DMA must not re-enter the same Rust board through MMIO
     * while its mutable borrow is live. Only guest memory is a DMA target. */
    return address_space_read(&address_space_memory, address,
                              (MemTxAttrs) { .memory = true }, buffer, length)
        == MEMTX_OK ? 0 : 1;
}

static void unifi_drain_rx(UnifiBoardState *s, UnifiHost *host)
{
    while (!g_queue_is_empty(&s->rx_packets) &&
           unifi_net_can_receive(s->board, s->nic_port)) {
        GBytes *packet = g_queue_pop_head(&s->rx_packets);
        gsize size;
        const uint8_t *buf = g_bytes_get_data(packet, &size);
        UnifiExecutionResult result = { 0 };
        unifi_net_rx(s->board, host, s->nic_port, buf, size, &result);
        unifi_consume_events(s, &result);
        unifi_arm_timer(s, &result);
        g_bytes_unref(packet);
    }
}

static bool unifi_nic_can_receive(NetClientState *nc)
{
    UnifiBoardState *s = qemu_get_nic_opaque(nc);
    bool ready = s->board && g_queue_is_empty(&s->rx_packets) &&
                 unifi_net_can_receive(s->board, s->nic_port);
    s->rx_blocked = !ready;
    return ready;
}

static ssize_t unifi_nic_receive(NetClientState *nc, const uint8_t *buf,
                                 size_t size)
{
    UnifiBoardState *s = qemu_get_nic_opaque(nc);
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiRxContext context = { .state = s };
    unifi_net_decode(s->net, buf, size, unifi_queue_wire, &context);
    unifi_drain_rx(s, &host);
    return (ssize_t)size;
}

static uint32_t unifi_dma_write(void *context, uint64_t address,
                                const uint8_t *buffer, size_t length)
{
    (void)context;
    return address_space_write(&address_space_memory, address,
                               (MemTxAttrs) { .memory = true }, buffer, length)
        == MEMTX_OK ? 0 : 1;
}

static void unifi_reset(DeviceState *dev)
{
    UnifiBoardState *s = UNIFI_BOARD(dev);
    unifi_net_reset(s->net);
    g_queue_clear_full(&s->rx_packets, (GDestroyNotify)g_bytes_unref);
    s->rx_blocked = false;
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiExecutionResult result = { 0 };

    unifi_board_reset(s->board, &host, &result);
    unifi_consume_events(s, &result);
    unifi_arm_timer(s, &result);
}

static MemTxResult unifi_read(void *opaque, hwaddr offset, uint64_t *value,
                              unsigned size, MemTxAttrs attrs)
{
    UnifiWindowRegion *window = opaque;
    (void)attrs;
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiExecutionResult result = { 0 };
    unifi_mmio_read(window->state->board, &host, window->base + offset, size,
                    &result);
    unifi_consume_events(window->state, &result);
    unifi_arm_timer(window->state, &result);
    /* The legacy MT7981 adapter holds SPI completion IRQ until Linux reads
     * SPI_IRQ. This is level-triggered, not a one-shot pulse. */
    if (window->base + offset == 0x1100901c) {
        qemu_irq_lower(window->state->irqs[142]);
    }
    *value = result.value;
    return result.status == UNIFI_OK
        ? MEMTX_OK
        : result.status == UNIFI_UNMAPPED ? MEMTX_DECODE_ERROR : MEMTX_ERROR;
}
/* Persist guest writes to the eMMC backing file.  The board model keeps the
 * card in memory, so without this every configuration the AP stores - its
 * `cfg` partition, the SSH host keys under /etc/persistent - is discarded at
 * power off and the device comes back factory fresh on the next boot. */
#define UNIFI_FLUSH_BLOCKS 32
static void unifi_flush_emmc(UnifiBoardState *s)
{
    if (s->emmc_fd < 0 || unifi_board_take_dirty_blocks(s->board, 2, NULL, NULL, 0) == 0) {
        return;
    }
    uint64_t blocks[UNIFI_FLUSH_BLOCKS];
    uint8_t data[UNIFI_FLUSH_BLOCKS * 512];
    size_t taken;
    while ((taken = unifi_board_take_dirty_blocks(s->board, 2, blocks, data,
                                                  UNIFI_FLUSH_BLOCKS)) != 0) {
        for (size_t i = 0; i < taken; i++) {
            off_t at = (off_t)blocks[i] * 512;
            if (pwrite(s->emmc_fd, &data[i * 512], 512, at) != 512) {
                error_report("unifi-board: eMMC write-back failed at block %"
                             PRIu64, blocks[i]);
                close(s->emmc_fd);
                s->emmc_fd = -1;
                return;
            }
        }
        if (taken < UNIFI_FLUSH_BLOCKS) {
            break;
        }
    }
}

static MemTxResult unifi_write(void *opaque, hwaddr offset, uint64_t value,
                               unsigned size, MemTxAttrs attrs)
{
    UnifiWindowRegion *window = opaque;
    UnifiBoardState *s = window->state;
    (void)attrs;
    UnifiHost host = {
        .now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
        .dma_read = unifi_dma_read,
        .dma_write = unifi_dma_write,
    };
    UnifiExecutionResult result = { 0 };
    unifi_mmio_write(s->board, &host, window->base + offset, size, value,
                     &result);
    unifi_consume_events(s, &result);
    unifi_arm_timer(s, &result);
    if (s->nic) {
        unifi_drain_rx(s, &host);
        if (s->rx_blocked && g_queue_is_empty(&s->rx_packets) &&
            unifi_net_can_receive(s->board, s->nic_port)) {
            s->rx_blocked = false;
            qemu_flush_queued_packets(qemu_get_queue(s->nic));
        }
    }
    /* Match the old adapter: ACT raises a level IRQ which the SPI status
     * read clears. Rust owns the transfer and result data. */
    if (result.status == UNIFI_OK && window->base + offset == 0x11009018
        && (value & 1) != 0) {
        qemu_irq_raise(s->irqs[142]);
    }
    unifi_flush_emmc(s);
    return result.status == UNIFI_OK
        ? MEMTX_OK
        : result.status == UNIFI_UNMAPPED ? MEMTX_DECODE_ERROR : MEMTX_ERROR;
}
static const MemoryRegionOps unifi_ops = {
    .read_with_attrs = unifi_read, .write_with_attrs = unifi_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    /* The legacy C adapters accepted the register widths used by the
     * vendor kernels.  Keep that compatibility at the QEMU boundary; the
     * Rust machines retain 32-bit register semantics internally. */
    .valid = { .min_access_size = 1, .max_access_size = 8 },
};
static void unifi_realize(DeviceState *dev, Error **errp)
{
    UnifiBoardState *s = UNIFI_BOARD(dev);
    UnifiWindow metadata[16];
    if (s->nic_port != 0 && (s->kind != 3 || s->nic_port != 1)) {
        error_setg(errp, "nic-port 1 is the US24PRO CMICd endpoint; other boards use 0");
        return;
    }
    s->emmc_fd = -1;
    s->board = unifi_board_new(s->kind, NULL);
    if (!s->board) { error_setg(errp, "invalid UniFi board kind %u", s->kind); return; }
    s->window_count = unifi_board_windows(s->board, metadata, ARRAY_SIZE(metadata));
    if (s->window_count > ARRAY_SIZE(s->windows)) {
        error_setg(errp, "UniFi board exposes too many MMIO windows");
        unifi_board_free(s->board);
        s->board = NULL;
        return;
    }
    if (s->wifi_socket != NULL) {
        if (s->kind != 1 || (s->wifi = unifi_wifi_new(s->wifi_socket)) == NULL) {
            error_setg(errp, "cannot connect MT7981 hwsim socket %s", s->wifi_socket);
            unifi_board_free(s->board);
            s->board = NULL;
            return;
        }
        s->wifi_timer = timer_new_ns(QEMU_CLOCK_REALTIME, unifi_wifi_timer_cb, s);
        timer_mod_ns(s->wifi_timer, qemu_clock_get_ns(QEMU_CLOCK_REALTIME));
    }
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, unifi_timer_cb, s);

    for (size_t i = 0; i < ARRAY_SIZE(s->irqs); i++) {
        sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irqs[i]);
    }
    if (s->has_nic) {
        qemu_macaddr_default_if_unset(&s->nic_conf.macaddr);
        s->nic = qemu_new_nic(&unifi_net_info, &s->nic_conf,
                              object_get_typename(OBJECT(dev)), dev->id,
                              &dev->mem_reentrancy_guard, s);
        s->net = unifi_net_new(qemu_get_queue(s->nic), s->ethernet_mode,
                               s->rx_gso, unifi_packet_sent, errp);
        if (!s->net) { return; }
        unifi_net_add_properties(s->net, OBJECT(s));
        if (!unifi_board_set_host_offload(s->board, unifi_net_accelerated(s->net))) {
            error_setg(errp, "host offload is unavailable for this board or capture session");
            return;
        }
        qemu_format_nic_info_str(qemu_get_queue(s->nic), s->nic_conf.macaddr.a);
    }
    const char *paths[] = { s->eeprom_path, s->emmc_path };
    const uint32_t kinds[] = { 1, 2 };
    for (size_t i = 0; i < ARRAY_SIZE(paths); i++) {
        if (paths[i] == NULL) {
            continue;
        }
        /* An eMMC path doubles as the write-back target, so an absent or
         * empty file is not an error: keep the board's seeded card, mark it
         * pending, and let the first flush populate the new image. */
        if (kinds[i] == 2) {
            s->emmc_fd = open(paths[i], O_RDWR | O_CREAT, 0644);
            if (s->emmc_fd < 0) {
                error_setg_errno(errp, errno, "unable to open eMMC image %s",
                                 paths[i]);
                return;
            }
            if (lseek(s->emmc_fd, 0, SEEK_END) <= 0) {
                unifi_board_mark_image_dirty(s->board, 2);
                unifi_flush_emmc(s);
                continue;
            }
        }
        gchar *contents = NULL;
        gsize length = 0;
        GError *file_error = NULL;
        bool loaded = g_file_get_contents(paths[i], &contents, &length,
                                          &file_error);
        if (!loaded || unifi_load_image(s->board, kinds[i],
                                        (const uint8_t *)contents, length) !=
                           UNIFI_OK) {
            g_free(contents);
            error_setg(errp, "failed to load UniFi image %s%s%s", paths[i],
                       file_error != NULL ? ": " : "",
                       file_error != NULL ? file_error->message : "invalid image");
            g_clear_error(&file_error);
            return;
        }
        g_clear_error(&file_error);
        g_free(contents);
    }
    for (size_t i = 0; i < s->window_count; i++) {
        s->windows[i].state = s;
        s->windows[i].base = metadata[i].base;
        memory_region_init_io(&s->windows[i].mmio, OBJECT(s), &unifi_ops,
                              &s->windows[i], "unifi-board-window",
                              metadata[i].size);
        memory_region_add_subregion_overlap(get_system_memory(),
                                            metadata[i].base,
                                            &s->windows[i].mmio,
                                            metadata[i].priority);
    }
}
static void unifi_unrealize(DeviceState *dev)
{
    UnifiBoardState *s = UNIFI_BOARD(dev);
    if (s->wifi_timer != NULL) {
        timer_del(s->wifi_timer);
        timer_free(s->wifi_timer);
        s->wifi_timer = NULL;
    }
    unifi_wifi_free(s->wifi);
    s->wifi = NULL;
    g_free(s->wifi_socket);
    s->wifi_socket = NULL;
    timer_del(s->timer);
    timer_free(s->timer);
    s->timer = NULL;
    unifi_net_free(s->net);
    s->net = NULL;
    qemu_del_nic(s->nic);
    s->nic = NULL;
    g_free(s->eeprom_path);
    g_free(s->emmc_path);
    s->eeprom_path = NULL;
    s->emmc_path = NULL;
    for (size_t i = 0; i < s->window_count; i++) {
        memory_region_del_subregion(get_system_memory(), &s->windows[i].mmio);
    }
    unifi_board_free(s->board);
    s->board = NULL;
}
static const Property unifi_props[] = {
    DEFINE_PROP_UINT32("kind", UnifiBoardState, kind, 1),
    DEFINE_PROP_UINT32("nic-port", UnifiBoardState, nic_port, 0),
    DEFINE_PROP_CHR("chardev", UnifiBoardState, chr),
    DEFINE_PROP_CHR("frontpanel", UnifiBoardState, frontpanel_chr),
    DEFINE_NIC_PROPERTIES(UnifiBoardState, nic_conf),
    DEFINE_PROP_STRING("eeprom", UnifiBoardState, eeprom_path),
    DEFINE_PROP_STRING("emmc", UnifiBoardState, emmc_path),
    DEFINE_PROP_STRING("ethernet-mode", UnifiBoardState, ethernet_mode),
    DEFINE_PROP_BOOL("rx-gso", UnifiBoardState, rx_gso, false),
    DEFINE_PROP_STRING("wifi-socket", UnifiBoardState, wifi_socket),
    DEFINE_PROP_BOOL("has-nic", UnifiBoardState, has_nic, true),
};
static void unifi_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = unifi_realize; dc->unrealize = unifi_unrealize;
    device_class_set_legacy_reset(dc, unifi_reset);
    device_class_set_props(dc, unifi_props);
}
static const TypeInfo unifi_info = {
    .name = TYPE_UNIFI_BOARD, .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(UnifiBoardState), .class_init = unifi_class_init,
};
static void unifi_register_types(void)
{
    type_register_static(&unifi_info);
}
type_init(unifi_register_types)
