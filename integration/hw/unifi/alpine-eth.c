/* Thin PCI transport for the Rust Alpine Ethernet model. */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/msix.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "unifi-net.h"
#include "migration/vmstate.h"

#define TYPE_ALPINE_ETH "alpine-eth-pci"
OBJECT_DECLARE_SIMPLE_TYPE(AlpineEthState, ALPINE_ETH)
struct AlpineEthState {
    PCIDevice parent_obj;
    MemoryRegion bars[5];
    NICConf conf;
    NICState *nic;
    UnifiAlpine *model;
    UnifiNet *net;
    char *ethernet_mode;
    bool rx_gso;
    QEMUBH *fabric_bh;
    GQueue fabric_packets;
    GQueue rx_packets;
};
/* Board-local port wiring; packet semantics and queues are in Rust. */
static GList *alpine_ports;

static uint32_t alpine_dma_read(void *opaque, uint64_t at, uint8_t *buf, size_t len)
{
    return pci_dma_read(PCI_DEVICE(opaque), at, buf, len) == MEMTX_OK ? 0 : 1;
}
static uint32_t alpine_dma_write(void *opaque, uint64_t at, const uint8_t *buf, size_t len)
{
    return pci_dma_write(PCI_DEVICE(opaque), at, buf, len) == MEMTX_OK ? 0 : 1;
}
static UnifiHost alpine_host(AlpineEthState *s)
{
    return (UnifiHost) { .dma_read = alpine_dma_read, .dma_write = alpine_dma_write, .context = s };
}
static void alpine_irqs(AlpineEthState *s, uint32_t effects)
{
    for (unsigned i = 0; i < 31; i++) {
        if (effects & (1U << i)) { msix_notify(PCI_DEVICE(s), i); }
    }
    if (effects & (0xfU << 7)) {
        pci_set_irq(PCI_DEVICE(s), 1);
        pci_set_irq(PCI_DEVICE(s), 0);
    }
}
static uint32_t alpine_wire_rx(AlpineEthState *s, const uint8_t *buf, size_t len)
{
    UnifiHost host = alpine_host(s);
    return unifi_alpine_receive(s->model, &host, buf, len);
}
static void alpine_fabric_run(void *opaque)
{
    AlpineEthState *s = opaque;
    GBytes *packet;
    while ((packet = g_queue_pop_head(&s->fabric_packets))) {
        gsize len;
        const uint8_t *buf = g_bytes_get_data(packet, &len);
        for (GList *entry = alpine_ports; entry; entry = entry->next) {
            AlpineEthState *peer = entry->data;
            if (peer != s && unifi_alpine_can_receive(peer->model)) {
                alpine_irqs(peer, alpine_wire_rx(peer, buf, len));
            }
        }
        g_bytes_unref(packet);
    }
}
static void alpine_fabric_emit(void *opaque, const uint8_t *header,
                               const uint8_t *buf, size_t len)
{
    AlpineEthState *s = opaque;
    if (s->fabric_packets.length < 256) {
        g_queue_push_tail(&s->fabric_packets, g_bytes_new(buf, len));
        qemu_bh_schedule(s->fabric_bh);
    }
}
static void alpine_tx(void *opaque, uint32_t queue, const UnifiNetRequest *req,
                       const uint8_t *buf, size_t len)
{
    AlpineEthState *s = opaque;
    unifi_net_submit(s->net, queue, req, buf, len);
    /* Internal fabric peers require complete frames, independent of each
     * endpoint's host offload mode. Delivery stays deferred beyond the FFI. */
    if (g_list_length(alpine_ports) > 1) {
        unifi_net_prepare(req, buf, len, 0, alpine_fabric_emit, s);
    }
}
static void alpine_sent(NetClientState *nc, ssize_t len)
{
    AlpineEthState *s = qemu_get_nic_opaque(nc);
    unifi_net_sent(s->net);
}
static bool alpine_can_receive(NetClientState *nc)
{
    AlpineEthState *s = qemu_get_nic_opaque(nc);
    return s->model && g_queue_is_empty(&s->rx_packets) &&
           unifi_alpine_can_receive(s->model);
}
typedef struct AlpineRxContext {
    AlpineEthState *state;
} AlpineRxContext;

static void alpine_queue_wire(void *opaque, const uint8_t *buf, size_t len)
{
    AlpineRxContext *context = opaque;
    g_queue_push_tail(&context->state->rx_packets, g_bytes_new(buf, len));
}
static uint32_t alpine_drain_rx(AlpineEthState *s)
{
    uint32_t effects = 0;
    while (!g_queue_is_empty(&s->rx_packets) &&
           unifi_alpine_can_receive(s->model)) {
        GBytes *packet = g_queue_pop_head(&s->rx_packets);
        gsize len;
        const uint8_t *buf = g_bytes_get_data(packet, &len);
        effects |= alpine_wire_rx(s, buf, len);
        alpine_fabric_emit(s, NULL, buf, len);
        g_bytes_unref(packet);
    }
    return effects;
}
static ssize_t alpine_receive(NetClientState *nc, const uint8_t *buf, size_t len)
{
    AlpineEthState *s = qemu_get_nic_opaque(nc);
    AlpineRxContext context = { .state = s };
    unifi_net_decode(s->net, buf, len, alpine_queue_wire, &context);
    alpine_irqs(s, alpine_drain_rx(s));
    return len;
}
static NetClientInfo alpine_net_info = {
    .type = NET_CLIENT_DRIVER_NIC, .size = sizeof(NICState),
    .can_receive = alpine_can_receive, .receive = alpine_receive,
};
static uint64_t alpine_read(void *opaque, hwaddr at, unsigned size)
{
    AlpineEthState *s = opaque;
    return unifi_alpine_read(s->model, at);
}
static void alpine_write(void *opaque, hwaddr at, uint64_t value, unsigned size)
{
    AlpineEthState *s = opaque;
    UnifiHost host = alpine_host(s);
    uint32_t effects = unifi_alpine_write(s->model, &host, at, value, alpine_tx, s);
    if (at == 0x11038) { effects |= alpine_drain_rx(s); }
    alpine_irqs(s, effects);
    if (at == 0x11038) { qemu_flush_queued_packets(qemu_get_queue(s->nic)); }
}
static const MemoryRegionOps alpine_ops = {
    .read = alpine_read, .write = alpine_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};
static void alpine_reset(DeviceState *dev)
{
    AlpineEthState *s = ALPINE_ETH(dev);
    unifi_net_reset(s->net);
    if (s->fabric_bh) { qemu_bh_cancel(s->fabric_bh); }
    g_queue_clear_full(&s->fabric_packets, (GDestroyNotify)g_bytes_unref);
    g_queue_clear_full(&s->rx_packets, (GDestroyNotify)g_bytes_unref);
    unifi_alpine_reset(s->model);
}
static void alpine_config_write(PCIDevice *dev, uint32_t at, uint32_t val, int len)
{
    pci_default_write_config(dev, at, val, len);
    msix_write_config(dev, at, val, len);
    AlpineEthState *s = ALPINE_ETH(dev);
    if (s->nic && (pci_get_word(dev->config + PCI_COMMAND) & PCI_COMMAND_MASTER)) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}
static void alpine_realize(PCIDevice *dev, Error **errp)
{
    AlpineEthState *s = ALPINE_ETH(dev);
    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->model = unifi_alpine_new(s->conf.macaddr.a);
    s->fabric_bh = qemu_bh_new(alpine_fabric_run, s);
    dev->config[PCI_CACHE_LINE_SIZE] = 0x10;
    dev->config[PCI_INTERRUPT_PIN] = 1;
    for (unsigned i = 0; i < 5; i++) {
        if (i == 3) { continue; }
        memory_region_init_io(&s->bars[i], OBJECT(s), &alpine_ops, s,
                              "alpine-rust-registers", i == 1 ? 0x40 : 0x20000);
        pci_register_bar(dev, i, i == 1 ? PCI_BASE_ADDRESS_SPACE_IO : PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bars[i]);
    }
    if (msix_init_exclusive_bar(dev, 32, 3, errp) < 0) { return; }
    for (unsigned i = 0; i < 32; i++) { msix_vector_use(dev, i); }
    s->nic = qemu_new_nic(&alpine_net_info, &s->conf, TYPE_ALPINE_ETH,
                         DEVICE(dev)->id, &DEVICE(dev)->mem_reentrancy_guard, s);
    NetClientState *nc = qemu_get_queue(s->nic);
    const char *mode = s->ethernet_mode;
    /* Unused board slots retain their NIC and private empty hub to preserve
     * guest numbering. Only externally attached ports use host offloads. */
    if (mode && !strcmp(mode, "virtio-offload") &&
        (!nc->peer || nc->peer->info->type == NET_CLIENT_DRIVER_HUBPORT)) {
        mode = "software";
    }
    s->net = unifi_net_new(nc, mode, s->rx_gso, alpine_sent, errp);
    if (!s->net) { return; }
    unifi_net_add_properties(s->net, OBJECT(s));
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);
    alpine_ports = g_list_append(alpine_ports, s);
}
static void alpine_exit(PCIDevice *dev)
{
    AlpineEthState *s = ALPINE_ETH(dev);
    alpine_ports = g_list_remove(alpine_ports, s);
    alpine_reset(DEVICE(dev));
    if (s->fabric_bh) { qemu_bh_delete(s->fabric_bh); }
    unifi_net_free(s->net);
    qemu_del_nic(s->nic);
    unifi_alpine_free(s->model);
    msix_uninit_exclusive_bar(dev);
}
static const Property alpine_props[] = {
    DEFINE_NIC_PROPERTIES(AlpineEthState, conf),
    DEFINE_PROP_STRING("ethernet-mode", AlpineEthState, ethernet_mode),
    DEFINE_PROP_BOOL("rx-gso", AlpineEthState, rx_gso, false),
};
static const VMStateDescription alpine_vmstate = { .name = TYPE_ALPINE_ETH, .unmigratable = true };
static void alpine_class_init(ObjectClass *klass, const void *data)
{
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->vmsd = &alpine_vmstate;
    pc->realize = alpine_realize;
    pc->exit = alpine_exit;
    pc->config_write = alpine_config_write;
    pc->vendor_id = 0x1c36; pc->device_id = 1; pc->revision = 2;
    pc->class_id = PCI_CLASS_NETWORK_ETHERNET;
    device_class_set_legacy_reset(dc, alpine_reset);
    device_class_set_props(dc, alpine_props);
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}
static const TypeInfo alpine_type = {
    .name = TYPE_ALPINE_ETH, .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AlpineEthState), .class_init = alpine_class_init,
    .interfaces = (const InterfaceInfo[]) { { INTERFACE_CONVENTIONAL_PCI_DEVICE }, {} },
};
static void alpine_register(void) { type_register_static(&alpine_type); }
type_init(alpine_register)
