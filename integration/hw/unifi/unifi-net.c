/* Board-independent packet transport. Device adapters retain DMA/IRQ policy. */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/error-report.h"
#include "unifi-net.h"

#define NET_QUEUES 64
#define QUEUE_PACKETS 256
#define QUEUE_BYTES (4 * 1024 * 1024)
struct UnifiNet {
    NetClientState *nc;
    Object *owner;
    NetPacketSent *sent;
    QEMUBH *bh;
    GQueue queues[NET_QUEUES];
    size_t bytes[NET_QUEUES];
    unsigned next;
    bool accelerated, pending;
    UnifiNetStats stats;
};

static void net_run(void *opaque)
{
    UnifiNet *n = opaque;
    for (unsigned budget = 0; budget < 64 && !n->pending; budget++) {
        GBytes *packet = NULL;
        unsigned q;
        for (unsigned i = 0; i < NET_QUEUES; i++) {
            q = n->next;
            n->next = (n->next + 1) % NET_QUEUES;
            packet = g_queue_pop_head(&n->queues[q]);
            if (packet) { break; }
        }
        if (!packet) { return; }
        gsize len;
        const uint8_t *buf = g_bytes_get_data(packet, &len);
        n->bytes[q] -= len;
        /* QEMU owns a copy if the peer defers this send. Do not submit another
         * until its callback, keeping the QEMU-side pending queue bounded. */
        ssize_t rc = qemu_send_packet_async(n->nc, buf, len, n->sent);
        n->pending = rc == 0;
        if (rc < 0) { n->stats.dropped++; }
        g_bytes_unref(packet);
    }
    if (!n->pending) { qemu_bh_schedule(n->bh); }
}

UnifiNet *unifi_net_new(NetClientState *nc, const char *mode, bool rx_gso,
                        NetPacketSent *sent, Error **errp)
{
    bool accelerated = mode && !strcmp(mode, "virtio-offload");
    if (mode && strcmp(mode, "software") && !accelerated) {
        error_setg(errp, "ethernet-mode must be software or virtio-offload");
        return NULL;
    }
    if (accelerated && (!nc->peer || nc->peer->info->type != NET_CLIENT_DRIVER_TAP ||
                        !qemu_has_vnet_hdr(nc->peer) ||
                        !qemu_has_vnet_hdr_len(nc->peer, 10))) {
        error_setg(errp, "virtio-offload requires a TAP peer with a 10-byte vnet header");
        return NULL;
    }
    UnifiNet *n = g_new0(UnifiNet, 1);
    n->nc = nc;
    n->sent = sent;
    n->accelerated = accelerated;
    n->bh = qemu_bh_new(net_run, n);
    if (accelerated) {
        /* TAP may batch TCP RX, but the shared decoder segments each batch
         * before the unchanged guest NIC receives ordinary wire frames. */
        NetOffloads offloads = { 0 };
        if (rx_gso) {
            offloads = (NetOffloads) { .csum = true, .tso4 = true,
                                      .tso6 = true, .ecn = true };
        }
        qemu_set_vnet_hdr_len(nc->peer, 10);
        if (qemu_set_vnet_le(nc->peer, true) < 0) {
            error_setg(errp, "backend cannot use little-endian vnet headers");
            qemu_bh_delete(n->bh);
            g_free(n);
            return NULL;
        }
        qemu_set_offload(nc->peer, &offloads);
    }
    return n;
}

void unifi_net_sent(UnifiNet *n)
{
    n->pending = false;
    qemu_bh_schedule(n->bh);
}

void unifi_net_reset(UnifiNet *n)
{
    if (!n) { return; }
    qemu_bh_cancel(n->bh);
    qemu_purge_queued_packets(n->nc);
    n->stats.reset_dropped += n->pending;
    n->pending = false;
    for (unsigned q = 0; q < NET_QUEUES; q++) {
        n->stats.reset_dropped += n->queues[q].length;
        g_queue_clear_full(&n->queues[q], (GDestroyNotify)g_bytes_unref);
        n->bytes[q] = 0;
    }
    n->next = 0;
}

void unifi_net_free(UnifiNet *n)
{
    if (!n) { return; }
    unifi_net_reset(n);
    if (n->owner) {
        const char *names[] = { "net-packets", "net-offloaded", "net-fallback", "net-invalid", "net-dropped", "net-reset-dropped", "net-rx-gso-packets", "net-rx-segments" };
        for (unsigned i = 0; i < ARRAY_SIZE(names); i++) {
            object_property_del(n->owner, names[i]);
        }
    }
    qemu_bh_delete(n->bh);
    g_free(n);
}

typedef struct Prepared { GQueue packets; bool accelerated; size_t bytes; } Prepared;
static void net_emit(void *opaque, const uint8_t *header, const uint8_t *buf, size_t len)
{
    Prepared *p = opaque;
    size_t prefix = p->accelerated ? 10 : 0;
    uint8_t *out = g_malloc(prefix + len);
    if (prefix) { memcpy(out, header, prefix); }
    memcpy(out + prefix, buf, len);
    g_queue_push_tail(&p->packets, g_bytes_new_take(out, prefix + len));
    p->bytes += prefix + len;
}

bool unifi_net_submit(UnifiNet *n, uint32_t q, const UnifiNetRequest *request,
                      const uint8_t *buf, size_t len)
{
    if (q >= NET_QUEUES) { n->stats.invalid++; return false; }
    Prepared p = { .accelerated = n->accelerated };
    int rc;
    if (request->version == 1 && request->flags == 0 && request->mss == 0 &&
        request->reserved == 0 && len >= 14 && len <= 65535) {
        /* Wire-ready packets need no Rust round trip or second payload copy. */
        const uint8_t header[10] = { 0 };
        net_emit(&p, header, buf, len);
        rc = 0;
    } else {
        rc = unifi_net_prepare(request, buf, len, n->accelerated ? 7 : 0, net_emit, &p);
    }
    if (rc < 0) { n->stats.invalid++; return false; }
    if (rc == 1) { n->stats.fallback++; }
    if (p.packets.length + n->queues[q].length > QUEUE_PACKETS ||
        p.bytes + n->bytes[q] > QUEUE_BYTES) {
        n->stats.dropped += p.packets.length;
        g_queue_clear_full(&p.packets, (GDestroyNotify)g_bytes_unref);
        return false;
    }
    n->bytes[q] += p.bytes;
    GBytes *packet;
    while ((packet = g_queue_pop_head(&p.packets))) {
        gsize size;
        const uint8_t *data = g_bytes_get_data(packet, &size);
        n->stats.offloaded += n->accelerated && data[0] != 0;
        n->stats.packets++;
        g_queue_push_tail(&n->queues[q], packet);
    }
    qemu_bh_schedule(n->bh);
    return true;
}

typedef struct Decoded {
    UnifiNetReceive receive;
    void *opaque;
    uint64_t segments;
} Decoded;

static void net_receive_emit(void *opaque, const uint8_t *header,
                             const uint8_t *buf, size_t len)
{
    (void)header;
    Decoded *decoded = opaque;
    decoded->receive(decoded->opaque, buf, len);
    decoded->segments++;
}

bool unifi_net_decode(UnifiNet *n, const uint8_t *buf, size_t len,
                      UnifiNetReceive receive, void *opaque)
{
    if (!n->accelerated) {
        receive(opaque, buf, len);
        return true;
    }
    if (len < 24 || len > 65607) { n->stats.invalid++; return false; }
    Decoded decoded = { .receive = receive, .opaque = opaque };
    intptr_t count = unifi_net_receive_batch(buf, buf + 10, len - 10,
                                              net_receive_emit, &decoded);
    if (count < 0 || decoded.segments != (uint64_t)count) {
        n->stats.invalid++;
        return false;
    }
    n->stats.rx_segments += decoded.segments;
    n->stats.rx_gso_packets += decoded.segments > 1;
    return true;
}
const UnifiNetStats *unifi_net_stats(UnifiNet *n) { return &n->stats; }
bool unifi_net_accelerated(UnifiNet *n) { return n->accelerated; }

void unifi_net_add_properties(UnifiNet *n, Object *owner)
{
    n->owner = owner;
    object_property_add_uint64_ptr(owner, "net-packets", &n->stats.packets, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-offloaded", &n->stats.offloaded, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-fallback", &n->stats.fallback, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-invalid", &n->stats.invalid, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-dropped", &n->stats.dropped, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-reset-dropped", &n->stats.reset_dropped, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-rx-gso-packets", &n->stats.rx_gso_packets, OBJ_PROP_FLAG_READ);
    object_property_add_uint64_ptr(owner, "net-rx-segments", &n->stats.rx_segments, OBJ_PROP_FLAG_READ);
}
