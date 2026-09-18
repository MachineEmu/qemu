#ifndef UNIFI_NET_H
#define UNIFI_NET_H
#include "net/net.h"
#include "qapi/error.h"
#include "unifi_board.h"
/* One transport per endpoint. Queue IDs are local, never global. All submit
 * data is copied before return; acceptance transfers no guest-memory borrow. */
typedef struct UnifiNet UnifiNet;
typedef struct UnifiNetStats {
    uint64_t packets, offloaded, fallback, invalid, dropped, reset_dropped;
    uint64_t rx_gso_packets, rx_segments;
} UnifiNetStats;
typedef void (*UnifiNetReceive)(void *opaque, const uint8_t *buf, size_t len);
UnifiNet *unifi_net_new(NetClientState *nc, const char *mode, bool rx_gso,
                        NetPacketSent *sent, Error **errp);
void unifi_net_free(UnifiNet *net);
void unifi_net_add_properties(UnifiNet *net, Object *owner);
void unifi_net_reset(UnifiNet *net);
void unifi_net_sent(UnifiNet *net);
bool unifi_net_submit(UnifiNet *net, uint32_t queue,
                      const UnifiNetRequest *request, const uint8_t *buf, size_t len);
/* Emits normalized wire frames. False means malformed RX. */
bool unifi_net_decode(UnifiNet *net, const uint8_t *buf, size_t len,
                      UnifiNetReceive receive, void *opaque);
const UnifiNetStats *unifi_net_stats(UnifiNet *net);
bool unifi_net_accelerated(UnifiNet *net);
#endif
