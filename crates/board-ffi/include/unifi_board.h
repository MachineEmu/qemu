#ifndef UNIFI_BOARD_H
#define UNIFI_BOARD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct UnifiBoard UnifiBoard;
typedef struct UnifiLcm UnifiLcm;
UnifiLcm *unifi_lcm_new(void);
UnifiLcm *unifi_lcm_new_udmpro(void);
void unifi_lcm_free(UnifiLcm *lcm);
void unifi_lcm_reset(UnifiLcm *lcm);
bool unifi_lcm_feed(UnifiLcm *lcm, const uint8_t *input, size_t len);
bool unifi_lcm_input(UnifiLcm *lcm, const uint8_t *input, size_t len);
size_t unifi_lcm_read(UnifiLcm *lcm, uint8_t *output, size_t cap, bool snapshot);
typedef struct {
    uint64_t now_ns;
    uint32_t (*dma_read)(void *context, uint64_t address, uint8_t *buffer, size_t length);
    uint32_t (*dma_write)(void *context, uint64_t address, const uint8_t *buffer, size_t length);
    void (*log)(void *context, uint32_t category, const uint8_t *message, size_t length);
    void *context;
} UnifiHost;
typedef struct { uint64_t base, size; uint32_t priority, device; } UnifiWindow;
typedef struct {
    const char *board_id;
    const char *vendor_id;
    const char *system_id;
    const char *serial_number;
    const char *model;
    uint64_t uart_base;
    uint32_t uart_irq;
    uint64_t bt_uart_base;
    uint32_t bt_uart_irq;
    uint64_t spi_base;
    uint32_t spi_irq;
    uint64_t watchdog_base;
    uint32_t watchdog_irq;
    uint64_t ethernet_bases[4];
    uint64_t gpio_bases[6];
    uint32_t gpio_base_indices[6];
} UnifiUdmProLayout;
/* Request ABI v1: flags IP=1, TCP=2, UDP=4, TSO=8, VLAN=16.
 * Software requests require mss=0 unless TSO is set; reserved must be zero. */
typedef struct { uint32_t version, flags; uint16_t mss, vlan_tci; uint32_t reserved; } UnifiNetRequest;
typedef void (*UnifiNetEmit)(void *, const uint8_t *header10, const uint8_t *bytes, size_t len);
int32_t unifi_net_prepare(const UnifiNetRequest *, const uint8_t *, size_t, uint32_t capabilities, UnifiNetEmit, void *);
intptr_t unifi_net_receive(const uint8_t *header10, const uint8_t *, size_t, uint8_t *output);
intptr_t unifi_net_receive_batch(const uint8_t *header10, const uint8_t *, size_t, UnifiNetEmit, void *);
bool unifi_board_set_host_offload(UnifiBoard *, bool enabled);
typedef struct { uint32_t kind, line_or_port; uint64_t value; const uint8_t *payload; size_t payload_len; UnifiNetRequest net_request; } UnifiEvent;
typedef enum {
    UNIFI_OK = 0,
    UNIFI_UNMAPPED = 1,
    UNIFI_INVALID_WIDTH = 2,
    UNIFI_MISALIGNED = 3,
    UNIFI_BUS_ERROR = 4,
} UnifiStatus;
typedef struct { UnifiStatus status; uint64_t value; uint64_t next_deadline_ns; const UnifiEvent *events; size_t event_count; } UnifiExecutionResult;

UnifiBoard *unifi_board_new(uint32_t kind, const char *config);
void unifi_board_free(UnifiBoard *board);
void unifi_board_reset(UnifiBoard *board, const UnifiHost *host, UnifiExecutionResult *out);
size_t unifi_board_windows(const UnifiBoard *board, UnifiWindow *out, size_t cap);
const UnifiUdmProLayout *unifi_udmpro_layout(void);
const uint8_t *unifi_udmpro_eeprom(size_t *size);
/* Same record, built for an arbitrary board table id. */
const uint8_t *unifi_udmpro_eeprom_for(uint16_t system_id, size_t *size);
uint16_t unifi_udmpro_default_system_id(void);
const uint8_t *unifi_bcm5616x_board_data(size_t *size);
uint64_t unifi_bcm5616x_board_data_offset(void);
const uint8_t *unifi_bcm5616x_nvram_env(size_t *size);
uint64_t unifi_bcm5616x_nvram_env_offset(void);
size_t unifi_board_irq_lines(const UnifiBoard *board, uint32_t *out, size_t cap);
UnifiStatus unifi_load_image(UnifiBoard *board, uint32_t kind, const uint8_t *data, size_t len);
/* Takes up to `cap` guest-written blocks of image `kind` (2 == eMMC) for the
 * host to persist.  With `cap == 0` this only reports whether any are pending. */
void unifi_board_mark_image_dirty(UnifiBoard *board, uint32_t kind);
size_t unifi_board_take_dirty_blocks(UnifiBoard *board, uint32_t kind,
                                     uint64_t *blocks, uint8_t *data, size_t cap);
void unifi_mmio_read(UnifiBoard *board, const UnifiHost *host, uint64_t addr, uint8_t width, UnifiExecutionResult *out);
void unifi_mmio_write(UnifiBoard *board, const UnifiHost *host, uint64_t addr, uint8_t width, uint64_t value, UnifiExecutionResult *out);
void unifi_uart_rx(UnifiBoard *board, const UnifiHost *host, uint32_t port, uint8_t byte, UnifiExecutionResult *out);
bool unifi_net_can_receive(const UnifiBoard *board, uint32_t port);
void unifi_net_rx(UnifiBoard *board, const UnifiHost *host, uint32_t port, const uint8_t *data, size_t length, UnifiExecutionResult *out);
void unifi_advance_to(UnifiBoard *board, const UnifiHost *host, UnifiExecutionResult *out);
typedef struct UnifiWifi UnifiWifi;
UnifiWifi *unifi_wifi_new(const char *path);
void unifi_wifi_free(UnifiWifi *wifi);
bool unifi_wifi_poll(UnifiWifi *wifi, UnifiBoard *board, const UnifiHost *host, UnifiExecutionResult *out);

typedef struct AlpineEthernet UnifiAlpine;
typedef void (*UnifiAlpineEmit)(void *, uint32_t queue, const UnifiNetRequest *, const uint8_t *, size_t);
UnifiAlpine *unifi_alpine_new(const uint8_t *mac6);
void unifi_alpine_free(UnifiAlpine *);
void unifi_alpine_reset(UnifiAlpine *);
uint32_t unifi_alpine_read(const UnifiAlpine *, uint64_t);
bool unifi_alpine_can_receive(const UnifiAlpine *);
uint32_t unifi_alpine_write(UnifiAlpine *, const UnifiHost *, uint64_t, uint32_t, UnifiAlpineEmit, void *);
uint32_t unifi_alpine_receive(UnifiAlpine *, const UnifiHost *, const uint8_t *, size_t);
#endif
