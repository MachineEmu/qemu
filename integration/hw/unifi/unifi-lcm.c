/* UniFi display USB transport. Application semantics live in the Rust model. */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/qdev-properties-system.h"
#include "hw/usb.h"
#include "hw/usb/desc.h"
#include "chardev/char-fe.h"
#include "migration/vmstate.h"
#include "unifi_board.h"

#define TYPE_UNIFI_LCM "unifi-lcm"
OBJECT_DECLARE_SIMPLE_TYPE(UnifiLcmState, UNIFI_LCM)

struct UnifiLcmState {
    USBDevice dev;
    UnifiLcm *model;
    bool udm_pro;
    CharFrontend events;
    CharFrontend input;
    uint8_t input_line[1024];
    size_t input_len;
    bool input_overflow;
    const char *input_reply;
    QEMUTimer *timer;
    uint8_t line_coding[7];
    uint16_t control_lines;
    uint8_t trace[65536];
    size_t trace_len, trace_pos;
};

static const USBDescStrings strings = {
    [1] = "Ubiquiti Networks (emulated)",
    [2] = "USW LCM semantic emulator",
    [3] = "US24-LCM-0001",
};

static const uint8_t cdc_header[] = { 5, 0x24, 0, 0x10, 0x01 };
static const uint8_t cdc_call[] = { 5, 0x24, 1, 0, 1 };
static const uint8_t cdc_acm[] = { 4, 0x24, 2, 2 };
static const uint8_t cdc_union[] = { 5, 0x24, 6, 0, 1 };
static const USBDescIface interfaces[] = {
    {
        .bInterfaceNumber = 0, .bNumEndpoints = 1,
        .bInterfaceClass = 2, .bInterfaceSubClass = 2, .bInterfaceProtocol = 1,
        .ndesc = 4,
        .descs = (USBDescOther[]) {
            { .length = sizeof(cdc_header), .data = cdc_header },
            { .length = sizeof(cdc_call), .data = cdc_call },
            { .length = sizeof(cdc_acm), .data = cdc_acm },
            { .length = sizeof(cdc_union), .data = cdc_union },
        },
        .eps = (USBDescEndpoint[]) {
            { .bEndpointAddress = 0x82, .bmAttributes = USB_ENDPOINT_XFER_INT,
              .wMaxPacketSize = 16, .bInterval = 16 },
        },
    }, {
        .bInterfaceNumber = 1, .bNumEndpoints = 2, .bInterfaceClass = 0x0a,
        .eps = (USBDescEndpoint[]) {
            { .bEndpointAddress = 0x01, .bmAttributes = USB_ENDPOINT_XFER_BULK,
              .wMaxPacketSize = 64 },
            { .bEndpointAddress = 0x81, .bmAttributes = USB_ENDPOINT_XFER_BULK,
              .wMaxPacketSize = 64 },
        },
    },
};
static const USBDescDevice device_desc = {
    .bcdUSB = 0x0200, .bDeviceClass = 2, .bMaxPacketSize0 = 64,
    .bNumConfigurations = 1,
    .confs = (USBDescConfig[]) {
        { .bNumInterfaces = 2, .bConfigurationValue = 1,
          .bmAttributes = USB_CFG_ATT_ONE, .bMaxPower = 50,
          .nif = 2, .ifs = interfaces },
    },
};
static const USBDesc desc = {
    .id = { .idVendor = 0x1f9b, .idProduct = 0x1581, .bcdDevice = 0x0100,
            .iManufacturer = 1, .iProduct = 2, .iSerialNumber = 3 },
    .full = &device_desc, .str = strings,
};

static void lcm_publish(void *opaque)
{
    UnifiLcmState *s = opaque;
    if (s->input_reply) {
        int n = qemu_chr_fe_write(&s->input, (const uint8_t *)s->input_reply,
                                 strlen(s->input_reply));
        if (n > 0) {
            s->input_reply += n;
            if (!*s->input_reply) {
                s->input_reply = NULL;
                qemu_chr_fe_accept_input(&s->input);
            }
        }
    }
    if (s->trace_pos == s->trace_len) {
        s->trace_len = unifi_lcm_read(s->model, s->trace, sizeof(s->trace), true);
        s->trace_pos = 0;
    }
    if (s->trace_len && qemu_chr_fe_backend_open(&s->events)) {
        int n = qemu_chr_fe_write(&s->events, s->trace + s->trace_pos,
                                 s->trace_len - s->trace_pos);
        if (n > 0) {
            s->trace_pos += n;
        }
    }
    timer_mod(s->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 50);
}

static int lcm_can_input(void *opaque)
{
    UnifiLcmState *s = opaque;
    return s->input_reply ? 0 : 1;
}

static void lcm_input(void *opaque, const uint8_t *buf, int size)
{
    UnifiLcmState *s = opaque;
    if (size != 1) { return; }
    if (*buf == '\n') {
        bool ok = !s->input_overflow &&
            unifi_lcm_input(s->model, s->input_line, s->input_len);
        s->input_len = 0;
        s->input_overflow = false;
        s->input_reply = ok ? "{\"ok\":true,\"delivery\":\"queued\"}\n" :
            "{\"ok\":false,\"error\":\"invalid action, not ready, or queue full\"}\n";
        if (ok) { usb_wakeup(usb_ep_get(&s->dev, USB_TOKEN_IN, 1), 0); }
        lcm_publish(s);
    } else if (s->input_len < sizeof(s->input_line)) {
        s->input_line[s->input_len++] = *buf;
    } else {
        s->input_overflow = true;
    }
}

static void lcm_input_event(void *opaque, QEMUChrEvent event)
{
    UnifiLcmState *s = opaque;
    if (event == CHR_EVENT_CLOSED) {
        s->input_len = 0;
        s->input_overflow = false;
        s->input_reply = NULL;
    }
}

static void lcm_reset(USBDevice *dev)
{
    UnifiLcmState *s = UNIFI_LCM(dev);
    static const uint8_t initial[] = { 0x00, 0xc2, 0x01, 0, 0, 0, 8 };
    memcpy(s->line_coding, initial, sizeof(initial));
    s->control_lines = 0;
    unifi_lcm_reset(s->model);
}

static void lcm_control(USBDevice *dev, USBPacket *p, int request,
                        int value, int index, int length, uint8_t *data)
{
    UnifiLcmState *s = UNIFI_LCM(dev);
    if (usb_desc_handle_control(dev, p, request, value, index, length, data) >= 0) {
        return;
    }
    if (index != 0) {
        p->status = USB_RET_STALL;
        return;
    }
    switch (request) {
    case 0x2120: /* CDC SET_LINE_CODING */
        if (length != 7) { break; }
        memcpy(s->line_coding, data, 7);
        return;
    case 0xa121: /* CDC GET_LINE_CODING */
        memcpy(data, s->line_coding, MIN(length, 7));
        p->actual_length = MIN(length, 7);
        return;
    case 0x2122: /* CDC SET_CONTROL_LINE_STATE */
        if (length) { break; }
        s->control_lines = value & 3;
        return;
    default:
        break;
    }
    p->status = USB_RET_STALL;
}

static void lcm_data(USBDevice *dev, USBPacket *p)
{
    UnifiLcmState *s = UNIFI_LCM(dev);
    uint8_t buf[64];
    if (p->pid == USB_TOKEN_OUT && p->ep->nr == 1) {
        /* xHCI submits an entire TD, not individual full-speed wire packets. */
        if (p->iov.size > 65536) {
            p->status = USB_RET_STALL;
            return;
        }
        g_autofree uint8_t *out = g_malloc(MAX(p->iov.size, 1));
        usb_packet_copy(p, out, p->iov.size);
        if (!unifi_lcm_feed(s->model, out, p->iov.size)) {
            p->actual_length = 0;
            p->status = USB_RET_NAK;
        } else {
            usb_wakeup(usb_ep_get(dev, USB_TOKEN_IN, 1), 0);
        }
    } else if (p->pid == USB_TOKEN_IN && p->ep->nr == 1) {
        size_t n = unifi_lcm_read(s->model, buf, MIN(p->iov.size, sizeof(buf)), false);
        if (!n) {
            p->status = USB_RET_NAK;
        } else {
            usb_packet_copy(p, buf, n);
        }
    } else if (p->pid == USB_TOKEN_IN && p->ep->nr == 2) {
        p->status = USB_RET_NAK; /* No asynchronous serial-state changes. */
    } else {
        p->status = USB_RET_STALL;
    }
}

static void lcm_realize(USBDevice *dev, Error **errp)
{
    UnifiLcmState *s = UNIFI_LCM(dev);
    if (!qemu_chr_fe_backend_connected(&s->events) ||
        !qemu_chr_fe_backend_connected(&s->input)) {
        error_setg(errp, "unifi-lcm requires events and input chardevs");
        return;
    }
    s->model = s->udm_pro ? unifi_lcm_new_udmpro() : unifi_lcm_new();
    usb_desc_create_serial(dev);
    usb_desc_init(dev);
    if (s->udm_pro) {
        usb_desc_set_string(dev, 1, "Ubiquiti Inc.");
        usb_desc_set_string(dev, 2, "Ulcd application");
        usb_desc_set_string(dev, 3, "UDMPRO-LCM-0001");
    }
    s->timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, lcm_publish, s);
    qemu_chr_fe_set_handlers(&s->input, lcm_can_input, lcm_input, lcm_input_event,
                             NULL, s, NULL, true);
    lcm_reset(dev);
    lcm_publish(s);
}

static void lcm_unrealize(USBDevice *dev)
{
    UnifiLcmState *s = UNIFI_LCM(dev);
    timer_free(s->timer);
    qemu_chr_fe_deinit(&s->events, false);
    qemu_chr_fe_deinit(&s->input, false);
    unifi_lcm_free(s->model);
}

static const VMStateDescription vmstate_lcm = {
    .name = TYPE_UNIFI_LCM, .unmigratable = 1,
};
static const Property properties[] = {
    DEFINE_PROP_BOOL("udm-pro", UnifiLcmState, udm_pro, false),
    DEFINE_PROP_CHR("events", UnifiLcmState, events),
    DEFINE_PROP_CHR("input", UnifiLcmState, input),
};
static void lcm_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);
    uc->product_desc = "UniFi LCM";
    uc->usb_desc = &desc;
    uc->realize = lcm_realize;
    uc->unrealize = lcm_unrealize;
    uc->handle_reset = lcm_reset;
    uc->handle_control = lcm_control;
    uc->handle_data = lcm_data;
    dc->vmsd = &vmstate_lcm;
    device_class_set_props(dc, properties);
}
static const TypeInfo lcm_info = {
    .name = TYPE_UNIFI_LCM, .parent = TYPE_USB_DEVICE,
    .instance_size = sizeof(UnifiLcmState), .class_init = lcm_class_init,
};
static void lcm_register(void) { type_register_static(&lcm_info); }
type_init(lcm_register)
