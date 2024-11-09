#include "tb_ota.h"
#include "tb_tp.h"

typedef enum {
    REBOOT_NORMAL = 0,
    REBOOT_UART_OTA,
    REBOOT_CAN_OTA,
} reboot_mode_t;

#define UART_CH 0
#define CAN_CH  1

void xprintf(const char* fmt, ...)
{
    // do printf
}
int32_t can_send_data(uint32_t bus, uint32_t id, uint8_t* data, uint32_t len)
{
    // do can send
    return 0;
}
int8_t flash_erase(uint32_t addr, uint32_t size)
{
    // do flash erase
    return 0;
}
int8_t flash_write(uint32_t addr, uint8_t* data, uint32_t size)
{
    // do flash write
    return 0;
}
int8_t flash_read(uint32_t addr, uint8_t* data, uint32_t size)
{
    // do flash read
    return 0;
}
void mdelay(uint32_t ms)
{
    // do delay
}
reboot_mode_t get_reboot_cause()
{
    // do get reboot cause
    return REBOOT_NORMAL;
}
void system_init()
{
    // do system init
}


int main()
{
    system_init();

    reboot_mode_t mode = get_reboot_cause();
    uint8_t       ota_channel;

    switch (mode) {
    case REBOOT_CAN_OTA:
        // init can
        // ...
        ota_channel = CAN_CH;
        break;
    case REBOOT_UART_OTA:
        // init uart
        // ...
        ota_channel = UART_CH;
        break;
    case REBOOT_NORMAL:
        // load app and start run it, never return
        // ...
        break;
    }

    bool     new_frame_flag;
    uint8_t  new_frame_data[1024];
    uint16_t new_frame_len;

    tp_activate(ota_channel);

    // rx_frm -> tp_proc -> ota_proc should be in same thread
    while (true) {
        // check if new frame arrived
        // ...
        if (new_frame_flag) {
            // pass the new frame to tp
            tp_rxfrm_if(ota_channel, new_frame_data, new_frame_len);
        }
        tp_mainproc();
        ota_mainproc();
        // delay or not
    }
}
