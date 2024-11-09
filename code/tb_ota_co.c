#include "tb_ota.h"
#include "tb_ota_cfg.h"
#include "tb_utils.h"

#include "tb_tp.h"

extern int8_t flash_erase(uint32_t addr, uint32_t size);
extern int8_t flash_write(uint32_t addr, uint8_t* data, uint32_t size);
extern int8_t flash_read(uint32_t addr, uint8_t* data, uint32_t size);
extern void   mdelay(uint32_t ms);

#define REALLY_PROGRAM 1

bool ota_msg_send_co(const uint8_t* data, uint16_t len)
{
    return tp_txmsg_if(data, len);
}

int ota_write_flash_co(uint32_t addr, uint8_t* data, uint32_t size)
{
#if REALLY_PROGRAM
    int8_t ret;

    ret = flash_erase(addr, size);
    if (ret != 0) {
        xprintf("flash_erase fail %d, addr=%x, size=%d\n", ret, addr, size);
        return -1;
    }

    ret = flash_write(addr, data, size);
    if (ret != 0) {
        xprintf("flash_write fail %d, addr=%x, size=%d\n", ret, addr, size);
        return -2;
    }
    mdelay(10);
#else
    mdelay(100);
#endif
    return 0;
}

int ota_read_flash_co(uint32_t addr, uint8_t* data, uint32_t size)
{
#if REALLY_PROGRAM
    int8_t ret;

    ret = flash_read(addr, data, size);
    if (ret != 0) {
        xprintf("flash_read fail %d, addr=%x, size=%d\n", ret, addr, size);
        return -1;
    }
    mdelay(10);
#endif
    return 0;
}
