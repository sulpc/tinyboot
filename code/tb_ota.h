#ifndef _TB_OTA_H_
#define _TB_OTA_H_

#include "tb_types.h"

void ota_init(void);
void ota_mainproc(void);
void ota_msg_recieved(const uint8_t* data, uint16_t len);
bool ota_msg_send_co(const uint8_t* data, uint16_t len);
int  ota_write_flash_co(uint32_t addr, uint8_t* data, uint32_t size);
int  ota_read_flash_co(uint32_t addr, uint8_t* data, uint32_t size);

#endif
