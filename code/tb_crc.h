#ifndef _TB_ALGOS_H_
#define _TB_ALGOS_H_

#include "tb_types.h"

uint16_t calc_crc16(const uint8_t* data, uint32_t length);
uint32_t calc_crc32(const uint8_t* data, uint32_t length);
uint32_t calc_crc32_pre();
uint32_t calc_crc32_step(const uint8_t* data, uint32_t length, uint32_t crc);
uint32_t calc_crc32_finish(uint32_t crc);

#endif
