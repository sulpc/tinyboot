#ifndef _TB_OTA_CFG_H_
#define _TB_OTA_CFG_H_

#include "tb_types.h"

#define FW_STORAGE_ADDR        0x20F00000u   // ram base
#define FW_STORAGE_THRE        (1024 * 32)
#define FLASH_WRITE_BLOCK_SIZE 4096
#define FLASH_READ_BLOCK_SIZE  (FLASH_WRITE_BLOCK_SIZE * 2)

// clang-format off
#define OTA_FLASH_PARTITIONS                                   \
    /* part item         id        offset      size    */      \
    /* boot1        */ { 0x10,     0x010000,   0x018000 },     \
    /* boot2        */ { 0x11,     0x028000,   0x018000 },     \
    /* app1         */ {    1,     0x040000,   0x0E0000 },     \
    /* app2         */ {    2,     0x120000,   0x080000 },     \
    /* app all      */ {    3,     0x040000,   0x160000 }
// clang-format on

#endif
