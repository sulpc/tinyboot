#include "tb_ota.h"
#include "tb_crc.h"
#include "tb_ota_cfg.h"
#include "tb_types.h"
#include "tb_utils.h"

#define log_debug tb_printf
#define log_error tb_printf

#define OTA_CTRL_MSG_LEN_MIN     2
#define OTA_CTRL_ACK_LEN_MIN     3
#define OTA_FWINFO_MSG_LEN       sizeof(ota_fwinfo_msg_t)
#define OTA_FWINFO_ACK_LEN       sizeof(ota_fwinfo_ack_t)
#define OTA_FWDATA_MSG_LEN(size) (size + 7 + 2)
#define OTA_FWDATA_ACK_LEN       sizeof(ota_fwdata_ack_t)
#define OTA_ERROR_MSG_LEN        sizeof(ota_error_msg_t)
#define OTA_FWDATA_ACK_OK        0
#define OTA_FWDATA_ACK_DELAY     1
#define OTA_FWDATA_ACK_BURNING   2


typedef enum {
    OTA_STA_IDLE = 0,    // wait fw info
    OTA_STA_RECEIVING,   // wait fw data
    OTA_STA_RECEIVED,    // received fw data
    OTA_STA_PROGRAM,     // program fw
    OTA_STA_CHECK,       // check fw
    OTA_STA_OK,
    OTA_STA_FAIL,
} ota_state_t;
const char* ota_state_info[] = {
    [OTA_STA_IDLE]      = "idle",        //
    [OTA_STA_RECEIVING] = "receiving",   //
    [OTA_STA_RECEIVED]  = "received",    //
    [OTA_STA_PROGRAM]   = "program",     //
    [OTA_STA_CHECK]     = "check",       //
    [OTA_STA_OK]        = "ok",          //
    [OTA_STA_FAIL]      = "fail",        //
};

typedef enum {
    OTA_ERR_NONE = 0,
    OTA_ERR_INVALID_MESSAGE,
    OTA_ERR_UNEXPECTED_MESSAGE,
    OTA_ERR_FWINFO_CRC_INVALID,
    OTA_ERR_FWINFO_ID_INVALID,
    OTA_ERR_FWINFO_ADDR_INVALID,
    OTA_ERR_FWINFO_SIZE_INVALID,
    OTA_ERR_FWINFO_CRYPTO_INVALID,
    OTA_ERR_FWDATA_CRC_INVALID,
    OTA_ERR_FWDATA_OFF_INVALID,
    OTA_ERR_FWDATA_SIZE_INVALID,
    OTA_ERR_FW_PROGRAM_FAIL,
    OTA_ERR_FW_CRCCHECK_FAIL,
    OTA_ERR_FW_RECHECK_FAIL,
    OTA_ERR_INTERUPT,
    // OTA_ERR_BUSY_PROGRAM,
    // OTA_ERR_BUSY_CHECK,
} ota_error_t;
const char* ota_error_info[] = {
    [OTA_ERR_NONE]                  = "NONE                 ",
    [OTA_ERR_INVALID_MESSAGE]       = "INVALID_MESSAGE      ",
    [OTA_ERR_UNEXPECTED_MESSAGE]    = "UNEXPECTED_MESSAGE   ",
    [OTA_ERR_FWINFO_CRC_INVALID]    = "FWINFO_CRC_INVALID   ",
    [OTA_ERR_FWINFO_ID_INVALID]     = "FWINFO_ID_INVALID    ",
    [OTA_ERR_FWINFO_ADDR_INVALID]   = "FWINFO_ADDR_INVALID  ",
    [OTA_ERR_FWINFO_SIZE_INVALID]   = "FWINFO_SIZE_INVALID  ",
    [OTA_ERR_FWINFO_CRYPTO_INVALID] = "FWINFO_CRYPTO_INVALID",
    [OTA_ERR_FWDATA_CRC_INVALID]    = "FWDATA_CRC_INVALID   ",
    [OTA_ERR_FWDATA_OFF_INVALID]    = "FWDATA_OFF_INVALID   ",
    [OTA_ERR_FWDATA_SIZE_INVALID]   = "FWDATA_SIZE_INVALID  ",
    [OTA_ERR_FW_PROGRAM_FAIL]       = "FW_PROGRAM_FAIL      ",
    [OTA_ERR_FW_CRCCHECK_FAIL]      = "FW_CRCCHECK_FAIL     ",
    [OTA_ERR_FW_RECHECK_FAIL]       = "FW_RECHECK_FAIL      ",
    [OTA_ERR_INTERUPT]              = "INTERUPT             ",
};

typedef enum {
    OTA_MSG_CTRL = 0,
    OTA_MSG_FWINFO,
    OTA_MSG_FWDATA,
    OTA_MSG_ERROR = 0xf,
} ota_msgtype_t;

typedef enum {
    OTA_CTRL_CMD_NONE = 0,
    OTA_CTRL_CMD_QUERYSTAT,
} ota_ctrl_cmd_t;

#pragma pack(1)
typedef struct {
    uint8_t msgtype;
    uint8_t cmd;
    uint8_t param[0];   // size: 0+
} ota_ctrl_msg_t;
typedef struct {
    uint8_t msgtype;
    uint8_t cmd;
    uint8_t result[1];   // size: 1+
} ota_ctrl_ack_t;

typedef struct {
    uint8_t msgtype;
    uint8_t fw_id;
    uint8_t fw_crypto;
    uint8_t fw_addr[4];
    uint8_t fw_size[4];
    uint8_t fw_crc32[4];
    uint8_t crc16[2];
} ota_fwinfo_msg_t;
typedef struct {
    uint8_t msgtype;
    uint8_t fw_id;
    uint8_t result;
} ota_fwinfo_ack_t;

typedef struct {
    uint8_t msgtype;
    uint8_t size[2];
    uint8_t offset[4];
    uint8_t data[0];   // data[size]|data[size+1] is crc16 of whole msg
} ota_fwdata_msg_t;
typedef struct {
    uint8_t msgtype;
    uint8_t size[2];
    uint8_t result;   // 0-ok, 1-delay, 2-burning
} ota_fwdata_ack_t;

typedef struct {
    uint8_t msgtype;
    uint8_t errno;
    uint8_t data;
} ota_error_msg_t;
#pragma pack()

typedef struct {
    ota_state_t    state;
    ota_error_t    errno;
    uint8_t        ctrl_cmd;   // uint8_t ctrl_param[OTA_CTRL_PARAM_LEN];
    bool           fwinfo_update;
    uint16_t       fwdata_size;
    uint8_t        fw_id;
    uint8_t        fw_crypto;
    uint32_t       fw_addr;
    uint32_t       fw_size;
    uint32_t       fw_crc32;
    uint32_t       data_received;
    uint32_t       data_programmed;
    uint32_t       data_checked;
    uint8_t* const fw_storage;
    uint8_t*       fw_wr_addr;   // ptr to recv
    uint32_t       crc32_run;    // part received, part counted
} ota_info_t;

typedef struct {
    uint32_t part_id;
    uint32_t part_offset;
    uint32_t part_size;
} ota_flash_partition_item_t;


static uint8_t    ota_rsp_buffer[16];
static ota_info_t ota_info = {
    .fw_storage = (uint8_t*)(FW_STORAGE_ADDR),
};
static ota_flash_partition_item_t ota_flash_partitions[] = {
    OTA_FLASH_PARTITIONS,
};

static ota_error_t ota_parse_ctrl_msg(const uint8_t* data, uint16_t len)
{
    if (len < OTA_CTRL_MSG_LEN_MIN) {
        return OTA_ERR_INVALID_MESSAGE;
    }
    ota_ctrl_msg_t* msg = (ota_ctrl_msg_t*)data;

    ota_info.ctrl_cmd = msg->cmd;
    // memcpy(ota_info.ctrl_param, msg->param, util_min2(len - OTA_CTRL_MSG_LEN_MIN, OTA_CTRL_PARAM_LEN));
    return OTA_ERR_NONE;
}

static ota_error_t ota_parse_fwinfo_msg(const uint8_t* data, uint16_t len)
{
    if (len != OTA_FWINFO_MSG_LEN) {
        return OTA_ERR_INVALID_MESSAGE;
    }
    ota_fwinfo_msg_t* msg = (ota_fwinfo_msg_t*)data;

    uint16_t crc16 = util_getbigendian2(msg->crc16);

    if (crc16 != calc_crc16(data, len - 2)) {
        return OTA_ERR_FWINFO_CRC_INVALID;
    }
    ota_info.fw_id     = msg->fw_id;
    ota_info.fw_crypto = msg->fw_crypto;
    ota_info.fw_addr   = util_getbigendian4(msg->fw_addr);
    ota_info.fw_size   = util_getbigendian4(msg->fw_size);
    ota_info.fw_crc32  = util_getbigendian4(msg->fw_crc32);

    uint8_t part_idx = 0;
    for (part_idx = 0; part_idx < util_arraylen(ota_flash_partitions); part_idx++) {
        if (ota_info.fw_id == ota_flash_partitions[part_idx].part_id) {
            break;
        }
    }
    if (part_idx >= util_arraylen(ota_flash_partitions)) {
        return OTA_ERR_FWINFO_ID_INVALID;
    }

    // todo check fw_crypto is support
    if (ota_info.fw_crypto != 0) {
        return OTA_ERR_FWINFO_CRYPTO_INVALID;
    }

    if (ota_info.fw_addr != ota_flash_partitions[part_idx].part_offset) {
        return OTA_ERR_FWINFO_ADDR_INVALID;
    }

    if (ota_info.fw_size > ota_flash_partitions[part_idx].part_size) {
        return OTA_ERR_FWINFO_SIZE_INVALID;
    }

    ota_info.fwinfo_update = true;
    ota_info.state         = OTA_STA_IDLE;

    log_debug("[-] ota recv fwinfo id=%d, fw_crypto=%d, addr=%x, size=%d, crc=%x\n", ota_info.fw_id, ota_info.fw_crypto,
              ota_info.fw_addr, ota_info.fw_size, ota_info.fw_crc32);
    return OTA_ERR_NONE;
}

static ota_error_t ota_parse_fwdata_msg(const uint8_t* data, uint16_t len)
{
    if (ota_info.state != OTA_STA_RECEIVING) {
        return OTA_ERR_UNEXPECTED_MESSAGE;
    }

    if (len < OTA_FWDATA_MSG_LEN(1)) {
        return OTA_ERR_INVALID_MESSAGE;
    }

    ota_fwdata_msg_t* msg    = (ota_fwdata_msg_t*)data;
    uint32_t          offset = util_getbigendian4(msg->offset);
    uint16_t          size   = util_getbigendian2(msg->size);


    if (len != OTA_FWDATA_MSG_LEN(size)) {
        return OTA_ERR_INVALID_MESSAGE;
    }

    if (offset != ota_info.data_received) {
        return OTA_ERR_FWDATA_OFF_INVALID;
    }

    uint8_t* crc_field = &msg->data[size];
    uint16_t crc16     = util_getbigendian2(crc_field);

    // check crc16
    if (crc16 == calc_crc16(data, len - 2)) {
        if (size + ota_info.data_received > ota_info.fw_size) {
            log_error("[!] ota recv fwdata size overflow!!!\n");
            return OTA_ERR_FWDATA_SIZE_INVALID;
        }
        memcpy(ota_info.fw_wr_addr, msg->data, size);
        ota_info.fwdata_size = size;
        ota_info.state       = OTA_STA_RECEIVED;
    } else {
        log_error("[!] ota recv fwdata when crc invalid!!!\n");
        return OTA_ERR_FWDATA_CRC_INVALID;
    }
    return OTA_ERR_NONE;
}

static ota_error_t ota_parse_error_msg(const uint8_t* data, uint16_t len)
{
    if (len != OTA_ERROR_MSG_LEN) {
        return OTA_ERR_INVALID_MESSAGE;
    }
    ota_error_msg_t* msg = (ota_error_msg_t*)data;

    return msg->errno;
}

static ota_error_t ota_proc_sta_idle(void)
{
    if (ota_info.fwinfo_update) {
        ota_info.fwinfo_update = false;

        ota_fwinfo_ack_t* rsp = (ota_fwinfo_ack_t*)ota_rsp_buffer;
        rsp->msgtype          = OTA_MSG_FWINFO;
        rsp->fw_id            = ota_info.fw_id;
        rsp->result           = 1;

        if (ota_msg_send_co(ota_rsp_buffer, OTA_FWINFO_ACK_LEN)) {
            log_debug("[-] ota send fwinfo ack\n");
        } else {
            log_error("[!] ota send fwinfo ack fail\n");
        }

        ota_info.data_received   = 0;
        ota_info.data_programmed = 0;
        ota_info.fw_wr_addr      = ota_info.fw_storage;
        ota_info.crc32_run       = calc_crc32_pre();
        ota_info.state           = OTA_STA_RECEIVING;
        log_debug("[-] ota into state  OTA_STA_RECEIVING\n\n");
    }
    return OTA_ERR_NONE;
}

static ota_error_t ota_proc_sta_receiving(void)
{
    return OTA_ERR_NONE;
}

static ota_error_t ota_proc_sta_received(void)
{
    // calc crc32, from ota_info.fw_wr_addr to ota_info.fw_wr_addr
    ota_info.crc32_run = calc_crc32_step(ota_info.fw_wr_addr, ota_info.fwdata_size, ota_info.crc32_run);

    log_debug("[-] ota recv fwdata %08x+%d\n", ota_info.data_received, ota_info.fwdata_size);

    ota_info.data_received += ota_info.fwdata_size;
    ota_info.fw_wr_addr += ota_info.fwdata_size;

    ota_fwdata_ack_t* rsp = (ota_fwdata_ack_t*)ota_rsp_buffer;

    if (ota_info.data_received == ota_info.fw_size) {
        ota_info.crc32_run = calc_crc32_finish(ota_info.crc32_run);
        // check crc32
        if (ota_info.crc32_run != ota_info.fw_crc32) {
            ota_info.state = OTA_STA_FAIL;
            return OTA_ERR_FW_CRCCHECK_FAIL;
        }
        rsp->result = OTA_FWDATA_ACK_OK;
        log_debug("[-] ota into state  OTA_STA_PROGRAM, wptr=%d\n\n", ota_info.fw_wr_addr - ota_info.fw_storage);
        ota_info.state = OTA_STA_PROGRAM;
    } else if (ota_info.fw_wr_addr - ota_info.fw_storage >= FW_STORAGE_THRE) {
        rsp->result = OTA_FWDATA_ACK_BURNING;
        log_debug("[-] ota into state  OTA_STA_PROGRAM, wptr=%d\n\n", ota_info.fw_wr_addr - ota_info.fw_storage);
        ota_info.state = OTA_STA_PROGRAM;
    } else {
        rsp->result = OTA_FWDATA_ACK_OK;
        // log_debug("[-] ota into state  OTA_STA_RECEIVING\n\n");
        ota_info.state = OTA_STA_RECEIVING;
    }

    rsp->msgtype = OTA_MSG_FWDATA;
    util_setbigendian2(rsp->size, ota_info.fwdata_size);
    ota_msg_send_co(ota_rsp_buffer, OTA_FWDATA_ACK_LEN);

    return OTA_ERR_NONE;
}

static ota_error_t ota_proc_sta_program(void)
{
    uint8_t* prog_ptr = ota_info.fw_wr_addr - (ota_info.data_received - ota_info.data_programmed);

    if ((ota_info.data_received == ota_info.fw_size) ||
        (ota_info.data_received - ota_info.data_programmed >= FLASH_WRITE_BLOCK_SIZE)) {
        uint32_t prog_len = util_min2(FLASH_WRITE_BLOCK_SIZE, ota_info.fw_wr_addr - prog_ptr);

        log_debug("[-] ota prog fwdata %08x+%d, pptr=%d\n", ota_info.data_programmed, prog_len,
                  prog_ptr - ota_info.fw_storage);
        if (ota_write_flash_co(ota_info.fw_addr + ota_info.data_programmed, prog_ptr, prog_len) == 0) {
            ota_info.data_programmed += prog_len;
        } else {
            ota_info.state = OTA_STA_FAIL;
            return OTA_ERR_FW_PROGRAM_FAIL;
        }
        if (ota_info.data_programmed == ota_info.fw_size) {
            log_debug("[-] ota into state  OTA_STA_CHECK, crc32=%x\n\n", ota_info.crc32_run);
            ota_info.data_checked = 0;
            ota_info.state        = OTA_STA_CHECK;
        }
    } else {
        uint32_t done = prog_ptr - ota_info.fw_storage;
        uint32_t move = ota_info.fw_wr_addr - prog_ptr;
        memcpy(prog_ptr, ota_info.fw_storage, move);
        ota_info.fw_wr_addr -= done;

        log_debug("[-] ota move fwdata pptr=%d, wptr=%d\n", prog_ptr - ota_info.fw_storage,
                  ota_info.fw_wr_addr - ota_info.fw_storage);
        log_debug("[-] ota into state  OTA_STA_RECEIVING\n\n");
        ota_info.state = OTA_STA_RECEIVING;
    }
    return OTA_ERR_NONE;
}

static ota_error_t ota_proc_sta_check(void)
{
    uint32_t chk_addr = ota_info.fw_addr + ota_info.data_checked;
    uint32_t chk_len  = util_min2(ota_info.fw_size - ota_info.data_checked, FLASH_READ_BLOCK_SIZE);

    if (ota_info.data_checked == 0) {
        ota_info.crc32_run = calc_crc32_pre();
    }

    if (ota_read_flash_co(chk_addr, ota_info.fw_storage, chk_len) != 0) {
        ota_info.state = OTA_STA_FAIL;
        log_error("[-] ota read flash fail\n");
        return OTA_ERR_FW_RECHECK_FAIL;
    }
    ota_info.crc32_run = calc_crc32_step(ota_info.fw_storage, chk_len, ota_info.crc32_run);
    log_debug("[-] ota chck fwdata %08x+%d\n", chk_addr, chk_len);

    ota_info.data_checked += chk_len;

    if (ota_info.data_checked == ota_info.fw_size) {
        ota_info.crc32_run = calc_crc32_finish(ota_info.crc32_run);

        if (ota_info.crc32_run == ota_info.fw_crc32) {
            log_debug("[-] ota into state  OTA_STA_OK\n\n");
            ota_info.state = OTA_STA_OK;
        } else {
            log_debug("[-] ota into state  OTA_STA_FAIL, check crc32=%x\n\n", ota_info.crc32_run);
            ota_info.state = OTA_STA_FAIL;
            return OTA_ERR_FW_RECHECK_FAIL;
        }
    }
    return OTA_ERR_NONE;
}

static void ota_proc_ctrl_cmd(void)
{
    if (ota_info.ctrl_cmd == OTA_CTRL_CMD_QUERYSTAT) {
        ota_ctrl_ack_t* msg = (ota_ctrl_ack_t*)ota_rsp_buffer;

        msg->msgtype   = OTA_MSG_CTRL;
        msg->cmd       = OTA_CTRL_CMD_QUERYSTAT;
        msg->result[0] = ota_info.state;
        msg->result[1] = 100;

        if (ota_info.state == OTA_STA_PROGRAM) {
            msg->result[1] = (uint8_t)(100.0 * ota_info.data_programmed / ota_info.fw_size);
        }
        else if (ota_info.state == OTA_STA_CHECK) {
            msg->result[1] = (uint8_t)(100.0 * ota_info.data_checked / ota_info.fw_size);
        }

        // log_debug("[-] ota stat query  %s: %d%%\n", ota_state_info[msg->result[0]], msg->result[1]);
        ota_msg_send_co(ota_rsp_buffer, 4);
    }
}

static void ota_proc_error(ota_error_t errno)
{
    log_error("[!] ota find error  `%s`, state=%d!!!\n", ota_error_info[errno], ota_info.state);
    // send err message
    ota_error_msg_t* msg = (ota_error_msg_t*)ota_rsp_buffer;

    msg->msgtype = OTA_MSG_ERROR;
    msg->errno   = errno;
    msg->data    = 0;
    ota_msg_send_co(ota_rsp_buffer, OTA_ERROR_MSG_LEN);
}


void ota_init(void)
{
    // todo: read partition table from flash
    memset(&ota_info, 0, sizeof(ota_info));
}

void ota_msg_recieved(const uint8_t* data, uint16_t len)
{
    if (len == 0) {
        ota_info.errno = OTA_ERR_INVALID_MESSAGE;
        return;
    }

    switch (data[0]) {
    case OTA_MSG_CTRL:
        ota_info.errno = ota_parse_ctrl_msg(data, len);
        break;
    case OTA_MSG_FWINFO:
        ota_info.errno = ota_parse_fwinfo_msg(data, len);
        break;
    case OTA_MSG_FWDATA:
        ota_info.errno = ota_parse_fwdata_msg(data, len);
        break;
    case OTA_MSG_ERROR:
        ota_info.errno = ota_parse_error_msg(data, len);
        break;
    default:
        ota_info.errno = OTA_ERR_INVALID_MESSAGE;
        break;
    }
}

void ota_mainproc(void)
{
    if (ota_info.ctrl_cmd != OTA_CTRL_CMD_NONE) {
        ota_proc_ctrl_cmd();
        ota_info.ctrl_cmd = OTA_CTRL_CMD_NONE;
        return;
    }

    if (ota_info.errno != OTA_ERR_NONE) {
        ota_proc_error(ota_info.errno);
        ota_info.errno = OTA_ERR_NONE;
        return;
    }

    ota_error_t errno = OTA_ERR_NONE;

    switch (ota_info.state) {
    case OTA_STA_IDLE:
        errno = ota_proc_sta_idle();
        break;
    case OTA_STA_RECEIVING:
        errno = ota_proc_sta_receiving();
        break;
    case OTA_STA_RECEIVED:
        errno = ota_proc_sta_received();
        break;
    case OTA_STA_PROGRAM:
        errno = ota_proc_sta_program();
        break;
    case OTA_STA_CHECK:
        errno = ota_proc_sta_check();
        break;
    case OTA_STA_OK:
        break;
    case OTA_STA_FAIL:
        break;
    default:
        break;
    }

    if (errno != OTA_ERR_NONE) {
        ota_proc_error(errno);
        return;
    }
}
