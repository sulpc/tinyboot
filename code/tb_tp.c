#include "tb_tp.h"
#include "tb_utils.h"

#define log_error tb_printf
#define log_debug tb_none

#define TP_PADDING_BYTE        0xAA
#define TP_FRM_BF              0x0
#define TP_FRM_SF              0x1
#define TP_FRM_FF              0x2
#define TP_FRM_CF              0x3
#define TP_FRM_ER              0x4
#define TP_BF_HEADLEN          1
#define TP_SF_HEADLEN          2
#define TP_FF_HEADLEN          2
#define TP_CF_HEADLEN          1
#define TP_ER_HEADLEN          3
#define TP_SEQ_MASK            0xf
#define TP_FRM_LEN_MIN         8
#define tp_reception_ready(tp) ((tp->state == TP_STA_IDLE) || (tp->state == TP_STA_WAIT_CF))

#pragma pack(1)
typedef union {
    struct {
        uint8_t length : 4;
        uint8_t type : 4;
        uint8_t data[TP_FRM_LEN_MIN - TP_BF_HEADLEN];
    } BF;
    struct {
        uint8_t lengthH : 4;
        uint8_t type : 4;
        uint8_t lengthL;
        uint8_t data[TP_FRM_LEN_MIN - TP_SF_HEADLEN];
    } SF;
    struct {
        uint8_t lengthH : 4;
        uint8_t type : 4;
        uint8_t lengthL;
        uint8_t data[TP_FRM_LEN_MIN - TP_FF_HEADLEN];
    } FF;
    struct {
        uint8_t seq : 4;
        uint8_t type : 4;
        uint8_t data[TP_FRM_LEN_MIN - TP_CF_HEADLEN];
    } CF;
    struct {
        uint8_t resv : 4;
        uint8_t type : 4;
        uint8_t errno;
        uint8_t param;
        uint8_t resv2[TP_FRM_LEN_MIN - TP_ER_HEADLEN];
    } ER;
} tp_frame_t;
#pragma pack()

static uint8_t current_chid = 0;

static tp_error_t tp_rxBF(tp_info_t* tp)
{
    tp_frame_t* rxfrm  = (tp_frame_t*)tp->rx_frm_buffer;
    uint16_t    length = rxfrm->BF.length;

    if ((length > tp->rx_frm_len - TP_BF_HEADLEN)) {
        return TP_ERR_INVALID_LENGTH;
    }

    log_debug("[TP] rx BF length=%d\n", length);
    tp->state = TP_STA_IDLE;
    tp->rx_msg_co(rxfrm->BF.data, length);
    return TP_ERR_NONE;
}
static tp_error_t tp_rxSF(tp_info_t* tp)
{
    tp_frame_t* rxfrm  = (tp_frame_t*)tp->rx_frm_buffer;
    uint16_t    length = ((uint16_t)rxfrm->SF.lengthH << 8) | rxfrm->SF.lengthL;

    if (length > tp->frm_size || length > tp->rx_frm_len - TP_SF_HEADLEN) {
        return TP_ERR_INVALID_LENGTH;
    }

    log_debug("[TP] rx SF length=%d\n", length);
    tp->state = TP_STA_IDLE;
    tp->rx_msg_co(rxfrm->SF.data, length);
    return TP_ERR_NONE;
}
static tp_error_t tp_rxFF(tp_info_t* tp)
{
    tp_frame_t* rxfrm  = (tp_frame_t*)tp->rx_frm_buffer;
    uint16_t    length = ((uint16_t)rxfrm->FF.lengthH << 8) | rxfrm->FF.lengthL;

    if ((length > tp->rx_msg_size) || (length <= tp->rx_frm_len - TP_FF_HEADLEN)) {
        return TP_ERR_INVALID_LENGTH;
    }
    tp->rx_msg_len = length;
    tp->rx_frm_seq = 0;

    length = tp->rx_frm_len - TP_FF_HEADLEN;
    memcpy(tp->rx_msg_buffer, rxfrm->FF.data, length);
    tp->rx_dat_num = length;

    log_debug("[TP] rx FF %d/%d\n", tp->rx_dat_num, tp->rx_msg_len);

    tp->state = TP_STA_WAIT_CF;
    return TP_ERR_NONE;
}
static tp_error_t tp_rxCF(tp_info_t* tp)
{
    tp_frame_t* rxfrm = (tp_frame_t*)tp->rx_frm_buffer;
    uint8_t     seq   = rxfrm->CF.seq;

    tp->rx_frm_seq = (tp->rx_frm_seq + 1) & TP_SEQ_MASK;
    if (seq != tp->rx_frm_seq) {
        return TP_ERR_FREME_SEQ;
    }

    uint16_t length = util_min2(tp->rx_msg_len - tp->rx_dat_num, tp->rx_frm_len - TP_CF_HEADLEN);
    memcpy(&tp->rx_msg_buffer[tp->rx_dat_num], rxfrm->CF.data, length);
    tp->rx_dat_num += length;

    log_debug("[TP] rx CF length=%d/%d\n", tp->rx_dat_num, tp->rx_msg_len);

    if (tp->rx_dat_num == tp->rx_msg_len) {
        tp->state = TP_STA_IDLE;

        tp->rx_msg_co(tp->rx_msg_buffer, tp->rx_msg_len);
    }
    return TP_ERR_NONE;
}
static tp_error_t tp_rxER(tp_info_t* tp)
{
    log_error("[TP] RX ER, clear tp state\r\n");

    if (tp->state == TP_STA_TX_CF) {
        if (tp->tx_msg_indication)
            tp->tx_msg_indication(false);
    }

    tp->state = TP_STA_IDLE;
    return TP_ERR_NONE;
}

static bool tp_txBF(tp_info_t* tp)
{
    // tx base frame, frame length is fixed at TP_FRM_LEN_MIN
    tp_frame_t* txfrm = (tp_frame_t*)tp->tx_frm_buffer;
    txfrm->BF.type    = TP_FRM_BF;
    txfrm->BF.length  = tp->tx_msg_len;
    // for BF, msg data is in tx_frm_buffer
    for (uint16_t i = tp->tx_msg_len + TP_BF_HEADLEN; i < TP_FRM_LEN_MIN; i++) {
        tp->tx_frm_buffer[i] = TP_PADDING_BYTE;
    }

    return tp->tx_frm_co(tp->tx_frm_buffer, TP_FRM_LEN_MIN);
}
static bool tp_txSF(tp_info_t* tp)
{
    // tx single frame, frame length is flexibly
    tp_frame_t* txfrm = (tp_frame_t*)tp->tx_frm_buffer;
    txfrm->SF.type    = TP_FRM_SF;
    txfrm->SF.lengthH = tp->tx_msg_len >> 8;
    txfrm->SF.lengthL = tp->tx_msg_len & 0xf;
    // for SF, msg data is in tx_frm_buffer

    return tp->tx_frm_co(tp->tx_frm_buffer, tp->tx_msg_len + TP_SF_HEADLEN);
}
static bool tp_txFF(tp_info_t* tp)
{
    // tx first frame, frame length is fixed at frame_len_max
    tp_frame_t* txfrm  = (tp_frame_t*)tp->tx_frm_buffer;
    uint16_t    length = tp->frm_size - TP_FF_HEADLEN;
    txfrm->FF.type     = TP_FRM_FF;
    txfrm->FF.lengthH  = tp->tx_msg_len >> 8;
    txfrm->FF.lengthL  = tp->tx_msg_len & 0xf;
    memcpy(txfrm->FF.data, tp->tx_msg_buffer, length);

    if (tp->tx_frm_co(tp->tx_frm_buffer, tp->frm_size)) {
        tp->tx_frm_seq = 0;
        tp->tx_dat_num = length;
        return true;
    } else {
        return false;
    }
}
static bool tp_txCF(tp_info_t* tp)
{
    // tx continous frame, frame length is fixed at frame_len_max
    tp_frame_t* txfrm  = (tp_frame_t*)tp->tx_frm_buffer;
    uint16_t    length = util_min2(tp->frm_size - TP_CF_HEADLEN, tp->tx_msg_len - tp->tx_dat_num);

    txfrm->CF.type = TP_FRM_CF;
    txfrm->CF.seq  = (tp->tx_frm_seq + 1) & TP_SEQ_MASK;
    memcpy(txfrm->CF.data, &tp->tx_msg_buffer[tp->tx_dat_num], length);
    for (uint16_t i = length + TP_CF_HEADLEN; i < tp->frm_size; i++) {
        tp->tx_frm_buffer[i] = TP_PADDING_BYTE;
    }

    if (tp->tx_frm_co(tp->tx_frm_buffer, tp->frm_size)) {
        tp->tx_dat_num += length;
        tp->tx_frm_seq = (tp->tx_frm_seq + 1) & TP_SEQ_MASK;
        return true;
    } else {
        return false;
    }
}
static bool tp_txER(tp_info_t* tp, tp_error_t errno, uint8_t param)
{
    tp_frame_t* txfrm = (tp_frame_t*)tp->tx_frm_buffer;
    txfrm->ER.type    = TP_FRM_ER;
    txfrm->ER.errno   = errno;
    txfrm->ER.param   = param;
    for (uint16_t i = TP_ER_HEADLEN; i < TP_FRM_LEN_MIN; i++) {
        tp->tx_frm_buffer[i] = TP_PADDING_BYTE;
    }

    return tp->tx_frm_co(tp->tx_frm_buffer, TP_FRM_LEN_MIN);
}

static void tp_rxproc(tp_info_t* tp)
{
    tp_error_t errno     = TP_ERR_NONE;
    uint8_t    err_param = 0;

    if (tp->rx_frm_flag) {
        uint8_t frm_type = (tp->rx_frm_buffer[0] >> 4) & 0xf;
        tp->rx_frm_flag  = false;
        errno            = TP_ERR_UNEXCEPT_FRAME;

        switch (frm_type) {
        case TP_FRM_BF:
            if (tp_reception_ready(tp)) {
                errno = tp_rxBF(tp);
            }
            break;
        case TP_FRM_SF:
            if (tp_reception_ready(tp)) {
                errno = tp_rxSF(tp);
            }
            break;
        case TP_FRM_FF:
            if (tp_reception_ready(tp)) {
                errno = tp_rxFF(tp);
            }
            break;
        case TP_FRM_CF:
            if (tp->state == TP_STA_WAIT_CF) {
                errno = tp_rxCF(tp);
            }
            break;
        case TP_FRM_ER:
            errno = tp_rxER(tp);
            break;
        default:
            errno = TP_ERR_INVALID_FRAME;
            break;
        }
    } else {
        // todo: timeout
    }

    if (errno != TP_ERR_NONE) {
        tp_txER(tp, errno, err_param);
        tp->state = TP_STA_IDLE;
    }
}
static void tp_txproc(tp_info_t* tp)
{
    if (!tp->tx_msg_flag) {
        return;
    }

    if (tp->state == TP_STA_TX_BF) {
        // base frame
        if (tp_txBF(tp)) {
            tp->tx_msg_flag = false;
            tp->state       = TP_STA_IDLE;
        }
    } else if (tp->state == TP_STA_TX_SF) {
        // single frame
        if (tp_txSF(tp)) {
            tp->tx_msg_flag = false;
            tp->state       = TP_STA_IDLE;
        }
    } else if (tp->state == TP_STA_TX_FF) {
        // multi frame
        if (tp_txFF(tp)) {
            tp->state = TP_STA_TX_CF;
        }
    } else if (tp->state == TP_STA_TX_CF) {
        // multi frame
        if (tp_txCF(tp)) {
            if (tp->tx_dat_num == tp->tx_msg_len) {
                tp->tx_msg_flag = false;
                tp->state       = TP_STA_IDLE;
            }
        }
    }

    if (!tp->tx_msg_flag) {
        if (tp->tx_msg_indication)
            tp->tx_msg_indication(true);
    }
}

bool tp_rxfrm_if(uint8_t chid, const uint8_t* data, uint16_t length)
{
    if (chid != current_chid) {
        return false;
    }
    tp_info_t* tp = &tp_info;

    if (length < TP_FRM_LEN_MIN) {
        return false;   // ignore
    }
    if (length > tp->frm_size) {
        length = tp->frm_size;   // cut off
    }

    memcpy(tp->rx_frm_buffer, data, length);
    tp->rx_frm_flag = true;
    tp->rx_frm_len  = length;
    return true;
}

bool tp_txmsg_if(const uint8_t* data, uint16_t length)
{
    tp_info_t* tp = &tp_info;

    if (tp->state != TP_STA_IDLE) {
        return false;
    }

    if (length <= TP_FRM_LEN_MIN - TP_BF_HEADLEN) {
        // base frame
        memcpy(tp->tx_frm_buffer + TP_BF_HEADLEN, data, length);
        tp->state = TP_STA_TX_BF;
    } else if (length <= tp->frm_size - TP_SF_HEADLEN) {
        // single frame
        memcpy(tp->tx_frm_buffer + TP_SF_HEADLEN, data, length);
        tp->state = TP_STA_TX_SF;
    } else {
        // multi frame
        if (length > tp->tx_msg_size) {
            return false;
        }
        memcpy(tp->tx_msg_buffer, data, length);
        tp->state = TP_STA_TX_FF;
    }

    log_debug("[TP] will tx msg len=%d!\n", length);

    tp->tx_msg_flag = true;
    tp->tx_msg_len  = length;
    return true;
}

void tp_activate(uint8_t chid)
{
    current_chid  = chid;
    tp_info.state = TP_STA_IDLE;
}

void tp_mainproc(void)
{
    tp_rxproc(&tp_info);
    tp_txproc(&tp_info);
}
