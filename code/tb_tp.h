#ifndef _TB_TP_H_
#define _TB_TP_H_

#include "tb_types.h"

typedef enum {
    TP_STA_IDLE = 0,
    TP_STA_WAIT_CF,
    TP_STA_TX_BF,
    TP_STA_TX_SF,
    TP_STA_TX_FF,
    TP_STA_TX_CF,
} tp_state_t;

typedef enum {
    TP_ERR_NONE = 0,
    TP_ERR_UNEXCEPT_FRAME,
    TP_ERR_INVALID_FRAME,
    TP_ERR_PROTO_CTRL,
    TP_ERR_MESSAGE_TOO_LONG,
    TP_ERR_INVALID_LENGTH,
    TP_ERR_FREME_SEQ,
} tp_error_t;

typedef void (*tp_rxmsg_co_t)(const uint8_t* data, uint16_t len);
typedef bool (*tp_txfrm_co_t)(const uint8_t* data, uint16_t len);
typedef void (*tp_txmsg_indication_t)(bool finish);


typedef struct {
    // config
    const tp_rxmsg_co_t         rx_msg_co;
    const tp_txfrm_co_t         tx_frm_co;
    const tp_txmsg_indication_t tx_msg_indication;
    uint8_t* const              rx_frm_buffer;
    uint8_t* const              tx_frm_buffer;
    const uint16_t              frm_size;        // frm_size == sizeof(frm_buffer)
    const uint16_t              tx_msg_size;     // tx_msg_size == sizeof(tx_msg_buffer)
    const uint16_t              rx_msg_size;     // rx_msg_size == sizeof(rx_msg_buffer)
    uint8_t* const              rx_msg_buffer;   // if multi frame is not used, msg_buffer could be nullptr,
    uint8_t* const              tx_msg_buffer;   //   and msg_size should be 0
    tp_state_t                  state;           // state
    uint16_t                    rx_frm_len;      //
    bool                        rx_frm_flag;     //
    bool                        tx_msg_flag;     //
    uint8_t                     rx_frm_seq;      // multi frame rx, frame seq
    uint8_t                     tx_frm_seq;      // multi frame tx, frame seq
    uint16_t                    rx_msg_len;      // multi frame rx, message len all
    uint16_t                    rx_dat_num;      // multi frame rx, data len received
    uint16_t                    tx_msg_len;      // multi frame tx, message len all
    uint16_t                    tx_dat_num;      // multi frame tx, data len sent
    uint32_t                    run_time;
} tp_info_t;

extern tp_info_t tp_info;

void tp_activate(uint8_t chid);
bool tp_rxfrm_if(uint8_t chid, const uint8_t* data, uint16_t len);
bool tp_txmsg_if(const uint8_t* data, uint16_t len);
void tp_mainproc(void);

#endif
