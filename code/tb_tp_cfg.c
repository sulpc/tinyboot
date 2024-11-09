#include "tb_tp.h"
#include "tb_utils.h"

#include "tb_ota.h"   // co: ota_msg_recieved


extern int32_t can_send_data(uint32_t bus, uint32_t id, uint8_t* data, uint32_t len);

static bool tp_send_frame_send_co(const uint8_t* data, uint16_t len)
{
    return (0 == can_send_data(0, 0x112, (uint8_t*)data, len));   // CAN_OTA_RSP_ID
}

#define TP_FRAME_SIZE      64
#define TP_TX_MESSAGE_SIZE (16)
#define TP_RX_MESSAGE_SIZE (1024 + 24)

static uint8_t tp_rx_frame_buffer[TP_FRAME_SIZE];
static uint8_t tp_tx_frame_buffer[TP_FRAME_SIZE];
static uint8_t tp_rx_message_buffer[TP_RX_MESSAGE_SIZE];
static uint8_t tp_tx_message_buffer[TP_TX_MESSAGE_SIZE];

tp_info_t tp_info = {
    .rx_msg_co     = ota_msg_recieved,
    .tx_frm_co     = tp_send_frame_send_co,
    .rx_frm_buffer = tp_rx_frame_buffer,
    .tx_frm_buffer = tp_tx_frame_buffer,
    .frm_size      = TP_FRAME_SIZE,
    .rx_msg_size   = TP_RX_MESSAGE_SIZE,
    .tx_msg_size   = TP_TX_MESSAGE_SIZE,
    .rx_msg_buffer = tp_rx_message_buffer,
    .tx_msg_buffer = tp_tx_message_buffer,
    .state         = TP_STA_IDLE,
};
