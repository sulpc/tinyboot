#-*- encoding:UTF-8 -*-
from tinytp import TinyTp

import abc
import datetime
import crcmod
from enum import Enum, auto
from queue import Queue

auto_inc_val = 0
def auto_inc(begin=None):
    global auto_inc_val
    if begin is not None:
        auto_inc_val = begin
    else:
        auto_inc_val += 1
    return auto_inc_val


FRAME_BATCH                 = 40
QUERY_PERIOD                = 200

WAIT_FWINFO_ACK_TIMEOUT     = 100    # 等待fwinfo ack, 超时则retry
WAIT_FWDATA_ACK_TIMEOUT     = 100    # 等待fwdata ack, 超时则开始query
WAIT_INTO_BOOT_TIMEOUT      = 1000   # 等待mcu进入boot, 周期query, 超时失败
WAIT_READY_RX_TIMEOUT       = 5000   # 等待mcu进入rx状态, 周期query, 超时失败
WAIT_OTA_FINISH_TIMEOUT     = 30000  # 等待ota结束, 周期query, 超时失败
WAIT_READY_RX_QUERY_PERIOD  = 100

class OtaState(Enum):
    START                   = auto()
    SEND_FWINFO             = auto()
    WAIT_FWINFO_ACK         = auto()
    SEND_FWDATA             = auto()
    WAIT_FWDATA_ACK         = auto()
    WAIT_RESULT             = auto()
    OK                      = auto()
    FAIL                    = auto()
    STAT_QUERY              = auto()

# ota_state_t
OTA_STA_IDLE                = auto_inc(0)
OTA_STA_RECEIVING           = auto_inc()
OTA_STA_RECEIVED            = auto_inc()
OTA_STA_PROGRAM             = auto_inc()
OTA_STA_CHECK               = auto_inc()
OTA_STA_OK                  = auto_inc()
OTA_STA_FAIL                = auto_inc()
ota_state_info = {
    OTA_STA_IDLE            : 'idle',
    OTA_STA_RECEIVING       : 'receiving',
    OTA_STA_RECEIVED        : 'received',
    OTA_STA_PROGRAM         : 'program',
    OTA_STA_CHECK           : 'check',
    OTA_STA_OK              : 'ok',
    OTA_STA_FAIL            : 'fail',
}

# ota_error_t
OTA_ERR_NONE                = auto_inc(0)
OTA_ERR_INVALID_MESSAGE     = auto_inc()
OTA_ERR_UNEXPECTED_MESSAGE  = auto_inc()
OTA_ERR_FWINFO_CRC_INVALID  = auto_inc()
OTA_ERR_FWINFO_ID_INVALID   = auto_inc()
OTA_ERR_FWINFO_ADDR_INVALID = auto_inc()
OTA_ERR_FWINFO_SIZE_INVALID = auto_inc()
OTA_ERR_FWINFO_CRYP_INVALID = auto_inc()
OTA_ERR_FWDATA_CRC_INVALID  = auto_inc()
OTA_ERR_FWDATA_OFF_INVALID  = auto_inc()
OTA_ERR_FWDATA_SIZE_INVALID = auto_inc()
OTA_ERR_FW_PROGRAM_FAIL     = auto_inc()
OTA_ERR_FW_CRCCHECK_FAIL    = auto_inc()
OTA_ERR_FW_RECHECK_FAIL     = auto_inc()
OTA_ERR_INTERUPT            = auto_inc()
ota_error_info = {
    OTA_ERR_NONE                : 'OTA_ERR_NONE               ',
    OTA_ERR_INVALID_MESSAGE     : 'OTA_ERR_INVALID_MESSAGE    ',
    OTA_ERR_UNEXPECTED_MESSAGE  : 'OTA_ERR_UNEXPECTED_MESSAGE ',
    OTA_ERR_FWINFO_CRC_INVALID  : 'OTA_ERR_FWINFO_CRC_INVALID ',
    OTA_ERR_FWINFO_ID_INVALID   : 'OTA_ERR_FWINFO_ID_INVALID  ',
    OTA_ERR_FWINFO_ADDR_INVALID : 'OTA_ERR_FWINFO_ADDR_INVALID',
    OTA_ERR_FWINFO_SIZE_INVALID : 'OTA_ERR_FWINFO_SIZE_INVALID',
    OTA_ERR_FWINFO_CRYP_INVALID : 'OTA_ERR_FWINFO_CRYP_INVALID',
    OTA_ERR_FWDATA_CRC_INVALID  : 'OTA_ERR_FWDATA_CRC_INVALID ',
    OTA_ERR_FWDATA_OFF_INVALID  : 'OTA_ERR_FWDATA_OFF_INVALID ',
    OTA_ERR_FWDATA_SIZE_INVALID : 'OTA_ERR_FWDATA_SIZE_INVALID',
    OTA_ERR_FW_PROGRAM_FAIL     : 'OTA_ERR_FW_PROGRAM_FAIL    ',
    OTA_ERR_FW_CRCCHECK_FAIL    : 'OTA_ERR_FW_CRCCHECK_FAIL   ',
    OTA_ERR_FW_RECHECK_FAIL     : 'OTA_ERR_FW_RECHECK_FAIL    ',
    OTA_ERR_INTERUPT            : 'OTA_ERR_INTERUPT           ',
}

# ota_msgtype_t
OTA_MSG_CTRL                = auto_inc(0)
OTA_MSG_FWINFO              = auto_inc()
OTA_MSG_FWDATA              = auto_inc()
OTA_MSG_ERROR               = 0xf

# ota_ctrl_cmd_t
OTA_CTRL_CMD_QUERYSTAT      = 1

OTA_CTRL_ACK_LEN_MIN        = 3
OTA_FWINFO_ACK_LEN          = 3
OTA_FWDATA_ACK_LEN          = 4
OTA_ERROR_MSG_LEN           = 3

OTA_FWDATA_ACK_OK           = auto_inc(0)
OTA_FWDATA_ACK_DELAY        = auto_inc()
OTA_FWDATA_ACK_BURNING      = auto_inc()


calc_crc32 = crcmod.predefined.mkPredefinedCrcFun('crc-32')
calc_crc16 = crcmod.predefined.mkPredefinedCrcFun('modbus')

def time_info():
    return f'[{datetime.datetime.now().strftime("%H:%M:%S.%f")}]'


def dump_bytes(data):
    return f'{" ".join([f"{d:02X}" for d in data])}'   # '%02X' % d


class FwInfo:
    def __init__(self) -> None:
        self.id      = 0
        self.addr    = 0
        self.size    = 0
        self.crypto  = 0
        self.crc32   = 0


class EndException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class TinyOta(abc.ABC):
    def __init__(self, dis_log=None, dis_msg=None, piece=1024) -> None:
        self._print_log = dis_log if dis_log else print
        self._print_msg = dis_msg if dis_msg else print

        self.tp         = TinyTp('tp',
                                 rx_msg_co=self.recv_message,
                                 tx_frm_co=self.send_frame,
                                 tx_msg_indication=self.send_message_indication,
                                 log_on=False)
        self.state      = OtaState.FAIL
        self.queue      = Queue()       # frame queue 
        self.fwinfo     = FwInfo()
        self.fwdata     = []
        self.tx_offset  = 0
        self.tx_just    = 0
        self.piece      = piece
        self.timer      = 0
        self.timeout    = 0
        self.state_last = OtaState.FAIL
        self.inboot     = False

    def send_message_indication(self, finish: bool):
        self.send_ok = True

    def send_message(self, data):
        '''
        send message, when fail, raise EndException
        '''
        if self.tp.txmsg_if(data):
            # self._print_msg(f'{time_info()} TX MSG {dump_bytes(data)}')
            self.send_ok = False
            return True
        else:
            self._print_log(f'[!] {time_info()} send message fail!')
            raise EndException()
            # return False

    def state_switch(self, newstate, timeout=0):
        '''
        wait state must has a timeout
        '''
        self.state_last = self.state
        self.timer      = 0
        self.timeout    = timeout
        self.state      = newstate

    def repeat_query(self, timeout, repeat_period=QUERY_PERIOD):
        '''
        enter query mode, send query ctrl msg periodicly

        if timeout < repeat_period, will be simply delay
        '''
        self.state_last     = self.state
        self.repeat_period  = repeat_period
        self.timer          = 0
        self.timeout        = timeout
        self.state          = OtaState.STAT_QUERY

    def recv_fwinfo_ack(self, data):
        if self.state == OtaState.WAIT_FWINFO_ACK:
            if len(data) != OTA_FWINFO_ACK_LEN:
                return False

            fw_id, result = self.parse_fwinfo_ack(data)

            if fw_id == self.fwinfo.id and result == 1:
                self._print_log(f'[-] {time_info()} ota recv fwinfo ack ok\n')

                self.tx_offset  = 0
                self.tx_just      = 0
                self.state      = OtaState.SEND_FWDATA
                return True
        return False

    def recv_fwdata_ack(self, data):
        if self.state == OtaState.WAIT_FWDATA_ACK:
            if len(data) != OTA_FWDATA_ACK_LEN:
                return False

            size, result = self.parse_fwdata_ack(data)
            if size == self.tx_just:
                # self._print_log(f'[-] {time_info()} ota recv fwdata ack {self.tx_offset:08x}+{size} {self.tx_offset+size}/{len(self.fwdata)} result={result}')
                self.tx_offset += size
                self.tx_just      = 0

                if self.tx_offset == len(self.fwdata):
                    self._print_log(f'[-] {time_info()} ota send fwdata finish\n')
                    self.state_switch(OtaState.WAIT_RESULT, WAIT_OTA_FINISH_TIMEOUT)
                    return True
                elif self.tx_offset < len(self.fwdata):
                    if result == OTA_FWDATA_ACK_OK:
                        self.state_switch(OtaState.SEND_FWDATA)
                    else:
                        self._print_log(f'[-] {time_info()} ota recv fwdata busy\n')
                        self.repeat_query(WAIT_READY_RX_TIMEOUT, repeat_period=WAIT_READY_RX_QUERY_PERIOD)
                    return True
                else:
                    self._print_log(f'[!] fwdata ack size overflow')
        return False

    def recv_error_msg(self, data):
        print(f'[!] ota recv errormsg {dump_bytes(data)}, {ota_error_info[data[1]]}')
        return False

    def recv_ctrl_ack(self, data):
        if len(data) < OTA_CTRL_ACK_LEN_MIN:
            return False
        
        if data[1] == OTA_CTRL_CMD_QUERYSTAT and self.state == OtaState.STAT_QUERY:
            if len(data) < OTA_CTRL_ACK_LEN_MIN + 1:
                return False

            state, progress = data[2], data[3]

            if self.state_last == OtaState.START:
                if True:   # state in (OTA_STA_IDLE, OTA_STA_OK, OTA_STA_FAIL):
                    self.inboot = True
                    self._print_log(f'[-] {time_info()} mcu in boot\n')
                    self.state_switch(OtaState.SEND_FWINFO)
                    return True

            if self.state_last == OtaState.WAIT_FWDATA_ACK:
                if state == OTA_STA_RECEIVING:
                    self._print_log(f'[-] {time_info()} ota send fwdata recover')
                    self.state_switch(OtaState.SEND_FWDATA)
                    return True
                elif state == OTA_STA_PROGRAM:
                    self._print_log(f'[-] {time_info()} mcu program {progress}%')
                    return True

            if self.state_last == OtaState.WAIT_RESULT:
                if state == OTA_STA_PROGRAM:
                    self._print_log(f'[-] {time_info()} mcu program {progress}%')
                    return True
                elif state == OTA_STA_CHECK:
                    self._print_log(f'[-] {time_info()} mcu check {progress}%')
                    return True
                elif state == OTA_STA_OK:
                    self.state_switch(OtaState.OK)
                    return True
                elif state == OTA_STA_FAIL:
                    self.state_switch(OtaState.FAIL)
                    return True

        return False

    def recv_message(self, data, length):
        # self._print_msg(f'{time_info()} RX MSG {dump_bytes(data)}')
        ok = False
        if data[0] == OTA_MSG_FWINFO:
            ok = self.recv_fwinfo_ack(data)
        elif data[0] == OTA_MSG_FWDATA:
            ok = self.recv_fwdata_ack(data)
        elif data[0] == OTA_MSG_ERROR:
            ok = self.recv_error_msg(data)
        elif data[0] == OTA_MSG_CTRL:
            ok = self.recv_ctrl_ack(data)

        if not ok:
            self._print_log(f'[!] rx invalid message {data} at {self.state}')
            raise EndException()

    def set_fwinfo(self, fw_id, fw_addr, fw_data, crypto):
        self.fwdata        = fw_data
        self.fwinfo.id     = fw_id
        self.fwinfo.addr   = fw_addr
        self.fwinfo.size   = len(fw_data)
        self.fwinfo.crypto = crypto
        self.fwinfo.crc32  = calc_crc32(self.fwdata)
        self.tx_offset     = 0
        self.tx_just       = 0

        self.state_switch(OtaState.START)
        self._print_log(f'set fwinfo: id={fw_id} addr=0x{fw_addr:08x} size={self.fwinfo.size} crc32={self.fwinfo.crc32:08x} piece={self.piece}')

    def ota_proc(self, period):
        self.timer += period

        if self.state == OtaState.START:
            if self.inboot:
                self.state_switch(OtaState.SEND_FWINFO)
            else:
                if self.send_ota_command():
                    self._print_log(f'[-] {time_info()} trigger mcu enter boot')
                    self.repeat_query(WAIT_INTO_BOOT_TIMEOUT)
                else:
                    self._print_log(f'[!] mcu enter boot fail')
                    raise EndException()

        elif self.state == OtaState.SEND_FWINFO:
            msg = self.make_fwinfo_msg(self.fwinfo.id, self.fwinfo.crypto, self.fwinfo.addr, self.fwinfo.size, self.fwinfo.crc32)
            self.send_message(msg)
            self._print_log(f'[-] {time_info()} ota send fwinfo')
            self.state_switch(OtaState.WAIT_FWINFO_ACK, WAIT_FWINFO_ACK_TIMEOUT)

        elif self.state == OtaState.WAIT_FWINFO_ACK:
            if self.timer > self.timeout:
                self._print_log(f'[-] {time_info()} ota recv fwinfo ack timeout')
                raise EndException()

        elif self.state == OtaState.SEND_FWDATA:
            self.tx_just = min(len(self.fwdata)-self.tx_offset, self.piece)

            msg = self.make_fwdata_msg(self.tx_just, self.tx_offset, self.fwdata[self.tx_offset: self.tx_offset+self.tx_just])
            self.send_message(msg)
            self._print_log(f'[-] {time_info()} ota send fwdata {self.tx_offset:08x}+{self.tx_just}')
            self.state_switch(OtaState.WAIT_FWDATA_ACK, WAIT_FWDATA_ACK_TIMEOUT)

        elif self.state == OtaState.WAIT_FWDATA_ACK:
            if self.timer > self.timeout:
                self._print_log(f'[!] {time_info()} ota recv fwdata ack timeout\n')
                raise EndException()

        elif self.state == OtaState.WAIT_RESULT:
            self.repeat_query(self.timeout)

        elif self.state == OtaState.OK:
            self._print_log(f'[-] {time_info()} ota ok')
            raise EndException()

        elif self.state == OtaState.FAIL:
            self._print_log(f'[!] {time_info()} ota fail')
            raise EndException()

        elif self.state == OtaState.STAT_QUERY:
            if self.timer >= self.repeat_period:
                self.timer = 0
                self.timeout -= self.repeat_period

                if self.timeout < 0:
                    self._print_log(f'[!] {time_info()} retry query timeout @{self.state_last}')
                    raise EndException()

                msg = self.make_ctrl_msg(OTA_CTRL_CMD_QUERYSTAT)
                self.send_message(msg)

    def mainproc(self, period, accelerate=True):
        '''
        ota main proc

        TP runs in query mode, query new frame, process it (tp.mainproc) must be in same thread
        TP and OTA should be executed in same thread, with same cycle

        tp can rx/tx one frame per cycle
        '''
        if not self.queue.empty():
            self.tp.rxfrm_if(self.queue.get())
        self.tp.mainproc()
        self.ota_proc(period)

        if accelerate:
            # if there are message to be sent, send them all in one loop
            for i in range(FRAME_BATCH):
                self.tp.mainproc()
                if self.tp.idle():
                    break

    def make_ctrl_msg(self, cmd, param=None):
        msg = [OTA_MSG_CTRL]
        msg.append(cmd)
        if param:
            msg.extend(param)
        return msg

    def make_fwdata_msg(self, size, offset, data):
        msg = bytearray([OTA_MSG_FWDATA])
        msg.append((size    >>  8) & 0xff)
        msg.append((size    >>  0) & 0xff)
        msg.append((offset  >> 24) & 0xff)
        msg.append((offset  >> 16) & 0xff)
        msg.append((offset  >>  8) & 0xff)
        msg.append((offset  >>  0) & 0xff)
        msg.extend(data)

        crc16 = calc_crc16(msg)
        msg.append((crc16  >>  8) & 0xff)
        msg.append((crc16  >>  0) & 0xff)
        return msg

    def parse_fwdata_ack(self, msg):
        size   = (msg[1] << 8) + msg[2]
        result = msg[3]
        return size, result

    def make_fwinfo_msg(self, fw_id, crypto, fw_addr, fw_size, fw_crc32):
        msg = bytearray([OTA_MSG_FWINFO, fw_id, crypto])
        msg.append((fw_addr  >> 24) & 0xff)
        msg.append((fw_addr  >> 16) & 0xff)
        msg.append((fw_addr  >>  8) & 0xff)
        msg.append((fw_addr  >>  0) & 0xff)
        msg.append((fw_size  >> 24) & 0xff)
        msg.append((fw_size  >> 16) & 0xff)
        msg.append((fw_size  >>  8) & 0xff)
        msg.append((fw_size  >>  0) & 0xff)
        msg.append((fw_crc32 >> 24) & 0xff)
        msg.append((fw_crc32 >> 16) & 0xff)
        msg.append((fw_crc32 >>  8) & 0xff)
        msg.append((fw_crc32 >>  0) & 0xff)

        crc16 = calc_crc16(msg)
        msg.append((crc16 >>  8) & 0xff)
        msg.append((crc16 >>  0) & 0xff)
        return msg

    def parse_fwinfo_ack(self, msg):
        fw_id  = msg[1]
        result = msg[2]
        return fw_id, result

    def recv_frame(self, data, length=8):
        '''
        should be called
        '''
        self.queue.put(data)

    @abc.abstractmethod
    def start(self, trace=False):
        '''
        initialize the communication interface,
        start a thread to handle the communication task,
        when a complete data frame is received, call `self.recv_frame(data)`.
        '''
        pass

    @abc.abstractmethod
    def close(self):
        '''
        base commu interface start
        '''
        pass

    @abc.abstractmethod
    def send_ota_command(self) -> bool:
        '''
        trigger mcu into boot mode
        '''
        pass

    @abc.abstractmethod
    def send_frame(self, data, length):
        '''
        send frame, when fail, raise EndException
        '''
        pass
