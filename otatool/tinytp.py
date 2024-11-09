#-*- encoding:UTF-8 -*-

# tp_state_t
TP_STA_IDLE                 = 0
TP_STA_WAIT_CF              = 1
TP_STA_TX_BF                = 2
TP_STA_TX_SF                = 3
TP_STA_TX_FF                = 4
TP_STA_TX_CF                = 5

# tp_error_t
TP_ERR_NONE                 = 0
TP_ERR_UNEXCEPT_FRAME       = 1
TP_ERR_INVALID_FRAME        = 2
TP_ERR_PROTO_CTRL           = 3
TP_ERR_MESSAGE_TOO_LONG     = 4
TP_ERR_INVALID_LENGTH       = 5
TP_ERR_FREME_SEQ            = 6

TP_PADDING_BYTE             = 0xAA
TP_FRM_BF                   = 0x0
TP_FRM_SF                   = 0x1
TP_FRM_FF                   = 0x2
TP_FRM_CF                   = 0x3
TP_FRM_ER                   = 0x4
TP_BF_HEADLEN               = 1
TP_SF_HEADLEN               = 2
TP_FF_HEADLEN               = 2
TP_CF_HEADLEN               = 1
TP_ER_HEADLEN               = 3
TP_SEQ_MASK                 = 0xf
TP_FRM_LEN_MIN              = 8

class TinyTp:
    def __init__(self, name, rx_msg_co, tx_frm_co, tx_msg_indication=None, frm_size=8, tx_msg_size=1048, rx_msg_size=1048, log_on=True) -> None:
        self.rx_msg_co      = rx_msg_co
        self.tx_frm_co      = tx_frm_co
        self.tx_msg_indication = tx_msg_indication
        self.rx_frm_buffer  = []
        self.tx_frm_buffer  = []
        self.frm_size       = frm_size      # frm_size == sizeof(rx_frm_buffer) == sizeof(tx_frm_buffer)
        self.tx_msg_size    = tx_msg_size   #
        self.rx_msg_size    = rx_msg_size   #
        self.rx_msg_buffer  = []            #
        self.tx_msg_buffer  = []            #
        self.state          = TP_STA_IDLE   # state

        self.rx_frm_len     = 0             #
        self.rx_frm_flag    = False         #
        self.tx_msg_flag    = False         #
        self.rx_frm_seq     = 0             # multi frame rx, frame seq
        self.tx_frm_seq     = 0             # multi frame tx, frame seq
        self.rx_msg_len     = 0             # multi frame rx, message len all
        self.rx_dat_num     = 0             # multi frame rx, data len received
        self.tx_msg_len     = 0             # multi frame tx, message len all
        self.tx_dat_num     = 0             # multi frame tx, data len sent

        self.log_on         = log_on
        self.name           = name

    def log(self, *args, **kwarg):
        if self.log_on:
            print(*args, **kwarg)

    def parse_frame(self, frame):
        frm_type = frame[0] >> 4
        if frm_type == TP_FRM_BF:
            length = frame[0] & 0xF
            data   = frame[TP_BF_HEADLEN:TP_BF_HEADLEN+length]
            return length, data
        if frm_type == TP_FRM_SF:
            length = (frame[0] & 0xF) * 256 + frame[1]
            data   = frame[TP_SF_HEADLEN:TP_SF_HEADLEN+length]
            return length, data
        if frm_type == TP_FRM_FF:
            length = (frame[0] & 0xF) * 256 + frame[1]
            data   = frame[TP_FF_HEADLEN:]
            return length, data
        if frm_type == TP_FRM_CF:
            seq    = frame[0] & 0xF
            data   = frame[TP_CF_HEADLEN:]
            return seq, data
        if frm_type == TP_FRM_ER:
            errno  = frame[1]
            param  = frame[2]
            return errno, param
        return None

    def make_frame(self, frm_type, **kwarg):
        frame = []
        if frm_type == TP_FRM_BF:
            length = kwarg['length']
            data   = kwarg['data']
            frame.append((frm_type << 4) + length)
            frame.extend(data)
            for i in range(length + TP_BF_HEADLEN, TP_FRM_LEN_MIN):
                frame.append(TP_PADDING_BYTE)
        if frm_type == TP_FRM_SF:
            length = kwarg['length']
            data   = kwarg['data']
            frame.append((frm_type << 4) + (length >> 8))
            frame.append(length & 0xFF)
            frame.extend(data)
        if frm_type == TP_FRM_FF:
            length = kwarg['length']
            data   = kwarg['data']
            frame.append((frm_type << 4) + (length >> 8))
            frame.append(length & 0xFF)
            frame.extend(data)
            for i in range(length + TP_FF_HEADLEN, self.frm_size):
                frame.append(TP_PADDING_BYTE)
        if frm_type == TP_FRM_CF:
            seq    = kwarg['seq']
            data   = kwarg['data']
            length = len(data)
            frame.append((frm_type << 4) + (seq & 0xf))
            frame.extend(data)
            for i in range(length + TP_CF_HEADLEN, self.frm_size):
                frame.append(TP_PADDING_BYTE)
        if frm_type == TP_FRM_ER:
            errno  = kwarg['errno']
            param  = kwarg['param']
            frame.append((frm_type << 4))
            frame.append(errno)
            frame.append(param)
            for i in range(3, TP_FRM_LEN_MIN):
                frame.append(TP_PADDING_BYTE)
        return frame

    def rxfrm_if(self, data):
        length = len(data)
        if length < TP_FRM_LEN_MIN:
            return False

        if length > self.frm_size:
            length = self.frm_size

        self.rx_frm_buffer = []
        self.rx_frm_buffer.extend(data[:length])
        self.rx_frm_flag = True
        self.rx_frm_len  = length
        return True

    def txmsg_if(self, data):
        if (self.state != TP_STA_IDLE):
            return False
        length = len(data)
    
        if length > self.tx_msg_size:
            return False
        
        # self.log(f"{self.name} TX MSG: {' '.join(['%02X ' % d for d in data])}")

        self.tx_msg_buffer = []
        self.tx_msg_buffer.extend(data)   # 和c代码相比，这里不进行优化，使用两级缓冲
        self.tx_msg_flag = True
        self.tx_msg_len  = length

        if length <= TP_FRM_LEN_MIN - TP_BF_HEADLEN:
            # base frame
            self.state = TP_STA_TX_BF
        elif length <= self.frm_size - TP_SF_HEADLEN:
            # single frame
            self.state = TP_STA_TX_SF
        else:
            # multi frame
            self.state = TP_STA_TX_FF

        self.tx_msg_flag = True
        return True

    def rxBF(self):
        length, data = self.parse_frame(self.rx_frm_buffer)

        if ((length > self.rx_frm_len - TP_BF_HEADLEN)):
            return TP_ERR_INVALID_LENGTH

        # self.log(f"    rx BF length={length}    {self.name}")
        self.state = TP_STA_IDLE
        self.rx_msg_co(data, length)
        return TP_ERR_NONE

    def rxSF(self):
        length, data = self.parse_frame(self.rx_frm_buffer)

        if (length > self.frm_size or length > self.rx_frm_len - TP_SF_HEADLEN):
            return TP_ERR_INVALID_LENGTH

        # self.log(f"    rx SF length={length}    {self.name}")
        self.state = TP_STA_IDLE
        self.rx_msg_co(data, length)
        return TP_ERR_NONE

    def rxFF(self):
        length, data = self.parse_frame(self.rx_frm_buffer)

        if ((length > self.rx_msg_size) or (length <= self.rx_frm_len - TP_FF_HEADLEN)):
            return TP_ERR_INVALID_LENGTH

        self.rx_msg_len = length
        self.rx_frm_seq = 0

        length = self.rx_frm_len - TP_FF_HEADLEN

        self.rx_msg_buffer = []
        self.rx_msg_buffer.extend(data)

        self.rx_dat_num = length

        # self.log(f"    rx FF {self.rx_dat_num}/{self.rx_msg_len}    {self.name}")

        self.state = TP_STA_WAIT_CF
        return TP_ERR_NONE

    def rxCF(self):
        seq, data = self.parse_frame(self.rx_frm_buffer)

        self.rx_frm_seq = (self.rx_frm_seq + 1) & TP_SEQ_MASK
        # self.log(f'tp rx cf wait seq {self.rx_frm_seq}, rx seq {seq}')
        if (seq != self.rx_frm_seq):
            self.log(f'tp rx cf seq error')
            return TP_ERR_FREME_SEQ

        length = min(self.rx_msg_len - self.rx_dat_num, self.rx_frm_len - TP_CF_HEADLEN)
        self.rx_msg_buffer.extend(data[:length])
        self.rx_dat_num += length

        # self.log(f"    rx CF {self.rx_dat_num}/{self.rx_msg_len}    {self.name}")

        if (self.rx_dat_num == self.rx_msg_len):
            self.state = TP_STA_IDLE
            self.rx_msg_co(self.rx_msg_buffer[:self.rx_msg_len], self.rx_msg_len)

        return TP_ERR_NONE

    def rxER(self):
        errno, param = self.parse_frame(self.rx_frm_buffer)
        self.log(f"{self.name} RX ER, errno={errno}, param={param}, clear tp state")
        if self.tx_msg_indication:
            self.tx_msg_indication(False)
        self.state = TP_STA_IDLE
        return TP_ERR_NONE

    def txBF(self):
        # self.log(f'    txBF            {self.name}')
        # tx base frame, frame length is fixed at TP_FRM_LEN_MIN
        self.tx_frm_buffer = self.make_frame(TP_FRM_BF, 
                                             data=self.tx_msg_buffer, 
                                             length=len(self.tx_msg_buffer))
        return self.tx_frm_co(self.tx_frm_buffer, TP_FRM_LEN_MIN)

    def txSF(self):
        # self.log(f'    txSF                    {self.name}')
        # tx single frame, frame length is flexibly
        self.tx_frm_buffer = self.make_frame(TP_FRM_SF, 
                                             data=self.tx_msg_buffer, 
                                             length=len(self.tx_msg_buffer))
        return self.tx_frm_co(self.tx_frm_buffer, len(self.tx_msg_buffer) + TP_SF_HEADLEN)

    def txFF(self):
        # self.log(f'    txFF                    {self.name}')
        # tx first frame, frame length is fixed at frame_len_max
        length = self.frm_size - TP_FF_HEADLEN
        self.tx_frm_buffer = self.make_frame(TP_FRM_FF, 
                                             data=self.tx_msg_buffer[:length], 
                                             length=len(self.tx_msg_buffer))
        if self.tx_frm_co(self.tx_frm_buffer, self.frm_size):
            self.tx_frm_seq = 1
            self.tx_dat_num = length
            return True
        else:
            return False

    def txCF(self):
        # self.log(f'    txCF                    {self.name}')
        # tx continous frame, frame length is fixed at frame_len_max
        length = min(self.frm_size - TP_CF_HEADLEN, self.tx_msg_len - self.tx_dat_num)
        
        self.tx_frm_buffer = self.make_frame(TP_FRM_CF, 
                                             data=self.tx_msg_buffer[self.tx_dat_num:self.tx_dat_num+length], 
                                             seq=self.tx_frm_seq)
        if self.tx_frm_co(self.tx_frm_buffer, self.frm_size):
            self.tx_dat_num += length
            self.tx_frm_seq += 1
            return True
        else:
            return False

    def txER(self, errno, param):
        self.log(f"{self.name} TX ER, errno={errno}, param={param}, clear tp state")
        self.tx_frm_buffer = self.make_frame(TP_FRM_ER, errno=errno, param=param)
        return self.tx_frm_co(self.tx_frm_buffer, TP_FRM_LEN_MIN)

    def rxproc(self):
        errno     = TP_ERR_NONE
        err_param = 0

        if (self.rx_frm_flag):
            frm_type = (self.rx_frm_buffer[0] >> 4) & 0xf
            self.rx_frm_flag  = False

            # self.log(f"{self.name} RX FRM: {' '.join(['%02X ' % d for d in self.rx_frm_buffer])}")

            if frm_type == TP_FRM_BF:
                if self.state == TP_STA_IDLE:
                    errno = self.rxBF()
                else:
                    errno = TP_ERR_UNEXCEPT_FRAME
            elif frm_type == TP_FRM_SF:
                if self.state == TP_STA_IDLE:
                    errno = self.rxSF()
                else:
                    errno = TP_ERR_UNEXCEPT_FRAME
            elif frm_type == TP_FRM_FF:
                if self.state == TP_STA_IDLE:
                    errno = self.rxFF()
                else:
                    errno = TP_ERR_UNEXCEPT_FRAME
            elif frm_type == TP_FRM_CF:
                if self.state == TP_STA_WAIT_CF:
                    errno = self.rxCF()
                else:
                    errno = TP_ERR_UNEXCEPT_FRAME
            elif frm_type == TP_FRM_ER:
                errno = self.rxER()
            else:
                errno = TP_ERR_INVALID_FRAME
        else:
            # todo: timeout
            pass

        if errno != TP_ERR_NONE:
            if errno == TP_ERR_UNEXCEPT_FRAME:
                self.log(f'err: unexcept frame={frm_type}, state={self.state}')

            self.txER(errno, err_param)
            self.state = TP_STA_IDLE

    def txproc(self):
        if not self.tx_msg_flag:
            return

        if (self.state == TP_STA_TX_BF):
            # base frame
            if (self.txBF()):
                self.tx_msg_flag = False
                self.state       = TP_STA_IDLE
        elif (self.state == TP_STA_TX_SF):
            # single frame
            if (self.txSF()):
                self.tx_msg_flag = False
                self.state       = TP_STA_IDLE
        elif (self.state == TP_STA_TX_FF):
            # multi frame
            if (self.txFF()):
                self.state = TP_STA_TX_CF
        elif (self.state == TP_STA_TX_CF):
            # multi frame
            if (self.txCF()):
                if (self.tx_dat_num == self.tx_msg_len):
                    self.tx_msg_flag = False
                    self.state       = TP_STA_IDLE

        if not self.tx_msg_flag:
            if self.tx_msg_indication:
                self.tx_msg_indication(True)

    def idle(self):
        return self.state == TP_STA_IDLE

    def mainproc(self):
        self.rxproc()
        self.txproc()


