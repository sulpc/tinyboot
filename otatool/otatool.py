#-*- encoding:UTF-8 -*-

from candev import CanDev
from tinyota import TinyOta, EndException

import argparse
import os
import sys
import datetime
import time
import threading

CAN_OTA_ID      = 0x111
CAN_OTA_RSP_ID  = 0x112
OTA_PERIOD      = 5

class CanOta(TinyOta):
    def __init__(self, dis_log=None, dis_msg=None, piece=1024) -> None:
        super().__init__(dis_log, dis_msg, piece)
        self.can        = CanDev(bitrate=1000)
        self.running    = False
        self.rx_thread  = None

    def _rx_thread_func(self):
        while self.running:
            ok, msg = self.can.ReadMessage()
            if not ok:
                print(f"[!] CAN ReadMessage fail!")
                break
            if msg and msg.id == CAN_OTA_RSP_ID:
                self.recv_frame(msg.data)
            time.sleep(0.005)

    def start(self, trace=False):
        '''
        open candev, start rx thread
        '''
        if not self.can.Open():
            print("CAN Open fail!")
            return

        self.trace = trace
        if self.trace:
            if not self.can.StartTrace():
                print("CAN StartTrace fail")
                self.trace = False
        print("[-] CAN open")

        self.running    = True
        self.rx_thread  = threading.Thread(target=self._rx_thread_func)
        self.rx_thread.start()

    def close(self):
        '''
        wait rx thread stop, close can interface
        '''
        self.running = False
        self.rx_thread.join()
        print(f"[-] thread rx_thread finished...")

        if self.trace:
            self.can.StopTrace()
        self.can.Close()
        print("[-] can close")

    def send_ota_command(self):
        '''do something, make the mcu into ota mode
        '''
        raise NotImplementedError()
        # todo

    def send_frame(self, data, length=8):
        if self.can.WriteMessage(CAN_OTA_ID, data):
            # self._print_msg(f'{time_info()} TX {CAN_OTA_ID:03X} {dump_bytes(data)}')
            return True
        else:
            self._print_log(f'[!] send frame fail!')
            raise EndException()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--addr', required=True, type=str, help='fw addr')
    parser.add_argument('-f', '--file', required=True, type=str, help='fw file')
    parser.add_argument('-i', '--id', required=True, type=str, help='fw id')
    parser.add_argument('--crypto', default='no', type=str, help='fw crypto algo')

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print('fw file not exist!')
        sys.exit(0)

    with open(args.file, 'rb') as file:
        fw_content = file.read()

    try:
        fw_addr = int(args.addr, 0)
        fw_id   = int(args.id, 0)
    except ValueError:
        print(f'fw addr invalid!')
        sys.exit(0)

    otatool = CanOta(piece=1024)
    otatool.start(trace=False)

    for i in range(1):
        otatool.set_fwinfo(fw_id, fw_addr, fw_content, 0)
        start_time = datetime.datetime.now()
        try:
            while True:
                otatool.mainproc(OTA_PERIOD, accelerate=True)
                time.sleep(0.001 * OTA_PERIOD)
        except (KeyboardInterrupt, EndException) as e:
            print(f'quit {e}')

        print(f'ota {i} finish, use time {datetime.datetime.now() - start_time}')
        print('')

    otatool.close()
