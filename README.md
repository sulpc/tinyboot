# tinyboot

A tiny bootloader for MCU platform.

TinyBoot named "boot", but it does not implement the boot function of the normal bootloader. After all, this part is strongly relevant to the specific platform.

TinyBoot implements a general 32-bit MCU OTA upgrade framework, and does not depend on any specific platform.

TinyBoot is designed for OTA upgrade based on frame mode data transmission, such as CAN. The tp layer realizes the splitting and reorganization between long message and short frame. The design refers to the network layer protocol of UDS, with some simplification and modification.

TinyBoot can also be used for software upgrade based on stream mode data transmission, such as UART, where the user needs to design his own scheme to extract frames from the stream. In this case, long frames can be used without using multiple frames, avoiding the consumption of intermediate layers.

## MCU

The files in the `code` directory will be used for the MCU:
- `tb_tp_cfg.c` contains the configuration and external dependencies of the tp layer, user could make some changes.
- `tb_ota_co.c` contains the external dependencies of the ota application layer, no user modifications is required.
- `tb_ota_cfg.h` is the ota configuration, like where to store the firmware data, layout of the firmware in flash, etc.
- `tb_example.c` is an example of how to use TinyBoot, which lists the functions that TinyBoot depends on externally, and the user has to implement these by himself.

## PC

The files in the `otatool` directory is a update tool runs in PC, which implement by python.

- `tinytp.py` implements the tp layer protocol, no user modifications is required.
- `tinyota.py` implements the OTA process, no user modifications is required.
- `candev.py` implements the CAN communication interface based on PCAN library.
- `otatool.py` is the entry program, user can inherit `TinyOta`, implement the `start`, `close`, `send_ota_command` methods. The `recv_frame` interface should be called when a new frame is received.

## PS

See the code for more specific information.
