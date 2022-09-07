# !/usr/bin/env python2
# coding=utf-8
from serial_debuger.vx5_arm_debugger import *
from serial_debuger.serialtube import serialtube
import logging
import socket
import time
import base64


def wait_move_on(print_string):
    print(print_string)
    #move_on = False
    task = ''
    while True:
        ans = raw_input("Y/y to move on,\n:")
        if ans.upper() == "Y":
            #move_on = True
            if task != '':
                debugger.task_resume(task)
            task = debugger.wait_break()
        elif ans.startswith('dump'):
            try:
                item = ans.split(' ')
                if len(item) != 3:
                    continue
                start_address = int(item[1],16)
                size = int(item[2],16)
                command = debugger.prepare_memory_dump_command(start_address, size)
                rsp_data = debugger.send_and_recvuntil(command, timeout=3)
                rsp_data = rsp_data.replace(command + '\r\n', '')
                print(rsp_data)
            except Exception as e:
                print(e)
        elif ans.startswith('u '):
            try:
                item = ans.split(' ')
                if len(item) != 3:
                    continue
                start_address = int(item[1],16)
                size = int(item[2],16)
                data = debugger.get_mem_dump(start_address,size)
                data_asm = debugger.disassemble(data, start_address, CS_ARCH_ARM, CS_MODE_ARM,CS_MODE_BIG_ENDIAN if debugger.endian == 1 else CS_MODE_LITTLE_ENDIAN)
                print(data_asm)
            except Exception as e:
                print(e)
        elif ans.startswith('bp '):
            try:
                item = ans.split(' ')
                if len(item) != 2:
                    continue
                start_address = int(item[1],16)
                debugger.add_break_point(start_address)
            except Exception as e:
                print(e) 
    return

serial_port = "/dev/tty.usbserial-14320"
debugger = Vx5ARMDebugger(endian=2,cache_update_address=0x403FB858,process_type = "ARM")
debugger.serial = serialtube(port=serial_port,baudrate=117500)

login_status = debugger.send_and_recvuntil('admin -login 52b2f8178990eeda51c9b8dced094994')
if 'success' not in login_status:
    print('login error')
    exit(-1)
#debugger.logger.setLevel(logging.DEBUG)
debugger.init_debugger(0x41ffb000)

#patch掉cmd的login验证
debugger.patch(0x4039A4DC,'MOV R3,#1')

#print(debugger.show_task_bp_regs("0x8"))

#debugger.add_break_point(0x402711D0)
debugger.add_break_point(0x402711D8)
#debugger.add_break_point(0x402EBEA8)
wait_move_on('success attach')