# !/usr/bin/env python2
# coding=utf-8
from scapy.packet import *
from scapy.fields import *
from vx_base_debugger import VxSerialBaseDebuger
from keystone import *
from capstone import *

ARM_INDEX_TO_REGS = {
    0:'r0',
    1:'r1',
    2:'r2',
    3:'r3',
    4:'r4',
    5:'r5',
    6:'r6',
    7:'r7',
    8:'r8',
    9:'r9',
    10:'r10',
    11:'r11',
    12:'r12',
    13:'sp',
    14:'lr',
    15:'pc',
    16:'PSR'  
}

class DebugStack(Packet):
    fields_desc = [
        XIntField("DbgFlag", 0),
        XIntField("OriginalRA", 0),
        XIntField("BreakPoint", 0),
        XIntField("CacheUpdateAddress", 0),
        XIntField("CacheUpdateSize", 0),
        XIntField("CacheUpdateCount", 0),
    ]

class Vx5ARMDebugger(VxSerialBaseDebuger):

    def text_update(self, update_address, update_size):
        """Update Process cache

        :param update_address: Memory address to update.
        :param update_size: Cache update size
        :return: True if update succeed
        """
        if self.current_bp_info["bp_address"] == 0:
            self.logger.debug("current bp_address is zero, skip text update.")
            return None
        flag_address = self.current_bp_info["flag_address"]
        pack_parm = ">I"
        if self.endian == 2:
            pack_parm = "<I"

        original_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
        self.write_memory_data(flag_address + 0x0c, struct.pack(pack_parm, update_address))
        self.write_memory_data(flag_address + 0x10, struct.pack(pack_parm, update_size))
        # set update flag
        self._set_dbg_flag(2)
        # wait text update
        current_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
        while current_update_count != original_update_count + 1:
            self.logger.debug("current_update_count: %s , should be: %s" % (hex(current_update_count),
                                                                hex(original_update_count + 1)))
            stack_data = self.get_mem_dump(flag_address, 0x18)
            dbg_status = DebugStack(stack_data)
            self.logger.debug("{:-^{width}}".format("Debug Status", width=80))
            self.logger.debug('##Debuger Status at %s' % hex(flag_address))
            dbg_status.show()

            # set update flag
            self._set_dbg_flag(2)
            current_update_count = struct.unpack(pack_parm, self.get_mem_dump(flag_address + 0x14, 0x04))[0]
            time.sleep(1)
        self.logger.debug('text_update succeed')
        return True

    def init_debugger(self, over_write_address):
        """Initialize Debuger, inject debug shellcode to target memory.

        :param over_write_address: Memory address to store debug shellcode
        :return: True if succeed

        dbg_statck:
            dbg_stack_address + 0xa4 ~ 0x200 = reserve
            dbg_stack_address + 0x20 ~ 0xa0 = regs store address
            dbg_stack_address + 0x18 ~ 0x1C = reserve
            dbg_stack_address + 0x14 = Cache updated count, use to sync update status.
            dbg_stack_address + 0x10 = Cache update size(Default is bp_overwrite_size)
            dbg_stack_address + 0x0c = Address Need Update Cache(Default is Break Point Address)
            dbg_stack_address + 0x08 = Break Point Address + bp_overwrite_size
            dbg_stack_address + 0x04 = Original $RA Value
            dbg_stack_address + 0x00 = Debug Flags(0: Keep loop, 1: Recover, 2: Need update cache)

        """
        self.logger.info("Init debugger asm at address: %s" % hex(over_write_address))
        reg_store_offset = 0x20

        ##########################
        #     Init DBG Stack     #
        ##########################

        # save regs to stack
        stack_offset = reg_store_offset

        #save LR
        asm_code = 'STR LR,[SP,#0x04]\n'
        #设置[SP+4]为breakpoint的地址，方便后面返回
        asm_code += 'LDR LR,[SP,#0x08]\n'
        asm_code += 'SUB LR,#0xC\n'
        asm_code += 'STR LR,[SP,#0x08]\n'

        #R0~R12
        for i in range(13):
            asm_code += "STR R%d, [SP,#%s]\n" % (i, hex(stack_offset))
            stack_offset += 0x04

        asm_code += '''/*set flag = 0*/
                       MOV R0,#0
                       STR R0,[SP,#0]
                    '''
        # init cache update stack value to default bp address
        asm_code += '''ADD LR,LR,#-%s
                       STR LR,[SP,#0x0c]
                       MOV LR,#%s
                       STR LR,[SP,#0x10]
                       MOV R0,#0
                       STR R0,[SP,#0x14]
                    ''' % (hex(self.bp_overwrite_size),hex(self.bp_overwrite_size))

        ##########################
        #        DBG Loop        #
        ##########################
        j = 'BL' if self.cache_update_address & 0x1 == 0 else 'BLX' #take 16bit into considerate
        textUpdate = hex((self.cache_update_address - over_write_address) & 0xffffffe)
        asm_code += '''dbg_loop:
                       /*call cacheTextUpdate if flag == 0x02*/
                       LDR R0,[SP,#0x00]
                       ADD R0, R0,#-0x02
                       CMP R0,#0
                       BNE continue
                       /*update cacheTextUpdate execute count*/
                       LDR R0, [SP,#0x14]
                       ADD R0,#0x01
                       STR R0,[SP,#0x14]
                       #call update cache
                       LDR R0,[SP,#0x0c]
                       LDR R1,[SP,#0x10]
                       %s %s
                       /*set flag to 0x00*/
                       MOV R0,#0
                       STR R0,[SP,#0]
                       continue:
                       /*if flag != 0x01 keep loop*/
                       LDR R0,[SP,#0x00]
                       ADD R0, R0,#-0x01
                       CMP R0,#0
                       BNE dbg_loop
                       /*Recover*/
                       /*update dbg stack cache before recover*/
                       MOV R0, SP
                       MOV R1, #%s
                       %s %s
                       ''' % (j,textUpdate,hex(self.dbg_stack_size),j,textUpdate)
        # recover regs
        stack_offset = reg_store_offset
        for i in range(13):
            asm_code += "LDR R%d, [SP,#%s]\n" % (i, hex(stack_offset))
            stack_offset += 0x04

        # return to bp
        asm_code += '''LDR LR,[SP, #0x04]
                       ADD SP, #%s
                       LDR PC,[SP,#0x8 - %s]
                    ''' % (hex(self.dbg_stack_size),hex(self.dbg_stack_size))


        self.logger.debug("asm_code: %s" % asm_code)
        asm_list = self.assemble(asm_code, KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
        if not asm_list:
            return None
        self.dbg_overwrite_size = len(asm_list) * 0x04
        self.logger.debug("self.dbg_overwrite_size: %s" % hex(self.dbg_overwrite_size))

        asm_data = "".join(asm_list).decode("hex")
        f = open('/Users/mac/Desktop/1.bin','wb')
        f.write(asm_data);
        f.close();
        self.write_memory_data(over_write_address, asm_data)
        self.debugger_base_address = over_write_address
        return True

    def patch(self,address,asm_code,mode = KS_MODE_ARM):
        asm_list = self.assemble(asm_code, KS_ARCH_ARM, mode, KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
        if not asm_list:
            return None
        asm_data = "".join(asm_list).decode("hex")
        self.write_memory_data(address, asm_data)

    def get_task_regs_from_string(self, raw_data, regs):
        regs_value = {}
        data_list = raw_data.split("\r\n")
        for data in data_list:
            if "=" in data:
                reg_data_list = data.split()
                if len(reg_data_list) == 4 or 'psr' in reg_data_list[0]:
                    for reg_x in reg_data_list:
                        pos = reg_x.find("=")
                        reg = reg_x[0:pos]
                        try:
                            value = reg_x[pos + 1:pos + 11]
                            int(value,16)
                            regs_value[reg] = value
                        except Exception as err:
                            self.logger.error("ERROR: %s" % err)
                            pass
        return regs_value

    def get_task_stack(self, task):
        """Get task stack with task name

        :param task: Task name
        :return: Task stack data
        """
        cmd = "task -stack %s" % task
        current_task_stack = self.send_and_recvuntil(cmd)
        return current_task_stack

    def get_task_regs(self, task):
        """Get task register value.

        :param task:
        :return:
        """
        current_task_info = self.get_task_info(task, show=False)
        regs = self.get_task_regs_from_string(current_task_info, self.process_regs)
        self.current_task_regs[task] = regs
        return regs

    def task_control(self, task, command):
        """Task control functions

        :param task: task name to control
        :param command: control command['suspend', 'resume', 'stop']
        :return:
        """
        cmd = "task -op %s %s" % (command, task)
        rsp = self.send_and_recvuntil(cmd)
        if "Task %s %s!" % (task, command) in rsp:
            return True
        else:
            self.task_control(task, command)

    def get_tasks_status(self):
        """Get running tasks status

        :return: Current tasks status dict.

        Return Example:
            {
            "inetd": {
                "status": "PEND",
                "pc": 0x80117ad8,
                "sp": 0x8094e8d8
            },
            "tNetTask":{
                "status": "READY",
                "pc": 0x80117ad8,
                "sp": 0x80fe3b90
            }
            }
        """
        current_tasks_status = {}
        cmd = "task -l"
        rsp = self.send_and_recvuntil(cmd)
        if cmd in rsp:
            task_data_list = rsp.split("\r\n")[4:]
            #print("len(task_data_list)=%d\n",len(task_data_list))
            for task_info in task_data_list:
                try:
                    task_info_list = task_info.split()
                    if len(task_info_list) == 12:
                        name, tid, pri, status, _,_,sp,_,_,_,_,_ = task_info_list
                        cmd = "task --context --detail " + tid
                        rsp = self.send_and_recvuntil(cmd)
                        pc = 0
                        r15 = rsp.find("r15=")
                        if r15 >= 0:
                           pc = rsp[r15+4:r15+4+10]
                        current_tasks_status[name] = {
                            "status": status,
                            "tid": tid,
                            "pc": pc,
                            "sp": sp
                        }
                except Exception as err:
                    self.logger.error("Some thing error")
                    pass
            return current_tasks_status
        else:
            return None

    def get_task_info(self, task, show=True):
        cmd = "task --context --detail %s" % task
        current_task_info = self.send_and_recvuntil(cmd)
        if show:
            self.logger.info("current task: %s info is: \r\n %s" % (task, current_task_info))
        return current_task_info

    def show_task_bp_regs(self, task):
        """Display task registers

        :param task: Task name
        :return:
        """
        # TODO: fix regs with debug loop
        regs = self.get_task_regs(task)
        # get original_reg_data from dbg stack
        flag_address = self.current_bp_info["flag_address"]
        original_reg_data = self.get_mem_dump(flag_address + 0x20, 0x80)
        for i in range(len(ARM_INDEX_TO_REGS)):
            print_reg = ARM_INDEX_TO_REGS[i]
            print_line = ""
            if i == 16:
                print_line += "{:6}={:>9}\t".format(print_reg, regs['psr'])
            elif print_reg == "pc":
                print_line += "{:6}={:>9}\t".format(print_reg, hex(self.current_bp_info["bp_address"]))
            elif print_reg == "lr":
                # TODO: check value
                print_line += "{:6}={:>9}\t".format(print_reg, hex(self.current_bp_info["original_ra"]))
            elif print_reg == "sp":
                print_line += "{:6}={:>9}\t".format(print_reg,
                                                    hex(int(regs['r13'], 16) + self.dbg_stack_size))
            else:
                pack_parm = ">I"
                if self.endian == 2:
                   pack_parm = "<I"
                reg_offset = i
                original_reg = struct.unpack(pack_parm, original_reg_data[reg_offset * 0x04: (reg_offset + 1) * 0x04])[0]
                print_line += "{:6}={:>9}\t".format(print_reg, hex(original_reg))

            print(print_line)
        return regs

    def show_task_stack(self, task_regs, lines=10):
        """Display task stack data

        :param task: Task name
        :return:
        """
        print_line = ""
        sp = int(task_regs['r13'],16) + self.dbg_stack_size
        task_stack = self.get_mem_dump(sp,0x30)
        pack_parm = ">I"
        if self.endian == 2:
            pack_parm = "<I"
        for i in range(0,0x30,0x4):
            data = task_stack[i:i+4]
            print_line += hex(sp + i) + " <- " + hex(struct.unpack(pack_parm, data)[0]) + "\t\n"

        print(print_line)

    def show_task_bp_trace(self, task):
        """Display task breakpoint trace back

        :param task: Task name
        :return:
        """
        trace_data = ""
        trace_data_list = []
        bp_address = self.current_bp_info["bp_address"]
        ra_address = self.current_bp_info["original_ra"]
        bp_asm_data = self.break_points[bp_address]["original_asm"][:4]
        bp_asm = self.disassemble(bp_asm_data, bp_address, CS_ARCH_ARM, CS_MODE_ARM,CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN)
        trace_data_list.append(bp_asm)
        # get ra asm
        ra_asm_data = None
        for bp_addr in self.break_points:
            if bp_addr <= ra_address <= bp_addr + 0x10:
                offset = ra_address - bp_addr
                ra_asm_data = self.break_points[bp_addr]["original_asm"][offset:offset + 4]
                break
        if not ra_asm_data:
            ra_asm_data = self.get_mem_dump(ra_address, 0x04)
        self.logger.debug("ra_asm_data: %s" % ra_asm_data.encode("hex"))
        ra_asm = self.disassemble(ra_asm_data, ra_address, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN)
        self.logger.debug("ra_asm: %s" % ra_asm)
        trace_data_list.append(ra_asm)
        for i in range(len(trace_data_list)):
            self.logger.debug("trace_data_list: %s" % trace_data_list)
            trace_data += "[{}] {}".format(i, trace_data_list[i])
        print(trace_data)

    def get_temp_bp_address(self, bp_address):
        """Calculate temp breakpoint address, this temp breakpoint is used to keep other breakpoints.

        :param bp_address: Breakpoint address
        :return: Temp breakpoint address list.
        """
        try:
            temp_bp_address_list = []
            bp_asm_data = self.break_points[bp_address]["original_asm"]
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | (CS_MODE_BIG_ENDIAN if self.endian == 1 else CS_MODE_LITTLE_ENDIAN))
            md.detail = True
            asm_code_data = {}
            for i in md.disasm(bp_asm_data, bp_address):
                asm_code_data[i.address] = [i.mnemonic, i.op_str]

            for asm in asm_code_data:
                mnemonic = asm_code_data[asm][0]
                op_str = asm_code_data[asm][1]
                # Find Branch asm
                if mnemonic.lower().startswith("b"):
                    self.logger.debug("Found Branch asm at address: %s" % hex(asm))
                    branch_address = int(op_str.split(", ")[1], 16)
                    self.logger.debug("Branch address: %s" % hex(branch_address))
                    if not bp_address - 0x10 <= branch_address <= bp_address + 0x10:
                        temp_bp_address_list.append(branch_address)

                if mnemonic == "jal":
                    self.logger.debug("Found jal at address: %s" % hex(asm))
                    self.logger.debug("Jump to %s" % hex(int(op_str, 16)))
                    # Get jal return address
                    jal_return_address = asm + 0x08
                    # make sure return address less than break point address + 0x10.
                    if not jal_return_address <= bp_address + 0x10:
                        temp_bp_address_list.append(int(op_str, 16))
                        return temp_bp_address_list

                if mnemonic == "jr":
                    self.logger.debug("Found jr at address: %s" % hex(asm))
                    return temp_bp_address_list

            last_asm_addr = max(asm_code_data.keys())
            self.logger.debug("last_asm_addr:%s" % hex(last_asm_addr))
            mnemonic = asm_code_data[last_asm_addr][0]
            if mnemonic.lower().startswith("b"):
                temp_bp_address_list.append(last_asm_addr + 0x08)
            else:
                temp_bp_address_list.append(last_asm_addr + 0x04)

            return temp_bp_address_list

        except Exception as err:
            self.logger.error("ERROR: %s" % err)
            return None

    def create_bp_asm(self, bp_address,is_16bit = False):
        """Create breakpoint asm code

        :param bp_address: break point address
        :return: Breakpoint shellcode
        """
        # increase stack size
        asm_code = "ADD SP,#-%s;" % hex(self.dbg_stack_size)
        # save current PC
        asm_code += "STR PC, [SP,#0x08];"
        # jump to dbg loop
        asm_code += "LDR PC, [PC, #-4]"
        
        if is_16bit:
            asm_list = self.assemble(str(asm_code), KS_ARCH_ARM, KS_MODE_THUMB,KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
            if not asm_list:
                return None
        else:
            asm_list = self.assemble(str(asm_code), KS_ARCH_ARM, KS_MODE_ARM,KS_MODE_BIG_ENDIAN if self.endian == 1 else KS_MODE_LITTLE_ENDIAN)
            if not asm_list:
                return None
        asm_data = "".join(asm_list).decode("hex")
        pack_parm = ">I"
        if self.endian == 2:
            pack_parm = "<I"
        asm_data += struct.pack(pack_parm, self.debugger_base_address)
        f = open('/Users/mac/Desktop/3.bin','wb')
        f.write(asm_data);
        f.close();

        self.logger.debug("asm_code: %s" % asm_code)
        return asm_data
