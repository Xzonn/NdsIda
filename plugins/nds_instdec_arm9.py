"""
Decompile arm9 instructions into functions.
"""

# Boilerplate
import os
import sys
if sys.version_info[0] != 3 or sys.version_info[1] < 10:
    Exception("Please update your python installation to 3.10.x or higher.")
script_name = os.path.basename(__file__)
script_path = os.path.realpath(__file__)
script_path = os.path.dirname(os.path.dirname(script_path)) + "/nds"
sys.path.insert(0, script_path)
#

import ida_hexrays
import ida_allins

import misc
import handlers

# Coprocessor Instruction Handler

class _udc_p15_t(ida_hexrays.udc_filter_t):
    def __init__(self):
        ida_hexrays.udc_filter_t.__init__(self)

    def set_symbol(self, name: str, rd: int, write: bool):
        ret_type = "void" if write else "unsigned int"
        rd_token = f"@<r{str(rd)}>"
        fname = name if write else f"{name + rd_token}"
        arg = f"unsigned int val{rd_token}" if write else "void"
        sym = f"{ret_type} __usercall {fname}({arg});"
        if not self.init(sym):
            raise Exception("Couldn't set symbol")

    def get_name(self, crn: int, crm: int, op1: int, op2: int, write: bool):
        if op1 != 0:
            return ""

        if crn == 1 and crm == 0 and op2 == 0: #  Control Register
            return "P15_WriteControlRegister" if write else "P15_ReadControlRegister"

        if crn == 2 and crm == 0: # Cache Config Register
            if op2 == 0:
                return "P15_WriteDataCachableBits" if write else "P15_ReadDataCachableBits"
            if op2 == 1:
                return "P15_WriteInstructionCachableBits" if write else "P15_ReadInstructionCachableBits"
            return ""

        if crn == 3 and crm == 0 and op2 == 0: # Write Buffer Control Register
            return "P15_WriteDataBufferableBits" if write else "P15_ReadDataBufferableBits"

        if crn == 5 and crm == 0: # Permission Register
            if op2 == 2:
                return "P15_WriteDataPermissionBits" if write else "P15_ReadDataPermissionBits"
            if op2 == 3:
                return "P15_WriteInstructionPermissionBits" if write else "P15_ReadInstructionPermissionBits"
            return ""

        if crn == 6 and op2 == 0: # Protection Register
            if crm >= 0 and crm <= 7:
                return f"P15_WriteProtectionRegister{crm}" if write else f"P15_ReadProtectionRegister{crm}"
            return ""

        if crn == 7: # Cache Register
            if crm == 0 and op2 == 4:
                return "P15_WaitForInterrupt"

            if crm == 5:
                if op2 == 0:
                    return "P15_FlushInstructionCache"
                if op2 == 1:
                    return "P15_FlushInstructionCacheSingleEntry"
                return ""

            if crm == 6:
                if op2 == 0:
                    return "P15_FlushDataCache"
                if op2 == 1:
                    return "P15_FlushDataCacheSingleEntry"
                return ""

            if crm == 10:
                if op2 == 1:
                    return "P15_CleanDataCacheEntryWithAddress"
                if op2 == 2:
                    return "P15_CleanDataCacheEntryWithIndexSegment"
                if op2 == 4:
                    return "P15_DrainWriteBuffer"
                return ""

            if crm == 13 and op2 == 1:
                return "P15_PrefetchInstructionCacheLine"

            if crm == 14:
                if op2 == 1:
                    return "P15_CleanAndFlushDataCacheEntryWithAddress"
                if op2 == 2:
                    return "P15_CleanAndFlushDataCacheEntryWithIndexSegment"
                return ""

        if crn == 9: # Cache Lockdown/TCM Region Register
            if crm == 0:
                if op2 == 0:
                    return "P15_WriteDataLockdownControl" if write else "P15_ReadDataLockdownControl"
                if op2 == 1:
                    return "P15_WriteInstructionLockdownControl" if write else "P15_ReadInstructionLockdownControl"
                return ""

            if crm == 1:
                if op2 == 0:
                    return "P15_WriteDTCMControl" if write else "P15_ReadDTCMControl"
                if op2 == 1:
                    return "P15_WriteITCMControl" if write else "P15_ReadITCMControl"
                return ""

            return ""

        return ""

    def match(self, cdg: ida_hexrays.codegen_t):
        WRITE = cdg.insn.itype == ida_allins.ARM_mcr

        # Check for instruction
        if cdg.insn.itype != ida_allins.ARM_mrc and not WRITE:
            return False

        # Get operands
        rd = cdg.insn.Op2.reg
        op1 = cdg.insn.Op2.value
        op2 = cdg.insn.Op3.value
        cp = cdg.insn.Op1.specflag1
        crn = cdg.insn.Op2.specflag1
        crm = cdg.insn.Op2.specflag2

        # Get function name
        name = self.get_name(crn, crm, op1, op2, WRITE)
        if name == "":
            return False

        # Found a match; set symbol
        self.set_symbol(name, rd, WRITE)
        return True

class P15Handler(handlers.GenericHandler):
    _p15handler = _udc_p15_t()
    def install(self):
        if misc.is_arm9():
            return ida_hexrays.install_microcode_filter(self._p15handler, True)
        return True

# Main

handlers.add_handler(P15Handler())