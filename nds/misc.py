"""
(Not-so) random stuff.
"""

import ida_lines
import ida_entry
import ida_segment
import ida_bytes
import ida_kernwin
import ida_nalt

ARM9_FORMAT = "Nintendo DS ROM (ARM9)"
ARM7_FORMAT = "Nintendo DS ROM (ARM7)"

PROT_READ = ida_segment.SEGPERM_READ
PROT_WRITE = ida_segment.SEGPERM_WRITE
PROT_EXEC = ida_segment.SEGPERM_EXEC
PROT_RW = PROT_READ | PROT_WRITE
PROT_RWX = PROT_RW | PROT_EXEC

def is_format_arm9(fmt):
    return fmt == ARM9_FORMAT

def is_format_arm7(fmt):
    return fmt == ARM7_FORMAT

def is_arm9():
    return is_format_arm9(ida_nalt.get_loader_format_name())

def is_arm7():
    return is_format_arm7(ida_nalt.get_loader_format_name())

def log_info(s):
    print(f"[nds.py] INFO: {s}")

def log_warning(s):
    print(f"[nds.py] WARNING: {s}")

def log_error(s):
    print(f"[nds.py] ERROR: {s}")

def add_line(ea, line):
    ida_lines.add_extra_line(ea, True, f"; {line}")

def add_comment(ea, cmt):
    ida_lines.add_extra_cmt(ea, True, f"[nds.py] {cmt}")

def remove_comment(ea):
    ida_lines.del_extra_cmt(ea, ida_lines.E_PREV)

def set_ep(ea):
    ida_entry.add_entry(ea, ea, "start", True)

def add_segment(start, size, name, perms):
    if perms & ida_segment.SEGPERM_EXEC:
        sclass = "CODE"
    else:
        sclass = "DATA"
    if not ida_segment.add_segm(0, start, start + size, name, sclass):
        raise Exception(f"Could not add {name} segment")
    seg = ida_segment.get_segm_by_name(name)
    ida_segment.set_segm_addressing(seg, 1)
    seg.perm = perms

def get_current_ea():
    return ida_kernwin.get_screen_ea()

def is_dword(ea):
    return ida_bytes.is_dword(ida_bytes.get_flags(ea))

def is_patched_range(start, end):
    return ida_bytes.visit_patched_bytes(start, end, lambda a, b, c, d : 1) == 1

def is_patched_dword(ea):
    return is_patched_range(ea, ea + 4)