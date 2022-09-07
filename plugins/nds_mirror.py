"""
Memory mirroring options.
"""

# Boilerplate
import os
import sys
if sys.version_info[0] != 3 or sys.version_info[1] < 10:
    Exception("Please update your python installation to 3.10.x or higher.")
script_name = os.path.basename(__file__)
script_path = os.path.realpath(__file__)
script_path = script_path.removesuffix(script_name) + "../nds"
sys.path.insert(0, script_path)
#

import ida_kernwin
import ida_bytes

import layout_arm9
import handlers
import misc

ACTION_NAME = "nds.py:mirror"
ACTION_LABEL = "[nds.py] Toggle mirroring"

def _unmirror_address(mirror):
    if misc.is_arm9():
        return layout_arm9.unmirror_address(mirror)
    return mirror

# Mirror Action

class MirrorAction(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def _toggle_mirror(self):
        ea = misc.get_current_ea()
        if misc.is_patched_dword(ea):
            mirror = ida_bytes.get_original_dword(ea)

            if not ida_bytes.patch_dword(ea, mirror):
                misc.log_error(f"mirror failed!")
                return
            
            misc.remove_comment(ea)
        else:
            mirror = ida_bytes.get_dword(ea)
            og = _unmirror_address(mirror)

            if og == mirror:
                return
            
            if not ida_bytes.patch_dword(ea, og):
                misc.log_error(f"unmirror failed!")
                return

            misc.add_comment(ea, f"mirrored to 0x{mirror:X}")  

    def activate(self, ctx):
        self._toggle_mirror()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# Mirror Handler

class _mirror_UI_Hooks(ida_kernwin.UI_Hooks):
    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def populating_widget_popup(self, widget, popup):
        ea = misc.get_current_ea()
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM and misc.is_dword(ea):
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)

class MirrorHandler(handlers.GenericHandler):
    _mirror_handler = _mirror_UI_Hooks()
    def install(self):
        desc = ida_kernwin.action_desc_t(ACTION_NAME, ACTION_LABEL, MirrorAction())
        return ida_kernwin.register_action(desc) and self._mirror_handler.hook()

# Main

handlers.add_handler(MirrorHandler())