"""
IDA Pro Nintendo DS ROM Loader.
"""

import ntrbin
import misc
import layout_arm9

import ida_bytes
import ida_loader

bininfo = ntrbin.NTRBIN()
call_count = 0

def accept_file_impl(li, filename):
    global call_count
    if call_count % 2 == 0:
        if bininfo.parse(li):
            call_count += 1
            return { 
                    "format" : misc.ARM9_FORMAT,
                    "processor" : "ARM",
                    "options" : 1 | ida_loader.ACCEPT_FIRST | ida_loader.ACCEPT_CONTINUE,
                }

    # We dont need to parse this time
    if call_count % 2 == 1:
        call_count += 1
        return {
            "format": misc.ARM7_FORMAT,
            "processor" : "ARM710A",
            "options" : 1,
        }

    return 0

def load_arm9():
    # Setup environment
    layout_arm9.setup_memory_layout()

     # Fill sections
    ida_bytes.put_bytes(bininfo.get_arm9_vaddr(), bininfo.get_arm9_binary())
    if bininfo.has_ov9():
        ida_bytes.put_bytes(bininfo.get_ov9_vaddr(0), bininfo.get_ov9_binary(0))
        misc.add_line(bininfo.get_ov9_vaddr(0), "Overlay starts here")

    ida_bytes.put_bytes(layout_arm9.HEADER_BASE, bininfo.get_hdr_binary())

    # Set entrypoint
    misc.set_ep(bininfo.get_arm9_ep())
    return layout_arm9.get_info_address()

def load_arm7():
    # TODO
    raise Exception("Unimplemented")

def load_file_impl(li, neflags, format):
    # Load selected binary
    if misc.is_format_arm9(format):
        info_address = load_arm9()
    elif misc.is_format_arm7(format):
        load_arm7()
    else:
        raise Exception("Load failed")

    # Add comments
    misc.add_line(info_address, "Loaded with nds.py")
    misc.add_line(info_address, "By nikki! :D")
    misc.add_line(info_address, f"ROM name: {bininfo.get_rom_name()}")
    misc.add_line(info_address, f"ROM code: {bininfo.get_rom_code()}")
    misc.add_line(info_address, f"Secure area checksum: {bininfo.get_sec_checksum():X}")
    misc.add_line(info_address, f"Logo checksum: {bininfo.get_logo_checksum():X}")
    misc.add_line(info_address, f"Header checksum: {bininfo.get_hdr_checksum():X}")

    return 1