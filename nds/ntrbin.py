"""
Basic interface for the Nintendo DS ROM format.
"""

import layout_arm9

import ctypes
import struct

ARM9_OFFSET = 0x20
ARM9_EP = 0x24
ARM9_VADDR = 0x28
ARM9_SIZE = 0x2C

ARM7_OFFSET = 0x30
ARM7_EP = 0x34
ARM7_VADDR = 0x38
ARM7_SIZE = 0x3C

FAT_OFFSET = 0x48
FAT_SIZE = 0x4C
OV9_OFFSET = 0x50
OV9_SIZE = 0x54

CRC_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
]

def _read_dword(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4:
        raise Exception("Invalid binary")
    return struct.unpack('<I', s)[0]

class Overlay9Item:
    ram_address: int = 0
    ram_size: int = 0
    binary: bytes = b''

    def __init__(self, ram_address: int, ram_size: int, binary: bytes):
        self.ram_address = ram_address
        self.ram_size = ram_size
        self.binary = binary

class FATItem:
    offset: int = 0
    size: int = 0

    def __init__(self, id: int, offset: int, size: int):
        self.offset = offset
        self.size = size

class NTRBIN:
    _arm9_offset: int
    _arm9_ep: int
    _arm9_vaddr: int
    _arm9_size: int

    _arm7_offset: int
    _arm7_ep: int
    _arm7_vaddr: int
    _arm7_size: int

    _ov9_list: list = []
    _ov9_current: Overlay9Item

    def _read_header(self, li):
        li.seek(0)
        self._header = li.read(0x160)
        return len(self._header) == 0x160

    def _handle_checksums(self, li):
        # Read checksums
        li.seek(0x6C)
        b = li.read(2)
        if len(b) != 2:
            return False
        self._sec_chk = struct.unpack('<H', b)[0]

        li.seek(0x15C)
        b = li.read(2)
        if len(b) != 2:
            return False
        self._logo_chk = struct.unpack('<H', b)[0]

        li.seek(0x15E)
        b = li.read(2)
        if len(b) < 2:
            return False
        self._hdr_chk = struct.unpack('<H', b)[0]

        # verify logo checksum
        crc16: ctypes.c_ushort = 0xFFFF
        for i in range(0xC0, 0x15C):
            crc16 = (crc16 >> 8) ^ CRC_TABLE[(crc16 ^ self._header[i]) & 0xFF]

        if self._logo_chk != crc16:
            return False

        # verify header checksum
        crc16 = 0xFFFF

        for i in range(0, 0x15E):
            crc16 = (crc16 >> 8) ^ CRC_TABLE[(crc16 ^ self._header[i]) & 0xFF]

        return self._hdr_chk == crc16

    def _validate(self, li):
        # Check ARM9 values
        # if self._arm9_offset < 0x4000:
            # return False
        if self._arm9_vaddr != layout_arm9.CODE_BASE:
            return False
        if self._arm9_ep < self._arm9_vaddr:
            return False
        if self._arm9_size > layout_arm9.CODE_SIZE:
            return False

        li.seek(self._arm9_offset)
        self._arm9_binary = li.read(self._arm9_size)
        if len(self._arm9_binary) != self._arm9_size:
            return False

        # TODO: Check ARM7 values

        return True

    def parse(self, li):
        if not self._read_header(li):
            return False

        if not self._handle_checksums(li):
            return False

        # Read ARM9 values
        self._arm9_offset = _read_dword(li, ARM9_OFFSET)
        self._arm9_ep = _read_dword(li, ARM9_EP)
        self._arm9_vaddr = _read_dword(li, ARM9_VADDR)
        self._arm9_size = _read_dword(li, ARM9_SIZE)

        # Read ARM7 values
        self._arm7_offset = _read_dword(li, ARM7_OFFSET)
        self._arm7_ep = _read_dword(li, ARM7_EP)
        self._arm7_vaddr = _read_dword(li, ARM7_VADDR)
        self._arm7_size = _read_dword(li, ARM7_SIZE)

        # Read ARM9 Overlay values
        fat_offset = _read_dword(li, FAT_OFFSET)
        fat_size = _read_dword(li, FAT_SIZE)
        li.seek(fat_offset)
        fat_table_binary = li.read(fat_size)

        ov9_offset = _read_dword(li, OV9_OFFSET)
        ov9_size = _read_dword(li, OV9_SIZE)
        li.seek(ov9_offset)
        ov9_table_binary = li.read(ov9_size)

        for i in range(0, ov9_size, 0x20):
            overlay_id, ram_address, ram_size, bss_size, static_initialiser_start_address, static_initialiser_end_address, file_id, reserved = struct.unpack('<8I', ov9_table_binary[i:i+0x20])
            file_offset, file_end = struct.unpack('<2I', fat_table_binary[file_id * 8:file_id * 8 + 8])
            li.seek(file_offset)
            ov9_binary = li.read(file_end - file_offset)
            self._ov9_list.append(Overlay9Item(ram_address, ram_size, ov9_binary))

        if len(self._ov9_list) > 0:
            self._ov9_current = self._ov9_list[0]

        return self._validate(li)

    def get_sec_checksum(self):
        return self._sec_chk

    def get_logo_checksum(self):
        return self._logo_chk

    def get_hdr_checksum(self):
        return self._hdr_chk

    def get_hdr_binary(self):
        return self._header

    def get_rom_name(self):
        return "UNIMPLEMENTED"

    def get_rom_code(self):
        return "UNIMPLEMENTED"

    def get_arm9_vaddr(self):
        return self._arm9_vaddr

    def get_arm9_ep(self):
        return self._arm9_ep

    def get_arm9_binary(self):
        return self._arm9_binary

    def has_ov9(self):
        return len(self._ov9_list) > 0

    def get_ov9_vaddr(self, ov9_id: int) -> int:
        return self._ov9_list[ov9_id].ram_address

    def get_ov9_binary(self, ov9_id: int) -> bytes:
        return self._ov9_list[ov9_id].binary