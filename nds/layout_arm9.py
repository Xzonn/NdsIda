"""
Setup arm9 memory layout.
"""

import ida_name
import misc

# Main RAM
CODE_BASE      = 0x2000000
CODE_SIZE      = 0x3BFE00
RAM1_BASE      = 0x23BFE00
RAM1_SIZE      = 0x3FE80
USERINFO_BASE  = 0x23FFC80
USERINFO_SIZE  = 0x70
RAM2_BASE      = 0x23FFCF0
RAM2_SIZE      = 0x110
HEADER_BASE    = 0x23FFE00
HEADER_SIZE    = 0x200
RAM_SIZE       = 0x400000

# WRAM
WRAM_BASE      = 0x3000000
WRAM_SIZE      = 0x8000

# IO Registers
IOREGS_BASE    = 0x4000000
IOREGS_SIZE    = 0x1000000

# VRAM
VRAM_BGA_BASE  = 0x6000000
VRAM_BGA_SIZE  = 0x80000
VRAM_BGB_BASE  = 0x6200000
VRAM_BGB_SIZE  = 0x20000
VRAM_OBJA_BASE = 0x6400000
VRAM_OBJA_SIZE = 0x40000
VRAM_OBJB_BASE = 0x6600000
VRAM_OBJB_SIZE = 0x20000

# OAM
OAM_BASE       = 0x7000000
OAM_SIZE       = 0x800

# BIOS
BIOS_BASE      = 0xFFFF0000
BIOS_SIZE      = 0xC00

# IO Registers

IOREGS = [

    # Display Engine A

    [0x0000, "DISPCNT_A"],
    [0x0004, "DISPSTAT"],
    [0x0006, "VCOUNT"],
    [0x0008, "BG0CNT_A"],
    [0x000A, "BG1CNT_A"],
    [0x000C, "BG2CNT_A"],
    [0x000E, "BG3CNT_A"],
    [0x0010, "BG0HOFS_A"],
    [0x0012, "BG0VOFS_A"],
    [0x0014, "BG1HOFS_A"],
    [0x0016, "BG1VOFS_A"],
    [0x0018, "BG2HOFS_A"],
    [0x001A, "BG2VOFS_A"],
    [0x001C, "BG3HOFS_A"],
    [0x001E, "BG3VOFS_A"],
    [0x0020, "BG2PA_A"],
    [0x0022, "BG2PB_A"],
    [0x0024, "BG2PC_A"],
    [0x0026, "BG2PD_A"],
    [0x0028, "BG2X_A"],
    [0x002C, "BG2Y_A"],
    [0x0030, "BG3PA_A"],
    [0x0032, "BG3PB_A"],
    [0x0034, "BG3PC_A"],
    [0x0036, "BG3PD_A"],
    [0x0038, "BG3X_A"],
    [0x003C, "BG3Y_A"],
    [0x0040, "WIN0H_A"],
    [0x0042, "WIN1H_A"],
    [0x0044, "WIN0V_A"],
    [0x0046, "WIN1V_A"],
    [0x0048, "WININ_A"],
    [0x004A, "WINOUT_A"],
    [0x004C, "MOSAIC_A"],
    # 0x004E - Not used
    [0x0050, "BLDCNT_A"],
    [0x0052, "BLDALPHA_A"],
    [0x0054, "BLDY_A"],
    # 0x0056 - Not used
    [0x0060, "DISP3DCNT"],
    [0x0064, "DISPCAPCNT"],
    [0x0068, "DISP_MMEM_FIFO"],
    [0x006C, "MASTER_BRIGHT"],

    # DMA

    [0x00B0, "DMA_CHANNEL0"],
    [0x00BC, "DMA_CHANNEL1"],
    [0x00C8, "DMA_CHANNEL2"],
    [0x00D4, "DMA_CHANNEL3"],
    [0x00E0, "DMA_FILL0"],
    [0x00E4, "DMA_FILL1"],
    [0x00E8, "DMA_FILL2"],
    [0x00EC, "DMA_FILL3"],

    # Timers

    [0x0100, "TIMER0"],
    [0x0104, "TIMER1"],
    [0x0108, "TIMER2"],
    [0x010C, "TIMER3"],

    # Keypad

    [0x0130, "KEYINPUT"],
    [0x0132, "KEYCNT"],

    # IPC/ROM

    [0x0180, "IPCSYNC"],
    [0x0184, "IPCFIFOCNT"],
    [0x0188, "IPCFIFOSEND"],
    [0x01A0, "AUXSPICNT"],
    [0x01A2, "AUXSPIDATA"],
    [0x01A4, "ROMCTRL"],
    [0x01A8, "CARD_COMMAND"],
    [0x01B0, "CARD_1B0"],
    [0x01B4, "CARD_1B4"],
    [0x01B8, "CARD_1B8"],
    [0x01BA, "CARD_1BA"],
    [0x100000, "IPCFIFORECV"],
    [0x100010, "CARD_DATA_RD"],

    # Memory & IRQ Control

    [0x0204, "EXMEMCNT"],
    [0x0208, "IME"],
    [0x0210, "IE"],
    [0x0214, "IF"],
    [0x0240, "VRAMCNT_A"],
    [0x0241, "VRAMCNT_B"],
    [0x0242, "VRAMCNT_C"],
    [0x0243, "VRAMCNT_D"],
    [0x0244, "VRAMCNT_E"],
    [0x0245, "VRAMCNT_F"],
    [0x0246, "VRAMCNT_G"],
    [0x0247, "WRAMCNT"],
    [0x0248, "VRAMCNT_H"],
    [0x0249, "VRAMCNT_I"],

    # Maths

    [0x0280, "DIVCNT"],
    [0x0290, "DIV_NUMER"],
    [0x0298, "DIV_DENOM"],
    [0x02A0, "DIV_RESULT"],
    [0x02A8, "DIVREM_RESULT"],
    [0x02B0, "SQRTCNT"],
    [0x02B4, "SQRT_RESULT"],
    [0x02B8, "SQRT_PARAM"],
    [0x0300, "POSTFLG"],
    [0x0304, "POWCNT1"],

    # 3D Engine
    #...

    # Display Engine B

    [0x1000, "DISPCNT_B"],
    [0x1008, "BG0CNT_B"],
    [0x100A, "BG1CNT_B"],
    [0x100C, "BG2CNT_B"],
    [0x100E, "BG3CNT_B"],
    [0x1010, "BG0HOFS_B"],
    [0x1012, "BG0VOFS_B"],
    [0x1014, "BG1HOFS_B"],
    [0x1016, "BG1VOFS_B"],
    [0x1018, "BG2HOFS_B"],
    [0x101A, "BG2VOFS_B"],
    [0x101C, "BG3HOFS_B"],
    [0x101E, "BG3VOFS_B"],
    [0x1020, "BG2PA_B"],
    [0x1022, "BG2PB_B"],
    [0x1024, "BG2PC_B"],
    [0x1026, "BG2PD_B"],
    [0x1028, "BG2X_B"],
    [0x102C, "BG2Y_B"],
    [0x1030, "BG3PA_B"],
    [0x1032, "BG3PB_B"],
    [0x1034, "BG3PC_B"],
    [0x1036, "BG3PD_B"],
    [0x1038, "BG3X_B"],
    [0x103C, "BG3Y_B"],
    [0x1040, "WIN0H_B"],
    [0x1042, "WIN1H_B"],
    [0x1044, "WIN0V_B"],
    [0x1046, "WIN1V_B"],
    [0x1048, "WININ_B"],
    [0x104A, "WINOUT_B"],
    [0x104C, "MOSAIC_B"],
    [0x1050, "BLDCNT_B"],
    [0x1052, "BLDALPHA_B"],
    [0x1054, "BLDY_B"],   
    [0x106C, "MASTER_BRIGHT_B"],
]

def setup_memory_layout():
    # Main RAM
    misc.add_segment(CODE_BASE, CODE_SIZE, "CODE", misc.PROT_RWX)
    misc.add_segment(RAM1_BASE, RAM1_SIZE, "RAM1", misc.PROT_RW)
    misc.add_segment(USERINFO_BASE, USERINFO_SIZE, "USERINFO", misc.PROT_RW)
    misc.add_segment(RAM2_BASE, RAM2_SIZE, "RAM2", misc.PROT_RW)
    misc.add_segment(HEADER_BASE, HEADER_SIZE, "HEADER", misc.PROT_RW)

    # WRAM
    misc.add_segment(WRAM_BASE, WRAM_SIZE, "WRAM", misc.PROT_RW)

    # IO Registers
    misc.add_segment(IOREGS_BASE, IOREGS_SIZE, "IOREGS", misc.PROT_RW)

    for reg in IOREGS:
        if not ida_name.set_name(IOREGS_BASE + reg[0], "REG_" + reg[1]):
            raise Exception(f"Couldn't set register name \"{reg[1]}\"")

    # VRAM
    misc.add_segment(VRAM_BGA_BASE, VRAM_BGA_SIZE, "VRAM_BGA", misc.PROT_RW)
    misc.add_segment(VRAM_BGB_BASE, VRAM_BGB_SIZE, "VRAM_BGB", misc.PROT_RW)
    misc.add_segment(VRAM_OBJA_BASE, VRAM_OBJA_SIZE, "VRAM_OBJA", misc.PROT_RW)
    misc.add_segment(VRAM_OBJB_BASE, VRAM_OBJB_SIZE, "VRAM_OBJB", misc.PROT_RW)

    # OAM
    misc.add_segment(OAM_BASE, OAM_SIZE, "OAM", misc.PROT_RW)

    # BIOS
    misc.add_segment(BIOS_BASE, BIOS_SIZE, "BIOS", misc.PROT_READ)

def unmirror_address(addr):
    # BIOS
    if addr & 0xFFFF0000 == BIOS_BASE:
        return BIOS_BASE + (addr & (BIOS_SIZE - 1))

    # IOREGS
    if addr & 0xFFF0FFFF == 0x4000800:
        return 0x4000800 # This seems to be the only mirrored register.
    
    # RAM
    if addr & 0xFF000000 == CODE_BASE:
        return CODE_BASE + (addr & (RAM_SIZE - 1))

    # WRAM
    if addr & 0xFF000000 == WRAM_BASE:
        return WRAM_BASE + (addr & (WRAM_SIZE - 1))

    # VRAM
    if addr & 0xFFF00000 == VRAM_BGA_BASE:
        return VRAM_BGA_BASE + (addr & (VRAM_BGA_SIZE - 1))
    if addr & 0xFFF00000 == VRAM_BGB_BASE:
        return VRAM_BGB_BASE + (addr & (VRAM_BGB_SIZE - 1))
    if addr & 0xFFF00000 == VRAM_OBJA_BASE:
        return VRAM_OBJA_BASE + (addr & (VRAM_OBJA_SIZE - 1))
    if addr & 0xFFF00000 == VRAM_OBJB_BASE:
        return VRAM_OBJB_BASE + (addr & (VRAM_OBJB_SIZE - 1))

    # OAM
    if addr & 0xFF000000 == OAM_BASE:
        return OAM_BASE + (addr & (OAM_SIZE - 1))

    return addr

def get_info_address():
    return CODE_BASE