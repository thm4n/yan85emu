from dataclasses import dataclass

# ANSI color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'

@dataclass
class static_arch_values:
    # Register IDs
    @dataclass
    class reg:
        a: int = 0x40
        b: int = 0x04
        c: int = 0x10
        d: int = 0x20
        s: int = 0x01
        i: int = 0x02
        f: int = 0x08

    #opcodes:
    class OpCodes:
        imm: int = 0x80
        add: int = 0x08
        stk: int = 0x40
        stm: int = 0x20
        ldm: int = 0x01
        cmp: int = 0x04
        jmp: int = 0x10
        sys: int = 0x02

    # Syscall IDs
    @dataclass
    class syscalls:
        sys_open:       int = 0x08
        sys_read:       int = 0x10
        sys_write:      int = 0x04
        sys_sleep:      int = 0x02
        sys_exit:       int = 0x20

    class flags:
        equal_to:       int = 0x04
        not_equal_to:   int = 0x10
        above:          int = 0x01
        below:          int = 0x08
        zero:           int = 0x02
