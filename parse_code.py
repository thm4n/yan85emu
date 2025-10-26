from dataclasses import dataclass
from typing import List

@dataclass
class Instruction:
    opcode: int
    arg1: int
    arg2: int
    address: int

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

def parse_code_segment(code_segment_raw: str, base_address: int) -> List[Instruction]:
    code_segment_str_length: int = len(code_segment_raw)
    if code_segment_str_length % 6 != 0:
        raise ValueError("Invalid code segment length, must be a multiple of 6")
    
    code_segment_length: int = int(code_segment_str_length / 2)
    code = []
    code_raw = []

    for i in range(code_segment_length):
        code_raw.append(int(code_segment_raw[2*i] + code_segment_raw[2*i + 1], 16))

    num_opcodes = int(code_segment_length / 3)
    for i in range(num_opcodes):
        code.append(
            Instruction(
                code_raw[i * 3 + 2], # opcode
                code_raw[i * 3 + 0], # arg1
                code_raw[i * 3 + 1], # arg2
                base_address + (i * 3)  # Address is the index of the instruction in the code segment
            )
        )
        print(f"  Opcode: {code[-1].opcode:02x}, Arg1: {code[-1].arg1:02x}, Arg2: {code[-1].arg2:02x}")

    return code


def get_reg(reg_id: int) -> str:
    reg_map = {
        static_arch_values.reg.a: "a",
        static_arch_values.reg.b: "b",
        static_arch_values.reg.c: "c",
        static_arch_values.reg.d: "d",
        static_arch_values.reg.s: "s",
        static_arch_values.reg.i: "i",
        static_arch_values.reg.f: "f"
    }
    return reg_map.get(reg_id, f"Unknown Register ID: {reg_id}")


def get_hex(value: int) -> str:
    return f"0x{value:02x}" if value >= 0 else f"-0x{-value:02x}"  # Handle negative values


def describe_instruction(instruction: Instruction) -> str:
    desc = f"0x{instruction.address:04x}: "
    if instruction.opcode == static_arch_values.OpCodes.sys:
        desc += f"SYS {get_hex(instruction.arg1)} "
        if instruction.arg1 == static_arch_values.syscalls.sys_open:
            desc += f"{get_reg(instruction.arg2)} ; (sys_open)"
        elif instruction.arg1 == static_arch_values.syscalls.sys_read:
            desc += f"{get_reg(instruction.arg2)} ; (sys_read)"
        elif instruction.arg1 == static_arch_values.syscalls.sys_write:
            desc += f"{get_reg(instruction.arg2)} ; (sys_write)"
        elif instruction.arg1 == static_arch_values.syscalls.sys_sleep:
            desc += f"{get_reg(instruction.arg2)} ; (sys_sleep)"
        elif instruction.arg1 == static_arch_values.syscalls.sys_exit:
            desc += " ; (sys_exit)"

    if instruction.opcode == static_arch_values.OpCodes.stm:
        desc += f"STM {get_reg(instruction.arg1)} {get_reg(instruction.arg2)}"

    if instruction.opcode == static_arch_values.OpCodes.imm:
        desc += f"IMM {get_reg(instruction.arg1)} {get_hex(instruction.arg2)}"

    if instruction.opcode == static_arch_values.OpCodes.stk:
        if instruction.arg1 == 0x00:
            desc += f"PUSH {get_reg(instruction.arg2)}"
        else:
            desc += f"POP {get_reg(instruction.arg1)}"

    if instruction.opcode == static_arch_values.OpCodes.ldm:
        desc += f"LDM {get_reg(instruction.arg1)} {get_reg(instruction.arg2)}"

    if instruction.opcode == static_arch_values.OpCodes.cmp:
        desc += f"CMP {get_reg(instruction.arg1)} {get_reg(instruction.arg2)}"

    if instruction.opcode == static_arch_values.OpCodes.jmp: # JMP not implemented
        desc += f"JMP {get_hex(instruction.arg1)} {get_reg(instruction.arg2)}"

    if instruction.opcode == static_arch_values.OpCodes.add:
        desc += f"ADD {get_reg(instruction.arg1)} {get_reg(instruction.arg2)}"
    
    if desc == f"{instruction.address:04x}: ":
        desc = f"Unknown Instruction: {instruction.opcode} {instruction.arg1} {instruction.arg2}"

    return desc


def main():
    with open("../19.1/code2.raw", "r") as f:
        code_segment_raw = f.read().strip()
    
    text = []

    insts = parse_code_segment(code_segment_raw, 0x03)
    for inst in insts:
        text.append(describe_instruction(inst))

    for line in text:
        print(line)
    


if __name__ == "__main__":
    main()
