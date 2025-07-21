# YAN85 Emulator

A Python implementation of the YAN85 architecture emulator that supports various instruction types including system calls, memory operations, stack operations, arithmetic, and control flow.

## Architecture Overview

The YAN85 architecture features:
- 8 general-purpose registers (r0-r7)
- Memory space (default 64KB)
- Stack for temporary storage
- Flags for conditional operations (zero, negative, carry, overflow)
- Program counter for instruction sequencing

## Instruction Set

### System Calls (`sys`)
```
sys <syscall_number> <return_register>
```
- Execute system call with given number
- Store return value in specified register

### Immediate Load (`imm`)
```
imm <destination_register> <immediate_value>
```
- Load an immediate value into a register

### Memory Store (`stm`)
```
stm <address_register> <value_register>
```
- Store value from register to memory address

### Memory Load (`ldm`)
```
ldm <destination_register> <address_register>
```
- Load value from memory address into register

### Stack Operations (`stk`)
```
stk 0 <register>     # Push register onto stack
stk <register> 0     # Pop from stack into register
stk <dest> <src>     # Move/copy between registers
```

### Compare (`cmp`)
```
cmp <register1> <register2>
```
- Compare two registers and set flags

### Jump (`jmp`)
```
jmp <condition_mask> <address_register>
```
- Conditional jump based on flags
- Condition masks:
  - 0: Unconditional jump
  - 1: Jump if zero
  - 2: Jump if not zero
  - 4: Jump if negative
  - 8: Jump if positive

### Addition (`add`)
```
add <destination_register> <source_register>
```
- Add source to destination register

## Usage

### Running a Program File
```bash
python3 __main__.py <program_file> [--debug]
```

### Example
```bash
python3 __main__.py test_program.yan85 --debug
```

### Interactive Mode
Run without arguments to see an example program:
```bash
python3 __main__.py
```

## Program Format

Programs are text files with one instruction per line:
```
# Comments start with #
imm r1 42        # Load 42 into register r1
imm r2 8         # Load 8 into register r2
add r1 r2        # Add r2 to r1
sys 60 r0        # Exit system call
```

## System Calls

Currently implemented system calls:
- `1`: Write (uses r1 as buffer address, r2 as length)
- `60`: Exit (uses r1 as exit code)

## Examples

See `test_program.yan85` for a comprehensive example demonstrating all instruction types.

## Features

- Debug mode for step-by-step execution
- Memory protection and bounds checking
- Stack overflow protection
- Comprehensive error handling
- State inspection capabilities
