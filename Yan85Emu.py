from typing import List, Dict
import sys
import time

from Config import static_arch_values, Colors
class YAN85Emulator:
    def __init__(self, memory_size: int = 0x300, code_size: int = 0x300, stdin_file: str = None):
        """Initialize the YAN85 emulator with separated code and data memory."""
        # Registers: a, b, c, d (generic), s (stack), i (instruction pointer), f (flags)
        self.registers: Dict[str, int] = {
            'a': 0,
            'b': 0, 
            'c': 0,
            'd': 0,
            's': 0,  # stack pointer
            'i': 0,  # instruction pointer (references code memory)
            'f': 0   # flags
        }

        self.last_command = ""
        
        # Separated memory architecture
        self.memory_size = memory_size
        self.memory = bytearray(memory_size)  # Data memory for stack, variables, etc.

        # code starts with address 0x03 - 0x00-0x02 is unused
        self.code_size = code_size
        self.code_memory = bytearray(code_size)  # Code memory for instructions only

        # Memory layout: 
        # - Code memory: separate space for instructions, accessed only by register 'i'
        # - Data memory: for stack, variables, general data operations
        
        # File descriptor management for syscalls
        self.file_descriptors = {
            0: 'stdin',   # Standard input
            1: 'stdout',  # Standard output
            2: 'stderr'   # Standard error
        }
        self.next_fd = 3
        self.open_files = {}  # fd -> file object mapping
        
        # Breakpoints
        self.breakpoints = set()

        # Running state
        self.running = True
        
        # Debug mode
        self.debug = False
        self.stdin_file = stdin_file  # Optional file for stdin emulation


    def load_program(self, program: List[str]) -> None:
        """Load a program into code memory starting at 0x00."""
        # For text files, convert yan85 assembly to bytecode first
        self.load_program_from_text(program)

    def load_program_from_text(self, program: List[str]) -> None:
        """Convert yan85 assembly text to 3-byte instructions and load into code memory."""
        current_addr = 0x03

        for line in program:
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty lines and comments
                # Parse the text instruction and convert to 3-byte format
                instruction_bytes = self._encode_text_instruction(line.split())
                
                # Check if we have enough code memory (each instruction is exactly 3 bytes)
                if current_addr + 3 > self.code_size:
                    raise RuntimeError("Program too large for code memory")
                
                # Store the 3 bytes in code memory
                for i, byte in enumerate(instruction_bytes):
                    self.code_memory[current_addr + i] = byte
                current_addr += 3
                    
        # Start execution at instruction 0x01
        self.registers['i'] = 0x01

    def load_program_from_binary_data(self, hex_data: str) -> None:
        """Load a program from hex string data into code memory (each instruction is 6 hex chars = 3 bytes)."""
        # Remove whitespace and ensure even length
        hex_data = hex_data.replace(' ', '').replace('\n', '').strip()
        
        if len(hex_data) % 6 != 0:
            raise ValueError("Invalid hex data length, must be a multiple of 6")
        
        current_addr = 0x03
        
        # Process each 6-character (3-byte) instruction
        for i in range(0, len(hex_data), 6):
            instruction_hex = hex_data[i:i+6]
            
            # Check code memory bounds
            if current_addr + 3 > self.code_size:
                raise RuntimeError("Program too large for code memory")
            
            # Convert hex string to 3 bytes and store in code memory
            # Format: arg2 arg1 opcode (as per parse_code.py)
            self.code_memory[current_addr] = int(instruction_hex[0:2], 16)     # arg2
            self.code_memory[current_addr + 1] = int(instruction_hex[2:4], 16) # arg1  
            self.code_memory[current_addr + 2] = int(instruction_hex[4:6], 16) # opcode
            current_addr += 3

        # Start execution at instruction 0x01
        self.registers['i'] = 0x01

    def _encode_text_instruction(self, instruction: List[str]) -> bytes:
        """Convert text instruction to 3-byte format."""
        if not instruction:
            return bytes([0, 0, 0])
        
        opcode_str = instruction[0].lower()
        
        # Map text opcodes to byte values
        opcode_map = {
            'sys': static_arch_values.OpCodes.sys,
            'stm': static_arch_values.OpCodes.stm,
            'imm': static_arch_values.OpCodes.imm,
            'stk': static_arch_values.OpCodes.stk,
            'ldm': static_arch_values.OpCodes.ldm,
            'cmp': static_arch_values.OpCodes.cmp,
            'jmp': static_arch_values.OpCodes.jmp,
            'add': static_arch_values.OpCodes.add,
        }
        
        # Map text register names to byte values
        reg_map = {
            'a': static_arch_values.reg.a,
            'b': static_arch_values.reg.b,
            'c': static_arch_values.reg.c,
            'd': static_arch_values.reg.d,
            's': static_arch_values.reg.s,
            'i': static_arch_values.reg.i,
            'f': static_arch_values.reg.f,
        }
        
        if opcode_str not in opcode_map:
            raise ValueError(f"Unknown opcode: {opcode_str}")
        
        opcode = opcode_map[opcode_str]
        arg1 = 0
        arg2 = 0
        
        # Parse arguments based on instruction type
        if len(instruction) >= 2:
            if instruction[1] in reg_map:
                arg1 = reg_map[instruction[1]]
            else:
                try:
                    arg1 = int(instruction[1]) & 0xFF
                except ValueError:
                    raise ValueError(f"Invalid argument: {instruction[1]}")
        
        if len(instruction) >= 3:
            if instruction[2] in reg_map:
                arg2 = reg_map[instruction[2]]
            else:
                try:
                    arg2 = int(instruction[2]) & 0xFF
                except ValueError:
                    raise ValueError(f"Invalid argument: {instruction[2]}")
        
        # Return in format: [arg2, arg1, opcode]
        return bytes([arg2, arg1, opcode])

    def _decode_instruction(self, instruction_num: int) -> tuple:
        """Decode a 3-byte instruction from code memory at given instruction number."""
        # Calculate byte address in code memory
        addr = instruction_num * 3
        
        if addr + 2 >= self.code_size:
            return None
        
        # Read 3 bytes from code memory: [arg2, arg1, opcode]
        arg2 = self.code_memory[addr]
        arg1 = self.code_memory[addr + 1]
        opcode = self.code_memory[addr + 2]
        
        return (opcode, arg1, arg2)

    def load_program_from_binary_file(self, filename: str) -> None:
        """Load a program from a binary file containing hex data."""
        with open(filename, 'r') as f:
            hex_data = f.read().strip()
        self.load_program_from_binary_data(hex_data)

    def load_program_from_file(self, filename: str) -> None:
        """Load a program from a file."""
        with open(filename, 'r') as f:
            lines = f.readlines()
        self.load_program(lines)

    def get_register_value(self, reg_id: int) -> int:
        """Get the value of a register by its ID."""
        if reg_id == static_arch_values.reg.a:
            return self.registers['a']
        elif reg_id == static_arch_values.reg.b:
            return self.registers['b']
        elif reg_id == static_arch_values.reg.c:
            return self.registers['c']
        elif reg_id == static_arch_values.reg.d:
            return self.registers['d']
        elif reg_id == static_arch_values.reg.s:
            return self.registers['s']
        elif reg_id == static_arch_values.reg.i:
            return self.registers['i']
        elif reg_id == static_arch_values.reg.f:
            return self.registers['f']
        else:
            raise ValueError(f"Invalid register ID: {reg_id:02x}")

    def set_register_value(self, reg_id: int, value: int) -> None:
        """Set the value of a register by its ID."""
        if reg_id == static_arch_values.reg.a:
            self.registers['a'] = value & 0xFF
        elif reg_id == static_arch_values.reg.b:
            self.registers['b'] = value & 0xFF
        elif reg_id == static_arch_values.reg.c:
            self.registers['c'] = value & 0xFF
        elif reg_id == static_arch_values.reg.d:
            self.registers['d'] = value & 0xFF
        elif reg_id == static_arch_values.reg.s:
            self.registers['s'] = value & 0xFF
        elif reg_id == static_arch_values.reg.i:
            self.registers['i'] = value & 0xFF
        elif reg_id == static_arch_values.reg.f:
            self.registers['f'] = value & 0xFF
        else:
            raise ValueError(f"Invalid register ID: {reg_id:02x}")

    def get_register_name(self, reg_id: int) -> str:
        """Get register name from register ID."""
        reg_map = {
            static_arch_values.reg.a: "a",
            static_arch_values.reg.b: "b",
            static_arch_values.reg.c: "c",
            static_arch_values.reg.d: "d",
            static_arch_values.reg.s: "s",
            static_arch_values.reg.i: "i",
            static_arch_values.reg.f: "f"
        }
        return reg_map.get(reg_id, f"Unknown Register ID: {reg_id:02x}")

    def read_memory(self, address: int) -> int:
        """Read from data memory."""
        if address < 0 or address >= self.memory_size:
            raise ValueError(f"Data memory access out of bounds: {address}")

        return self.memory[address]

    def write_memory(self, address: int, value: int) -> None:
        """Write to data memory."""
        if address < 0 or address >= self.memory_size:
            raise ValueError(f"Data memory access out of bounds: {address}")

        self.memory[address] = value & 0xFF

    def read_code_memory(self, instruction_num: int) -> tuple:
        """Read instruction from code memory at given instruction number."""
        return self._decode_instruction(instruction_num)

    def execute_sys(self, arg1: int, arg2: int) -> None:
        """Execute system call instruction."""
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}sys{Colors.RESET} {arg1:02x} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET}")
        
        # Handle different system calls based on static_arch_values.syscalls
        if arg1 == static_arch_values.syscalls.sys_exit:
            # sys_exit: exit program
            exit_code = self.get_register_value(static_arch_values.reg.a)
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_exit{Colors.RESET}: Program exiting with code {Colors.BOLD}{exit_code}{Colors.RESET}")
            self.running = False
            self.set_register_value(arg2, 0)
            
        elif arg1 == static_arch_values.syscalls.sys_write:
            # sys_write: write to fd(A) from memory address(B) for (C) bytes
            fd = self.get_register_value(static_arch_values.reg.a)
            start_addr = self.get_register_value(static_arch_values.reg.b) - 1
            num_bytes = self.get_register_value(static_arch_values.reg.c)
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}sys_write{Colors.RESET}: fd={Colors.BOLD}{fd}{Colors.RESET}, addr={Colors.BOLD}0x{start_addr:04x}{Colors.RESET}, bytes={Colors.BOLD}{num_bytes}{Colors.RESET}")
            
            bytes_written = 0
            
            # Read the string from data memory and write it
            try:
                output_data = ""
                for i in range(num_bytes):
                    if start_addr + i < self.memory_size:
                        byte_val = self.memory[start_addr + i]
                        output_data += chr(byte_val) if byte_val != 0 else chr(0)
                    else:
                        break  # Out of memory bounds
                
                if fd == 1:  # stdout
                    print(output_data, end='')
                    bytes_written = len(output_data)
                elif fd == 2:  # stderr
                    print(output_data, end='', file=sys.stderr)
                    bytes_written = len(output_data)
                elif fd in self.open_files:
                    try:
                        self.open_files[fd].write(output_data)
                        self.open_files[fd].flush()
                        bytes_written = len(output_data)
                    except:
                        bytes_written = -1  # Error
                else:
                    if self.debug:
                        print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_write{Colors.RESET}: Invalid file descriptor {Colors.BOLD}{fd}{Colors.RESET}")
                    bytes_written = -1  # Error - invalid fd
                    
            except Exception as e:
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_write error{Colors.RESET}: {e}")
                bytes_written = -1
            
            # Store number of bytes written in the result register
            self.set_register_value(arg2, bytes_written & 0xFF if bytes_written >= 0 else 0xFF)
                
        elif arg1 == static_arch_values.syscalls.sys_read:
            # sys_read: read from fd(A) into memory address(B) for (C) bytes
            fd = self.get_register_value(static_arch_values.reg.a)
            buffer_addr = self.get_register_value(static_arch_values.reg.b)
            num_bytes = self.get_register_value(static_arch_values.reg.c)
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}sys_read{Colors.RESET}: fd={Colors.BOLD}{fd}{Colors.RESET}, addr={Colors.BOLD}0x{buffer_addr:04x}{Colors.RESET}, bytes={Colors.BOLD}{num_bytes}{Colors.RESET}")
            
            bytes_read = 0
            
            try:
                if fd == 0:  # stdin
                    try:
                        # Read from stdin
                        data: bytes = b''
                        if self.debug and self.stdin_file:
                            with open(self.stdin_file, 'rb') as f:
                                data = f.read(num_bytes)
                        else:
                            data = input()[:num_bytes].encode('utf-8')  # Limit to requested bytes

                        for i, char in enumerate(data):
                            if buffer_addr + i < self.memory_size:
                                self.memory[buffer_addr + i] = int(char)  # Write to data memory
                                bytes_read += 1
                            else:
                                break  # Out of memory bounds
                    except:
                        bytes_read = -1
                elif fd in self.open_files:
                    try:
                        data = self.open_files[fd].read(num_bytes)
                        for i, char in enumerate(data):
                            if buffer_addr + i < self.memory_size:
                                self.memory[buffer_addr + i] = ord(char) if isinstance(char, str) else char  # Write to data memory
                                bytes_read += 1
                            else:
                                break  # Out of memory bounds
                    except:
                        bytes_read = -1
                else:
                    if self.debug:
                        print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_read{Colors.RESET}: Invalid file descriptor {Colors.BOLD}{fd}{Colors.RESET}")
                    bytes_read = -1  # Error - invalid fd
                    
            except Exception as e:
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_read error{Colors.RESET}: {e}")
                bytes_read = -1
                
            # Store number of bytes read in the result register
            self.set_register_value(arg2, bytes_read & 0xFF if bytes_read >= 0 else 0xFF)
            
        elif arg1 == static_arch_values.syscalls.sys_open:
            # sys_open: open file (filename in memory starting at address in register A)
            filename_addr = self.get_register_value(static_arch_values.reg.a)
            
            # Read null-terminated filename from memory
            filename = ""
            addr = filename_addr
            while addr < self.memory_size and self.memory[addr] != 0:  # Read from data memory
                filename += chr(self.memory[addr])
                addr += 1
                if len(filename) > 255:  # Prevent infinite loop
                    break
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}sys_open{Colors.RESET}: filename='{Colors.BOLD}{filename}{Colors.RESET}'")
            
            try:
                # Try to open file for reading
                file_obj = open(filename, 'r')
                fd = self.next_fd
                self.file_descriptors[fd] = filename
                self.open_files[fd] = file_obj
                self.next_fd += 1
                self.set_register_value(arg2, fd)
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}sys_open{Colors.RESET}: opened '{Colors.BOLD}{filename}{Colors.RESET}' as fd {Colors.BOLD}{fd}{Colors.RESET}")
            except FileNotFoundError:
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_open{Colors.RESET}: file not found '{Colors.BOLD}{filename}{Colors.RESET}'")
                self.set_register_value(arg2, -1)  # Error - file not found
            except:
                if self.debug:
                    print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}sys_open{Colors.RESET}: error opening '{Colors.BOLD}{filename}{Colors.RESET}'")
                self.set_register_value(arg2, -1)  # Error
                
        elif arg1 == static_arch_values.syscalls.sys_sleep:
            # sys_sleep: sleep for (A) milliseconds
            sleep_ms = self.get_register_value(static_arch_values.reg.a)
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}sys_sleep{Colors.RESET}: sleeping for {Colors.BOLD}{sleep_ms}{Colors.RESET} ms")
            
            time.sleep(sleep_ms / 1000.0)  # Convert ms to seconds
            self.set_register_value(arg2, 0)  # Success
            
        else:
            # Unknown syscall
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.RED}Unknown syscall{Colors.RESET}: {Colors.BOLD}{arg1:02x}{Colors.RESET}")
            self.set_register_value(arg2, arg1)  # Return syscall number

    def execute_stm(self, arg1: int, arg2: int) -> None:
        """Execute store to memory instruction."""
        address = self.get_register_value(arg1)
        value = self.get_register_value(arg2)
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}stm{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> mem[{Colors.BOLD}{address:02x}{Colors.RESET}] = {Colors.BOLD}{value}{Colors.RESET}")
        
        self.write_memory(address, value)

    def execute_imm(self, arg1: int, arg2: int) -> None:
        """Execute immediate value instruction."""
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}imm{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} {Colors.BOLD}{arg2:02x}{Colors.RESET}")
        
        self.set_register_value(arg1, arg2)

    def execute_stk(self, arg1: int, arg2: int) -> None:
        """Execute stack operation instruction."""
        if arg2 != 0x00:  # Push operation
            value = self.get_register_value(arg2)
            
            # Push to data memory using stack pointer
            stack_ptr = self.get_register_value(static_arch_values.reg.s)
            if stack_ptr >= self.memory_size:
                raise RuntimeError("Stack overflow - out of data memory")
            
            self.memory[stack_ptr] = value & 0xFF  # Write to data memory
            self.set_register_value(static_arch_values.reg.s, stack_ptr + 1)
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}push{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> mem[{Colors.BOLD}{stack_ptr:04x}{Colors.RESET}] = {Colors.BOLD}{value}{Colors.RESET}")
                
        if arg1 != 0x00:  # Pop operation
            stack_ptr = self.get_register_value(static_arch_values.reg.s)
            
            if stack_ptr == 0:
                raise RuntimeError("Stack underflow")
            
            stack_ptr -= 1
            value = self.memory[stack_ptr]  # Read from data memory
            self.set_register_value(arg1, value)
            self.set_register_value(static_arch_values.reg.s, stack_ptr)
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.GREEN}pop{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} <- mem[{Colors.BOLD}{stack_ptr:04x}{Colors.RESET}] = {Colors.BOLD}{value}{Colors.RESET}")

    def execute_ldm(self, arg1: int, arg2: int) -> None:
        """Execute load from memory instruction."""
        address = self.get_register_value(arg2)
        value = self.read_memory(address)
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}ldm{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} = mem[{Colors.BOLD}{address:02x}{Colors.RESET}] = {Colors.BOLD}{value}{Colors.RESET}")
        
        self.set_register_value(arg1, value)

    def execute_cmp(self, arg1: int, arg2: int) -> None:
        """Execute compare instruction."""
        val1 = self.get_register_value(arg1)
        val2 = self.get_register_value(arg2)
        result = val1 - val2

        self.registers['f'] = 0  # Clear flags before setting new ones

        if val1 == val2 == 0:
            self.registers['f'] |= static_arch_values.flags.zero
        
        if result == 0:
            self.registers['f'] |= static_arch_values.flags.equal_to
        else:
            self.registers['f'] |= static_arch_values.flags.not_equal_to

        if result < 0:
            self.registers['f'] |= static_arch_values.flags.below
        
        if result > 0:
            self.registers['f'] |= static_arch_values.flags.above
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}cmp{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> {Colors.BOLD}{val1}{Colors.RESET} - {Colors.BOLD}{val2}{Colors.RESET} = {Colors.BOLD}{result}{Colors.RESET}, flags: {Colors.MAGENTA}{self.registers['f']:02x}{Colors.RESET}")

    def execute_jmp(self, arg1: int, arg2: int) -> None:
        """Execute jump instruction."""
        jump_instruction = self.get_register_value(arg2)
        
        should_jump = False        
        if self.registers['f'] & arg1 != 0:
            should_jump = True

        if self.debug:
            jump_color = Colors.GREEN if should_jump else Colors.RED
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}jmp{Colors.RESET} {Colors.BOLD}{arg1:02x}{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> instruction: {Colors.BOLD}{jump_instruction}{Colors.RESET}, {jump_color}should_jump: {should_jump}{Colors.RESET}, flags: {Colors.MAGENTA}{self.registers['f']:02x}{Colors.RESET}")

        if should_jump:
            # Jump to instruction number (will be converted to byte address during execution)
            self.registers['i'] = jump_instruction

    def execute_add(self, arg1: int, arg2: int) -> None:
        """Execute addition instruction."""
        dest_val = self.get_register_value(arg1)
        src_val = self.get_register_value(arg2)
        
        result = dest_val + src_val
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.YELLOW}add{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg1)}{Colors.RESET} {Colors.BLUE}{self.get_register_name(arg2)}{Colors.RESET} -> {Colors.BOLD}{dest_val}{Colors.RESET} + {Colors.BOLD}{src_val}{Colors.RESET} = {Colors.BOLD}{result}{Colors.RESET}")
        
        self.set_register_value(arg1, result)

    def execute_instruction(self, opcode: int, arg1: int, arg2: int) -> None:
        """Execute a single instruction."""
        if opcode == static_arch_values.OpCodes.sys:
            self.execute_sys(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.stm:
            self.execute_stm(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.imm:
            self.execute_imm(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.stk:
            self.execute_stk(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.ldm:
            self.execute_ldm(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.cmp:
            self.execute_cmp(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.jmp:
            self.execute_jmp(arg1, arg2)
        elif opcode == static_arch_values.OpCodes.add:
            self.execute_add(arg1, arg2)
        else:
            raise ValueError(f"Unknown opcode: {opcode:02x}")

    def run(self) -> None:
        """Run the loaded program."""
        self.running = True
        self.registers['i'] = 0x01  # Start at instruction number 1

        while self.running:
            # Register 'i' contains instruction number (not byte address)
            instruction_num = self.registers['i']
            
            # Check bounds for code memory
            if instruction_num * 3 + 2 >= self.code_size:
                break
            
            # Check for breakpoints (convert instruction number to byte address for compatibility)
            byte_addr = instruction_num * 3
            if byte_addr in self.breakpoints:
                print(f"{Colors.RED}Hit breakpoint at PC {instruction_num:04x} (instruction #{instruction_num}){Colors.RESET}")
                # Enter interactive debugging mode
                self._enter_debug_mode()
                # If we return from debug mode and the program is no longer running, exit
                if not self.running:
                    break
                
            # Decode instruction from code memory
            instruction = self._decode_instruction(instruction_num)
            if instruction is None:
                break
                
            opcode, arg1, arg2 = instruction
            
            if self.debug:
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.MAGENTA}PC: {instruction_num:04x}{Colors.RESET} (instruction #{instruction_num}), Instruction: {Colors.YELLOW}{opcode:02x} {arg1:02x} {arg2:02x}{Colors.RESET}")
                register_display = ", ".join([f"{Colors.BLUE}{k}{Colors.RESET}:{Colors.BOLD}{v:02x}{Colors.RESET}" for k, v in self.registers.items()])
                print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} Registers: {register_display}")
            
            # Store current PC before execution (for jump detection)
            current_pc = self.registers['i']
            
            # Execute instruction
            self.execute_instruction(opcode, arg1, arg2)
            
            # Move to next instruction only if PC wasn't changed by jump or other instruction
            if self.running:
                self.registers['i'] += 1  # Move to next instruction number

    def print_state(self) -> None:
        """Print the current state of the emulator."""
        print(f"PC (register i): {self.registers['i']:04x} (instruction #{self.registers['i']})")
        print("Registers:")
        print(" | ".join([f"{reg}: 0x{val:02x}" for reg, val in self.registers.items()]))

    def step(self) -> bool:
        """Execute one instruction and return True if successful."""
        if not self.running:
            return False
        # Register 'i' contains instruction number 
        instruction_num = self.registers['i']
        
        # Check bounds for code memory
        if instruction_num * 3 + 2 >= self.code_size:
            return False
        
        # Check for breakpoints (convert instruction number to byte address for compatibility)
        byte_addr = instruction_num * 3
        if byte_addr in self.breakpoints:
            print(f"{Colors.RED}Hit breakpoint at PC {instruction_num:04x} (instruction #{instruction_num}){Colors.RESET}")
            # Don't execute the instruction, just return False to indicate we stopped at breakpoint
            return False
            
        # Decode instruction from code memory
        instruction = self._decode_instruction(instruction_num)
        if instruction is None:
            return False
            
        opcode, arg1, arg2 = instruction
        
        if self.debug:
            print(f"{Colors.CYAN}[DEBUG]{Colors.RESET} {Colors.MAGENTA}PC: {instruction_num:04x}{Colors.RESET} (instruction #{instruction_num}), Instruction: {Colors.YELLOW}{opcode:02x} {arg1:02x} {arg2:02x}{Colors.RESET}")
            
        # Store current PC before execution (for jump detection)
        
        try:
            self.execute_instruction(opcode, arg1, arg2)
            # Move to next instruction only if PC wasn't changed by jump or other instruction
            if self.running:
                self.registers['i'] += 1  # Move to next instruction number
            return True
        except Exception as e:
            print(f"Error executing instruction: {e}")
            return False

    def set_breakpoint(self, addr: int) -> None:
        """Set a breakpoint at the given byte address."""
        self.breakpoints.add(addr)

    def set_breakpoint_instruction(self, instruction_num: int) -> None:
        """Set a breakpoint at the given instruction number (converted to byte address)."""
        byte_addr = instruction_num * 3
        self.breakpoints.add(byte_addr)

    def print_registers(self) -> None:
        """Print all register values."""
        print("Registers:")
        for reg, val in self.registers.items():
            print(f"  {reg}: {val} (0x{val:02x})")

    def print_memory(self) -> None:
        """Print data memory contents (first 64 bytes)."""
        print("Data Memory (first 64 bytes):")
        for i in range(0, min(64, self.memory_size), 16):
            line = f"  {i:04x}: "
            for j in range(16):
                if i + j < self.memory_size:
                    line += f"{self.memory[i + j]:02x} "
                else:
                    line += "   "
            line += " |"
            for j in range(16):
                if i + j < self.memory_size:
                    byte = self.memory[i + j]
                    line += chr(byte) if 32 <= byte <= 126 else "."
                else:
                    line += " "
            line += "|"
            print(line)

    def print_code_memory(self) -> None:
        """Print code memory contents (first 64 bytes)."""
        print("Code Memory (first 64 bytes):")
        for i in range(0, min(64, self.code_size), 16):
            line = f"  {i:04x}: "
            for j in range(16):
                if i + j < self.code_size:
                    line += f"{self.code_memory[i + j]:02x} "
                else:
                    line += "   "
            line += " |"
            for j in range(16):
                if i + j < self.code_size:
                    byte = self.code_memory[i + j]
                    line += chr(byte) if 32 <= byte <= 126 else "."
                else:
                    line += " "
            line += "|"
            print(line)

    def print_memory_at_address(self, start_addr: int, num_bytes: int = 64) -> None:
        """Print data memory contents starting from a specific address."""
        if start_addr < 0:
            print(f"Invalid address: {start_addr:04x} (negative)")
            return
        
        if start_addr >= self.memory_size:
            print(f"Address {start_addr:04x} is beyond data memory size ({self.memory_size:04x})")
            return
        
        # Adjust num_bytes if it would go beyond memory
        end_addr = min(start_addr + num_bytes, self.memory_size)
        actual_bytes = end_addr - start_addr
        
        print(f"Data Memory from {start_addr:04x} to {end_addr-1:04x} ({actual_bytes} bytes):")
        
        # Align to 16-byte boundaries for display
        display_start = (start_addr // 16) * 16
        
        for i in range(display_start, end_addr, 16):
            line = f"  {i:04x}: "
            
            # Hex bytes
            for j in range(16):
                addr = i + j
                if addr < start_addr or addr >= end_addr:
                    if addr < self.memory_size and addr >= start_addr - (start_addr % 16):
                        # Show bytes before start_addr in gray if they're in the same line
                        line += f"{Colors.GRAY}{self.memory[addr]:02x}{Colors.RESET} "
                    else:
                        line += "   "
                elif addr < self.memory_size:
                    if addr < start_addr:
                        line += f"{Colors.GRAY}{self.memory[addr]:02x}{Colors.RESET} "
                    else:
                        line += f"{self.memory[addr]:02x} "
                else:
                    line += "   "
            
            line += " |"
            
            # ASCII representation
            for j in range(16):
                addr = i + j
                if addr < start_addr or addr >= end_addr:
                    if addr < self.memory_size and addr >= start_addr - (start_addr % 16):
                        byte = self.memory[addr]
                        char = chr(byte) if 32 <= byte <= 126 else "."
                        line += f"{Colors.GRAY}{char}{Colors.RESET}"
                    else:
                        line += " "
                elif addr < self.memory_size:
                    byte = self.memory[addr]
                    char = chr(byte) if 32 <= byte <= 126 else "."
                    if addr < start_addr:
                        line += f"{Colors.GRAY}{char}{Colors.RESET}"
                    else:
                        line += char
                else:
                    line += " "
            
            line += "|"
            print(line)

    def print_code_memory_at_address(self, start_addr: int, num_bytes: int = 64) -> None:
        """Print code memory contents starting from a specific address."""
        if start_addr < 0:
            print(f"Invalid address: {start_addr:04x} (negative)")
            return
        
        if start_addr >= self.code_size:
            print(f"Address {start_addr:04x} is beyond code memory size ({self.code_size:04x})")
            return
        
        # Adjust num_bytes if it would go beyond memory
        end_addr = min(start_addr + num_bytes, self.code_size)
        actual_bytes = end_addr - start_addr
        
        print(f"Code Memory from {start_addr:04x} to {end_addr-1:04x} ({actual_bytes} bytes):")
        
        # Align to 16-byte boundaries for display
        display_start = (start_addr // 16) * 16
        
        for i in range(display_start, end_addr, 16):
            line = f"  {i:04x}: "
            
            # Hex bytes
            for j in range(16):
                addr = i + j
                if addr < start_addr or addr >= end_addr:
                    if addr < self.code_size and addr >= start_addr - (start_addr % 16):
                        # Show bytes before start_addr in gray if they're in the same line
                        line += f"{Colors.GRAY}{self.code_memory[addr]:02x}{Colors.RESET} "
                    else:
                        line += "   "
                elif addr < self.code_size:
                    if addr < start_addr:
                        line += f"{Colors.GRAY}{self.code_memory[addr]:02x}{Colors.RESET} "
                    else:
                        line += f"{self.code_memory[addr]:02x} "
                else:
                    line += "   "
            
            line += " |"
            
            # ASCII representation
            for j in range(16):
                addr = i + j
                if addr < start_addr or addr >= end_addr:
                    if addr < self.code_size and addr >= start_addr - (start_addr % 16):
                        byte = self.code_memory[addr]
                        char = chr(byte) if 32 <= byte <= 126 else "."
                        line += f"{Colors.GRAY}{char}{Colors.RESET}"
                    else:
                        line += " "
                elif addr < self.code_size:
                    byte = self.code_memory[addr]
                    char = chr(byte) if 32 <= byte <= 126 else "."
                    if addr < start_addr:
                        line += f"{Colors.GRAY}{char}{Colors.RESET}"
                    else:
                        line += char
                else:
                    line += " "
            
            line += "|"
            print(line)

    def get_register(self, reg: str) -> int:
        """Get register value by name."""
        reg = reg.lower()
        if reg in self.registers:
            return self.registers[reg]
        return None

    def reset(self) -> None:
        """Reset the emulator to initial state."""
        self.registers = {reg: 0 for reg in self.registers.keys()}
        self.memory = bytearray(self.memory_size)  # Reset data memory
        self.code_memory = bytearray(self.code_size)  # Reset code memory
        self.registers['i'] = 0x01
        self.running = True
        self.breakpoints.clear()

    def _enter_debug_mode(self) -> None:
        """Enter interactive debugging mode when a breakpoint is hit."""
        print(f"{Colors.YELLOW}=== Entering Debug Mode ==={Colors.RESET}")
        self.print_state()
        
        while True:
            try:
                cmd = input(f"{Colors.CYAN}$ {Colors.RESET}").strip().lower()
                if not cmd:
                    cmd = self.last_command
                else:
                    self.last_command = cmd
                
                if not cmd:
                    continue

                parts = cmd.split()
                command = parts[0]
                
                if command in ['c', 'continue']:
                    print("Continuing execution...")
                    break
                elif command in ['s', 'step']:
                    if self.step():
                        self.print_state()
                    else:
                        print("Program finished or error occurred")
                        break
                elif command in ['n', 'next']:
                    # Execute one instruction without entering debug mode for inner breakpoints
                    saved_breakpoints = self.breakpoints.copy()
                    self.breakpoints.clear()
                    if self.step():
                        self.print_state()
                    else:
                        print("Program finished or error occurred")
                        break
                    self.breakpoints = saved_breakpoints
                elif command in ['q', 'quit']:
                    self.running = False
                    print("Terminating program execution")
                    break
                elif command in ['h', 'help']:
                    print("Debug commands:")
                    print("  continue, c - Continue execution")
                    print("  step, s - Execute one instruction")
                    print("  next, n - Execute one instruction (skip breakpoints)")
                    print("  info registers, i r - Show register state")
                    print("  info memory [addr], i m [addr] - Show data memory state (64 bytes from addr or 0x00)")
                    print("  info code [addr], i c [addr] - Show code memory state (64 bytes from addr or 0x00)")
                    print("  print <reg>, p <reg> - Print register value")
                    print("  quit, q - Terminate program")
                    print("  help, h - Show this help")
                elif command == 'info' and len(parts) > 1:
                    if parts[1] in ['registers', 'r']:
                        self.print_registers()
                    elif parts[1] in ['memory', 'm']:
                        # Check if address is provided
                        if len(parts) > 2:
                            try:
                                addr = int(parts[2], 0)  # Support hex with 0x prefix
                                self.print_memory_at_address(addr)
                            except ValueError:
                                print(f"Invalid address format: {parts[2]}")
                        else:
                            self.print_memory()  # Default data memory view
                    elif parts[1] in ['code', 'c']:
                        # Check if address is provided
                        if len(parts) > 2:
                            try:
                                addr = int(parts[2], 0)  # Support hex with 0x prefix
                                self.print_code_memory_at_address(addr)
                            except ValueError:
                                print(f"Invalid address format: {parts[2]}")
                        else:
                            self.print_code_memory()  # Default code memory view
                elif command in ['print', 'p'] and len(parts) > 1:
                    reg = parts[1].lower()
                    if reg in self.registers:
                        value = self.registers[reg]
                        print(f"{reg}: {value} (0x{value:02x})")
                    else:
                        print(f"Unknown register: {reg}")
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Use 'quit' to terminate or 'continue' to resume{Colors.RESET}")
            except EOFError:
                self.running = False
                break
