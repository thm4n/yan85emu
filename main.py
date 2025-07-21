#!/usr/bin/env python3
"""
YAN85 Architecture Emulator

This emulator implements the YAN85 instruction set architecture with support for:
- System calls
- Memory operations
- Stack operations
- Arithmetic operations
- Control flow
"""

import sys
import argparse

from Yan85Emu import YAN85Emulator

def parse_args(args):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="YAN85 Emulator")
    parser.add_argument("-i", "--insts", help="Path to the program file")
    parser.add_argument("-b", "--bin", help="Path to the binary file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-s", "--stdin", help="File to read stdin from (optional)", default=None)
    return parser.parse_args(args)

def validate_args(args):
    """Validate command line arguments."""
    if not args.insts and not args.bin:
        print("Error: You must specify either a program file with -i or a binary file with -b.")
        sys.exit(1)
    if args.insts and args.bin:
        print("Error: You cannot specify both a program file and a binary file.")
        sys.exit(1)

def main():
    """Main function to run the emulator."""
    args = parse_args(sys.argv[1:])  # Skip script name
    validate_args(args)

    emulator = YAN85Emulator(stdin_file=args.stdin)
    
    if args.debug:
        emulator.debug = True

    if args.insts:
        emulator.load_program_from_file(args.insts)
    elif args.bin:
        emulator.load_program_from_binary_file(args.bin)

    # If debug mode is enabled, enter debug mode before running the first instruction
    if args.debug:
        print("Debug mode enabled - entering debugger before first instruction")
        emulator._enter_debug_mode()
        # Only continue running if the emulator is still in running state after debug mode
        if emulator.running:
            emulator.run()
    else:
        # Run the program normally - debugging is handled automatically by breakpoints or memory address 0x6c
        emulator.run()
    emulator.print_state()

if __name__ == "__main__":
    main()
