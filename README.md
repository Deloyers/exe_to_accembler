#PE Disassembler

**О проекте**
---------------

This script is designed to disassemble Portable Executable (PE) executable files, using the powerful `pefile` tools for processing PE files and `capstone` for disassembling machine code. The script automatically detects the architecture of the file (x86 or x64) and saves the disassembly result to an ASM file.

**Functionality**
----------------------

- **Auto architecture detection**: x86 (32-bit) and x64 (64-bit) file support.
- **Executable code disassembly**: Process only sections marked as executable.
- **Detailed Output**: Includes information about the file, sections, virtual addresses, section sizes, and instruction details.
- **Ease of Use**: Simple command line interface for quick startup.
