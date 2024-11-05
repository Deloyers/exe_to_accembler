#PE Disassembler

**About the Project**
---------------

This script is designed to disassemble Portable Executable (PE) executable files, using the powerful `pefile` tools for processing PE files and `capstone` for disassembling machine code. The script automatically detects the architecture of the file (x86 or x64) and saves the disassembly result to an ASM file.

**Functionality**
----------------------

- **Auto architecture detection**: x86 (32-bit) and x64 (64-bit) file support.
- **Executable code disassembly**: Process only sections marked as executable.
- **Detailed Output**: Includes information about the file, sections, virtual addresses, section sizes, and instruction details.
- **Ease of Use**: Simple command line interface for quick startup.

**Installing and Using the PE Disassembler**
----------------------------------------------

### Repository Cloning:
- Open a terminal or command line.
- Navigate to the directory where you want to save the project using the command cd /path/to/directory.
- To clone the repository, execute:

```bash
git clone https://github.com/Deloyers/exe_to_accembler.git
```

### Dependency Setup

- Installing dependencies from requirements.txt:
```bash
pip install -r requirements.txt
```

### Using PE Disassembler

- Starting the disassembler:
```bash
python disassembler.py /path/your/file.exe
```
