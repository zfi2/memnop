memnop is a command-line tool for memory patching in Windows x64 processes. Built on the Capstone disassembly framework, it allows for NOP-ing out specified memory regions.

## Key features:
- Utilizes Capstone for x86-64 instruction disassembly
- Selection of WinAPI or NTAPI for process interaction
- Patches specified memory ranges in target processes with NOP instructions
- Handles varying instruction lengths when applying NOPs
- Provides options for elevated privileges to ensure access

Note: This tool is for educational and research purposes.

## License

Copyright (c) 2024 zfi2\
This project is licensed under the [MIT](https://opensource.org/license/mit/) License - see the [LICENSE](LICENSE) file for details.
