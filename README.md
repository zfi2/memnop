memnop is a command-line tool for memory patching in Windows x64 processes. Built on the Capstone disassembly framework, it allows for NOP-ing out specified memory regions.

## Key features:
- Utilizes Capstone for x86-64 instruction disassembly
- Selection of WinAPI or NTAPI for process interaction
- Patches specified memory ranges in target processes with NOP instructions
- Handles varying instruction lengths when applying NOPs
- Provides options for elevated privileges to ensure access

This software and its code examples are provided for educational purposes and research only.
The author provides no guarantees or warranties concerning the usability or reliability of
this software. By using this software, you agree that the author shall not be held responsible
for any damage or loss of data that may occur as a result of its use. Use this software at your
own risk.

## License

Copyright (c) 2024 zfi2\
This project is licensed under the [MIT](https://opensource.org/license/mit/) License - see the [LICENSE](LICENSE) file for details.
