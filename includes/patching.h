#ifndef PATCHING_H
#define PATCHING_H

#include <iostream>
#include <capstone/capstone.h>
#include <windows.h>
#include <winternl.h>

// Used for: getting PID by name, setting SeDebugPrivilege
#include <utils.h>

// Used for: function prototypes and definitions
#include <defs.h>

namespace patching {
    inline bool patch_memory(HANDLE h_process, uintptr_t start_address, uintptr_t end_address, bool use_nt_functions) {
        csh handle;
        cs_insn* insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
            std::cerr << "[-] Failed to initialize Capstone" << std::endl;
            return false;
        }

        if (use_nt_functions) {
            if (!function_definitions::nt_write_virtual_memory || !function_definitions::nt_read_virtual_memory) {
                std::cerr << "[-] Failed to load NT functions" << std::endl;
                cs_close(&handle);
                return false;
            }
        }

        // Determine the size of the instruction at the end address
        std::vector<uint8_t> end_buffer(15);
        SIZE_T end_bytes_read;
        NTSTATUS status;
        if (use_nt_functions) {
            status = function_definitions::nt_read_virtual_memory(h_process, reinterpret_cast<PVOID>(end_address), end_buffer.data(), static_cast<ULONG>(end_buffer.size()), reinterpret_cast<PULONG>(&end_bytes_read));
            if (!NT_SUCCESS(status)) {
                std::cerr << "[-] Failed to read process memory at end address" << std::endl;
                cs_close(&handle);
                return false;
            }
        }
        else {
            if (!ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(end_address), end_buffer.data(), end_buffer.size(), &end_bytes_read)) {
                std::cerr << "[-] Failed to read process memory at end address" << std::endl;
                cs_close(&handle);
                return false;
            }
        }

        count = cs_disasm(handle, end_buffer.data(), end_bytes_read, end_address, 1, &insn);
        if (count == 0) {
            std::cerr << "[-] Failed to disassemble instruction at end address" << std::endl;
            cs_close(&handle);
            return false;
        }
        size_t end_instruction_size = insn[0].size;
        cs_free(insn, count);

        // Read the entire region plus the size of the end instruction
        size_t region_size = (end_address - start_address) + end_instruction_size;
        std::vector<uint8_t> buffer(region_size);
        SIZE_T bytes_read;

        if (use_nt_functions) {
            status = function_definitions::nt_read_virtual_memory(h_process, reinterpret_cast<PVOID>(start_address), buffer.data(), static_cast<ULONG>(buffer.size()), reinterpret_cast<PULONG>(&bytes_read));
            if (!NT_SUCCESS(status)) {
                std::cerr << "[-] Failed to read process memory" << std::endl;
                cs_close(&handle);
                return false;
            }
        }
        else {
            if (!ReadProcessMemory(h_process, reinterpret_cast<LPCVOID>(start_address), buffer.data(), buffer.size(), &bytes_read)) {
                std::cerr << "[-] Failed to read process memory" << std::endl;
                cs_close(&handle);
                return false;
            }
        }

        uintptr_t address = start_address;
        while (address <= end_address) {
            count = cs_disasm(handle, &buffer[address - start_address], bytes_read - (address - start_address), address, 1, &insn);
            if (count > 0) {
                size_t instruction_size = insn[0].size;

                // Fill with NOPs
                std::vector<uint8_t> nops(instruction_size, 0x90);

                SIZE_T bytes_written;

                BOOL write_success;
                if (use_nt_functions) {
                    DWORD oldProtect;
                    if (!VirtualProtectEx(h_process, reinterpret_cast<LPVOID>(address), nops.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        DWORD error = GetLastError();
                        std::cerr << "[-] VirtualProtectEx failed at address 0x" << std::hex << address
                            << " with error code: " << std::dec << error << std::endl;
                        cs_close(&handle);
                        return false;
                    }

                    status = function_definitions::nt_write_virtual_memory(h_process, reinterpret_cast<PVOID>(address), nops.data(), static_cast<ULONG>(nops.size()), reinterpret_cast<PULONG>(&bytes_written));

                    VirtualProtectEx(h_process, reinterpret_cast<LPVOID>(address), nops.size(), oldProtect, &oldProtect);

                    write_success = NT_SUCCESS(status);
                    if (!write_success) {
                        std::cerr << "[-] NtWriteVirtualMemory failed at address 0x" << std::hex << address
                            << " with NTSTATUS: 0x" << std::hex << status << std::endl;
                        cs_close(&handle);
                        return false;
                    }
                }
                else {
                    write_success = WriteProcessMemory(h_process, reinterpret_cast<LPVOID>(address), nops.data(), nops.size(), &bytes_written);
                    if (!write_success) {
                        DWORD error = GetLastError();
                        std::cerr << "[-] WriteProcessMemory failed at address 0x" << std::hex << address
                            << " with error code: " << std::dec << error << std::endl;
                        cs_close(&handle);
                        return false;
                    }
                }

                if (!write_success) {
                    std::cerr << "[-] Failed to write NOPs at address 0x" << std::hex << address << std::endl;
                    cs_close(&handle);
                    return false;
                }

                address += instruction_size;
                cs_free(insn, count);

                if (address > end_address) {
                    break;
                }
            }
            else {
                // If we can't disassemble, just NOP out this byte
                BYTE nop = 0x90;
                SIZE_T bytes_written;

                BOOL write_success;
                if (use_nt_functions) {
                    status = function_definitions::nt_write_virtual_memory(h_process, reinterpret_cast<PVOID>(address), &nop, 1, reinterpret_cast<PULONG>(&bytes_written));
                    write_success = NT_SUCCESS(status);
                    if (!write_success) {
                        std::cerr << "[-] NtWriteVirtualMemory failed at address 0x" << std::hex << address
                            << " with NTSTATUS: 0x" << std::hex << status << std::endl;
                        cs_close(&handle);
                        return false;
                    }
                }
                else {
                    write_success = WriteProcessMemory(h_process, reinterpret_cast<LPVOID>(address), &nop, 1, &bytes_written);
                    if (!write_success) {
                        DWORD error = GetLastError();
                        std::cerr << "[-] WriteProcessMemory failed at address 0x" << std::hex << address
                            << " with error code: " << std::dec << error << std::endl;
                        cs_close(&handle);
                        return false;
                    }
                }

                if (!write_success) {
                    std::cerr << "[-] Failed to write NOP at address 0x" << std::hex << address << std::endl;
                    cs_close(&handle);
                    return false;
                }
                address++;
            }
        }

        cs_close(&handle);
        return true;
    }
}

#endif // PATCHING_H