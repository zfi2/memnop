#ifndef DEFS_H
#define DEFS_H

#include <windows.h>
#include <winternl.h>

namespace function_definitions {
    typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesRead
    );

    // Load NT functions if needed
    HMODULE ntdll = nullptr;
    pNtOpenProcess nt_open_process = nullptr;
    pNtClose nt_close = nullptr;
    pNtWriteVirtualMemory nt_write_virtual_memory = nullptr;
    pNtReadVirtualMemory nt_read_virtual_memory = nullptr;

    inline bool load_ntapi_functions() {
        ntdll = GetModuleHandle(L"ntdll.dll");
        if (!ntdll)
            return false;

        nt_open_process = reinterpret_cast<pNtOpenProcess>(GetProcAddress(ntdll, "NtOpenProcess"));
        nt_close = reinterpret_cast<pNtClose>(GetProcAddress(ntdll, "NtClose"));
        nt_write_virtual_memory = reinterpret_cast<pNtWriteVirtualMemory>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
        nt_read_virtual_memory = reinterpret_cast<pNtReadVirtualMemory>(GetProcAddress(ntdll, "NtReadVirtualMemory"));

        if (!nt_write_virtual_memory && !nt_read_virtual_memory)
            return false;

        return true;
    }
}

#endif // DEFS_H