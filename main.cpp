#include <iostream>

// Used for: getting PID by name, setting SeDebugPrivilege
#include <utils.h>

// Used for: function prototypes and definitions
#include <defs.h>

// Used for: main patching functionality
#include <patching.h>

int main() {
    if (!utils::se_debug_privilege()) {
        std::cout << "[!] Couldn't set SeDebugPrivilege, the program may not function properly.\n\n";
    }

    if (!utils::is_ran_as_admin()) {
        std::cout << "[!] The memnop process isn't elevated, the program may not function properly.\n\n";
    }

    std::wstring process_name;
    uintptr_t start_address, end_address;
    bool use_nt_functions;

    std::wcout << L"Enter target process name: ";
    std::wcin >> process_name;

    std::cout << "Enter start address (hex): 0x";
    std::cin >> std::hex >> start_address;

    std::cout << "Enter end address (hex): 0x";
    std::cin >> std::hex >> end_address;

    std::cout << "Use NT functions? (1 for NTAPI, 0 for WinAPI functions): ";
    std::cin >> use_nt_functions;

    DWORD process_id = utils::get_process_id_by_name(process_name);
    if (process_id == 0) {
        std::cerr << "[-] Process not found" << std::endl;
        return 1;
    }

    if (use_nt_functions) {
        if (!function_definitions::load_ntapi_functions()) {
            std::cerr << "[-] Couldn't initialize NTAPI functions" << std::endl;
            return 1;
        }
    }

    HANDLE h_process;
    if (use_nt_functions) {
        OBJECT_ATTRIBUTES obj_attributes = { sizeof(OBJECT_ATTRIBUTES) };
        function_definitions::CLIENT_ID client_id = { reinterpret_cast<HANDLE>(process_id), nullptr };

        NTSTATUS status = function_definitions::nt_open_process(&h_process, PROCESS_ALL_ACCESS, &obj_attributes, &client_id);
        if (!NT_SUCCESS(status)) {
            std::cerr << "[-] Failed to open process with NtOpenProcess" << std::endl;
            return 1;
        }
    }
    else {
        h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (h_process == NULL) {
            std::cerr << "[-] Failed to open process" << std::endl;
            return 1;
        }
    }

    if (!patching::patch_memory(h_process, start_address, end_address, use_nt_functions)) {
        std::cerr << "[-] Failed to patch memory" << std::endl;
        if (use_nt_functions)
            function_definitions::nt_close(h_process);
        else 
            CloseHandle(h_process);

        return 1;
    }

    std::cout << "[+] Memory patched successfully!" << std::endl;

    if (use_nt_functions)
        function_definitions::nt_close(h_process);
    else 
        CloseHandle(h_process);

    return 0;
}