#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

namespace utils {
    inline bool se_debug_privilege() {
        BOOL bRet = FALSE;
        HANDLE hToken = NULL;
        LUID luid = { 0 };

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
            {
                TOKEN_PRIVILEGES tokenPriv = { 0 };
                tokenPriv.PrivilegeCount = 1;
                tokenPriv.Privileges[0].Luid = luid;
                tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            }
        }

        return bRet;
    }

    inline DWORD get_process_id_by_name(const std::wstring& process_name) {
        PROCESSENTRY32 entry{ sizeof(PROCESSENTRY32) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &entry)) {
            do {
                if (process_name == entry.szExeFile) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    inline bool is_ran_as_admin()
    {
        BOOL is_admin = FALSE;
        SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
        PSID administrators_group;

        if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators_group))
        {
            if (!CheckTokenMembership(NULL, administrators_group, &is_admin))
            {
                is_admin = FALSE;
            }
            FreeSid(administrators_group);
        }

        return is_admin == TRUE;
    }
}

#endif // UTILS_H