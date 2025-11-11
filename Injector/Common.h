#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <tlhelp32.h>
#include "Console.h"

struct HandleDeleter {
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using unique_handle = std::unique_ptr<void, HandleDeleter>;

struct ProcessInfo {
    DWORD pid = 0;
    std::wstring name;
};

struct CommandLineArgs {
    std::wstring processName;
    std::wstring dllUrl;
    bool forceWaitProcessStart = false;
};

inline std::wstring SanitizeInput(const std::wstring& input) {
    std::wstring sanitized = input;

    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), [](wchar_t c) {
        return c == L'"' || c == L';' || c == L'|' || c == L'&' || c == L'<' || c == L'>' || c == L'\'';
        }), sanitized.end());

    const size_t MAX_LEN = 512;
    if (sanitized.length() > MAX_LEN) {
        sanitized = sanitized.substr(0, MAX_LEN);
    }
    return sanitized;
}

inline bool ParseCommandLine(int argc, wchar_t* argv[], CommandLineArgs& args) {
    if (argc < 3) {
        PrintMessage(L"错误：缺少必要的命令行参数。");
        PrintMessage(L"用法：" + std::wstring(argv[0]) + L" -process=<进程名.exe> -dll=<DLL URL> [-force_wait_process_start=true|false]");
        return false;
    }

    bool hasProcess = false;
    bool hasDll = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = SanitizeInput(argv[i]);
        if (arg.empty()) {
            continue;
        }

        size_t pos = arg.find(L'=');
        if (pos == std::wstring::npos || pos == 0 || pos == arg.length() - 1) {
            PrintMessage(L"错误：无效的参数格式或值为空：" + arg);
            return false;
        }

        std::wstring key = arg.substr(0, pos);
        std::wstring value = arg.substr(pos + 1);

        if (key == L"-process") {
            args.processName = value;
            hasProcess = true;
        }
        else if (key == L"-dll") {
            args.dllUrl = value;
            hasDll = true;
        }
        else if (key == L"-force_wait_process_start") {
            std::transform(value.begin(), value.end(), value.begin(), ::towlower);
            if (value == L"true") {
                args.forceWaitProcessStart = true;
            }
            else if (value == L"false") {
                args.forceWaitProcessStart = false;
            }
            else {
                PrintMessage(L"错误：无效的 -force_wait_process_start 值：" + value + L"。应为 'true' 或 'false'。");
                return false;
            }
        }
        else {
            PrintMessage(L"警告：未知参数被忽略：" + key);
        }
    }

    if (!hasProcess) {
        PrintMessage(L"错误：必须提供 -process 参数。");
        return false;
    }
    if (!hasDll) {
        PrintMessage(L"错误：必须提供 -dll 参数。");
        return false;
    }

    if (args.processName.length() < 4 || _wcsicmp(args.processName.substr(args.processName.length() - 4).c_str(), L".exe") != 0) {
        PrintMessage(L"错误：-process 必须以 .exe 结尾：" + args.processName);
        return false;
    }

    if (args.dllUrl.length() < 4 || _wcsicmp(args.dllUrl.substr(args.dllUrl.length() - 4).c_str(), L".dll") != 0) {
        PrintMessage(L"警告：-dll 参数提供的 URL (" + args.dllUrl + L") 不以 .dll 结尾。程序将继续，但这可能不是一个有效的 DLL 文件。");
    }

    return true;
}

inline bool EnableDebugPrivilege() {
    PrintMessage(L"尝试启用 SeDebugPrivilege...");
    HANDLE hToken;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintMessage(L"错误：OpenProcessToken 失败。无法获取进程令牌。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }
    unique_handle tokenHandle(hToken);

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        PrintMessage(L"错误：LookupPrivilegeValue 失败。无法查找 SeDebugPrivilege LUID。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            PrintMessage(L"警告：AdjustTokenPrivileges 失败。SeDebugPrivilege 未完全分配。这可能是因为当前用户没有该权限。错误代码：" + std::to_wstring(lastError));
        }
        else {
            PrintMessage(L"警告：AdjustTokenPrivileges 失败。错误代码：" + std::to_wstring(lastError));
        }
        return true;
    }

    PrintMessage(L"SeDebugPrivilege 已尝试启用。");
    return true;
}

inline std::vector<ProcessInfo> ListProcesses() {
    std::vector<ProcessInfo> processes;

    unique_handle snapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshotHandle.get() == INVALID_HANDLE_VALUE) {
        PrintMessage(L"错误：CreateToolhelp32Snapshot 失败。无法创建进程快照。错误代码：" + std::to_wstring(GetLastError()));
        return processes;
    }

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (Process32First(snapshotHandle.get(), &pe32)) {
        do {
            if (pe32.th32ProcessID == 0) continue;
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;
            processes.push_back(info);
        } while (Process32Next(snapshotHandle.get(), &pe32));
    }
    else {
        DWORD lastError = GetLastError();
        if (lastError != ERROR_NO_MORE_FILES) {
            PrintMessage(L"错误：Process32First/Next 迭代进程列表失败。错误代码：" + std::to_wstring(lastError));
        }
    }
    return processes;
}

inline DWORD FindTargetProcess(const std::wstring& processName, bool forceWait) {
    DWORD pid = 0;
    PrintMessage(L"正在查找目标进程: " + processName);

    if (forceWait) {
        PrintMessage(L"启动了强制等待模式。如果进程未运行，将一直等待...");
        while (pid == 0) {
            auto processes = ListProcesses();
            for (const auto& proc : processes) {
                if (_wcsicmp(proc.name.c_str(), processName.c_str()) == 0) {
                    pid = proc.pid;
                    break;
                }
            }
            if (pid == 0) {
                std::wcout << L"> 未找到目标进程 " << processName << L"，正在等待...   \r" << std::flush;
                std::this_thread::sleep_for(std::chrono::nanoseconds(0));
            }
        }
        PrintMessage(L"找到目标进程 " + processName);
    }
    else {
        auto processes = ListProcesses();
        for (const auto& proc : processes) {
            if (_wcsicmp(proc.name.c_str(), processName.c_str()) == 0) {
                pid = proc.pid;
                break;
            }
        }
        if (pid == 0) {
            PrintMessage(L"错误：未找到目标进程 " + processName + L"。");
        }
        else {
            PrintMessage(L"找到目标进程 " + processName + L"。");
        }
    }

    return pid;
}

#endif