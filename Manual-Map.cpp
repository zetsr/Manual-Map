#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#define NOMINMAX // Prevents conflicts with min/max macros in windows.h
#include <windows.h>
#include <tlhelp32.h> // For process listing
#include <memory>     // For std::unique_ptr
#include <limits>
#include <cstdint>
#include <wininet.h>  // For downloading DLL from URL
#include <io.h>       // For _fileno
#include <fcntl.h>    // For _O_U16TEXT
#include <stdio.h>    // For _fileno (some compilers)
#include <iostream>   // For std::wcout, std::wcin, std::endl
#include <thread>     // For std::this_thread::sleep_for
#include <chrono>     // For std::chrono::milliseconds
#include <conio.h>    // For _getwch
#include <iomanip>    // For std::setw, std::setfill

// Assume ManualMapInjector.h contains the definition of the ManualMapInjector class
// and the static ManualMapInject method used below.
/*
#ifndef MANUALMAPINJECTOR_H
#define MANUALMAPINJECTOR_H
#include <windows.h>
#include <cstdint>
class ManualMapInjector {
public:
    static bool ManualMapInject(DWORD pid, BYTE* dllBuffer, size_t dllSize);
#ifdef _WIN64
    static const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_AMD64; // Compiled as 64-bit
#else
    static const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_I386; // Compiled as 32-bit
#endif
};
#endif // MANUALMAPINJECTOR_H
*/
#include "ManualMapInjector.h" // Include your ManualMapInjector.h file

#pragma comment(lib, "wininet.lib")

// --- RAII Wrappers for WinINet handles ---
struct InternetHandleDeleter {
    void operator()(HINTERNET handle) const {
        if (handle != NULL) {
            InternetCloseHandle(handle);
        }
    }
};
using unique_internet_handle = std::unique_ptr<void, InternetHandleDeleter>;

// --- Console Utility ---
// Hides or shows the console cursor
void SetConsoleCursorVisibility(bool visible) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }

    CONSOLE_CURSOR_INFO cursorInfo;
    if (!GetConsoleCursorInfo(hConsole, &cursorInfo)) {
        return;
    }

    cursorInfo.bVisible = visible;
    SetConsoleCursorInfo(hConsole, &cursorInfo);
}

// Clears the console screen using Windows API
void ClearConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return; // Cannot clear
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        return; // Cannot clear
    }

    DWORD dwWritten;
    // Calculate the number of cells in the current buffer
    DWORD dwConsoleSize = csbi.dwSize.X * csbi.dwSize.Y;
    COORD cursorHome = { 0, 0 }; // Top-left corner

    // Fill the entire screen buffer with spaces
    if (!FillConsoleOutputCharacterW(hConsole, L' ', dwConsoleSize, cursorHome, &dwWritten)) {
        return; // Cannot clear
    }

    // Fill the entire screen buffer with the current attributes
    if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConsoleSize, cursorHome, &dwWritten)) {
        return; // Cannot clear
    }

    // Move the cursor to the top-left corner
    SetConsoleCursorPosition(hConsole, cursorHome);
}

// --- Custom Output Function ---
// Encapsulates output to add a consistent prefix and use wide characters
void PrintMessage(const std::wstring& message) {
    std::wcout << L"> " << message << std::endl;
}

// --- Utility for Graphical Banner ---
// Prints text character by character or in batches with a delay
// chars_per_sleep: number of characters to print before sleeping
void PrintTypewriter(const std::wstring& text, int delay_ms, int chars_per_sleep = 1) {
    if (chars_per_sleep <= 0) chars_per_sleep = 1; // Ensure at least 1 character per sleep

    int chars_printed_in_batch = 0;
    for (wchar_t c : text) {
        std::wcout << c << std::flush;
        chars_printed_in_batch++;
        // Sleep only if delay is positive and we've printed enough characters in the batch
        if (delay_ms > 0 && chars_printed_in_batch >= chars_per_sleep) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            chars_printed_in_batch = 0; // Reset batch count after sleeping
        }
    }
    // Optional: Add a small final sleep after the line is done if the last batch wasn't full
    // if (delay_ms > 0 && chars_printed_in_batch > 0) {
    //    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    // }
}

// --- Graphical Banner ---
// Displays the animated "ZETSR" banner and program title
void DisplayBanner() {
    const std::wstring banner[] = {
        L"####### ####### ####### ####### #######",
        L"      # #             # #       #     #",
        L"     #  #             # #       #     #",
        L"    #   ######        # ####### #######",
        L"   #    #             #       # #   #  ",
        L"  #     #             #       # #    # ",
        L"####### #######       # ####### #     #"
    };
    PrintMessage(L""); // Add a newline before the banner
    // Experiment with delay_ms and chars_per_sleep to find the desired speed
    // Example: 1ms delay every 5 characters (should be much faster than 1ms per char)
    int delay_ms_per_batch = 1;
    int chars_per_sleep_batch = 5; // Print 5 characters, then wait 1ms

    for (const auto& line : banner) {
        PrintTypewriter(line, delay_ms_per_batch, chars_per_sleep_batch);
        std::wcout << std::endl; // Newline after each line
    }
    PrintMessage(L""); // Add a newline after the banner
    PrintMessage(L"C++ 手动映射 DLL 注入器");
    PrintMessage(L"注入器架构：" + std::wstring((ManualMapInjector::TARGET_MACHINE == IMAGE_FILE_MACHINE_AMD64 ? L"64位" : L"32位")));
    PrintMessage(L""); // Add a newline
}

// --- Helper Structures and Types ---

// Represents basic information about a running process
struct ProcessInfo {
    DWORD pid = 0;
    std::wstring name;
};

// Custom deleter for Windows HANDLEs using std::unique_ptr
struct HandleDeleter {
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

using unique_handle = std::unique_ptr<void, HandleDeleter>;

// Structure to hold parsed command line arguments
struct CommandLineArgs {
    std::wstring processName;
    std::wstring dllUrl;
    bool forceWaitProcessStart = false;
};

// --- Progress Bar Implementation ---
class WgetStyleProgressBar {
private:
    size_t total_size;
    size_t downloaded;
    std::chrono::steady_clock::time_point start_time;
    int last_progress_percent;
    int console_width;

    std::wstring FormatSize(size_t bytes) {
        const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB" };
        int unit_index = 0;
        double size = static_cast<double>(bytes);

        while (size >= 1024.0 && unit_index < 3) {
            size /= 1024.0;
            unit_index++;
        }

        std::wstringstream ss;
        ss << std::fixed << std::setprecision(1) << size << L" " << units[unit_index];
        return ss.str();
    }

    std::wstring FormatTime(double seconds) {
        int hours = static_cast<int>(seconds) / 3600;
        int minutes = (static_cast<int>(seconds) % 3600) / 60;
        int secs = static_cast<int>(seconds) % 60;

        std::wstringstream ss;
        if (hours > 0) {
            ss << hours << L":" << std::setw(2) << std::setfill(L'0') << minutes
                << L":" << std::setw(2) << std::setfill(L'0') << secs;
        }
        else {
            ss << minutes << L":" << std::setw(2) << std::setfill(L'0') << secs;
        }
        return ss.str();
    }

    void GetConsoleWidth() {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
            console_width = csbi.dwSize.X;
        }
        else {
            console_width = 80; // Default width
        }
    }

public:
    WgetStyleProgressBar(size_t total) : total_size(total), downloaded(0),
        last_progress_percent(-1), console_width(80) {
        start_time = std::chrono::steady_clock::now();
        GetConsoleWidth();
    }

    void Update(size_t new_downloaded) {
        downloaded = new_downloaded;

        if (total_size == 0) {
            // Unknown total size - show indeterminate progress
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            double speed = (elapsed > 0) ? static_cast<double>(downloaded) / elapsed : 0;

            std::wcout << L"\r" << FormatSize(downloaded) << L" ["
                << std::setw(5) << std::setprecision(1) << std::fixed
                << speed << L"B/s]";
            std::wcout.flush();
            return;
        }

        int percent = static_cast<int>((static_cast<double>(downloaded) / total_size) * 100);
        if (percent == last_progress_percent && percent < 100) {
            return; // Don't update if percentage hasn't changed
        }
        last_progress_percent = percent;

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        double speed = (elapsed > 0) ? static_cast<double>(downloaded) / elapsed : 0;

        // Calculate ETA
        double eta_seconds = (speed > 0) ? (total_size - downloaded) / speed : 0;

        // Create progress bar
        int bar_width = std::max(20, console_width - 50);
        int completed_width = static_cast<int>((static_cast<double>(bar_width) * percent) / 100);

        std::wstringstream progress_bar;
        progress_bar << L"[";
        for (int i = 0; i < bar_width; i++) {
            if (i < completed_width) {
                progress_bar << L"=";
            }
            else if (i == completed_width) {
                progress_bar << L">";
            }
            else {
                progress_bar << L" ";
            }
        }
        progress_bar << L"]";

        std::wcout << L"\r" << std::setw(3) << percent << L"% " << progress_bar.str()
            << L" " << FormatSize(downloaded) << L" " << FormatSize(static_cast<size_t>(speed)) << L"/s"
            << L" eta " << FormatTime(eta_seconds);
        std::wcout.flush();
    }

    void Finish() {
        if (total_size > 0) {
            Update(total_size); // Ensure we show 100%
        }
        std::wcout << std::endl;
    }
};

// --- Core Utility Functions ---

// Sanitizes input strings to prevent basic injection attempts
std::wstring SanitizeInput(const std::wstring& input) {
    std::wstring sanitized = input;
    // Remove characters potentially harmful in command execution or file paths
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), [](wchar_t c) {
        return c == L'"' || c == L';' || c == L'|' || c == L'&' || c == L'<' || c == L'>' || c == L'\''; // Added single quote
        }), sanitized.end());
    // Limit length to prevent buffer overflows or excessively long inputs
    const size_t MAX_LEN = 512; // Increased max length slightly
    if (sanitized.length() > MAX_LEN) {
        sanitized = sanitized.substr(0, MAX_LEN);
    }
    return sanitized;
}

// Parses command line arguments into the CommandLineArgs structure
bool ParseCommandLine(int argc, wchar_t* argv[], CommandLineArgs& args) {
    if (argc < 3) { // Need at least progname, -process, -dll
        PrintMessage(L"错误：缺少必要的命令行参数。");
        PrintMessage(L"用法：" + std::wstring(argv[0]) + L" -process=<进程名.exe> -dll=<DLL URL> [-force_wait_process_start=true|false]");
        return false;
    }

    bool hasProcess = false;
    bool hasDll = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = SanitizeInput(argv[i]);
        if (arg.empty()) {
            continue; // Skip empty or fully sanitized-out arguments
        }

        // Arguments are expected in key=value format
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

    // Basic validation for .exe and .dll extensions
    if (args.processName.length() < 4 || _wcsicmp(args.processName.substr(args.processName.length() - 4).c_str(), L".exe") != 0) {
        PrintMessage(L"错误：-process 必须以 .exe 结尾：" + args.processName);
        return false;
    }

    if (args.dllUrl.length() < 4 || _wcsicmp(args.dllUrl.substr(args.dllUrl.length() - 4).c_str(), L".dll") != 0) {
        // Note: This check is basic. A URL doesn't *have* to end in .dll
        // but for simplicity and common use cases, we'll issue a warning.
        PrintMessage(L"警告：-dll 参数提供的 URL (" + args.dllUrl + L") 不以 .dll 结尾。程序将继续，但这可能不是一个有效的 DLL 文件。");
    }

    return true;
}

// Attempts to enable SeDebugPrivilege for the current process
bool EnableDebugPrivilege() {
    PrintMessage(L"尝试启用 SeDebugPrivilege...");
    HANDLE hToken;
    // TOKEN_ADJUST_PRIVILEGES for enabling, TOKEN_QUERY to check current privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintMessage(L"错误：OpenProcessToken 失败。无法获取进程令牌。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }
    unique_handle tokenHandle(hToken); // Use unique_handle for RAII

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        PrintMessage(L"错误：LookupPrivilegeValue 失败。无法查找 SeDebugPrivilege LUID。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust token privileges
    if (!AdjustTokenPrivileges(tokenHandle.get(), FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_NOT_ALL_ASSIGNED) {
            PrintMessage(L"警告：AdjustTokenPrivileges 失败。SeDebugPrivilege 未完全分配。这可能是因为当前用户没有该权限。错误代码：" + std::to_wstring(lastError));
        }
        else {
            PrintMessage(L"警告：AdjustTokenPrivileges 失败。错误代码：" + std::to_wstring(lastError));
        }
        // In some cases, failing to get the privilege is not fatal, but should be warned about.
        // We return true here because the attempt was made, but the warning is printed.
        // If the target process requires SeDebugPrivilege and we don't have it, OpenProcess will fail later.
        return true;
    }

    PrintMessage(L"SeDebugPrivilege 已尝试启用。");
    return true; // Attempt succeeded (might not have been granted if user lacks permission)
}

// Lists running processes
std::vector<ProcessInfo> ListProcesses() {
    std::vector<ProcessInfo> processes;
    // TH32CS_SNAPPROCESS includes all processes
    unique_handle snapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshotHandle.get() == INVALID_HANDLE_VALUE) {
        PrintMessage(L"错误：CreateToolhelp32Snapshot 失败。无法创建进程快照。错误代码：" + std::to_wstring(GetLastError()));
        return processes;
    }

    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    if (Process32First(snapshotHandle.get(), &pe32)) {
        do {
            // Skip idle and system processes with PID 0
            if (pe32.th32ProcessID == 0) continue;
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;
            processes.push_back(info);
        } while (Process32Next(snapshotHandle.get(), &pe32));
    }
    else {
        DWORD lastError = GetLastError();
        // ERROR_NO_MORE_FILES is expected when iteration finishes
        if (lastError != ERROR_NO_MORE_FILES) {
            PrintMessage(L"错误：Process32First/Next 迭代进程列表失败。错误代码：" + std::to_wstring(lastError));
        }
    }
    return processes;
}

// Finds the PID of the target process by name
DWORD FindTargetProcess(const std::wstring& processName, bool forceWait) {
    DWORD pid = 0;
    PrintMessage(L"正在查找目标进程: " + processName);

    if (forceWait) {
        PrintMessage(L"启动了强制等待模式。如果进程未运行，将一直等待...");
        while (pid == 0) {
            auto processes = ListProcesses();
            for (const auto& proc : processes) {
                if (_wcsicmp(proc.name.c_str(), processName.c_str()) == 0) {
                    pid = proc.pid;
                    break; // Found it
                }
            }
            if (pid == 0) {
                // Use carriage return \r to overwrite the waiting message on the same line
                std::wcout << L"> 未找到目标进程 " << processName << L"，正在等待...   \r" << std::flush;
                std::this_thread::sleep_for(std::chrono::nanoseconds(0)); // Wait before trying again
            }
        }
        // After finding, print a final newline to clear the "Waiting..." line and print success
        PrintMessage(L"找到目标进程 " + processName); // This message will overwrite the waiting line
    }
    else {
        auto processes = ListProcesses();
        for (const auto& proc : processes) {
            if (_wcsicmp(proc.name.c_str(), processName.c_str()) == 0) {
                pid = proc.pid;
                break; // Found it
            }
        }
        if (pid == 0) {
            PrintMessage(L"错误：未找到目标进程 " + processName + L"。");
        }
        else {
            PrintMessage(L"找到目标进程 " + processName + L"。");
        }
    }

    return pid; // Returns 0 if not found (and not waiting), or the PID
}

// Gets the size of a file from a HTTP/HTTPS URL
// Uses separate InternetOpen/Url/Close handles as it's a distinct step
bool GetHttpFileSize(const std::wstring& url, size_t& fileSize) {
    fileSize = 0;

    unique_internet_handle hInternet(InternetOpenW(L"DLLDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    if (!hInternet) {
        PrintMessage(L"错误：[GetSize] InternetOpenW 失败。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    unique_internet_handle hUrl(InternetOpenUrlW(hInternet.get(), url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0));
    if (!hUrl) {
        PrintMessage(L"错误：[GetSize] InternetOpenUrlW 失败。无法打开 URL：" + url + L"。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    DWORD contentLength = 0;
    DWORD length = sizeof(contentLength);
    // Query for Content-Length header
    if (!HttpQueryInfoW(hUrl.get(), HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &length, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_HTTP_HEADER_NOT_FOUND) {
            PrintMessage(L"警告：[GetSize] 无法获取 Content-Length 头部。下载将继续，但无法预知文件大小。");
            fileSize = 0; // Indicate size is unknown
        }
        else {
            PrintMessage(L"错误：[GetSize] HttpQueryInfoW 失败。无法获取 Content-Length。错误代码：" + std::to_wstring(lastError));
            return false; // Critical error if not just header not found
        }
    }
    else {
        fileSize = static_cast<size_t>(contentLength);
        if (fileSize == 0) {
            PrintMessage(L"警告：[GetSize] 获取到 Content-Length 为 0。DLL 文件可能为空。");
        }
        else {
            PrintMessage(L"远程文件大小估算：" + std::to_wstring(fileSize) + L" 字节。");
        }
    }

    return true; // Return true even if size is 0 or unknown (warning issued)
}

// Downloads the DLL from a URL into a memory buffer
std::unique_ptr<BYTE[]> DownloadDLLToMemory(const std::wstring& url, size_t& outSize) {
    outSize = 0;
    size_t fileSize = 0;

    // Attempt to get file size first, but proceed even if unknown
    // GetHttpFileSize handles its own InternetOpen/Url/Close handles
    bool sizeKnown = GetHttpFileSize(url, fileSize);

    unique_internet_handle hInternet(InternetOpenW(L"DLLDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    if (!hInternet) {
        PrintMessage(L"错误：InternetOpenW 失败。无法初始化网络连接。错误代码：" + std::to_wstring(GetLastError()));
        return nullptr;
    }

    unique_internet_handle hUrl(InternetOpenUrlW(hInternet.get(), url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE, 0));
    if (!hUrl) {
        PrintMessage(L"错误：InternetOpenUrlW 失败。无法打开 URL：" + url + L"。错误代码：" + std::to_wstring(GetLastError()));
        return nullptr;
    }

    // Create progress bar
    WgetStyleProgressBar progressBar(fileSize);
    PrintMessage(L"正在从 " + url + L" 下载 DLL...");

    // Calculate initial buffer size
    size_t bufferSize = sizeKnown && fileSize > 0 ?
        fileSize + std::max<size_t>(fileSize / 10, 1024 * 1024) :
        10 * 1024 * 1024; // 10MB initial buffer if size unknown

    // Ensure a minimum buffer size even if estimated size is tiny or 0
    if (bufferSize < 4096) bufferSize = 4096;

    // Allocate initial buffer
    std::unique_ptr<BYTE[]> buffer(new (std::nothrow) BYTE[bufferSize]);
    if (!buffer) {
        PrintMessage(L"错误：内存分配失败。无法分配下载缓冲区（" + std::to_wstring(bufferSize) + L" 字节）。可能由于内存不足或碎片化。");
        return nullptr;
    }

    size_t totalRead = 0;
    BYTE temp[8192]; // Increased read buffer size for better performance
    DWORD bytesRead;

    while (InternetReadFile(hUrl.get(), temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
        // Check if we need to resize buffer
        if (totalRead + bytesRead > bufferSize) {
            // Calculate new buffer size
            size_t newBufferSize = bufferSize * 2;

            // Cap maximum buffer size to prevent excessive memory use
            const size_t MAX_BUFFER_SIZE = 256 * 1024 * 1024; // 256MB
            if (newBufferSize > MAX_BUFFER_SIZE) {
                if (totalRead + bytesRead > MAX_BUFFER_SIZE) {
                    PrintMessage(L"错误：下载数据超出最大允许缓冲区大小 (" + std::to_wstring(MAX_BUFFER_SIZE) + L" 字节)。");
                    return nullptr;
                }
                newBufferSize = MAX_BUFFER_SIZE;
            }

            // Reallocate buffer
            std::unique_ptr<BYTE[]> newBuffer(new (std::nothrow) BYTE[newBufferSize]);
            if (!newBuffer) {
                PrintMessage(L"错误：内存重新分配失败。无法扩展下载缓冲区。");
                return nullptr;
            }

            // Copy existing data
            std::copy(buffer.get(), buffer.get() + totalRead, newBuffer.get());
            buffer = std::move(newBuffer);
            bufferSize = newBufferSize;

            PrintMessage(L"警告：下载缓冲区不足，尝试重新分配到 " + std::to_wstring(bufferSize) + L" 字节。");
        }

        // Copy new data to buffer
        std::copy(temp, temp + bytesRead, buffer.get() + totalRead);
        totalRead += bytesRead;

        // Update progress bar
        progressBar.Update(totalRead);
    }

    // Check for download errors
    DWORD lastInternetError = GetLastError();
    if (totalRead == 0 && lastInternetError != ERROR_SUCCESS) {
        PrintMessage(L"错误：DLL 下载失败，未读取到任何数据。InternetReadFile 错误代码：" + std::to_wstring(lastInternetError));
        return nullptr;
    }
    else if (totalRead == 0) {
        PrintMessage(L"警告：下载的 DLL 为空（0 字节）。");
        return nullptr;
    }

    // Finalize progress bar
    progressBar.Finish();

    // Create final buffer with exact size
    std::unique_ptr<BYTE[]> finalBuffer(new (std::nothrow) BYTE[totalRead]);
    if (!finalBuffer) {
        PrintMessage(L"错误：无法分配最终 DLL 缓冲区 (" + std::to_wstring(totalRead) + L" 字节)。可能由于内存不足。");
        return nullptr;
    }

    // Copy data to final buffer
    std::copy(buffer.get(), buffer.get() + totalRead, finalBuffer.get());
    outSize = totalRead;

    PrintMessage(L"DLL 成功下载到内存。大小：" + std::to_wstring(outSize) + L" 字节。");
    return finalBuffer;
}

// --- Main Program ---

int wmain(int argc, wchar_t* argv[]) {
    // Configure console for Unicode output and input (important for _getwch)
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    // Hide console cursor permanently as requested
    SetConsoleCursorVisibility(false);

    // Clear the console before displaying the banner
    ClearConsole();

    DisplayBanner(); // Display the graphical banner

    // Parse command line arguments
    CommandLineArgs args;
    if (!ParseCommandLine(argc, argv, args)) {
        PrintMessage(L"参数解析失败。程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch(); // Wait for a wide character input
        return 1; // Exit with error code
    }

    PrintMessage(L"配置详情：");
    PrintMessage(L"  目标进程: " + args.processName);
    PrintMessage(L"  DLL URL: " + args.dllUrl);
    PrintMessage(L"  强制等待进程启动: " + std::wstring(args.forceWaitProcessStart ? L"是" : L"否"));
    PrintMessage(L""); // Add a newline

    // Attempt to enable debug privilege
    if (!EnableDebugPrivilege()) {
        // Non-critical failure, warning is printed by the function
    }
    PrintMessage(L""); // Add a newline

    // Find the target process
    DWORD targetPID = FindTargetProcess(args.processName, args.forceWaitProcessStart);
    if (targetPID == 0) {
        PrintMessage(L"未能找到目标进程。程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch();
        return 1; // Exit with error code
    }
    PrintMessage(L"目标进程 " + args.processName + L" 的 PID 是: " + std::to_wstring(targetPID));
    PrintMessage(L""); // Add a newline

    // Download the DLL
    size_t dllSize = 0;
    auto dllBuffer = DownloadDLLToMemory(args.dllUrl, dllSize);

    // Check if download was successful
    if (!dllBuffer || dllSize == 0) {
        PrintMessage(L"错误：DLL 下载失败或文件为空。无法进行注入。");
        PrintMessage(L"程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch();
        return 1; // Exit with error code
    }

    PrintMessage(L""); // Add a newline

    // Execute the manual mapping injection
    PrintMessage(L"开始手动映射注入...");
    bool injectionSuccess = ManualMapInjector::ManualMapInject(targetPID, dllBuffer.get(), dllSize);

    // Securely zero the DLL buffer in memory regardless of injection success/failure
    SecureZeroMemory(dllBuffer.get(), dllSize);
    PrintMessage(L"DLL 内存缓冲区已安全擦除。");

    if (injectionSuccess) {
        PrintMessage(L"手动映射注入成功！");
    }
    else {
        PrintMessage(L"错误：手动映射注入失败。");
    }

    PrintMessage(L""); // Add a newline
    PrintMessage(L"注入过程已完成。");
    PrintMessage(L"按任意键继续...");
    _getwch(); // Wait for user input before closing

    return injectionSuccess ? 0 : 1; // Return 0 on success, 1 on failure
}