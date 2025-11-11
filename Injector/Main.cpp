#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#define NOMINMAX
#include <windows.h>
#include <memory>
#include <limits>
#include <cstdint>
#include <io.h>
#include <fcntl.h> 
#include <stdio.h>
#include <iostream>
#include <thread> 
#include <chrono>
#include <conio.h> 
#include <iomanip> 

#include "../API/ManualMapInjector.h"
#include "Common.h"
#include "Console.h"
#include "Print.h"
#include "Http.h"

int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    SetConsoleCursorVisibility(false);
    ClearConsole();
    DisplayBanner();

    CommandLineArgs args;
    if (!ParseCommandLine(argc, argv, args)) {
        PrintMessage(L"参数解析失败。程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch();
        return 1;
    }

    PrintMessage(L"配置详情：");
    PrintMessage(L"  目标进程: " + args.processName);
    PrintMessage(L"  DLL URL: " + args.dllUrl);
    PrintMessage(L"  强制等待进程启动: " + std::wstring(args.forceWaitProcessStart ? L"是" : L"否"));
    PrintMessage(L"");

    if (!EnableDebugPrivilege()) {

    }
    PrintMessage(L"");

    DWORD targetPID = FindTargetProcess(args.processName, args.forceWaitProcessStart);
    if (targetPID == 0) {
        PrintMessage(L"未能找到目标进程。程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch();
        return 1;
    }
    PrintMessage(L"目标进程 " + args.processName + L" 的 PID 是: " + std::to_wstring(targetPID));
    PrintMessage(L"");

    size_t dllSize = 0;
    auto dllBuffer = DownloadDLLToMemory(args.dllUrl, dllSize);

    if (!dllBuffer || dllSize == 0) {
        PrintMessage(L"错误：DLL 下载失败或文件为空。无法进行注入。");
        PrintMessage(L"程序将退出。");
        PrintMessage(L"按任意键继续...");
        _getwch();
        return 1;
    }

    PrintMessage(L"");

    PrintMessage(L"开始手动映射注入...");
    bool injectionSuccess = ManualMapInjector::ManualMapInject(targetPID, dllBuffer.get(), dllSize);

    SecureZeroMemory(dllBuffer.get(), dllSize);
    PrintMessage(L"DLL 内存缓冲区已安全擦除。");

    if (injectionSuccess) {
        PrintMessage(L"手动映射注入成功！");
    }
    else {
        PrintMessage(L"错误：手动映射注入失败。");
    }

    PrintMessage(L"");
    PrintMessage(L"注入过程已完成。");
    PrintMessage(L"按任意键继续...");
    _getwch();

    return injectionSuccess ? 0 : 1;
}