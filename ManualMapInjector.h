#ifndef MANUAL_MAP_INJECTOR_H
#define MANUAL_MAP_INJECTOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

namespace ManualMapInjector {

    // --- 配置 ---
#if defined(_WIN64)
    using IMAGE_NT_HEADERS_CURRENT = IMAGE_NT_HEADERS64;
    using PIMAGE_NT_HEADERS_CURRENT = PIMAGE_NT_HEADERS64;
    using IMAGE_NT_OPTIONAL_HDR_CURRENT = IMAGE_OPTIONAL_HEADER64;
    using TULONGLONG = ULONGLONG;
    const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_AMD64;
#define IMAGE_REL_BASED_SELF_ARCH IMAGE_REL_BASED_DIR64
#else
    using IMAGE_NT_HEADERS_CURRENT = IMAGE_NT_HEADERS32;
    using PIMAGE_NT_HEADERS_CURRENT = PIMAGE_NT_HEADERS32;
    using IMAGE_NT_OPTIONAL_HDR_CURRENT = IMAGE_OPTIONAL_HEADER32;
    using TULONGLONG = DWORD;
    const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_I386;
#define IMAGE_REL_BASED_SELF_ARCH IMAGE_REL_BASED_HIGHLOW
#endif

    // --- Shellcode 函数指针类型定义 ---
    typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpFileName);
    typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
    typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

    // --- Shellcode 数据结构 ---
    struct ShellcodeData {
        LPVOID InjectedDllBase;
        LoadLibraryA_t pLoadLibraryA;
        GetProcAddress_t pGetProcAddress;
        DWORD ImportDirRVA;
        DWORD ImportDirSize;
    };

    // --- Shellcode 函数 ---
    DWORD WINAPI Shellcode(LPVOID lpParameter) {
        if (!lpParameter) return (DWORD)-1;

        ShellcodeData* data = (ShellcodeData*)lpParameter;
        LPVOID imageBase = data->InjectedDllBase;
        LoadLibraryA_t pLoadLibraryA = data->pLoadLibraryA;
        GetProcAddress_t pGetProcAddress = data->pGetProcAddress;
        DWORD importDirRVA = data->ImportDirRVA;
        DWORD importDirSize = data->ImportDirSize;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return (DWORD)-2;

        PIMAGE_NT_HEADERS_CURRENT pNtHeaders = (PIMAGE_NT_HEADERS_CURRENT)((LPBYTE)imageBase + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return (DWORD)-3;

        if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) return (DWORD)-4;

        if (importDirRVA != 0 && importDirSize > 0) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)imageBase + importDirRVA);
            LPBYTE importDirEnd = (LPBYTE)pImportDesc + importDirSize;

            while ((LPBYTE)pImportDesc < importDirEnd &&
                (pImportDesc->Name != 0 || pImportDesc->OriginalFirstThunk != 0 || pImportDesc->FirstThunk != 0)) {
                char* dllName = (char*)((LPBYTE)imageBase + pImportDesc->Name);
                HMODULE hMod = pLoadLibraryA(dllName);
                if (!hMod) return (DWORD)-5;

                PIMAGE_THUNK_DATA pThunkILT = (pImportDesc->OriginalFirstThunk == 0) ?
                    (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + pImportDesc->FirstThunk) :
                    (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pThunkIAT = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + pImportDesc->FirstThunk);

                while (pThunkILT->u1.AddressOfData != 0) {
                    FARPROC funcAddress = NULL;
                    if (IMAGE_SNAP_BY_ORDINAL(pThunkILT->u1.Ordinal)) {
                        WORD ordinal = IMAGE_ORDINAL(pThunkILT->u1.Ordinal);
                        funcAddress = pGetProcAddress(hMod, (LPCSTR)ordinal);
                    }
                    else {
                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)imageBase + pThunkILT->u1.AddressOfData);
                        char* funcName = (char*)pImportByName->Name;
                        funcAddress = pGetProcAddress(hMod, funcName);
                    }
                    if (!funcAddress) return (DWORD)-6;

#if defined(_WIN64)
                    pThunkIAT->u1.Function = (TULONGLONG)funcAddress;
#else
                    pThunkIAT->u1.Function = (DWORD)funcAddress;
#endif
                    pThunkILT++;
                    pThunkIAT++;
                }
                pImportDesc++;
            }
        }

        DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        if (entryPointRVA != 0) {
            DllEntryProc dllMain = (DllEntryProc)((LPBYTE)imageBase + entryPointRVA);
            BOOL success = dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
            return (DWORD)success;
        }
        return (DWORD)1;
    }

    // --- 辅助结构和类型 ---
    struct HandleDeleter {
        using pointer = HANDLE;
        void operator()(HANDLE handle) const {
            if (handle != NULL && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        }
    };

    using unique_handle = std::unique_ptr<void, HandleDeleter>;

    // --- 实用函数 ---

    // 将 std::wstring 转换为 std::string
    std::string WstringToString(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        std::string str(size, 0);
        WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], size, NULL, NULL);
        str.resize(size - 1);
        return str;
    }

    // 获取目标进程中的模块基址
    HMODULE GetModuleBaseInTargetProcess(HANDLE hProcess, const std::wstring& moduleName) {
        unique_handle snapshotHandle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess)));
        if (snapshotHandle.get() == INVALID_HANDLE_VALUE) {
            return NULL;
        }

        MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
        if (Module32First(snapshotHandle.get(), &me32)) {
            do {
                if (_wcsicmp(me32.szModule, moduleName.c_str()) == 0) {
                    return (HMODULE)me32.modBaseAddr;
                }
            } while (Module32Next(snapshotHandle.get(), &me32));
        }
        return NULL;
    }

    // 查找远程函数地址
    FARPROC FindRemoteProcAddress(HANDLE hProcess, const std::wstring& moduleName, const std::string& procName) {
        HMODULE hTargetMod = GetModuleBaseInTargetProcess(hProcess, moduleName);
        if (!hTargetMod) {
            wprintf(L"错误：模块 '%s' 在目标进程中未找到。\n", moduleName.c_str());
            return NULL;
        }

        std::string moduleNameAnsi = WstringToString(moduleName);
        HMODULE hInjectorMod = LoadLibraryA(moduleNameAnsi.c_str());
        if (!hInjectorMod) {
            wprintf(L"错误：LoadLibraryA 失败，模块 '%s'。错误代码：%lu\n", moduleName.c_str(), GetLastError());
            return NULL;
        }
        unique_handle injectorModHandle(hInjectorMod);

        FARPROC injectorFuncAddr = GetProcAddress(hInjectorMod, procName.c_str());
        if (!injectorFuncAddr) {
            wprintf(L"错误：GetProcAddress 失败，函数 '%S' 在模块 '%s' 中。错误代码：%lu\n", procName.c_str(), moduleName.c_str(), GetLastError());
            return NULL;
        }

        TULONGLONG funcOffset = (TULONGLONG)injectorFuncAddr - (TULONGLONG)hInjectorMod;
        return (FARPROC)((LPBYTE)hTargetMod + funcOffset);
    }

    // 将 RVA 转换为文件偏移
    DWORD RvaToFileOffset(PIMAGE_NT_HEADERS_CURRENT pNtHeaders, DWORD rva, size_t fileSize) {
        if (rva < pNtHeaders->OptionalHeader.SizeOfHeaders) return rva;

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
                if (rva - pSectionHeader->VirtualAddress < pSectionHeader->SizeOfRawData) {
                    DWORD offset = rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
                    if (offset < static_cast<DWORD>(fileSize)) return offset;
                }
                return 0;
            }
        }
        return 0;
    }

    // 手动映射注入函数
    bool ManualMapInject(DWORD targetPID, BYTE* dllBuffer, size_t fileSize) {
        wprintf(L"正在将 DLL 注入到 PID: %lu\n", targetPID);

        // 解析 PE 头
        if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
            wprintf(L"错误：缓冲区过小，无法包含 DOS 头。\n");
            return false;
        }
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBuffer);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            wprintf(L"错误：无效的 DOS 签名。\n");
            return false;
        }

        if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS_CURRENT) > fileSize) {
            wprintf(L"错误：无效的 PE 头偏移。\n");
            return false;
        }

        PIMAGE_NT_HEADERS_CURRENT pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS_CURRENT>(dllBuffer + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            wprintf(L"错误：无效的 NT 签名。\n");
            return false;
        }

        if (pNtHeaders->FileHeader.Machine != TARGET_MACHINE) {
            wprintf(L"错误：架构不匹配。注入器=%s，DLL=%s\n",
                (TARGET_MACHINE == IMAGE_FILE_MACHINE_AMD64 ? L"64位" : L"32位"),
                (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? L"64位" : L"32位"));
            return false;
        }
        wprintf(L"PE 头解析成功。\n");

        // 打开目标进程
        unique_handle processHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID));
        if (!processHandle.get()) {
            wprintf(L"错误：OpenProcess 失败。错误代码：%lu\n", GetLastError());
            return false;
        }
        wprintf(L"目标进程已打开。\n");

        // 在目标进程中分配内存
        LPVOID allocatedBase = VirtualAllocEx(processHandle.get(), reinterpret_cast<LPVOID>(pNtHeaders->OptionalHeader.ImageBase),
            pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!allocatedBase) {
            DWORD preferredAllocError = GetLastError();
            wprintf(L"警告：首选基址分配失败于 0x%p。错误代码：%lu。尝试在任意位置分配...\n",
                (void*)pNtHeaders->OptionalHeader.ImageBase, preferredAllocError);

            allocatedBase = VirtualAllocEx(processHandle.get(), NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (!allocatedBase) {
                wprintf(L"错误：VirtualAllocEx 失败。错误代码：%lu\n", GetLastError());
                return false;
            }
        }
        wprintf(L"为 DLL 镜像分配内存于：0x%p\n", allocatedBase);

        // 写入 PE 头
        SIZE_T bytesWritten;
        DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders > fileSize) {
            wprintf(L"错误：SizeOfHeaders 大于缓冲区大小。\n");
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        if (!WriteProcessMemory(processHandle.get(), allocatedBase, dllBuffer, sizeOfHeaders, &bytesWritten) ||
            bytesWritten != sizeOfHeaders) {
            wprintf(L"错误：WriteProcessMemory（头）失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }
        wprintf(L"PE 头已写入目标进程。\n");

        // 写入节
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->PointerToRawData != 0 &&
                (pSectionHeader->PointerToRawData > fileSize ||
                    pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > fileSize)) {
                wprintf(L"错误：节 %d 原始数据超出范围。\n", i);
                VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
                return false;
            }

            if (static_cast<TULONGLONG>(pSectionHeader->VirtualAddress) + pSectionHeader->Misc.VirtualSize > pNtHeaders->OptionalHeader.SizeOfImage) {
                wprintf(L"错误：节 %d 虚拟地址超出分配内存范围。\n", i);
                VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
                return false;
            }

            if (pSectionHeader->SizeOfRawData > 0) {
                LPVOID sectionTargetAddress = (LPBYTE)allocatedBase + pSectionHeader->VirtualAddress;
                LPVOID sectionSourceAddress = dllBuffer + pSectionHeader->PointerToRawData;
                if (!WriteProcessMemory(processHandle.get(), sectionTargetAddress, sectionSourceAddress,
                    pSectionHeader->SizeOfRawData, &bytesWritten) ||
                    bytesWritten != pSectionHeader->SizeOfRawData) {
                    wprintf(L"错误：WriteProcessMemory（节 %d）失败。错误代码：%lu\n", i, GetLastError());
                    VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
                    return false;
                }
            }
        }
        wprintf(L"节已写入目标进程。\n");

        // 处理重定位
        TULONGLONG delta = (TULONGLONG)((LPBYTE)allocatedBase - pNtHeaders->OptionalHeader.ImageBase);
        if (delta != 0) {
            wprintf(L"需要重定位。偏移量：0x%llX\n", delta);
            IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
                wprintf(L"警告：需要重定位但缺少重定位表。\n");
            }
            else {
                DWORD relocOffset = RvaToFileOffset(pNtHeaders, relocDir.VirtualAddress, fileSize);
                if (relocOffset == 0 || relocOffset + relocDir.Size > fileSize) {
                    wprintf(L"错误：重定位目录超出范围。\n");
                    VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
                    return false;
                }

                PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(dllBuffer + relocOffset);
                LPBYTE relocTableEnd = (LPBYTE)pRelocBlock + relocDir.Size;

                while ((LPBYTE)pRelocBlock < relocTableEnd && pRelocBlock->SizeOfBlock > 0) {
                    if ((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock > relocTableEnd) {
                        wprintf(L"错误：无效的重定位块大小。\n");
                        VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
                        return false;
                    }

                    DWORD count = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelocEntry = (PWORD)((LPBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < count; ++i, ++pRelocEntry) {
                        WORD type = (*pRelocEntry >> 12);
                        WORD offset = (*pRelocEntry & 0xFFF);

                        if (type == IMAGE_REL_BASED_SELF_ARCH) {
                            LPVOID patchAddrTarget = (LPBYTE)allocatedBase + pRelocBlock->VirtualAddress + offset;
                            TULONGLONG originalAddr;
                            SIZE_T bytesRead;
                            if (!ReadProcessMemory(processHandle.get(), patchAddrTarget, &originalAddr, sizeof(TULONGLONG), &bytesRead) ||
                                bytesRead != sizeof(TULONGLONG)) {
                                wprintf(L"警告：ReadProcessMemory 在 0x%p 失败。\n", patchAddrTarget);
                                continue;
                            }

                            TULONGLONG newAddr = originalAddr + delta;
                            if (!WriteProcessMemory(processHandle.get(), patchAddrTarget, &newAddr, sizeof(TULONGLONG), &bytesWritten) ||
                                bytesWritten != sizeof(TULONGLONG)) {
                                wprintf(L"警告：WriteProcessMemory（重定位）在 0x%p 失败。\n", patchAddrTarget);
                                continue;
                            }
                        }
                    }
                    pRelocBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);
                }
                wprintf(L"重定位已处理。\n");
            }
        }
        else {
            wprintf(L"无需重定位。\n");
        }

        // 准备 Shellcode
        FARPROC pLoadLibraryA_Remote = FindRemoteProcAddress(processHandle.get(), L"kernel32.dll", "LoadLibraryA");
        FARPROC pGetProcAddress_Remote = FindRemoteProcAddress(processHandle.get(), L"kernel32.dll", "GetProcAddress");

        if (!pLoadLibraryA_Remote || !pGetProcAddress_Remote) {
            wprintf(L"错误：无法找到 LoadLibraryA 或 GetProcAddress。\n");
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        LPVOID shellcodeDataMem = VirtualAllocEx(processHandle.get(), NULL, sizeof(ShellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!shellcodeDataMem) {
            wprintf(L"错误：VirtualAllocEx（ShellcodeData）失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        ShellcodeData data;
        data.InjectedDllBase = allocatedBase;
        data.pLoadLibraryA = (LoadLibraryA_t)pLoadLibraryA_Remote;
        data.pGetProcAddress = (GetProcAddress_t)pGetProcAddress_Remote;
        data.ImportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        data.ImportDirSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (!WriteProcessMemory(processHandle.get(), shellcodeDataMem, &data, sizeof(ShellcodeData), &bytesWritten) || bytesWritten != sizeof(ShellcodeData)) {
            wprintf(L"错误：WriteProcessMemory（ShellcodeData）失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), shellcodeDataMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        SIZE_T shellcodeSize = 4096;
        LPVOID shellcodeMem = VirtualAllocEx(processHandle.get(), NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeMem) {
            wprintf(L"错误：VirtualAllocEx（shellcode）失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), shellcodeDataMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        if (!WriteProcessMemory(processHandle.get(), shellcodeMem, (LPVOID)Shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
            wprintf(L"错误：WriteProcessMemory（shellcode）失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), shellcodeMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), shellcodeDataMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        // 擦除原始 DLL 缓冲区
        SecureZeroMemory(dllBuffer, fileSize);
        wprintf(L"原始 DLL 缓冲区已从内存中擦除。\n");

        // 执行 Shellcode
        unique_handle threadHandle(CreateRemoteThread(processHandle.get(), NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeMem, shellcodeDataMem, 0, NULL));
        if (!threadHandle.get()) {
            wprintf(L"错误：CreateRemoteThread 失败。错误代码：%lu\n", GetLastError());
            VirtualFreeEx(processHandle.get(), shellcodeMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), shellcodeDataMem, 0, MEM_RELEASE);
            VirtualFreeEx(processHandle.get(), allocatedBase, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(threadHandle.get(), INFINITE);
        DWORD exitCode = 0;
        GetExitCodeThread(threadHandle.get(), &exitCode);
        wprintf(L"远程线程完成，退出代码：%lu\n", exitCode);

        if (exitCode == 0) {
            wprintf(L"警告：DllMain 返回 FALSE 或无入口点。\n");
        }
        else if (exitCode < 100) {
            if (exitCode == (DWORD)-1) wprintf(L"错误：Shellcode 失败 - 无效参数。\n");
            else if (exitCode == (DWORD)-2) wprintf(L"错误：Shellcode 失败 - 无效 DOS 签名。\n");
            else if (exitCode == (DWORD)-3) wprintf(L"错误：Shellcode 失败 - 无效 NT 签名。\n");
            else if (exitCode == (DWORD)-4) wprintf(L"错误：Shellcode 失败 - 非 DLL 文件。\n");
            else if (exitCode == (DWORD)-5) wprintf(L"错误：Shellcode 失败 - 加载依赖 DLL 失败。\n");
            else if (exitCode == (DWORD)-6) wprintf(L"错误：Shellcode 失败 - 获取函数地址失败。\n");
            else if (exitCode != (DWORD)TRUE) wprintf(L"注意：Shellcode 返回退出代码 (%lu)。\n", exitCode);
        }

        VirtualFreeEx(processHandle.get(), shellcodeMem, 0, MEM_RELEASE);
        VirtualFreeEx(processHandle.get(), shellcodeDataMem, 0, MEM_RELEASE);
        wprintf(L"注入完成。\n");
        return true;
    }

} // namespace ManualMapInjector

#endif // MANUAL_MAP_INJECTOR_H