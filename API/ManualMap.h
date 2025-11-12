#ifndef MM_MANUALMAP_H
#define MM_MANUALMAP_H
#include "API.h"
#include <cstdio>
#include "Util.h"
#include "NT.h"
#include <thread>
#include <chrono>

#pragma warning(disable: 28251)  // 忽略 NTSTATUS 警告

namespace ManualMapInjector {
    // 等待进程稳定
    inline bool WaitForProcessStability(HANDLE processH, DWORD timeoutMs = 2000) {
        const int maxChecks = 20;
        const int checkDelayMs = timeoutMs / maxChecks;

        wprintf(L"提示：等待目标进程稳定...\n");

        for (int check = 0; check < maxChecks; ++check) {
            HMODULE kernel32Base = GetModuleBaseInTargetProcess(processH, L"kernel32.dll");
            HMODULE ntdllBase = GetModuleBaseInTargetProcess(processH, L"ntdll.dll");

            if (kernel32Base && ntdllBase) {
                wprintf(L"成功：进程稳定，耗时 ~%d ms。\n", check * checkDelayMs);
                return true;
            }

            if (check < maxChecks - 1) {
                wprintf(L"等待... 检查 %d/%d\n", check + 1, maxChecks);
                std::this_thread::sleep_for(std::chrono::milliseconds(checkDelayMs));
            }
        }

        wprintf(L"警告：进程稳定超时 (%d ms)。\n", timeoutMs);
        return false;
    }

    inline bool ManualMapInject(DWORD targetPID, BYTE* dllBuffer, size_t fileSize) {
        wprintf(L"正在将 DLL 注入到 PID: %lu\n", targetPID);
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

        LoadNtDll();
        HANDLE processHandle = NULL;
        OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
        CLIENT_ID clientId = { (HANDLE)targetPID, NULL };
        NTSTATUS status = NtOpenProcess ? NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &objAttr, &clientId) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || !processHandle) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtOpenProcess 失败。错误代码：%lu\n", error);
            return false;
        }
        unique_handle uniqueProcessHandle(static_cast<void*>(processHandle), HandleDeleter());
        wprintf(L"目标进程已打开。\n");
        HANDLE processH = static_cast<HANDLE>(uniqueProcessHandle.get());

        if (!WaitForProcessStability(processH)) {
            return false;
        }

        // ==================== 分配远程内存 ====================
        void* allocatedBase = reinterpret_cast<void*>(pNtHeaders->OptionalHeader.ImageBase);
        SIZE_T imageSize = pNtHeaders->OptionalHeader.SizeOfImage;
        SIZE_T regionSize = imageSize;
        status = NtAllocateVirtualMemory ? NtAllocateVirtualMemory(processH, &allocatedBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) {
            DWORD preferredAllocError = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"警告：首选基址分配失败于 " TULONGLONG_FORMAT "。错误代码：%lu。尝试在任意位置分配...\n",
                (TULONGLONG)pNtHeaders->OptionalHeader.ImageBase, preferredAllocError);
            allocatedBase = NULL;
            regionSize = imageSize;
            status = NtAllocateVirtualMemory ? NtAllocateVirtualMemory(processH, &allocatedBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : STATUS_UNSUCCESSFUL;
            if (!NT_SUCCESS(status)) {
                DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
                wprintf(L"错误：NtAllocateVirtualMemory 失败。错误代码：%lu\n", error);
                return false;
            }
        }
        VirtualFreeDeleter deleter(processH);
        unique_virtual_mem allocatedBaseWrapper(allocatedBase, deleter);
        wprintf(L"为 DLL 镜像分配内存于： " TULONGLONG_FORMAT "\n", (TULONGLONG)allocatedBase);

        // ==================== 在本地构建完整镜像（包含重定位） ====================
        BYTE* localImage = new BYTE[imageSize]();  // 初始化为零

        // 复制 PE 头
        DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders > fileSize) {
            wprintf(L"错误：SizeOfHeaders 大于缓冲区大小。\n");
            delete[] localImage;
            return false;
        }
        memcpy(localImage, dllBuffer, sizeOfHeaders);

        // 复制节数据
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->PointerToRawData != 0 &&
                (pSectionHeader->PointerToRawData > fileSize ||
                    pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > fileSize)) {
                wprintf(L"错误：节 %d 原始数据超出范围。\n", i);
                delete[] localImage;
                return false;
            }
            if (static_cast<TULONGLONG>(pSectionHeader->VirtualAddress) + pSectionHeader->Misc.VirtualSize > imageSize) {
                wprintf(L"错误：节 %d 虚拟地址超出分配内存范围。\n", i);
                delete[] localImage;
                return false;
            }
            if (pSectionHeader->SizeOfRawData > 0) {
                void* sectionTargetAddress = localImage + pSectionHeader->VirtualAddress;
                LPVOID sectionSourceAddress = dllBuffer + pSectionHeader->PointerToRawData;
                memcpy(sectionTargetAddress, sectionSourceAddress, pSectionHeader->SizeOfRawData);
            }
        }
        wprintf(L"本地镜像构建完成。\n");

        // ==================== 在本地处理重定位 ====================
        TULONGLONG delta = (TULONGLONG)allocatedBase - pNtHeaders->OptionalHeader.ImageBase;
        if (delta != 0) {
            wprintf(L"需要重定位。偏移量：" TULONGLONG_FORMAT "\n", delta);
            IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
                wprintf(L"警告：需要重定位但缺少重定位表。\n");
            }
            else {
                DWORD relocOffset = RvaToFileOffset(pNtHeaders, relocDir.VirtualAddress, fileSize);
                if (relocOffset == 0 || relocOffset + relocDir.Size > fileSize) {
                    wprintf(L"错误：重定位目录超出范围。\n");
                    delete[] localImage;
                    return false;
                }
                PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(dllBuffer + relocOffset);
                LPBYTE relocTableEnd = (LPBYTE)pRelocBlock + relocDir.Size;

                unsigned long relocationSuccessCount = 0;
                unsigned long relocationSkippedCount = 0;
                unsigned long relocationFailedCount = 0;
                unsigned long long relocationCounter = 0;

                while ((LPBYTE)pRelocBlock < relocTableEnd && pRelocBlock->SizeOfBlock > 0) {
                    if ((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock > relocTableEnd) {
                        wprintf(L"错误：无效的重定位块大小。\n");
                        delete[] localImage;
                        return false;
                    }
                    DWORD count = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelocEntry = (PWORD)((LPBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < count; ++i, ++pRelocEntry) {
                        WORD type = (*pRelocEntry >> 12);
                        WORD offset = (*pRelocEntry & 0xFFF);
                        relocationCounter++;

                        if (type == IMAGE_REL_BASED_ABSOLUTE) { // 0
                            relocationSkippedCount++;
                            continue;
                        }

                        DWORD rva = pRelocBlock->VirtualAddress + offset;
                        void* patchAddrLocal = localImage + rva;

                        if ((LPBYTE)patchAddrLocal < localImage || (LPBYTE)patchAddrLocal >= localImage + imageSize) {
                            // 重定位失败日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)type,
                                (unsigned long long)offset,
                                rva);
                            relocationFailedCount++;
                            continue;
                        }

#if defined(_WIN64)
                        // x64 注入 (只处理 DIR64) - 保持原有操作
                        if (type == IMAGE_REL_BASED_DIR64) { // 10
                            TULONGLONG* patchAddr = reinterpret_cast<TULONGLONG*>(patchAddrLocal);
                            TULONGLONG originalValue = *patchAddr;
                            TULONGLONG newValue = originalValue + delta;
                            *patchAddr = newValue;

                            // 重定位成功日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)patchAddrLocal,
                                originalValue, newValue,
                                (unsigned long long)offset,
                                rva);
                            relocationSuccessCount++;
                        }
                        else {
                            // 重定位失败日志（不支持的类型）
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)type,
                                (unsigned long long)offset,
                                rva);
                            relocationFailedCount++;
                        }
#else
                        // x86 注入 (处理 HIGHLOW 和 HIGHADJ) - 保持原有操作
                        if (type == IMAGE_REL_BASED_HIGHLOW) { // 3
                            DWORD* patchAddr = reinterpret_cast<DWORD*>(patchAddrLocal);
                            DWORD originalValue = *patchAddr;
                            DWORD newValue = originalValue + static_cast<DWORD>(delta);
                            *patchAddr = newValue;

                            // 重定位成功日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)patchAddrLocal,
                                (unsigned long long)originalValue, (unsigned long long)newValue,
                                (unsigned long long)offset,
                                rva);
                            relocationSuccessCount++;
                        }
                        else if (type == IMAGE_REL_BASED_HIGH) { // 1
                            WORD* patchAddr = reinterpret_cast<WORD*>(patchAddrLocal);
                            WORD originalValue = *patchAddr;
                            WORD newValue = originalValue + HIWORD(static_cast<DWORD>(delta));
                            *patchAddr = newValue;

                            // 重定位成功日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)patchAddrLocal,
                                (unsigned long long)originalValue, (unsigned long long)newValue,
                                (unsigned long long)offset,
                                rva);
                            relocationSuccessCount++;
                        }
                        else if (type == IMAGE_REL_BASED_LOW) { // 2
                            WORD* patchAddr = reinterpret_cast<WORD*>(patchAddrLocal);
                            WORD originalValue = *patchAddr;
                            WORD newValue = originalValue + LOWORD(static_cast<DWORD>(delta));
                            *patchAddr = newValue;

                            // 重定位成功日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)patchAddrLocal,
                                (unsigned long long)originalValue, (unsigned long long)newValue,
                                (unsigned long long)offset,
                                rva);
                            relocationSuccessCount++;
                        }
                        else if (type == IMAGE_REL_BASED_HIGHADJ) { // 4
                            if (i + 1 >= count) {
                                // 重定位失败日志（HIGHADJ 缺少调整值）
                                wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX\n",
                                    relocationCounter,
                                    (unsigned long long)type,
                                    (unsigned long long)offset,
                                    rva);
                                relocationFailedCount++;
                                continue;
                            }
                            ++i; // 消耗下一个条目
                            ++pRelocEntry;
                            SHORT adjustment = static_cast<SHORT>(*pRelocEntry); // 这是调整值

                            WORD* highPartAddr = reinterpret_cast<WORD*>(patchAddrLocal);
                            WORD originalValue = *highPartAddr;

                            // 计算完整的 32 位地址
                            DWORD originalAddr = (originalValue << 16) + adjustment;
                            DWORD newAddr = originalAddr + static_cast<DWORD>(delta);

                            // 写回新的 16 位高位，必须 +0x8000 来处理有符号的低位
                            WORD newValue = static_cast<WORD>((newAddr + 0x8000) >> 16);
                            *highPartAddr = newValue;

                            // 重定位成功日志 - 使用指定格式
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)patchAddrLocal,
                                (unsigned long long)originalValue, (unsigned long long)newValue,
                                (unsigned long long)offset,
                                rva);
                            relocationSuccessCount++;
                        }
                        else {
                            // 重定位失败日志（不支持的类型）
                            wprintf(L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX\n",
                                relocationCounter,
                                (unsigned long long)type,
                                (unsigned long long)offset,
                                rva);
                            relocationFailedCount++;
                        }
#endif
                    }
                    pRelocBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);
                }
                wprintf(L"重定位已处理。成功：%lu，失败：%lu，跳过：%lu\n",
                    relocationSuccessCount, relocationFailedCount, relocationSkippedCount);
            }
        }
        else {
            wprintf(L"无需重定位。\n");
        }

        // ==================== 一次性写入完整镜像 ====================
        SIZE_T bytesWritten;
        status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, allocatedBase, localImage, imageSize, &bytesWritten) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || bytesWritten != imageSize) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtWriteVirtualMemory（完整镜像）失败。错误代码：%lu\n", error);
            delete[] localImage;
            return false;
        }
        wprintf(L"完整镜像已写入目标进程。\n");

        // 清理本地镜像
        delete[] localImage;

        // ==================== 准备 shellcode 数据 ====================
        FARPROC pLoadLibraryA_Remote = FindRemoteProcAddress(processH, L"kernel32.dll", "LoadLibraryA");
        FARPROC pGetProcAddress_Remote = FindRemoteProcAddress(processH, L"kernel32.dll", "GetProcAddress");
        if (!pLoadLibraryA_Remote || !pGetProcAddress_Remote) {
            wprintf(L"错误：无法找到 LoadLibraryA 或 GetProcAddress。\n");
            return false;
        }

        // 验证导入表目录
        IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
            wprintf(L"警告：DLL 没有导入表。\n");
        }

        void* shellcodeDataMem = NULL;
        SIZE_T shellcodeDataSize = sizeof(ShellcodeData);
        status = NtAllocateVirtualMemory ? NtAllocateVirtualMemory(processH, &shellcodeDataMem, 0, &shellcodeDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtAllocateVirtualMemory（ShellcodeData）失败。错误代码：%lu\n", error);
            return false;
        }
        unique_virtual_mem shellcodeDataWrapper(shellcodeDataMem, deleter);

        // ==================== 关键修复：确保 ShellcodeData 结构正确 ====================
        ShellcodeData data;
        memset(&data, 0, sizeof(ShellcodeData));  // 清零初始化

        data.InjectedDllBase = allocatedBase;
        data.pLoadLibraryA = (LoadLibraryA_t)pLoadLibraryA_Remote;
        data.pGetProcAddress = (GetProcAddress_t)pGetProcAddress_Remote;
        data.ImportDirRVA = importDir.VirtualAddress;
        data.ImportDirSize = importDir.Size;

        // 添加调试信息
        wprintf(L"ShellcodeData 信息:\n");
        wprintf(L"  InjectedDllBase: " TULONGLONG_FORMAT "\n", (TULONGLONG)data.InjectedDllBase);
        wprintf(L"  pLoadLibraryA: " TULONGLONG_FORMAT "\n", (TULONGLONG)data.pLoadLibraryA);
        wprintf(L"  pGetProcAddress: " TULONGLONG_FORMAT "\n", (TULONGLONG)data.pGetProcAddress);
        wprintf(L"  ImportDirRVA: 0x%08X\n", data.ImportDirRVA);
        wprintf(L"  ImportDirSize: 0x%08X\n", data.ImportDirSize);

        status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, shellcodeDataMem, &data, sizeof(ShellcodeData), &bytesWritten) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || bytesWritten != sizeof(ShellcodeData)) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtWriteVirtualMemory（ShellcodeData）失败。错误代码：%lu\n", error);
            return false;
        }

        // ==================== 写入 shellcode ====================
        SIZE_T shellcodeSize = GetFunctionSize(Shellcode);
        wprintf(L"Shellcode 大小: %zu 字节\n", shellcodeSize);

        // 验证 shellcode 大小
        if (shellcodeSize == 0 || shellcodeSize > 4096) {
            wprintf(L"错误：无效的 shellcode 大小。\n");
            return false;
        }

        void* shellcodeMem = NULL;
        SIZE_T shellcodeAllocSize = shellcodeSize;
        status = NtAllocateVirtualMemory ? NtAllocateVirtualMemory(processH, &shellcodeMem, 0, &shellcodeAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtAllocateVirtualMemory（shellcode）失败。错误代码：%lu\n", error);
            return false;
        }
        unique_virtual_mem shellcodeWrapper(shellcodeMem, deleter);

        status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, shellcodeMem, (LPVOID)Shellcode, shellcodeSize, &bytesWritten) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || bytesWritten != shellcodeSize) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtWriteVirtualMemory（shellcode）失败。错误代码：%lu\n", error);
            return false;
        }

        // ==================== 清理和创建线程 ====================
        SecureZeroMemory(dllBuffer, fileSize);
        wprintf(L"原始 DLL 缓冲区已从内存中擦除。\n");

        // 添加短暂延迟确保内存稳定
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        HANDLE threadHandle = NULL;
        OBJECT_ATTRIBUTES threadObjAttr = { sizeof(OBJECT_ATTRIBUTES) };
        status = NtCreateThreadEx ? NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, &threadObjAttr, processH, (PVOID)shellcodeMem, shellcodeDataMem, 0, 0, 0, 0, NULL) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || !threadHandle) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtCreateThreadEx 失败。错误代码：%lu\n", error);
            return false;
        }
        unique_handle uniqueThreadHandle(static_cast<void*>(threadHandle), HandleDeleter());

        status = NtWaitForSingleObject ? NtWaitForSingleObject(static_cast<HANDLE>(uniqueThreadHandle.get()), FALSE, NULL) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"警告：NtWaitForSingleObject 失败。错误代码：%lu\n", error);
        }

        DWORD exitCode = 0;
        GetExitCodeThread(static_cast<HANDLE>(uniqueThreadHandle.get()), &exitCode);

        // 输出详细的退出代码信息
        if (exitCode == 0xC00001A5) {
            wprintf(L"远程线程完成，退出代码：0xC00001A5 (检测到无效的异常处理程序例程)\n");
        }
        else if (exitCode == 0xC0000005) {
            wprintf(L"远程线程完成，退出代码：0xC0000005 (访问冲突)\n");
            wprintf(L"崩溃分析：可能的原因：\n");
            wprintf(L"  1. 导入表解析失败\n");
            wprintf(L"  2. DLL 依赖项缺失\n");
            wprintf(L"  3. Shellcode 参数错误\n");
            wprintf(L"  4. 重定位不完整\n");
        }
        else {
            wprintf(L"远程线程完成，退出代码：0x%08X (%lu)\n", exitCode, exitCode);
        }

        // 详细的错误代码解析
        if (exitCode == 0xC0000005) {
            wprintf(L"崩溃：访问违规 - 检查 DLL 依赖或内存页。\n");
        }
        else if (exitCode == (DWORD)-2) {
            wprintf(L"错误：Shellcode 失败 - 无效 DOS 签名（重定位后恢复）。\n");
        }
        else if (exitCode == 0) {
            wprintf(L"警告：DllMain 返回 FALSE。\n");
        }
        else if (exitCode < 100) {
            if (exitCode == (DWORD)-1) wprintf(L"错误：Shellcode 失败 - 无效参数。\n");
            else if (exitCode == (DWORD)-3) wprintf(L"错误：Shellcode 失败 - 无效 NT 签名。\n");
            else if (exitCode == (DWORD)-4) wprintf(L"错误：Shellcode 失败 - 非 DLL 文件。\n");
            else if (exitCode == (DWORD)-5) wprintf(L"错误：Shellcode 失败 - 加载依赖 DLL 失败。\n");
            else if (exitCode == (DWORD)-6) wprintf(L"错误：Shellcode 失败 - 获取函数地址失败。\n");
            else if (exitCode == (DWORD)-7) wprintf(L"错误：Shellcode 失败 - RVA 越界。\n");
            else if (exitCode == (DWORD)-8) wprintf(L"错误：Shellcode 失败 - DllMain 异常。\n");
            else wprintf(L"注意：Shellcode 返回 %lu。\n", exitCode);
        }

        allocatedBaseWrapper.release();
        shellcodeDataWrapper.release();
        shellcodeWrapper.release();
        wprintf(L"注入完成。\n");
        return exitCode == 1;  // 成功时 shellcode 应该返回 1
    }
}
#endif