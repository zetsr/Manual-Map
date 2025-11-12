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

        void* allocatedBase = reinterpret_cast<void*>(pNtHeaders->OptionalHeader.ImageBase);
        SIZE_T regionSize = pNtHeaders->OptionalHeader.SizeOfImage;
        status = NtAllocateVirtualMemory ? NtAllocateVirtualMemory(processH, &allocatedBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status)) {
            DWORD preferredAllocError = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"警告：首选基址分配失败于 " TULONGLONG_FORMAT "。错误代码：%lu。尝试在任意位置分配...\n",
                (TULONGLONG)pNtHeaders->OptionalHeader.ImageBase, preferredAllocError);
            allocatedBase = NULL;
            regionSize = pNtHeaders->OptionalHeader.SizeOfImage;
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

        SIZE_T bytesWritten;
        DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders > fileSize) {
            wprintf(L"错误：SizeOfHeaders 大于缓冲区大小。\n");
            return false;
        }
        status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, allocatedBase, dllBuffer, sizeOfHeaders, &bytesWritten) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || bytesWritten != sizeOfHeaders) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtWriteVirtualMemory（头）失败。错误代码：%lu\n", error);
            return false;
        }
        wprintf(L"PE 头已写入目标进程。\n");

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->PointerToRawData != 0 &&
                (pSectionHeader->PointerToRawData > fileSize ||
                    pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > fileSize)) {
                wprintf(L"错误：节 %d 原始数据超出范围。\n", i);
                return false;
            }
            if (static_cast<TULONGLONG>(pSectionHeader->VirtualAddress) + pSectionHeader->Misc.VirtualSize > pNtHeaders->OptionalHeader.SizeOfImage) {
                wprintf(L"错误：节 %d 虚拟地址超出分配内存范围。\n", i);
                return false;
            }
            if (pSectionHeader->SizeOfRawData > 0) {
                void* sectionTargetAddress = (LPBYTE)allocatedBase + pSectionHeader->VirtualAddress;
                LPVOID sectionSourceAddress = dllBuffer + pSectionHeader->PointerToRawData;
                status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, sectionTargetAddress, sectionSourceAddress,
                    pSectionHeader->SizeOfRawData, &bytesWritten) : STATUS_UNSUCCESSFUL;
                if (!NT_SUCCESS(status) || bytesWritten != pSectionHeader->SizeOfRawData) {
                    DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
                    wprintf(L"错误：NtWriteVirtualMemory（节 %d）失败。错误代码：%lu\n", i, error);
                    return false;
                }
            }
        }
        wprintf(L"节已写入目标进程。\n");

        TULONGLONG delta = (TULONGLONG)((LPBYTE)allocatedBase - pNtHeaders->OptionalHeader.ImageBase);
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
                    return false;
                }
                PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(dllBuffer + relocOffset);
                LPBYTE relocTableEnd = (LPBYTE)pRelocBlock + relocDir.Size;

                // 全局重定位计数器（以十进制计数，方括号中显示十进制；地址/偏移以十六进制显示）
                unsigned long long relocationCounter = 0;

                while ((LPBYTE)pRelocBlock < relocTableEnd && pRelocBlock->SizeOfBlock > 0) {
                    if ((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock > relocTableEnd) {
                        wprintf(L"错误：无效的重定位块大小。\n");
                        return false;
                    }
                    DWORD count = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelocEntry = (PWORD)((LPBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
                    for (DWORD i = 0; i < count; ++i, ++pRelocEntry) {
                        WORD type = (*pRelocEntry >> 12);
                        WORD offset = (*pRelocEntry & 0xFFF);
                        if (type == 0) continue;
                        if (type == IMAGE_REL_BASED_SELF_ARCH) {
                            void* patchAddrTarget = (LPBYTE)allocatedBase + pRelocBlock->VirtualAddress + offset;
                            // 修复：检查 patchAddrTarget 在图像范围内
                            if ((LPBYTE)patchAddrTarget < (LPBYTE)allocatedBase || (LPBYTE)patchAddrTarget >= (LPBYTE)allocatedBase + pNtHeaders->OptionalHeader.SizeOfImage) {
                                // 仍然只输出一行日志（表明跳过），原/新地址用 -- 占位
                                relocationCounter++;
                                wprintf(
                                    L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX\n",
                                    (unsigned long long)relocationCounter,
                                    (unsigned long long)(uintptr_t)patchAddrTarget,
                                    (unsigned long long)relocationCounter,
                                    (unsigned long)pRelocBlock->VirtualAddress
                                );
                                continue;
                            }

                            // 增加计数（以十进制显示在方括号里）
                            relocationCounter++;

                            TULONGLONG originalAddr;
                            SIZE_T bytesRead;
                            status = NtReadVirtualMemory ? NtReadVirtualMemory(processH, patchAddrTarget, &originalAddr, sizeof(TULONGLONG), &bytesRead) : STATUS_UNSUCCESSFUL;
                            if (!NT_SUCCESS(status) || bytesRead != sizeof(TULONGLONG)) {
                                // 只输出一行日志，包含失败信息（原/新地址用 -- 占位）
                                wprintf(
                                    L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=-- → -- | Offset=0x%llX | RVA=0x%lX | NOTE=ReadFail\n",
                                    (unsigned long long)relocationCounter,
                                    (unsigned long long)(uintptr_t)patchAddrTarget,
                                    (unsigned long long)relocationCounter,
                                    (unsigned long)pRelocBlock->VirtualAddress
                                );
                                continue;
                            }

                            TULONGLONG newAddr = originalAddr + delta;
                            // 修复：x86 模 4GB 防止溢出
#if !defined(_WIN64)
                            newAddr &= 0xFFFFFFFF;  // 低 32 位
#endif
                            SIZE_T bytesWritten;
                            status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, patchAddrTarget, &newAddr, sizeof(TULONGLONG), &bytesWritten) : STATUS_UNSUCCESSFUL;
                            if (!NT_SUCCESS(status) || bytesWritten != sizeof(TULONGLONG)) {
                                // 写入失败也只输出一行日志，包含原始与期望新地址以便排查
                                wprintf(
                                    L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX | NOTE=WriteFail\n",
                                    (unsigned long long)relocationCounter,
                                    (unsigned long long)(uintptr_t)patchAddrTarget,
                                    (unsigned long long)originalAddr, (unsigned long long)newAddr,
                                    (unsigned long long)relocationCounter,
                                    (unsigned long)pRelocBlock->VirtualAddress
                                );
                                continue;
                            }

                            // 成功：只输出一行格式化信息（方括号内计数为十进制；地址与偏移等按十六进制显示）
                            wprintf(
                                L"[github.com/zetsr] [%llu] Relocation=0x%llX | Address=0x%llX → 0x%llX | Offset=0x%llX | RVA=0x%lX\n",
                                (unsigned long long)relocationCounter,
                                (unsigned long long)(uintptr_t)patchAddrTarget,
                                (unsigned long long)originalAddr, (unsigned long long)newAddr,
                                (unsigned long long)relocationCounter,
                                (unsigned long)pRelocBlock->VirtualAddress
                            );
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


        FARPROC pLoadLibraryA_Remote = FindRemoteProcAddress(processH, L"kernel32.dll", "LoadLibraryA");
        FARPROC pGetProcAddress_Remote = FindRemoteProcAddress(processH, L"kernel32.dll", "GetProcAddress");
        if (!pLoadLibraryA_Remote || !pGetProcAddress_Remote) {
            wprintf(L"错误：无法找到 LoadLibraryA 或 GetProcAddress。\n");
            return false;
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

        ShellcodeData data;
        data.InjectedDllBase = allocatedBase;
        data.pLoadLibraryA = (LoadLibraryA_t)pLoadLibraryA_Remote;
        data.pGetProcAddress = (GetProcAddress_t)pGetProcAddress_Remote;
        data.ImportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        data.ImportDirSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        status = NtWriteVirtualMemory ? NtWriteVirtualMemory(processH, shellcodeDataMem, &data, sizeof(ShellcodeData), &bytesWritten) : STATUS_UNSUCCESSFUL;
        if (!NT_SUCCESS(status) || bytesWritten != sizeof(ShellcodeData)) {
            DWORD error = RtlNtStatusToDosError ? RtlNtStatusToDosError(status) : GetLastError();
            wprintf(L"错误：NtWriteVirtualMemory（ShellcodeData）失败。错误代码：%lu\n", error);
            return false;
        }

        SIZE_T shellcodeSize = GetFunctionSize(Shellcode);
        wprintf(L"Shellcode 大小: %zu 字节\n", shellcodeSize);
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

        SecureZeroMemory(dllBuffer, fileSize);
        wprintf(L"原始 DLL 缓冲区已从内存中擦除。\n");

        // 移除 unlink（之前引起 -2），或可选恢复 DOS 签名
        // 如果需要防误认，可在注入后写回原签名
        // WORD origMagic = 0x5A4D;
        // status = NtWriteVirtualMemory(processH, allocatedBase, &origMagic, sizeof(WORD), &bytesWritten);
        // wprintf(L"DOS 签名已恢复。\n");

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
        wprintf(L"远程线程完成，退出代码：%lu\n", exitCode);

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
        return true;
    }
}
#endif