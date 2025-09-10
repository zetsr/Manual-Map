#ifndef MANUAL_MAP_INJECTOR_H
#define MANUAL_MAP_INJECTOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

namespace ManualMapInjector {

    // --- ���� ---
#if defined(_WIN64)
    using IMAGE_NT_HEADERS_CURRENT = IMAGE_NT_HEADERS64;
    using PIMAGE_NT_HEADERS_CURRENT = PIMAGE_NT_HEADERS64;
    using IMAGE_NT_OPTIONAL_HDR_CURRENT = IMAGE_OPTIONAL_HEADER64;
    using TULONGLONG = ULONGLONG;
    const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_AMD64;
#define IMAGE_REL_BASED_SELF_ARCH IMAGE_REL_BASED_DIR64
#define TULONGLONG_FORMAT "0x%llX"
#else
    using IMAGE_NT_HEADERS_CURRENT = IMAGE_NT_HEADERS32;
    using PIMAGE_NT_HEADERS_CURRENT = PIMAGE_NT_HEADERS32;
    using IMAGE_NT_OPTIONAL_HDR_CURRENT = IMAGE_OPTIONAL_HEADER32;
    using TULONGLONG = DWORD;
    const WORD TARGET_MACHINE = IMAGE_FILE_MACHINE_I386;
#define IMAGE_REL_BASED_SELF_ARCH IMAGE_REL_BASED_HIGHLOW
#define TULONGLONG_FORMAT "0x%X"
#endif

    // --- Shellcode ����ָ�����Ͷ��� ---
    typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR lpFileName);
    typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
    typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

    // --- Shellcode ���ݽṹ ---
    struct ShellcodeData {
        LPVOID InjectedDllBase;
        LoadLibraryA_t pLoadLibraryA;
        GetProcAddress_t pGetProcAddress;
        DWORD ImportDirRVA;
        DWORD ImportDirSize;
    };

    // --- Shellcode ���� ---
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

                if (pImportDesc->Name == 0) {
                    pImportDesc++;
                    continue;
                }

                char* dllName = (char*)((LPBYTE)imageBase + pImportDesc->Name);
                HMODULE hMod = pLoadLibraryA(dllName);
                if (!hMod) return (DWORD)-5;

                // ȷ��ʹ���ĸ�thunk��INT��IAT��
                PIMAGE_THUNK_DATA pThunkILT = nullptr;
                if (pImportDesc->OriginalFirstThunk != 0) {
                    pThunkILT = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + pImportDesc->OriginalFirstThunk);
                }
                else if (pImportDesc->FirstThunk != 0) {
                    pThunkILT = (PIMAGE_THUNK_DATA)((LPBYTE)imageBase + pImportDesc->FirstThunk);
                }
                else {
                    pImportDesc++;
                    continue;
                }

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
            // ע�⣺ĳЩDLL���ܲ��������ֶ�ӳ�䣬DllMain���ܷ���FALSE
            BOOL success = dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
            return (DWORD)success;
        }
        return (DWORD)1;
    }

    // ���㺯����С
#pragma optimize("", off)
    template<typename T>
    size_t GetFunctionSize(T* function) {
        uint8_t* ptr = (uint8_t*)function;
        while (true) {
            // Ѱ�Һ�������ģʽ (RETָ��)
#if defined(_WIN64)
            if (ptr[0] == 0xC3 || ptr[0] == 0xC2)
#else
            if (ptr[0] == 0xC3 || ptr[0] == 0xC2 || ptr[0] == 0xC9 || ptr[0] == 0xCA)
#endif
            {
                // ȷ��������������
                bool isFunctionEnd = true;
                for (int i = 1; i < 8; i++) {
                    if (ptr[i] == 0xCC) break; // ���͵ĺ������ģʽ
                    if (ptr[i] != 0x00 && ptr[i] != 0x90) { // NOP��NULL
                        isFunctionEnd = false;
                        break;
                    }
                }
                if (isFunctionEnd) {
                    return (ptr - (uint8_t*)function) + 1;
                }
            }
            ptr++;
        }
    }
#pragma optimize("", on)

    // --- �����ṹ������ ---
    struct HandleDeleter {
        using pointer = HANDLE;
        void operator()(HANDLE handle) const {
            if (handle != NULL && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        }
    };

    using unique_handle = std::unique_ptr<void, HandleDeleter>;

    // �����ڴ��ͷ���
    struct VirtualFreeDeleter {
        HANDLE hProcess;
        VirtualFreeDeleter(HANDLE process) : hProcess(process) {}

        void operator()(LPVOID memory) const {
            if (memory) VirtualFreeEx(hProcess, memory, 0, MEM_RELEASE);
        }
    };

    using unique_virtual_mem = std::unique_ptr<void, VirtualFreeDeleter>;

    // --- ʵ�ú��� ---

    // �� std::wstring ת��Ϊ std::string (UTF-8)
    std::string WstringToUtf8(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
        std::string str(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, NULL, NULL);
        str.resize(size - 1);
        return str;
    }

    // ��ȡĿ������е�ģ���ַ
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

    // ����Զ�̺�����ַ
    FARPROC FindRemoteProcAddress(HANDLE hProcess, const std::wstring& moduleName, const std::string& procName) {
        HMODULE hTargetMod = GetModuleBaseInTargetProcess(hProcess, moduleName);
        if (!hTargetMod) {
            wprintf(L"����ģ�� '%s' ��Ŀ�������δ�ҵ���\n", moduleName.c_str());
            return NULL;
        }

        std::string moduleNameUtf8 = WstringToUtf8(moduleName);
        HMODULE hInjectorMod = GetModuleHandleA(moduleNameUtf8.c_str());
        if (!hInjectorMod) {
            hInjectorMod = LoadLibraryA(moduleNameUtf8.c_str());
            if (!hInjectorMod) {
                wprintf(L"����LoadLibraryA ʧ�ܣ�ģ�� '%s'��������룺%lu\n", moduleName.c_str(), GetLastError());
                return NULL;
            }
        }

        // ע�⣺���ǲ����ͷ�hInjectorMod����Ϊ�����ͨ��GetModuleHandle��ȡ�ģ���Ӧ���ͷ�
        // �����ͨ��LoadLibrary���صģ�����һ��С���ڴ�й©�������ǵ�ʹ�ó��������Խ���

        FARPROC injectorFuncAddr = GetProcAddress(hInjectorMod, procName.c_str());
        if (!injectorFuncAddr) {
            wprintf(L"����GetProcAddress ʧ�ܣ����� '%hs' ��ģ�� '%s' �С�������룺%lu\n",
                procName.c_str(), moduleName.c_str(), GetLastError());
            return NULL;
        }

        TULONGLONG funcOffset = (TULONGLONG)injectorFuncAddr - (TULONGLONG)hInjectorMod;
        return (FARPROC)((LPBYTE)hTargetMod + funcOffset);
    }

    // �� RVA ת��Ϊ�ļ�ƫ��
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

    // �ֶ�ӳ��ע�뺯��
    bool ManualMapInject(DWORD targetPID, BYTE* dllBuffer, size_t fileSize) {
        wprintf(L"���ڽ� DLL ע�뵽 PID: %lu\n", targetPID);

        // ���� PE ͷ
        if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
            wprintf(L"���󣺻�������С���޷����� DOS ͷ��\n");
            return false;
        }
        PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBuffer);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            wprintf(L"������Ч�� DOS ǩ����\n");
            return false;
        }

        if (pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS_CURRENT) > fileSize) {
            wprintf(L"������Ч�� PE ͷƫ�ơ�\n");
            return false;
        }

        PIMAGE_NT_HEADERS_CURRENT pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS_CURRENT>(dllBuffer + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            wprintf(L"������Ч�� NT ǩ����\n");
            return false;
        }

        if (pNtHeaders->FileHeader.Machine != TARGET_MACHINE) {
            wprintf(L"���󣺼ܹ���ƥ�䡣ע����=%s��DLL=%s\n",
                (TARGET_MACHINE == IMAGE_FILE_MACHINE_AMD64 ? L"64λ" : L"32λ"),
                (pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? L"64λ" : L"32λ"));
            return false;
        }
        wprintf(L"PE ͷ�����ɹ���\n");

        // ��Ŀ�����
        unique_handle processHandle(OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID));
        if (!processHandle.get()) {
            wprintf(L"����OpenProcess ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }
        wprintf(L"Ŀ������Ѵ򿪡�\n");

        // ��Ŀ������з����ڴ�
        LPVOID allocatedBase = VirtualAllocEx(processHandle.get(), reinterpret_cast<LPVOID>(pNtHeaders->OptionalHeader.ImageBase),
            pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!allocatedBase) {
            DWORD preferredAllocError = GetLastError();
            wprintf(L"���棺��ѡ��ַ����ʧ���� " TULONGLONG_FORMAT "��������룺%lu������������λ�÷���...\n",
                (TULONGLONG)pNtHeaders->OptionalHeader.ImageBase, preferredAllocError);

            allocatedBase = VirtualAllocEx(processHandle.get(), NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (!allocatedBase) {
                wprintf(L"����VirtualAllocEx ʧ�ܡ�������룺%lu\n", GetLastError());
                return false;
            }
        }

        // ʹ��RAII��װ������ڴ�
        VirtualFreeDeleter deleter(processHandle.get());
        unique_virtual_mem allocatedBaseWrapper(allocatedBase, deleter);

        wprintf(L"Ϊ DLL ��������ڴ��ڣ� " TULONGLONG_FORMAT "\n", (TULONGLONG)allocatedBase);

        // д�� PE ͷ
        SIZE_T bytesWritten;
        DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
        if (sizeOfHeaders > fileSize) {
            wprintf(L"����SizeOfHeaders ���ڻ�������С��\n");
            return false;
        }

        if (!WriteProcessMemory(processHandle.get(), allocatedBase, dllBuffer, sizeOfHeaders, &bytesWritten) ||
            bytesWritten != sizeOfHeaders) {
            wprintf(L"����WriteProcessMemory��ͷ��ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }
        wprintf(L"PE ͷ��д��Ŀ����̡�\n");

        // д���
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->PointerToRawData != 0 &&
                (pSectionHeader->PointerToRawData > fileSize ||
                    pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > fileSize)) {
                wprintf(L"���󣺽� %d ԭʼ���ݳ�����Χ��\n", i);
                return false;
            }

            if (static_cast<TULONGLONG>(pSectionHeader->VirtualAddress) + pSectionHeader->Misc.VirtualSize > pNtHeaders->OptionalHeader.SizeOfImage) {
                wprintf(L"���󣺽� %d �����ַ���������ڴ淶Χ��\n", i);
                return false;
            }

            if (pSectionHeader->SizeOfRawData > 0) {
                LPVOID sectionTargetAddress = (LPBYTE)allocatedBase + pSectionHeader->VirtualAddress;
                LPVOID sectionSourceAddress = dllBuffer + pSectionHeader->PointerToRawData;
                if (!WriteProcessMemory(processHandle.get(), sectionTargetAddress, sectionSourceAddress,
                    pSectionHeader->SizeOfRawData, &bytesWritten) ||
                    bytesWritten != pSectionHeader->SizeOfRawData) {
                    wprintf(L"����WriteProcessMemory���� %d��ʧ�ܡ�������룺%lu\n", i, GetLastError());
                    return false;
                }
            }
        }
        wprintf(L"����д��Ŀ����̡�\n");

        // �����ض�λ
        TULONGLONG delta = (TULONGLONG)((LPBYTE)allocatedBase - pNtHeaders->OptionalHeader.ImageBase);
        if (delta != 0) {
            wprintf(L"��Ҫ�ض�λ��ƫ������" TULONGLONG_FORMAT "\n", delta);

            IMAGE_DATA_DIRECTORY relocDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
                wprintf(L"���棺��Ҫ�ض�λ��ȱ���ض�λ��\n");
            }
            else {
                DWORD relocOffset = RvaToFileOffset(pNtHeaders, relocDir.VirtualAddress, fileSize);
                if (relocOffset == 0 || relocOffset + relocDir.Size > fileSize) {
                    wprintf(L"�����ض�λĿ¼������Χ��\n");
                    return false;
                }

                PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(dllBuffer + relocOffset);
                LPBYTE relocTableEnd = (LPBYTE)pRelocBlock + relocDir.Size;

                while ((LPBYTE)pRelocBlock < relocTableEnd && pRelocBlock->SizeOfBlock > 0) {
                    if ((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock > relocTableEnd) {
                        wprintf(L"������Ч���ض�λ���С��\n");
                        return false;
                    }

                    DWORD count = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    PWORD pRelocEntry = (PWORD)((LPBYTE)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

                    for (DWORD i = 0; i < count; ++i, ++pRelocEntry) {
                        WORD type = (*pRelocEntry >> 12);
                        WORD offset = (*pRelocEntry & 0xFFF);

                        // ��������0����䣩
                        if (type == 0) continue;

                        if (type == IMAGE_REL_BASED_SELF_ARCH) {
                            LPVOID patchAddrTarget = (LPBYTE)allocatedBase + pRelocBlock->VirtualAddress + offset;
                            TULONGLONG originalAddr;
                            SIZE_T bytesRead;
                            if (!ReadProcessMemory(processHandle.get(), patchAddrTarget, &originalAddr, sizeof(TULONGLONG), &bytesRead) ||
                                bytesRead != sizeof(TULONGLONG)) {
                                wprintf(L"���棺ReadProcessMemory �� " TULONGLONG_FORMAT " ʧ�ܡ�\n", (TULONGLONG)patchAddrTarget);
                                continue;
                            }

                            TULONGLONG newAddr = originalAddr + delta;
                            if (!WriteProcessMemory(processHandle.get(), patchAddrTarget, &newAddr, sizeof(TULONGLONG), &bytesWritten) ||
                                bytesWritten != sizeof(TULONGLONG)) {
                                wprintf(L"���棺WriteProcessMemory���ض�λ���� " TULONGLONG_FORMAT " ʧ�ܡ�\n", (TULONGLONG)patchAddrTarget);
                                continue;
                            }
                        }
                        // ������������Ӷ������ض�λ���͵�֧��
                    }
                    pRelocBlock = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocBlock + pRelocBlock->SizeOfBlock);
                }
                wprintf(L"�ض�λ�Ѵ���\n");
            }
        }
        else {
            wprintf(L"�����ض�λ��\n");
        }

        // ׼�� Shellcode
        FARPROC pLoadLibraryA_Remote = FindRemoteProcAddress(processHandle.get(), L"kernel32.dll", "LoadLibraryA");
        FARPROC pGetProcAddress_Remote = FindRemoteProcAddress(processHandle.get(), L"kernel32.dll", "GetProcAddress");

        if (!pLoadLibraryA_Remote || !pGetProcAddress_Remote) {
            wprintf(L"�����޷��ҵ� LoadLibraryA �� GetProcAddress��\n");
            return false;
        }

        LPVOID shellcodeDataMem = VirtualAllocEx(processHandle.get(), NULL, sizeof(ShellcodeData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!shellcodeDataMem) {
            wprintf(L"����VirtualAllocEx��ShellcodeData��ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }
        unique_virtual_mem shellcodeDataWrapper(shellcodeDataMem, deleter);

        ShellcodeData data;
        data.InjectedDllBase = allocatedBase;
        data.pLoadLibraryA = (LoadLibraryA_t)pLoadLibraryA_Remote;
        data.pGetProcAddress = (GetProcAddress_t)pGetProcAddress_Remote;
        data.ImportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        data.ImportDirSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (!WriteProcessMemory(processHandle.get(), shellcodeDataMem, &data, sizeof(ShellcodeData), &bytesWritten) || bytesWritten != sizeof(ShellcodeData)) {
            wprintf(L"����WriteProcessMemory��ShellcodeData��ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }

        // ��̬����Shellcode��С
        SIZE_T shellcodeSize = GetFunctionSize(Shellcode);
        wprintf(L"Shellcode ��С: %zu �ֽ�\n", shellcodeSize);

        LPVOID shellcodeMem = VirtualAllocEx(processHandle.get(), NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeMem) {
            wprintf(L"����VirtualAllocEx��shellcode��ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }
        unique_virtual_mem shellcodeWrapper(shellcodeMem, deleter);

        if (!WriteProcessMemory(processHandle.get(), shellcodeMem, (LPVOID)Shellcode, shellcodeSize, &bytesWritten) || bytesWritten != shellcodeSize) {
            wprintf(L"����WriteProcessMemory��shellcode��ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }

        // ����ԭʼ DLL ������
        SecureZeroMemory(dllBuffer, fileSize);
        wprintf(L"ԭʼ DLL �������Ѵ��ڴ��в�����\n");

        // ִ�� Shellcode
        unique_handle threadHandle(CreateRemoteThread(processHandle.get(), NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeMem, shellcodeDataMem, 0, NULL));
        if (!threadHandle.get()) {
            wprintf(L"����CreateRemoteThread ʧ�ܡ�������룺%lu\n", GetLastError());
            return false;
        }

        WaitForSingleObject(threadHandle.get(), INFINITE);
        DWORD exitCode = 0;
        GetExitCodeThread(threadHandle.get(), &exitCode);
        wprintf(L"Զ���߳���ɣ��˳����룺%lu\n", exitCode);

        if (exitCode == 0) {
            wprintf(L"���棺DllMain ���� FALSE ������ڵ㡣\n");
        }
        else if (exitCode < 100) {
            if (exitCode == (DWORD)-1) wprintf(L"����Shellcode ʧ�� - ��Ч������\n");
            else if (exitCode == (DWORD)-2) wprintf(L"����Shellcode ʧ�� - ��Ч DOS ǩ����\n");
            else if (exitCode == (DWORD)-3) wprintf(L"����Shellcode ʧ�� - ��Ч NT ǩ����\n");
            else if (exitCode == (DWORD)-4) wprintf(L"����Shellcode ʧ�� - �� DLL �ļ���\n");
            else if (exitCode == (DWORD)-5) wprintf(L"����Shellcode ʧ�� - �������� DLL ʧ�ܡ�\n");
            else if (exitCode == (DWORD)-6) wprintf(L"����Shellcode ʧ�� - ��ȡ������ַʧ�ܡ�\n");
            else if (exitCode != (DWORD)TRUE) wprintf(L"ע�⣺Shellcode �����˳����� (%lu)��\n", exitCode);
        }

        // �ͷŰ�װ������Ȩ����RAII�����ں�������ʱ�Զ�����
        allocatedBaseWrapper.release();
        shellcodeDataWrapper.release();
        shellcodeWrapper.release();

        wprintf(L"ע����ɡ�\n");
        return true;
    }

} // namespace ManualMapInjector

#endif // MANUAL_MAP_INJECTOR_H