# 📚 Manual Map Injector API 文档

这是一个用于 Windows 平台的高级 DLL 注入库。它实现了手动映射（Manual Map）注入技术，允许将 DLL 字节数组直接加载到目标进程的内存空间中，而无需依赖标准的 Windows 加载器。

## 📦 模块概览

本库的核心功能通过 `ManualMapInjector` 命名空间中的一个主要函数暴露。

| 文件 | 描述 |
| :--- | :--- |
| `API.h` | 外部 API 的声明（主接口）。 |
| `ManualMapInjector.h` | 兼容性头文件，包含了所有必要的模块。 |
| `Config.h` | 内部配置，定义了 32/64 位架构的类型抽象。 |
| `Util.h` | 内部工具函数，包括 PE 解析、句柄和内存管理。 |
| `Shellcode.h` | 内部 Shellcode 定义及其数据结构。 |

-----

## 🎯 核心 API 接口

核心功能通过以下函数实现。您需要包含 `API.h` 或 `ManualMapInjector.h` 来使用它。

### 1\. ManualMapInject

执行手动映射注入操作。

```cpp
namespace ManualMapInjector {
    bool ManualMapInject(DWORD targetPID, BYTE* dllBuffer, size_t fileSize);
}
```

#### 参数

| 参数名 | 类型 | 描述 |
| :--- | :--- | :--- |
| `targetPID` | `DWORD` | **目标进程的进程 ID (PID)**。这是 DLL 将要注入的进程标识符。 |
| `dllBuffer` | `BYTE*` | **包含 DLL 镜像数据的缓冲区指针**。该缓冲区应包含完整的 DLL 文件内容（从磁盘读取的字节数据）。 **注意：** 注入成功后，为了安全考虑，本函数会在返回前使用 `SecureZeroMemory` **擦除**此缓冲区内容。 |
| `fileSize` | `size_t` | **`dllBuffer` 的大小（以字节为单位）**。必须与 DLL 文件的大小一致。 |

#### 返回值

| 类型 | 描述 |
| :--- | :--- |
| `bool` | `true` 表示注入尝试成功（DLL 的 `DllMain` 已被调用），`false` 表示注入失败。 |

#### 详细操作流程（内部）

此函数执行以下复杂步骤：

1.  **PE 校验与架构检查**：解析 `dllBuffer` 中的 DOS 头和 NT 头，验证 PE 签名，并确保 DLL 的架构（32位/64位）与注入器兼容。
2.  **目标进程准备**：打开目标进程句柄 (`OpenProcess`)。
3.  **远程内存分配**：在目标进程中分配一块足够容纳整个 DLL 镜像的内存 (`VirtualAllocEx`)，并尝试使用 DLL 建议的首选基址。
4.  **写入镜像数据**：将 DLL 的 PE 头和所有 Section（节）的数据分别通过 `WriteProcessMemory` 写入到目标进程内存中。
5.  **基址重定位**：如果实际分配地址与 DLL 建议的首选基址不符，计算偏移量并修复 DLL 内部的硬编码地址指针。
6.  **Shellcode 准备**：定位远程 `kernel32.dll` 中的 `LoadLibraryA` 和 `GetProcAddress` 函数地址，准备 Shellcode 所需的数据结构。
7.  **Shellcode 执行**：将 Shellcode 代码和数据写入目标进程内存，并使用 `CreateRemoteThread` 启动 Shellcode。
8.  **导入表修复与入口点调用**：在远程进程中执行的 Shellcode 负责加载 DLL 依赖项，修复导入表，并最终调用 DLL 的 `DllMain` 函数（以 `DLL_PROCESS_ATTACH` 方式）。
9.  **资源清理**：等待远程线程结束，并安全释放本地缓冲区 (`dllBuffer`)。

-----

## ⚙️ 内部辅助结构（仅供参考）

虽然外部调用者通常不需要直接操作这些结构，但了解它们有助于理解注入器的工作原理。

### 1\. ShellcodeData

该结构用于向远程进程中的 Shellcode 传递必要的数据和函数指针。

定义于 `Shellcode.h`：

```cpp
struct ShellcodeData {
    LPVOID InjectedDllBase;       // DLL 在目标进程中的基址
    LoadLibraryA_t pLoadLibraryA; // 远程 LoadLibraryA 函数指针
    GetProcAddress_t pGetProcAddress; // 远程 GetProcAddress 函数指针
    DWORD ImportDirRVA;           // 导入目录的 RVA
    DWORD ImportDirSize;          // 导入目录的大小
};
```

-----

## ⚠️ 错误处理与退出码

`ManualMapInject` 函数通过返回 `false` 来表示注入失败。如果注入成功，由远程 `Shellcode` 启动的线程将返回一个 `DWORD` 退出代码。

| 退出代码（来自远程线程） | 描述 |
| :--- | :--- |
| **`TRUE` (1)** | 默认成功值，或 `DllMain` 返回 `TRUE`。 |
| **0** | `DllMain` 返回 `FALSE`，或者 DLL 没有入口点。 |
| **`-1` (4294967295)** | Shellcode 失败：无效的参数。 |
| **`-2` (4294967294)** | Shellcode 失败：无效的 DOS 签名。 |
| **`-3` (4294967293)** | Shellcode 失败：无效的 NT 签名。 |
| **`-4` (4294967292)** | Shellcode 失败：不是 DLL 文件。 |
| **`-5` (4294967291)** | Shellcode 失败：加载依赖 DLL 失败（无法调用远程 `LoadLibraryA`）。 |
| **`-6` (4294967290)** | Shellcode 失败：获取函数地址失败（无法调用远程 `GetProcAddress`）。 |

-----
