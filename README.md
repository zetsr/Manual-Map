# Manual-Map

支持 x64/x86，基于 C++20 实现的手动映射 DLL 注入工具，支持从指定的 URL 下载 DLL 文件并将其注入到目标进程中。

[文档/Docs](https://github.com/zetsr/Manual-Map/blob/main/DOCS.md)

## To-Do 

Updated 2025.12.16

- 改进注入流程以优化性能开销
- 解决x86架构的早期注入与随机崩溃问题
- 完全迁移至NT API
- 更直观的文档
- 更完善的API

## Usage (命令行启动参数)

通过以下命令行参数指定目标进程和 DLL：

```bash
Manual-Map_x64.exe -process=<进程名.exe> -dll=<DLL URL> [-force_wait_process_start=<true|false>]
```
示例
```base
Manual-Map_x64.exe -process=cs2.exe -dll=https://example.com/cs2.dll -force_wait_process_start=true
Manual-Map_x86.exe -process=csgo.exe -dll=https://example.com/csgo.dll -force_wait_process_start=false
```
