# Manual-Map

基于 C++20 实现的手动映射 DLL 注入工具，支持从指定的 URL 下载 DLL 文件并将其注入到目标进程中。

## Usage (命令行启动参数)

通过以下命令行参数指定目标进程和 DLL：

```bash
Manual-Map.exe -process=<进程名.exe> -dll=<DLL URL> [-force_wait_process_start=<true|false>]
```
