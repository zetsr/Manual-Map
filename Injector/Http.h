#ifndef HTTP_H
#define HTTP_H

#include <windows.h>
#include <wininet.h>
#include <string>
#include <memory>
#include <vector>
#include <algorithm>
#include <limits>
#include "Console.h"
#include "Print.h"

#pragma comment(lib, "wininet.lib")

struct InternetHandleDeleter {
    void operator()(HINTERNET handle) const {
        if (handle != NULL) {
            InternetCloseHandle(handle);
        }
    }
};
using unique_internet_handle = std::unique_ptr<void, InternetHandleDeleter>;

inline bool GetHttpFileSize(const std::wstring& url, size_t& fileSize) {
    fileSize = 0;

    unique_internet_handle hInternet(InternetOpenW(L"DLLDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    if (!hInternet) {
        PrintMessage(L"错误：[GetSize] InternetOpenW 失败。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    DWORD flags = INTERNET_FLAG_RELOAD;
    if (url.find(L"https://") == 0) {
        flags |= INTERNET_FLAG_SECURE;
    }

    unique_internet_handle hUrl(InternetOpenUrlW(hInternet.get(), url.c_str(), NULL, 0, flags, 0));
    if (!hUrl) {
        PrintMessage(L"错误：[GetSize] InternetOpenUrlW 失败。无法打开 URL：" + url + L"。错误代码：" + std::to_wstring(GetLastError()));
        return false;
    }

    DWORD contentLength = 0;
    DWORD length = sizeof(contentLength);

    if (!HttpQueryInfoW(hUrl.get(), HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &contentLength, &length, NULL)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_HTTP_HEADER_NOT_FOUND) {
            PrintMessage(L"警告：[GetSize] 无法获取 Content-Length 头部。下载将继续，但无法预知文件大小。");
            fileSize = 0;
        }
        else {
            PrintMessage(L"错误：[GetSize] HttpQueryInfoW 失败。无法获取 Content-Length。错误代码：" + std::to_wstring(lastError));
            return false;
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

    return true;
}

inline std::unique_ptr<BYTE[]> DownloadDLLToMemory(const std::wstring& url, size_t& outSize) {
    outSize = 0;
    size_t fileSize = 0;

    bool sizeKnown = GetHttpFileSize(url, fileSize);

    unique_internet_handle hInternet(InternetOpenW(L"DLLDownloader", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0));
    if (!hInternet) {
        PrintMessage(L"错误：InternetOpenW 失败。无法初始化网络连接。错误代码：" + std::to_wstring(GetLastError()));
        return nullptr;
    }

    DWORD flags = INTERNET_FLAG_RELOAD;
    if (url.find(L"https://") == 0) {
        flags |= INTERNET_FLAG_SECURE;
    }

    unique_internet_handle hUrl(InternetOpenUrlW(hInternet.get(), url.c_str(), NULL, 0, flags, 0));
    if (!hUrl) {
        PrintMessage(L"错误：InternetOpenUrlW 失败。无法打开 URL：" + url + L"。错误代码：" + std::to_wstring(GetLastError()));
        return nullptr;
    }

    WgetStyleProgressBar progressBar(fileSize);
    PrintMessage(L"正在从 " + url + L" 下载 DLL...");

    size_t bufferSize = sizeKnown && fileSize > 0 ?
        fileSize + std::max<size_t>(fileSize / 10, 1024 * 1024) :
        10 * 1024 * 1024;

    if (bufferSize < 4096) bufferSize = 4096;

    std::unique_ptr<BYTE[]> buffer(new (std::nothrow) BYTE[bufferSize]);
    if (!buffer) {
        PrintMessage(L"错误：内存分配失败。无法分配下载缓冲区（" + std::to_wstring(bufferSize) + L" 字节）。可能由于内存不足或碎片化。");
        return nullptr;
    }

    size_t totalRead = 0;
    BYTE temp[8192];
    DWORD bytesRead;

    while (InternetReadFile(hUrl.get(), temp, sizeof(temp), &bytesRead) && bytesRead > 0) {
        if (totalRead + bytesRead > bufferSize) {
            size_t newBufferSize = bufferSize * 2;

            const size_t MAX_BUFFER_SIZE = 256 * 1024 * 1024;
            if (newBufferSize > MAX_BUFFER_SIZE) {
                if (totalRead + bytesRead > MAX_BUFFER_SIZE) {
                    PrintMessage(L"错误：下载数据超出最大允许缓冲区大小 (" + std::to_wstring(MAX_BUFFER_SIZE) + L" 字节)。");
                    return nullptr;
                }
                newBufferSize = MAX_BUFFER_SIZE;
            }

            std::unique_ptr<BYTE[]> newBuffer(new (std::nothrow) BYTE[newBufferSize]);
            if (!newBuffer) {
                PrintMessage(L"错误：内存重新分配失败。无法扩展下载缓冲区。");
                return nullptr;
            }

            std::copy(buffer.get(), buffer.get() + totalRead, newBuffer.get());
            buffer = std::move(newBuffer);
            bufferSize = newBufferSize;

            PrintMessage(L"警告：下载缓冲区不足，尝试重新分配到 " + std::to_wstring(bufferSize) + L" 字节。");
        }

        std::copy(temp, temp + bytesRead, buffer.get() + totalRead);
        totalRead += bytesRead;

        progressBar.Update(totalRead);
    }

    DWORD lastInternetError = GetLastError();
    if (totalRead == 0 && lastInternetError != ERROR_SUCCESS) {
        PrintMessage(L"错误：DLL 下载失败，未读取到任何数据。InternetReadFile 错误代码：" + std::to_wstring(lastInternetError));
        return nullptr;
    }
    else if (totalRead == 0) {
        PrintMessage(L"警告：下载的 DLL 为空（0 字节）。");
        return nullptr;
    }

    progressBar.Finish();

    std::unique_ptr<BYTE[]> finalBuffer(new (std::nothrow) BYTE[totalRead]);
    if (!finalBuffer) {
        PrintMessage(L"错误：无法分配最终 DLL 缓冲区 (" + std::to_wstring(totalRead) + L" 字节)。可能由于内存不足。");
        return nullptr;
    }

    std::copy(buffer.get(), buffer.get() + totalRead, finalBuffer.get());
    outSize = totalRead;

    PrintMessage(L"DLL 成功下载到内存。大小：" + std::to_wstring(outSize) + L" 字节。");
    return finalBuffer;
}

#endif