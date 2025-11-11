#ifndef CONSOLE_H
#define CONSOLE_H

#include <windows.h>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <io.h>
#include <fcntl.h>

inline void SetConsoleCursorVisibility(bool visible) {
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

inline void ClearConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) {
        return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        return;
    }

    DWORD dwWritten;
    DWORD dwConsoleSize = csbi.dwSize.X * csbi.dwSize.Y;
    COORD cursorHome = { 0, 0 };

    if (!FillConsoleOutputCharacterW(hConsole, L' ', dwConsoleSize, cursorHome, &dwWritten)) {
        return;
    }

    if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConsoleSize, cursorHome, &dwWritten)) {
        return;
    }

    SetConsoleCursorPosition(hConsole, cursorHome);
}

inline void PrintMessage(const std::wstring& message) {
    std::wcout << L"> " << message << std::endl;
}

inline void PrintTypewriter(const std::wstring& text, int delay_ms, int chars_per_sleep = 1) {
    if (chars_per_sleep <= 0) chars_per_sleep = 1;

    int chars_printed_in_batch = 0;
    for (wchar_t c : text) {
        std::wcout << c << std::flush;
        chars_printed_in_batch++;

        if (delay_ms > 0 && chars_printed_in_batch >= chars_per_sleep) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            chars_printed_in_batch = 0;
        }
    }
}

#endif