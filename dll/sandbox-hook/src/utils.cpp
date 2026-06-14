// utils.cpp — 工具函数

#include "utils.h"
#include <windows.h>
#include <string>
#include <algorithm>

// ============================================================================
// 编码转换
// ============================================================================

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], len);
    return result;
}

// ============================================================================
// Glob 匹配（简化版，支持 * 和 **）
// ============================================================================

bool GlobMatch(const std::wstring& pattern, const std::wstring& path) {
    size_t pi = 0, ti = 0;
    size_t pLen = pattern.length(), tLen = path.length();

    // 归一化大小写
    auto eq = [](wchar_t a, wchar_t b) {
        return towupper(a) == towupper(b);
    };

    while (pi < pLen) {
        if (pattern[pi] == L'*') {
            pi++;
            // ** — 跨路径分隔符匹配
            bool crossDir = (pi < pLen && pattern[pi] == L'*');
            if (crossDir) pi++;

            if (pi == pLen) return true; // 末尾 * 匹配一切

            while (ti < tLen) {
                if (eq(pattern[pi], path[ti])) {
                    if (GlobMatch(pattern.substr(pi), path.substr(ti)))
                        return true;
                }
                // ** 可以跨目录
                if (!crossDir && path[ti] == L'\\') break;
                ti++;
            }
            return false;
        }

        if (ti >= tLen) return false;

        if (pattern[pi] == L'?') {
            pi++; ti++;
            continue;
        }

        if (!eq(pattern[pi], path[ti])) return false;

        pi++; ti++;
    }

    return ti == tLen;
}

// ============================================================================
// DLL 路径
// ============================================================================

std::wstring GetCurrentModulePath(HMODULE hModule) {
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(hModule, path, MAX_PATH);
    return std::wstring(path);
}

// ============================================================================
// 环境变量
// ============================================================================

std::wstring GetEnvWide(const std::wstring& name) {
    wchar_t buf[1024] = {0};
    DWORD len = GetEnvironmentVariableW(name.c_str(), buf, 1024);
    if (len == 0 || len >= 1024) return L"";
    return std::wstring(buf);
}

// ============================================================================
// 设备路径检测
// ============================================================================

bool IsDevicePath(const std::wstring& path) {
    // \Device\... — NT 设备路径
    if (path.find(L"\\Device\\") == 0 || path.find(L"\\DEVICE\\") == 0)
        return true;

    // DOS 设备名（无路径分隔符和冒号）
    if (path.find(L'\\') == std::wstring::npos &&
        path.find(L':') == std::wstring::npos &&
        path.find(L'/') == std::wstring::npos)
        return true;

    // NUL, CON, PRN, AUX — DOS 保留设备名
    std::wstring upper = path;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);
    if (upper == L"NUL" || upper == L"CON" || upper == L"PRN" || upper == L"AUX" ||
        upper == L"COM1" || upper == L"COM2" || upper == L"LPT1" || upper == L"LPT2")
        return true;

    return false;
}
