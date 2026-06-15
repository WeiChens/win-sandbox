// path_resolver.cpp — 从 HANDLE 解析文件路径（双层级策略）
//
// ★ Tier 1: NtQueryObject — 轻量，无递归风险，<1μs（Trae 方案）
// ★ Tier 2: GetFinalPathNameByHandleW — 回退，带 TLS 重入守卫
//
// 从 hook_engine.cpp 拆分而来，原文件缩小 ~200 行。

#include "hook_engine.h"
#include "utils.h"

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cwchar>

// ============================================================================
// NT API 类型
// ============================================================================

typedef LONG NTSTATUS;

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} MY_UNICODE_STRING;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION {
    MY_UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION;

typedef NTSTATUS (NTAPI *PFN_NtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

// ============================================================================
// TLS 重入守卫（仅用于 Tier 2 回退路径）
// ============================================================================

static DWORD g_tls_handle_path = TLS_OUT_OF_INDEXES;

static bool EnterGetPath() {
    if (g_tls_handle_path == TLS_OUT_OF_INDEXES) {
        g_tls_handle_path = TlsAlloc();
        if (g_tls_handle_path == TLS_OUT_OF_INDEXES) return false;
    }
    if (TlsGetValue(g_tls_handle_path) != 0) return false;
    TlsSetValue(g_tls_handle_path, (LPVOID)1);
    return true;
}

static void LeaveGetPath() {
    if (g_tls_handle_path != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_handle_path, (LPVOID)0);
}

// ============================================================================
// ★ NtQueryObject 路径解析（Tier 1 — 快速路径）
// ============================================================================

static PFN_NtQueryObject g_NtQueryObject = nullptr;

static bool InitNtQueryObject() {
    if (g_NtQueryObject) return true;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    g_NtQueryObject = (PFN_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
    return g_NtQueryObject != nullptr;
}

// DOS 设备名 → NT 设备路径 映射缓存（如 C: ↔ \Device\HarddiskVolume2）
static std::vector<std::pair<std::wstring, wchar_t>> g_deviceMap;
static bool g_deviceMapInitialized = false;
static std::mutex g_deviceMapMutex;

static void InitDeviceMap() {
    std::lock_guard<std::mutex> lock(g_deviceMapMutex);
    if (g_deviceMapInitialized) return;

    wchar_t drives[256];
    DWORD len = GetLogicalDriveStringsW(256, drives);
    if (len == 0 || len > 256) return;

    for (wchar_t* p = drives; *p; p += wcslen(p) + 1) {
        wchar_t root[4] = {p[0], L':', L'\\', L'\0'};
        wchar_t ntDev[1024] = {0};
        if (QueryDosDeviceW(root, ntDev, 1024) > 0) {
            std::wstring devPath(ntDev);
            std::transform(devPath.begin(), devPath.end(), devPath.begin(), ::towupper);
            g_deviceMap.push_back({devPath, p[0]});
        }
    }
    g_deviceMapInitialized = true;
}

/// 使用 NtQueryObject 从 HANDLE 获取文件路径（NT 路径→DOS 路径转换）
/// 比 GetFinalPathNameByHandleW 快 100x，且无递归 Hook 风险
bool GetPathFromHandleNt(HANDLE hFile, wchar_t* out, size_t outSize) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE || !out || outSize == 0)
        return false;
    if (!InitNtQueryObject())
        return false;
    if (!g_deviceMapInitialized)
        InitDeviceMap();

    // 第一次调用：查询所需缓冲区大小
    ULONG returnLen = 0;
    NTSTATUS status = g_NtQueryObject(hFile, ObjectNameInformation, nullptr, 0, &returnLen);
    if (status != (NTSTATUS)0xC0000004L && status != (NTSTATUS)0xC0000023L)
        return false;
    if (returnLen == 0 || returnLen > 65536)
        return false;

    // 分配缓冲区并第二次查询
    std::vector<BYTE> buf(returnLen + sizeof(wchar_t));
    status = g_NtQueryObject(hFile, ObjectNameInformation, buf.data(), (ULONG)buf.size(), &returnLen);
    if (status < 0)
        return false;

    auto* nameInfo = reinterpret_cast<OBJECT_NAME_INFORMATION*>(buf.data());
    if (!nameInfo->Name.Buffer || nameInfo->Name.Length == 0)
        return false;

    // 提取 NT 路径（如 \Device\HarddiskVolume2\Users\Me\file.txt）
    size_t nameLen = nameInfo->Name.Length / sizeof(wchar_t);
    std::wstring ntPath(nameInfo->Name.Buffer, nameLen);
    std::transform(ntPath.begin(), ntPath.end(), ntPath.begin(), ::towupper);

    // 将 NT 路径转换为 DOS 路径（C:\...）
    for (const auto& [ntDev, driveLetter] : g_deviceMap) {
        if (wcsncmp(ntPath.c_str(), ntDev.c_str(), ntDev.length()) == 0) {
            std::wstring remainder = ntPath.substr(ntDev.length());
            if (!remainder.empty() && remainder[0] == L'\\')
                remainder = remainder.substr(1);

            std::wstring dosPath = std::wstring(1, driveLetter) + L":\\" + remainder;
            wcsncpy_s(out, outSize, dosPath.c_str(), _TRUNCATE);
            return out[0] != L'\0';
        }
    }

    return false; // 未找到对应的盘符映射
}

// ============================================================================
// GetFinalPathNameByHandleW 回退路径（Tier 2 — 带 TLS 守卫）
// ============================================================================

/// 从 HANDLE 获取文件路径（大写归一化），失败返回 false
bool GetPathFromHandle(HANDLE hFile, wchar_t* out, size_t outSize) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE || !out || outSize == 0)
        return false;
    if (!EnterGetPath()) return false;

    DWORD len = GetFinalPathNameByHandleW(hFile, out, (DWORD)outSize, 0);
    if (len == 0 || len >= outSize) {
        LeaveGetPath();
        return false;
    }

    // 去掉 \\?\ 前缀
    if (wcsncmp(out, L"\\\\?\\", 4) == 0) {
        size_t remaining = outSize - 4;
        memmove(out, out + 4, (remaining) * sizeof(wchar_t));
    }

    // 大写归一化
    std::transform(out, out + wcslen(out), out, ::towupper);

    LeaveGetPath();
    return true;
}
