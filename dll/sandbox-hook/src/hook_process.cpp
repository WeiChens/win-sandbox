// hook_process.cpp — 进程管理 Hook（NtCreateUserProcess/NtResumeThread）
//                    + 自注入引擎（SelfInject + GetWow64LoadLibraryW）
//                    + 进程追踪（TrackedProcess）
//
// 从 hook_engine.cpp 拆分而来，原文件缩小 ~340 行。

#include "hook_engine.h"
#include "detour.h"
#include "ipc_client.h"
#include "utils.h"

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

// ============================================================================
// NT 类型和常量
// ============================================================================

typedef LONG NTSTATUS;
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)

#define CREATE_SUSPENDED_FLAG 0x00000004

// ============================================================================
// 全局变量（在 header 中声明为 extern）
// ============================================================================

std::atomic<bool> g_dll_detaching{false};
std::vector<TrackedProcess> g_tracked;
CRITICAL_SECTION g_track_cs;

// DLL 路径缓存
std::wstring g_dllPathX64;
std::wstring g_dllPathX86;
std::wstring g_dllPathSelf;

// WOW64 LoadLibraryW 地址缓存
static uint32_t g_wow64LoadLibraryW = 0;
static bool g_wow64LoadLibraryW_resolved = false;

// ============================================================================
// 原始函数指针
// ============================================================================

static NTSTATUS (WINAPI *Real_NtCreateUserProcess)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
    PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PVOID) = nullptr;

static NTSTATUS (WINAPI *Real_NtResumeThread)(HANDLE) = nullptr;

// ============================================================================
// 进程追踪辅助
// ============================================================================

TrackedProcess* FindByThread(HANDLE hThread) {
    EnterCriticalSection(&g_track_cs);
    for (auto& tp : g_tracked) {
        if (tp.hThread == hThread && tp.hProcess != nullptr) {
            LeaveCriticalSection(&g_track_cs);
            return &tp;
        }
    }
    LeaveCriticalSection(&g_track_cs);
    return nullptr;
}

void ClearTracked(TrackedProcess* tp) {
    if (tp->hInitEvent) {
        CloseHandle(tp->hInitEvent);
        tp->hInitEvent = nullptr;
    }
    tp->hProcess = nullptr;
    tp->hThread = nullptr;
    tp->dwProcessId = 0;
    tp->bInjected = false;
}

// ============================================================================
// CLR 检测 / DLL 路径
// ============================================================================

bool IsClrLoaded() {
    return GetModuleHandleA("clr.dll") != nullptr
        || GetModuleHandleA("coreclr.dll") != nullptr;
}

std::wstring GetCurrentDllPath() {
    return GetCurrentModulePath();
}

void CacheDllPaths() {
    g_dllPathSelf = GetCurrentDllPath();

    wchar_t buf[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"SBOX_DLL_PATH_X64", buf, MAX_PATH) > 0) {
        g_dllPathX64 = buf;
    } else {
        g_dllPathX64 = g_dllPathSelf;
    }

    ZeroMemory(buf, sizeof(buf));
    if (GetEnvironmentVariableW(L"SBOX_DLL_PATH_X86", buf, MAX_PATH) > 0) {
        g_dllPathX86 = buf;
    } else {
        g_dllPathX86 = g_dllPathSelf;
    }
}

std::wstring GetDllPathForArch(bool isWow64) {
    if (isWow64) {
        return g_dllPathX86.empty() ? g_dllPathSelf : g_dllPathX86;
    }
    return g_dllPathX64.empty() ? g_dllPathSelf : g_dllPathX64;
}

// ============================================================================
// GetWow64LoadLibraryW — 获取 32 位 kernel32!LoadLibraryW 地址
// ============================================================================

uint32_t GetWow64LoadLibraryW() {
    if (g_wow64LoadLibraryW_resolved) {
        return g_wow64LoadLibraryW;
    }
    g_wow64LoadLibraryW_resolved = true;  // only try once

    std::wstring helperExe = L"C:\\Windows\\SysWOW64\\cmd.exe";
    std::wstring helperCmd = L"cmd.exe /c exit";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(helperExe.c_str(), &helperCmd[0],
                        nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        OutputDebugStringA("[sandbox_hook] GetWow64LoadLibraryW: CreateProcess failed\n");
        return 0;
    }

    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    uint32_t k32base = 0;
    MODULEENTRY32W me = { sizeof(me) };
    if (Module32FirstW(hSnapshot, &me)) {
        do {
            if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) {
                k32base = (uint32_t)(uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnapshot, &me));
    }
    CloseHandle(hSnapshot);

    if (k32base == 0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // PE 导出表解析
    IMAGE_DOS_HEADER dosHdr;
    SIZE_T bytesRead;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)k32base, &dosHdr, sizeof(dosHdr), &bytesRead);

    uint32_t ntOffset = k32base + dosHdr.e_lfanew;
    IMAGE_NT_HEADERS32 ntHdr;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)ntOffset, &ntHdr, sizeof(ntHdr), &bytesRead);

    uint32_t exportDirRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + exportDirRVA),
                      &exportDir, sizeof(exportDir), &bytesRead);

    // 读取名称表、序号表、地址表
    std::vector<uint32_t> names(exportDir.NumberOfNames);
    std::vector<uint16_t> ordinals(exportDir.NumberOfNames);
    std::vector<uint32_t> funcs(exportDir.NumberOfFunctions);

    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + exportDir.AddressOfNames),
                      names.data(), names.size() * 4, &bytesRead);
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + exportDir.AddressOfNameOrdinals),
                      ordinals.data(), ordinals.size() * 2, &bytesRead);
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + exportDir.AddressOfFunctions),
                      funcs.data(), funcs.size() * 4, &bytesRead);

    uint32_t llwRVA = 0;
    for (uint32_t i = 0; i < exportDir.NumberOfNames; i++) {
        char funcName[64] = {};
        ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + names[i]),
                          funcName, sizeof(funcName) - 1, &bytesRead);
        if (strcmp(funcName, "LoadLibraryW") == 0) {
            llwRVA = funcs[ordinals[i]];
            break;
        }
    }

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);

    if (llwRVA == 0) return 0;

    g_wow64LoadLibraryW = k32base + llwRVA;
    return g_wow64LoadLibraryW;
}

// ============================================================================
// ★ 自注入引擎
// ============================================================================

bool SelfInject(DWORD pid, HANDLE hProcess, HANDLE hThread) {
    HANDLE hTarget = hProcess;
    bool needClose = false;
    if (!hTarget || hTarget == INVALID_HANDLE_VALUE) {
        hTarget = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE, pid);
        if (!hTarget) {
            AuditLog(AuditEventType::Error, L"", L"self-inject: OpenProcess failed", 0, GetLastError());
            return false;
        }
        needClose = true;
    }

    BOOL isWow64 = FALSE;
    IsWow64Process(hTarget, &isWow64);

    std::wstring dllPath = GetDllPathForArch(isWow64 != FALSE);
    if (dllPath.empty()) {
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    size_t dllBytes = (dllPath.length() + 1) * sizeof(wchar_t);
    void* remoteMem = VirtualAllocEx(hTarget, nullptr, dllBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hTarget, remoteMem, dllPath.c_str(), dllBytes, &written)) {
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryW = nullptr;
    if (isWow64) {
        uint32_t llw32 = GetWow64LoadLibraryW();
        if (llw32 == 0) {
            VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
            if (needClose) CloseHandle(hTarget);
            return false;
        }
        pLoadLibraryW = (LPTHREAD_START_ROUTINE)(uintptr_t)llw32;
    } else {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (!k32) {
            VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
            if (needClose) CloseHandle(hTarget);
            return false;
        }
        pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
        if (!pLoadLibraryW) {
            VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
            if (needClose) CloseHandle(hTarget);
            return false;
        }
    }

    HANDLE hRemoteThread = CreateRemoteThread(hTarget, nullptr, 0,
                                               pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hRemoteThread) {
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    DWORD waitRet = WaitForSingleObject(hRemoteThread, 5000);
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
    if (needClose) CloseHandle(hTarget);

    if (waitRet == WAIT_OBJECT_0) {
        AuditLog(AuditEventType::InjectComplete, std::to_wstring(pid),
                 L"self-inject ok", isWow64 ? 0x86 : 0x64, 0);
        return true;
    }

    AuditLog(AuditEventType::Error, std::to_wstring(pid),
             L"self-inject: wait timeout", 0, waitRet);
    return false;
}

// ============================================================================
// NtCreateUserProcess Hook
// ============================================================================

static NTSTATUS WINAPI Hook_NtCreateUserProcess(
    PHANDLE ProcessHandle, PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
    PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes,
    ULONG ProcessFlags, ULONG ThreadFlags,
    PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList)
{
    if (!Real_NtCreateUserProcess) {
        if (ProcessHandle) *ProcessHandle = nullptr;
        if (ThreadHandle) *ThreadHandle = nullptr;
        return STATUS_ACCESS_DENIED;
    }

    // ★ 所有子进程统一挂起 + 在 NtResumeThread 中注入。
    //    不论父进程是否是 CLR（PowerShell等），子进程都是非 CLR 进程，
    //    挂起+注入是最安全的方式（避免 loader lock 竞争）。
    //    /GS 栈检测冲突已由 detour.cpp 的 CALL rel32 重定位修复解决。

    NTSTATUS status = Real_NtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        ProcessFlags | CREATE_SUSPENDED_FLAG,
        ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);

    wchar_t recurEnv[4] = {0};
    if (GetEnvironmentVariableW(L"SBOX_RECURSIVE_INJECTION", recurEnv, 4) > 0) {
        if (recurEnv[0] == L'0') return status;
    }

    if (status >= 0 && ProcessHandle && *ProcessHandle
        && *ProcessHandle != INVALID_HANDLE_VALUE) {

        DWORD pid = GetProcessId(*ProcessHandle);
        DWORD tid = GetThreadId(*ThreadHandle);

        EnterCriticalSection(&g_track_cs);
        TrackedProcess tp;
        tp.hProcess = *ProcessHandle;
        tp.hThread = *ThreadHandle;
        tp.dwProcessId = pid;
        tp.dwThreadId = tid;
        tp.bInjected = false;

        wchar_t eventName[128];
        swprintf_s(eventName, L"Global\\SBox_Init_%lu", pid);
        tp.initEventName = eventName;
        tp.hInitEvent = CreateEventW(nullptr, TRUE, FALSE, eventName);
        g_tracked.push_back(tp);
        LeaveCriticalSection(&g_track_cs);

        AuditLog(AuditEventType::ProcessCreate, std::to_wstring(pid),
                 L"created_suspended", 0, status);
    }

    return status;
}

// ============================================================================
// NtResumeThread Hook（★ 自注入触发点）
// ============================================================================

static NTSTATUS WINAPI Hook_NtResumeThread(HANDLE hThread) {
    if (!Real_NtResumeThread) return STATUS_ACCESS_DENIED;

    if (g_dll_detaching.load()) return STATUS_ACCESS_DENIED;

    TrackedProcess* tp = FindByThread(hThread);
    if (tp && !tp->bInjected) {
        bool injected = SelfInject(tp->dwProcessId, tp->hProcess, tp->hThread);

        if (injected) {
            tp->bInjected = true;
            if (tp->hInitEvent) {
                WaitForSingleObject(tp->hInitEvent, 0);
            }
            AuditLog(AuditEventType::InjectComplete,
                     std::to_wstring(tp->dwProcessId),
                     L"child_injected", 0, 0);
        } else {
            AuditLog(AuditEventType::Error,
                     std::to_wstring(tp->dwProcessId),
                     L"child_inject_failed", 0, -1);
        }

        EnterCriticalSection(&g_track_cs);
        ClearTracked(tp);
        LeaveCriticalSection(&g_track_cs);
    }

    return Real_NtResumeThread(hThread);
}

// ============================================================================
// 安装函数
// ============================================================================

void InstallNtCreateUserProcessHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtCreateUserProcess");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtCreateUserProcess, "NtCreateUserProcess");
        if (tramp) Real_NtCreateUserProcess = (decltype(Real_NtCreateUserProcess))tramp;
    }
}

void InstallNtResumeThreadHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtResumeThread");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtResumeThread, "NtResumeThread");
        if (tramp) Real_NtResumeThread = (decltype(Real_NtResumeThread))tramp;
    }
}
