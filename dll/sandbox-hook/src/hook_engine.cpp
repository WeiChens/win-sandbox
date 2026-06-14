// hook_engine.cpp — Hook 管理器 + ★ 自注入引擎（核心架构改进）
//
// ============================================================================
// ★ 与 Failure-01 的关键区别：
//
//   Failure-01:
//     Hook_NtResumeThread → IPC 到 Rust Host → Host 注入 → (5秒超时) → Resume
//     问题: CLR 检测到延迟 → COR_E_EXECUTIONENGINE
//
//   新方案 (本文件):
//     Hook_NtResumeThread → SelfInject() [同进程直投] → Resume
//     全部在 DLL 内部完成，<100μs，CLR 无感知
//
//   TRAE 也是这样做的（trae_sbox.dll 内自注入），这是唯一经过验证的可靠方案。
// ============================================================================

#include "hook_engine.h"
#include "detour.h"
#include "file_acl.h"
#include "net_acl.h"
#include "ipc_client.h"
#include "shared_config.h"
#include "utils.h"

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

// ============================================================================
// NT API 类型
// ============================================================================

typedef LONG NTSTATUS;
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)

// OBJECT_ATTRIBUTES (简化版)
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PMY_UNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES, *PMY_OBJECT_ATTRIBUTES;

// NtCreateUserProcess flags
#define CREATE_SUSPENDED_FLAG 0x00000004

// ============================================================================
// 全局状态
// ============================================================================

static std::atomic<bool> g_dll_detaching{false};
static std::mutex g_track_mutex;
static std::vector<TrackedProcess> g_tracked;
static CRITICAL_SECTION g_track_cs;
static bool g_track_cs_initialized = false;

// DLL 路径缓存（从环境变量读取）
static std::wstring g_dllPathX64;
static std::wstring g_dllPathX86;
static std::wstring g_dllPathSelf;

// WOW64 LoadLibraryW 地址缓存
static uint32_t g_wow64LoadLibraryW = 0;
static bool g_wow64LoadLibraryW_resolved = false;

// ============================================================================
// 原始函数指针
// ============================================================================

static NTSTATUS (WINAPI *Real_NtCreateFile)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, PLARGE_INTEGER,
    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = nullptr;

static NTSTATUS (WINAPI *Real_NtOpenFile)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG) = nullptr;

static NTSTATUS (WINAPI *Real_NtDeleteFile)(PVOID) = nullptr;

static NTSTATUS (WINAPI *Real_NtCreateUserProcess)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
    PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PVOID) = nullptr;

static NTSTATUS (WINAPI *Real_NtResumeThread)(HANDLE) = nullptr;

static NTSTATUS (WINAPI *Real_NtSetInformationFile)(
    HANDLE, PVOID, PVOID, ULONG, ULONG) = nullptr;

// ============================================================================
// 辅助函数
// ============================================================================

static TrackedProcess* FindByThread(HANDLE hThread) {
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

static void ClearTracked(TrackedProcess* tp) {
    if (tp->hInitEvent) {
        CloseHandle(tp->hInitEvent);
        tp->hInitEvent = nullptr;
    }
    tp->hProcess = nullptr;
    tp->hThread = nullptr;
    tp->dwProcessId = 0;
    tp->bInjected = false;
}

bool IsClrLoaded() {
    return GetModuleHandleA("clr.dll") != nullptr
        || GetModuleHandleA("coreclr.dll") != nullptr;
}

std::wstring GetCurrentDllPath() {
    return GetCurrentModulePath();
}

// ============================================================================
// DLL 路径管理
// ============================================================================

void CacheDllPaths() {
    // 自身路径
    g_dllPathSelf = GetCurrentDllPath();

    // 从环境变量读取 x64/x86 路径
    wchar_t buf[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"SBOX_DLL_PATH_X64", buf, MAX_PATH) > 0) {
        g_dllPathX64 = buf;
    } else {
        g_dllPathX64 = g_dllPathSelf; // fallback
    }

    ZeroMemory(buf, sizeof(buf));
    if (GetEnvironmentVariableW(L"SBOX_DLL_PATH_X86", buf, MAX_PATH) > 0) {
        g_dllPathX86 = buf;
    } else {
        g_dllPathX86 = g_dllPathSelf; // fallback
    }

    char dbg[512];
    snprintf(dbg, sizeof(dbg), "[sandbox_hook] DLL paths cached:\n  self=%ls\n  x64=%ls\n  x86=%ls\n",
             g_dllPathSelf.c_str(), g_dllPathX64.c_str(), g_dllPathX86.c_str());
    OutputDebugStringA(dbg);
}

std::wstring GetDllPathForArch(bool isWow64) {
    if (isWow64) {
        return g_dllPathX86.empty() ? g_dllPathSelf : g_dllPathX86;
    }
    return g_dllPathX64.empty() ? g_dllPathSelf : g_dllPathX64;
}

// ============================================================================
// GetWow64LoadLibraryW — 获取 32 位 kernel32!LoadLibraryW 地址
//
// 原理：
//   - 创建 32 位辅助进程 (C:\Windows\SysWOW64\cmd.exe)
//   - 通过 ToolHelp32 快照获取 kernel32.dll 的 32 位基址
//   - 通过 ReadProcessMemory 读取 PE 导出表，解析 LoadLibraryW 的 RVA
//   - 实际地址 = 基址 + RVA
//   - 同一启动会话内，所有 32 位进程的 kernel32 加载地址相同（ASLR per-boot）
// ============================================================================

// PE 导出目录定义（使用 winnt.h 中的 IMAGE_EXPORT_DIRECTORY）
// winnt.h 已通过 windows.h 包含

uint32_t GetWow64LoadLibraryW() {
    if (g_wow64LoadLibraryW_resolved) {
        return g_wow64LoadLibraryW;
    }
    g_wow64LoadLibraryW_resolved = true; // only try once

    // 1. 创建 32 位辅助进程
    std::wstring helperExe = L"C:\\Windows\\SysWOW64\\cmd.exe";
    std::wstring helperCmd = L"cmd.exe /c exit";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(helperExe.c_str(), &helperCmd[0],
                        nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        OutputDebugStringA("[sandbox_hook] GetWow64LoadLibraryW: CreateProcess(SysWOW64\\cmd) failed\n");
        return 0;
    }

    // 等待进程初始化
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);

    // 2. ToolHelp 快照 — 获取 kernel32.dll 基址
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[sandbox_hook] GetWow64LoadLibraryW: CreateToolhelp32Snapshot failed\n");
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
        OutputDebugStringA("[sandbox_hook] GetWow64LoadLibraryW: kernel32.dll not found\n");
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // 3. 读取 PE 导出表
    // DOS header → e_lfanew → NT header → OptionalHeader.DataDirectory[0]
    IMAGE_DOS_HEADER dosHdr;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)k32base,
                           &dosHdr, sizeof(dosHdr), &bytesRead) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // NT header (32-bit: IMAGE_NT_HEADERS32)
    uint32_t ntOffset = k32base + dosHdr.e_lfanew;
    IMAGE_NT_HEADERS32 ntHdr;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)ntOffset,
                           &ntHdr, sizeof(ntHdr), &bytesRead) || ntHdr.Signature != IMAGE_NT_SIGNATURE) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    uint32_t exportDirRVA = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t exportDirSize = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (exportDirRVA == 0 || exportDirSize == 0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // 读取导出目录
    uint32_t exportDirAddr = k32base + exportDirRVA;
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)exportDirAddr,
                           &exportDir, sizeof(exportDir), &bytesRead)) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        return 0;
    }

    // 读取名称表、序号表、地址表
    uint32_t namesAddr = k32base + exportDir.AddressOfNames;
    uint32_t ordinalsAddr = k32base + exportDir.AddressOfNameOrdinals;
    uint32_t funcsAddr = k32base + exportDir.AddressOfFunctions;

    std::vector<uint32_t> names(exportDir.NumberOfNames);
    std::vector<uint16_t> ordinals(exportDir.NumberOfNames);
    std::vector<uint32_t> funcs(exportDir.NumberOfFunctions);

    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)namesAddr,
                      names.data(), names.size() * 4, &bytesRead);
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)ordinalsAddr,
                      ordinals.data(), ordinals.size() * 2, &bytesRead);
    ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)funcsAddr,
                      funcs.data(), funcs.size() * 4, &bytesRead);

    // 4. 二分 / 线性搜索 "LoadLibraryW"
    uint32_t llwRVA = 0;
    for (uint32_t i = 0; i < exportDir.NumberOfNames; i++) {
        char funcName[64] = {};
        ReadProcessMemory(pi.hProcess, (LPCVOID)(uintptr_t)(k32base + names[i]),
                          funcName, sizeof(funcName) - 1, &bytesRead);

        if (strcmp(funcName, "LoadLibraryW") == 0) {
            uint16_t ordinal = ordinals[i];
            llwRVA = funcs[ordinal];
            break;
        }
    }

    // 清理辅助进程
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);

    if (llwRVA == 0) {
        OutputDebugStringA("[sandbox_hook] GetWow64LoadLibraryW: LoadLibraryW not found in exports\n");
        return 0;
    }

    g_wow64LoadLibraryW = k32base + llwRVA;

    char dbg[128];
    snprintf(dbg, sizeof(dbg), "[sandbox_hook] WOW64 LoadLibraryW = 0x%08X\n", g_wow64LoadLibraryW);
    OutputDebugStringA(dbg);

    return g_wow64LoadLibraryW;
}

// ============================================================================
// ★ 自注入引擎（关键路径！）
// ============================================================================

bool SelfInject(DWORD pid, HANDLE hProcess, HANDLE hThread) {
    // 1. 打开目标进程（如果需要）
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

    // 2. 检测目标架构 → 选择 DLL 路径
    BOOL isWow64 = FALSE;
    IsWow64Process(hTarget, &isWow64);

    std::wstring dllPath = GetDllPathForArch(isWow64 != FALSE);
    if (dllPath.empty()) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: no DLL path for arch", 0, -1);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    char dbg[256];
    snprintf(dbg, sizeof(dbg), "[sandbox_hook] SelfInject: PID=%lu, WOW64=%d, DLL=%ls\n",
             pid, isWow64, dllPath.c_str());
    OutputDebugStringA(dbg);

    // 3. 在目标进程中分配内存
    size_t dllBytes = (dllPath.length() + 1) * sizeof(wchar_t);
    void* remoteMem = VirtualAllocEx(hTarget, nullptr, dllBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: VirtualAllocEx failed", 0, GetLastError());
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 4. 写入 DLL 路径
    SIZE_T written = 0;
    if (!WriteProcessMemory(hTarget, remoteMem, dllPath.c_str(), dllBytes, &written)) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: WriteProcessMemory failed", 0, GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 5. 获取 LoadLibraryW 地址
    // ★ WOW64 目标：使用 32 位 kernel32!LoadLibraryW 地址
    //    x64 目标：使用 64 位 kernel32!LoadLibraryW 地址
    LPTHREAD_START_ROUTINE pLoadLibraryW = nullptr;

    if (isWow64) {
        uint32_t llw32 = GetWow64LoadLibraryW();
        if (llw32 == 0) {
            AuditLog(AuditEventType::Error, L"", L"self-inject: GetWow64LoadLibraryW failed", 0, -1);
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

    // 6. 创建远程线程
    HANDLE hRemoteThread = CreateRemoteThread(hTarget, nullptr, 0,
                                               pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hRemoteThread) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: CreateRemoteThread failed", 0, GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 7. 等待 LoadLibraryW 完成（必须在 ResumeThread 前完成）
    DWORD waitRet = WaitForSingleObject(hRemoteThread, 5000);
    CloseHandle(hRemoteThread);

    // 8. 清理
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
// Hook 函数实现
// ============================================================================

// ---- NtCreateFile Hook ----
static NTSTATUS WINAPI Hook_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (!Real_NtCreateFile) {
        if (FileHandle) *FileHandle = nullptr;
        return STATUS_ACCESS_DENIED;
    }

    // 提取路径
    wchar_t path[1024] = {0};
    if (!ExtractPathFromOA(ObjectAttributes, path, 1024) || !path[0]) {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    // 放行设备路径和 DOS 设备名
    std::wstring pathStr(path);
    if (IsDevicePath(pathStr)) {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    // ACL 检查
    FilePermission perm = IsAclInitialized() ? CheckFilePermission(pathStr) : FilePermission::Inherit;

    if (perm == FilePermission::Deny) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_create", DesiredAccess, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    if (perm == FilePermission::ReadOnly) {
        // 剥离写权限
        DWORD writeFlags = GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA
                         | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE;
        DWORD stripped = DesiredAccess & ~writeFlags;

        if ((DesiredAccess & writeFlags) && stripped == 0) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_write", DesiredAccess, STATUS_ACCESS_DENIED);
            if (FileHandle) *FileHandle = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }

        if (DesiredAccess & writeFlags) {
            AuditLog(AuditEventType::FileDowngrade, pathStr, L"readonly_downgrade", DesiredAccess, 0);
        }

        // 降级放行
        return Real_NtCreateFile(FileHandle, stripped, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    // PERM_INHERIT: 放行
    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

// ---- NtOpenFile Hook ----
static NTSTATUS WINAPI Hook_NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    if (!Real_NtOpenFile) {
        if (FileHandle) *FileHandle = nullptr;
        return STATUS_ACCESS_DENIED;
    }

    wchar_t path[1024] = {0};
    if (!ExtractPathFromOA(ObjectAttributes, path, 1024) || !path[0]) {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring pathStr(path);
    if (IsDevicePath(pathStr)) {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, ShareAccess, OpenOptions);
    }

    FilePermission perm = CheckFilePermission(pathStr);
    if (perm == FilePermission::Deny) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_open", DesiredAccess, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                           IoStatusBlock, ShareAccess, OpenOptions);
}

// ---- NtDeleteFile Hook ----
static NTSTATUS WINAPI Hook_NtDeleteFile(PVOID ObjectAttributes) {
    if (!Real_NtDeleteFile) return STATUS_ACCESS_DENIED;

    wchar_t path[1024] = {0};
    if (ExtractPathFromOA(ObjectAttributes, path, 1024) && path[0]) {
        std::wstring pathStr(path);
        FilePermission perm = CheckFilePermission(pathStr);
        if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_delete", DELETE, STATUS_ACCESS_DENIED);
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Real_NtDeleteFile(ObjectAttributes);
}

// ============================================================================
// ★ NtCreateUserProcess Hook — 强制挂起 + 记录追踪
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

    // ★ CLR 进程不强制挂起子进程（避免破坏 CLR 运行时）
    //    注意：在自注入架构下，即使是 CLR 进程的子进程，
    //    我们也可以在以后通过其他机制注入
    bool isClr = IsClrLoaded();

    NTSTATUS status = Real_NtCreateUserProcess(
        ProcessHandle, ThreadHandle,
        ProcessDesiredAccess, ThreadDesiredAccess,
        ProcessObjectAttributes, ThreadObjectAttributes,
        isClr ? ProcessFlags : (ProcessFlags | CREATE_SUSPENDED_FLAG),
        ThreadFlags,
        ProcessParameters, CreateInfo, AttributeList);

    // CLR 进程：跳过追踪
    if (isClr) return status;

    // 检查是否允许递归注入
    wchar_t recurEnv[4] = {0};
    if (GetEnvironmentVariableW(L"SBOX_RECURSIVE_INJECTION", recurEnv, 4) > 0) {
        if (recurEnv[0] == L'0') return status;
    }

    // 仅在成功创建时追踪
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
// ★ NtResumeThread Hook — 自注入 + 恢复（核心！）
// ============================================================================
static NTSTATUS WINAPI Hook_NtResumeThread(HANDLE hThread) {
    if (!Real_NtResumeThread) return STATUS_ACCESS_DENIED;

    // DLL 正在卸载，不操作
    if (g_dll_detaching.load()) return STATUS_ACCESS_DENIED;

    // CLR 进程：直接放行（不注入子进程，避免破坏 CLR）
    if (IsClrLoaded()) return Real_NtResumeThread(hThread);

    // 查找追踪记录
    TrackedProcess* tp = FindByThread(hThread);
    if (tp && !tp->bInjected) {
        // ★ 关键：在 DLL 内部直接注入，无 IPC！
        bool injected = SelfInject(tp->dwProcessId, tp->hProcess, tp->hThread);

        if (injected) {
            tp->bInjected = true;

            // 等待子进程 DLL 初始化完成（非阻塞轮询）
            if (tp->hInitEvent) {
                WaitForSingleObject(tp->hInitEvent, 0);
            }

            AuditLog(AuditEventType::InjectComplete,
                     std::to_wstring(tp->dwProcessId),
                     L"child_injected", 0, 0);
        } else {
            // 注入失败也恢复线程（不阻塞子进程）
            AuditLog(AuditEventType::Error,
                     std::to_wstring(tp->dwProcessId),
                     L"child_inject_failed", 0, -1);
        }

        // 清理追踪
        EnterCriticalSection(&g_track_cs);
        ClearTracked(tp);
        LeaveCriticalSection(&g_track_cs);
    }

    // 放行原始调用
    return Real_NtResumeThread(hThread);
}

// ============================================================================
// 安装 Hook
// ============================================================================

static void InstallNtCreateFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtCreateFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtCreateFile, "NtCreateFile");
        if (tramp) Real_NtCreateFile = (decltype(Real_NtCreateFile))tramp;
    }
}

static void InstallNtOpenFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtOpenFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtOpenFile, "NtOpenFile");
        if (tramp) Real_NtOpenFile = (decltype(Real_NtOpenFile))tramp;
    }
}

static void InstallNtDeleteFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtDeleteFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtDeleteFile, "NtDeleteFile");
        if (tramp) Real_NtDeleteFile = (decltype(Real_NtDeleteFile))tramp;
    }
}

static void InstallNtCreateUserProcessHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtCreateUserProcess");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtCreateUserProcess, "NtCreateUserProcess");
        if (tramp) Real_NtCreateUserProcess = (decltype(Real_NtCreateUserProcess))tramp;
    }
}

static void InstallNtResumeThreadHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtResumeThread");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtResumeThread, "NtResumeThread");
        if (tramp) Real_NtResumeThread = (decltype(Real_NtResumeThread))tramp;
    }
}

// ============================================================================
// 公开 API
// ============================================================================

// ============================================================================
// Hook 引擎公开 API
// ============================================================================

// VEH 前置声明
static LONG CALLBACK SandboxVehHandler(PEXCEPTION_POINTERS ExceptionInfo);

bool InitHookEngine() {
    InitializeCriticalSection(&g_track_cs);
    g_track_cs_initialized = true;
    g_tracked.reserve(64);

    // ★ 注册 VEH（Vectored Exception Handler）作为安全网
    // 在 DLL 卸载期间，如果内核在 trampoline 释放后仍调用 NtResumeThread，
    // VEH 捕获 ACCESS_VIOLATION 并安全处理（跳过故障指令）
    AddVectoredExceptionHandler(1, SandboxVehHandler);

    return true;
}

// ============================================================================
// ★ VEH — 向量化异常处理器（x86 卸载崩溃安全网）
//
// 在 x86 上，进程退出时内核可能在线程清理中调用 NtResumeThread。
// 如果此时 trampoline 已被释放，跳转到已释放内存会触发
// STATUS_ACCESS_VIOLATION。VEH 检测并安全降级。
// ============================================================================

static LONG CALLBACK SandboxVehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD record = ExceptionInfo->ExceptionRecord;

    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        record->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // 检查故障地址是否在我们的跳板区域内
    PVOID faultAddr = record->ExceptionAddress;
    if (IsAddressInTrampoline(reinterpret_cast<const BYTE*>(faultAddr))) {
        // 跳板已被释放，跳过故障指令继续执行
        // 修改指令指针到安全位置
#if defined(_M_IX86) || defined(__i386__)
        // x86: 跳过 JMP 指令（5 字节 E9 xx xx xx xx）
        ExceptionInfo->ContextRecord->Eip += 5;
#else
        // x64: 跳过 JMP 指令（14 字节 FF 25 ...）
        ExceptionInfo->ContextRecord->Rip += 14;
#endif
        OutputDebugStringA("[sandbox_hook] VEH: caught trampoline access violation, skipping\n");
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallAllHooks() {
    // 文件系统 Hook
    InstallNtCreateFileHook();
    InstallNtOpenFileHook();
    InstallNtDeleteFileHook();

    // 进程/递归注入 Hook
    InstallNtCreateUserProcessHook();
    InstallNtResumeThreadHook();  // ★ 这个最重要

    // 网络 Hook（如果启用）
    wchar_t netEnv[4] = {0};
    if (GetEnvironmentVariableW(L"SBOX_NETWORK_ISOLATION", netEnv, 4) == 0 || netEnv[0] != L'0') {
        InstallNetHooks();
    }

    AuditLog(AuditEventType::ProcessCreate, L"", L"all_hooks_installed", 0, 0);
}

void UninstallAllHooks() {
    // ★ 严格的卸载顺序（解决 x86 崩溃）：
    // 1. 首先设置 detaching 标志 → Hook 函数立即返回 STATUS_ACCESS_DENIED
    // 2. 短暂延迟 → 等待所有正在执行的 Hook 完成
    // 3. 恢复 hook 字节 → 后续 NtResumeThread 走原始函数
    // 4. 释放跳板内存
    g_dll_detaching.store(true);

    // 让正在执行的 Hook 有时间完成（特别是 Hook_NtResumeThread）
    Sleep(5);

    DetourUninstallAll();
}

void SignalInitComplete() {
    DWORD pid = GetCurrentProcessId();
    wchar_t eventName[128];
    swprintf_s(eventName, L"Global\\SBox_Init_%lu", pid);

    HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName);
    if (hEvent) {
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }

    AuditLog(AuditEventType::InjectComplete, std::to_wstring(pid),
             L"dll_init_complete", 0, 0);
}
