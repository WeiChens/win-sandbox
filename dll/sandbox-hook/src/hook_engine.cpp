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
// ★ 自注入引擎（关键路径！）
// ============================================================================

bool SelfInject(DWORD pid, HANDLE hProcess, HANDLE hThread) {
    // 1. 获取当前 DLL 路径
    std::wstring dllPath = GetCurrentDllPath();
    if (dllPath.empty()) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: empty DLL path", 0, -1);
        return false;
    }

    // 2. 如果需要，打开目标进程
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

    // 3. 检测目标架构（选择正确的 DLL）
    BOOL isWow64 = FALSE;
    IsWow64Process(hTarget, &isWow64);

    // 对于 WOW64 目标，需要使用 x86 DLL 路径
    // 此处简化处理：通过检测自身架构来决定
    // 实际生产环境需要从文件系统选择对应架构的 DLL

    // 4. 在目标进程中分配内存
    size_t dllBytes = (dllPath.length() + 1) * sizeof(wchar_t);
    void* remoteMem = VirtualAllocEx(hTarget, nullptr, dllBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: VirtualAllocEx failed", 0, GetLastError());
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 5. 写入 DLL 路径
    SIZE_T written = 0;
    if (!WriteProcessMemory(hTarget, remoteMem, dllPath.c_str(), dllBytes, &written)) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: WriteProcessMemory failed", 0, GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 6. 获取 LoadLibraryW
    // ★ 对于 WOW64 目标，需要获取 32 位 kernel32 的 LoadLibraryW
    //    这里简化：直接使用 kernel32!LoadLibraryW（x64 下对 x64 目标有效）
    //    x86 目标需要额外处理（通过 ToolHelp 获取 32 位地址）
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    auto* pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(k32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 7. 创建远程线程
    HANDLE hRemoteThread = CreateRemoteThread(hTarget, nullptr, 0,
                                               pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hRemoteThread) {
        AuditLog(AuditEventType::Error, L"", L"self-inject: CreateRemoteThread failed", 0, GetLastError());
        VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
        if (needClose) CloseHandle(hTarget);
        return false;
    }

    // 8. 等待 LoadLibraryW 完成（最关键：必须在 ResumeThread 之前完成）
    //    超时时间设为 5 秒（正常情况下 DLL 加载只需几毫秒）
    DWORD waitRet = WaitForSingleObject(hRemoteThread, 5000);
    CloseHandle(hRemoteThread);

    // 9. 清理
    VirtualFreeEx(hTarget, remoteMem, 0, MEM_RELEASE);
    if (needClose) CloseHandle(hTarget);

    if (waitRet == WAIT_OBJECT_0) {
        AuditLog(AuditEventType::InjectComplete, std::to_wstring(pid),
                 L"self-inject success", 0, 0);
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
#if defined(_M_IX86) || defined(__i386__)
    // x86: 跳过 NtResumeThread hook（DLL 卸载时内核态调用导致崩溃）
    // 子进程的沙箱化由 Rust Host 直接注入完成
    (void)Hook_NtResumeThread;
    return;
#else
    BYTE* target = FindFunction("ntdll.dll", "NtResumeThread");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtResumeThread, "NtResumeThread");
        if (tramp) Real_NtResumeThread = (decltype(Real_NtResumeThread))tramp;
    }
#endif
}

// ============================================================================
// 公开 API
// ============================================================================

bool InitHookEngine() {
    InitializeCriticalSection(&g_track_cs);
    g_track_cs_initialized = true;
    g_tracked.reserve(64);
    return true;
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
    g_dll_detaching.store(true);
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
