// hook_engine.cpp — Hook 管理器编排器
//
// ★ 文件拆分后本文件仅包含：
//   InitHookEngine()   — 初始化关键区、注册 VEH
//   InstallAllHooks()  — 安装所有 Hook
//   UninstallAllHooks()— 卸载所有 Hook（DLL_PROCESS_DETACH）
//   SignalInitComplete()— 通知父进程 DLL 就绪
//
// ★ 拆分出去的模块：
//   path_resolver.cpp  — TLS 守卫 + GetPathFromHandle + GetPathFromHandleNt
//   hook_file.cpp      — NtCreateFile/NtOpenFile/NtDeleteFile/NtSetInfoFile/NtWriteFile
//   hook_process.cpp   — NtCreateUserProcess/NtResumeThread + SelfInject + TrackedProcess
//   hook_crash.cpp     — VEH + CorExitProcess + SetUnhandledExceptionFilter

#include "hook_engine.h"
#include "detour.h"
#include "file_acl.h"
#include "net_acl.h"
#include "ipc_client.h"
#include "shared_config.h"

#include <windows.h>
#include <cstdio>

// ============================================================================
// InitHookEngine — 初始化（DllMain DLL_PROCESS_ATTACH 时调用）
// ============================================================================

bool InitHookEngine() {
    InitializeCriticalSection(&g_track_cs);
    // std::list 不需要预分配（reserve）

    // ★ 注册 VEH 作为安全网（在 hook_crash.cpp 中实现）
    // VEH 覆盖：trampoline 访问违规 + CLR /GS 崩溃
    InstallVehHandler();

    return true;
}

// ============================================================================
// InstallAllHooks — 安装所有沙箱 Hook
// ============================================================================

void InstallAllHooks() {
    InstallNtCreateFileHook();
    InstallNtOpenFileHook();
    InstallNtDeleteFileHook();
    InstallNtSetInformationFileHook();
    InstallNtWriteFileHook();      // ★ 已通过 NtQueryObject 解决性能+递归问题
    InstallNtQueryDirectoryFileHook();  // ★ 目录枚举过滤
    InstallNtMapViewOfSectionHook();    // ★ 内存映射文件 ACL
    InstallNtOpenSectionHook();         // ★ Section 打开追踪
    InstallNtCreateUserProcessHook();
    InstallNtResumeThreadHook();
    InstallNetHooks();

    // ★ CorExitProcess Hook — 拦截 .NET CLR 进程退出，刷出审计
    // 暂时禁用：在某些 .NET 版本上导致 ACCESS_VIOLATION (0xC0000005)
    // InstallCorExitProcessHook();

    // ★ CorExitProcess Hook — 拦截 .NET CLR 进程退出，刷出审计
    // 暂时禁用：在某些 .NET 版本上可能导致兼容性问题
    // InstallCorExitProcessHook();

    // ★ SetUnhandledExceptionFilter Hook — 崩溃前刷出审计
    //    使用 __try/__except 保护，防止自身崩溃
    InstallCrashHandlerHook();

    AuditLog(AuditEventType::ProcessCreate, L"", L"all_hooks_installed", 0, 0);
}

// ============================================================================
// UninstallAllHooks — 卸载所有 Hook（DLL_PROCESS_DETACH）
// ============================================================================

void UninstallAllHooks() {
    g_dll_detaching.store(true);
    Sleep(5);
    DetourUninstallAll();
}

// ============================================================================
// SignalInitComplete — 通知父进程 DLL 初始化完成
// ============================================================================

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
