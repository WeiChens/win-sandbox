// hook_crash.cpp — 崩溃处理与安全网 Hook
//
// ★ VEH（Vectored Exception Handler）— trampoline 访问违规安全网
// ★ CorExitProcess Hook — 拦截 .NET CLR 进程退出
// ★ SetUnhandledExceptionFilter Hook — 崩溃前刷出审计
//
// 从 hook_engine.cpp 拆分而来，原文件缩小 ~120 行。

#include "hook_engine.h"
#include "detour.h"
#include "ipc_client.h"

#include <windows.h>
#include <cstdio>
#include <cstdlib>

// ============================================================================
// VEH — 向量化异常处理器
// ============================================================================

static LONG CALLBACK SandboxVehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    PEXCEPTION_RECORD record = ExceptionInfo->ExceptionRecord;

    // ★ 处理 /GS Stack Buffer Overrun (CLR 兼容)
    if (record->ExceptionCode == 0xC0000409) {  // STATUS_STACK_BUFFER_OVERRUN
        OutputDebugStringA("[sandbox_hook] VEH: caught STATUS_STACK_BUFFER_OVERRUN, exiting cleanly\n");
        AuditLog(AuditEventType::Error, L"", L"gs_buffer_overrun_caught",
                 record->ExceptionCode, 0);
        ExitProcess(1);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        record->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // 检查故障地址是否在跳板区域内
    PVOID faultAddr = record->ExceptionAddress;
    if (IsAddressInTrampoline(reinterpret_cast<const BYTE*>(faultAddr))) {
#if defined(_M_IX86) || defined(__i386__)
        ExceptionInfo->ContextRecord->Eip += 5;
#else
        ExceptionInfo->ContextRecord->Rip += 14;
#endif
        OutputDebugStringA("[sandbox_hook] VEH: caught trampoline access violation, skipping\n");
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================================
// CorExitProcess Hook — 拦截 .NET CLR 进程退出
// ============================================================================

typedef void (STDMETHODCALLTYPE *PFN_CorExitProcess)(int exitCode);
static PFN_CorExitProcess Real_CorExitProcess = nullptr;

static void STDMETHODCALLTYPE Hook_CorExitProcess(int exitCode) {
    AuditLog(AuditEventType::ProcessCreate, L"", L"clr_exit_intercepted", exitCode, 0);
    if (Real_CorExitProcess) {
        Real_CorExitProcess(exitCode);
    } else {
        TerminateProcess(GetCurrentProcess(), exitCode);
    }
}

// ============================================================================
// SetUnhandledExceptionFilter Hook — 崩溃前刷出审计
// ============================================================================

typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *PFN_SetUnhandledExceptionFilter)(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
static PFN_SetUnhandledExceptionFilter Real_SetUnhandledExceptionFilter = nullptr;

static LONG WINAPI SandboxUefHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    AuditLog(AuditEventType::Error, L"", L"unhandled_exception",
             ExceptionInfo->ExceptionRecord->ExceptionCode, 0);
    OutputDebugStringA("[sandbox_hook] Unhandled exception caught, audit flushed\n");
    return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    SetUnhandledExceptionFilter(SandboxUefHandler);
    return Real_SetUnhandledExceptionFilter
        ? Real_SetUnhandledExceptionFilter(lpTopLevelExceptionFilter)
        : nullptr;
}

// ============================================================================
// VEH 注册（在 InitHookEngine 中调用）
// ============================================================================

void InstallVehHandler() {
    AddVectoredExceptionHandler(1, SandboxVehHandler);
}
