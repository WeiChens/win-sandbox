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
// SetUnhandledExceptionFilter Hook — 崩溃前刷出审计，并调用应用 handler
// ============================================================================

typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *PFN_SetUnhandledExceptionFilter)(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
static PFN_SetUnhandledExceptionFilter Real_SetUnhandledExceptionFilter = nullptr;

/// 保存应用原始 UEF handler，刷出审计后调用
static LPTOP_LEVEL_EXCEPTION_FILTER g_appUefHandler = nullptr;

static LONG WINAPI SandboxUefHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    // 1. 先刷出审计
    AuditLog(AuditEventType::Error, L"", L"unhandled_exception",
             ExceptionInfo->ExceptionRecord->ExceptionCode, 0);
    OutputDebugStringA("[sandbox_hook] Unhandled exception caught, audit flushed\n");

    // 2. 调用应用原本的 handler（如果有）
    if (g_appUefHandler) {
        return g_appUefHandler(ExceptionInfo);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    // ★ 重要：不能在此调用 SetUnhandledExceptionFilter()，
    //    会递归进入本 Hook → 栈溢出 (0xC00000FD)。
    //    通过 Real_ 指针调用原始函数以避免递归。
    //
    // ★ 保存应用的 handler，在 SandboxUefHandler 中先刷审计再调用
    g_appUefHandler = lpTopLevelExceptionFilter;

    // 安装我们的 handler（通过原始函数）
    if (Real_SetUnhandledExceptionFilter) {
        Real_SetUnhandledExceptionFilter(SandboxUefHandler);
    }

    // 返回 nullptr 表示旧 handler（Windows 文档说 SetUnhandledExceptionFilter
    // 返回旧的 handler 指针，但我们替换了它，返回旧值可能被应用误用）
    // 返回非空值让应用知道有一个 handler 已存在
    return (LPTOP_LEVEL_EXCEPTION_FILTER)(LONG_PTR)1;
}

// ============================================================================
// VEH 注册（在 InitHookEngine 中调用）
// ============================================================================

void InstallVehHandler() {
    AddVectoredExceptionHandler(1, SandboxVehHandler);
}

// ============================================================================
// 安装 Hook（在 InstallAllHooks 中调用）
// ============================================================================

void InstallCorExitProcessHook() {
    HMODULE hClr = GetModuleHandleW(L"clr.dll");
    if (!hClr) {
        hClr = GetModuleHandleW(L"coreclr.dll");
    }
    if (!hClr) {
        // .NET 未加载，跳过（进程启动后 .NET 可能延迟加载）
        return;
    }

    auto* target = (BYTE*)GetProcAddress(hClr, "CorExitProcess");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_CorExitProcess, "CorExitProcess");
        if (tramp) Real_CorExitProcess = (PFN_CorExitProcess)tramp;
    }
}

void InstallCrashHandlerHook() {
    // ★ Hook SetUnhandledExceptionFilter — 崩溃前刷出审计
    //   优先 Hook kernelbase.dll（Win10 上 kernel32 的 UEF 是转发到 kernelbase 的 JMP）
    //   避免 Hook 转发 stub 导致的兼容性问题
    BYTE* target = FindFunction("kernelbase.dll", "SetUnhandledExceptionFilter");
    if (!target) {
        target = FindFunction("kernel32.dll", "SetUnhandledExceptionFilter");
    }
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_SetUnhandledExceptionFilter, "SetUnhandledExceptionFilter");
        if (tramp) Real_SetUnhandledExceptionFilter = (PFN_SetUnhandledExceptionFilter)tramp;
    }
}
