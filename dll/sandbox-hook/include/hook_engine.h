// hook_engine.h — Hook 管理器 + 自注入引擎
//
// ★ 核心架构改进（vs Failure-01）：
//   递归注入在 C++ DLL 内部直接完成，不再通过 IPC 到 Rust Host。
//   Hook_NtResumeThread → OpenProcess → VirtualAllocEx →
//   WriteProcessMemory → CreateRemoteThread(LoadLibraryW) → ResumeThread
//   全部在同一调用栈完成，耗时 <100μs，CLR 不会检测到。

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>

// ============================================================================
// 进程追踪
// ============================================================================

/// 追踪待注入的子进程
struct TrackedProcess {
    HANDLE  hProcess = nullptr;
    HANDLE  hThread = nullptr;
    DWORD   dwProcessId = 0;
    DWORD   dwThreadId = 0;
    bool    bInjected = false;
    std::wstring initEventName;
    HANDLE  hInitEvent = nullptr;
};

// ============================================================================
// Hook 引擎
// ============================================================================

/// 初始化 Hook 引擎
/// 在 DllMain DLL_PROCESS_ATTACH 调用
bool InitHookEngine();

/// 安装所有沙箱 Hook
void InstallAllHooks();

/// 卸载所有 Hook（在 DllMain DLL_PROCESS_DETACH 调用）
void UninstallAllHooks();

/// 信号初始化完成（通知父进程 DLL 已就绪）
void SignalInitComplete();

// ============================================================================
// 自注入引擎（关键路径！）
// ============================================================================

/// 直接将沙箱 DLL 注入目标进程（同进程直投，无 IPC）
/// @param pid       目标进程 PID
/// @param hProcess  目标进程句柄（可选，nullptr 则内部 OpenProcess）
/// @param hThread   目标主线程句柄（用于获取架构信息）
/// @return 成功返回 true
bool SelfInject(DWORD pid, HANDLE hProcess, HANDLE hThread);

/// 检测当前进程是否加载了 .NET CLR
bool IsClrLoaded();

/// 获取当前 DLL 路径
std::wstring GetCurrentDllPath();
