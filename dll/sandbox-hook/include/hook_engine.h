// hook_engine.h — Hook 管理器 + 自注入引擎（拆分后的公共接口）
//
// ★ 核心架构改进（vs Failure-01）：
//   递归注入在 C++ DLL 内部直接完成，不再通过 IPC 到 Rust Host。
//   Hook_NtResumeThread → OpenProcess → VirtualAllocEx →
//   WriteProcessMemory → CreateRemoteThread(LoadLibraryW) → ResumeThread
//   全部在同一调用栈完成，耗时 <100μs，CLR 不会检测到。
//
// ★ 文件拆分 (1379→5文件)：
//   hook_engine.cpp    — 编排器：Init/InstallAll/UninstallAll/SignalInitComplete
//   path_resolver.cpp  — TLS守卫 + GetPathFromHandle + GetPathFromHandleNt
//   hook_file.cpp      — NtCreate/NtOpen/NtDelete/NtSetInfo/NtWriteFile + Install
//   hook_process.cpp   — NtCreateUserProcess/NtResumeThread/SelfInject + TrackedProcess
//   hook_crash.cpp     — VEH + CorExitProcess + SetUnhandledExceptionFilter

#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <atomic>

// ============================================================================
// 共享全局变量（在 hook_engine.cpp 中定义，其他 .cpp 通过 extern 访问）
// ============================================================================

/// DLL 正在卸载标志（VEH 和 NtResumeThread 检查此标志避免操作已释放内存）
extern std::atomic<bool> g_dll_detaching;

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

/// 追踪记录列表 + 关键区（在 hook_process.cpp 中定义）
extern std::vector<TrackedProcess> g_tracked;
extern CRITICAL_SECTION g_track_cs;

/// 在追踪列表中查找指定线程
TrackedProcess* FindByThread(HANDLE hThread);

/// 清理追踪记录
void ClearTracked(TrackedProcess* tp);

// ============================================================================
// Hook 引擎（编排器）
// ============================================================================

/// 初始化 Hook 引擎（在 DllMain DLL_PROCESS_ATTACH 调用）
bool InitHookEngine();

/// 缓存 DLL 路径（从环境变量读取 x64/x86 路径）
void CacheDllPaths();

/// 安装所有沙箱 Hook
void InstallAllHooks();

/// 卸载所有 Hook（在 DllMain DLL_PROCESS_DETACH 调用）
void UninstallAllHooks();

/// 信号初始化完成（通知父进程 DLL 已就绪）
void SignalInitComplete();

// ============================================================================
// 自注入引擎（hook_process.cpp）
// ============================================================================

/// 直接将沙箱 DLL 注入目标进程（同进程直投，无 IPC）
bool SelfInject(DWORD pid, HANDLE hProcess, HANDLE hThread);

/// 获取 32 位 kernel32!LoadLibraryW 地址（用于 WOW64 注入）
uint32_t GetWow64LoadLibraryW();

/// 检测当前进程是否加载了 .NET CLR
bool IsClrLoaded();

/// 获取当前 DLL 路径
std::wstring GetCurrentDllPath();

/// 获取指定架构的 DLL 路径
std::wstring GetDllPathForArch(bool isWow64);

/// DLL 路径缓存（在 hook_process.cpp 中定义）
extern std::wstring g_dllPathX64;
extern std::wstring g_dllPathX86;
extern std::wstring g_dllPathSelf;

// ============================================================================
// 路径解析（path_resolver.cpp）
// ============================================================================

/// 从 HANDLE 获取文件路径（旧方案，GetFinalPathNameByHandleW，带 TLS 守卫）
/// 失败返回 false
bool GetPathFromHandle(HANDLE hFile, wchar_t* out, size_t outSize);

/// 从 HANDLE 获取文件路径（新方案，NtQueryObject，无递归风险，<1μs）
/// 失败返回 false
bool GetPathFromHandleNt(HANDLE hFile, wchar_t* out, size_t outSize);

// ============================================================================
// 各 Hook 的安装函数（在各自文件中定义）
// ============================================================================

void InstallNtCreateFileHook();
void InstallNtOpenFileHook();
void InstallNtDeleteFileHook();
void InstallNtSetInformationFileHook();
void InstallNtWriteFileHook();
void InstallNtCreateUserProcessHook();
void InstallNtResumeThreadHook();
void InstallNetHooks();         // 在 net_acl.cpp 中定义

// ============================================================================
// 崩溃处理（hook_crash.cpp）
// ============================================================================

/// 注册 VEH 向量化异常处理器（在 InitHookEngine 中调用）
void InstallVehHandler();
