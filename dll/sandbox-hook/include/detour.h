// detour.h — x64/x86 内联 Hook 引擎接口
//
// 从 Failure-01 的 detour.c 移植，C++ 化。
// 核心算法保持不变：指令长度解码、RIP-relative 重定位、安全 patch。

#pragma once
#include <windows.h>
#include <cstdint>

#define HOOK_MIN_SIZE   5       // x86 jmp rel32 最小 5 字节
#define HOOK_PATCH_SIZE 32      // 最大 patch 大小
#define JMP_SIZE        14      // x64: FF 25 + disp32 + addr (14 bytes)

/// Hook 上下文 — 跟踪已安装的 hook
struct DetourContext {
    BYTE*   target = nullptr;           // 目标函数地址
    BYTE*   detour_fn = nullptr;        // 我们的 hook 函数
    BYTE*   trampoline = nullptr;       // 跳板（执行原始指令后跳回）
    BYTE    original_bytes[HOOK_PATCH_SIZE] = {}; // 原始字节
    int     patch_size = 0;             // 实际 patch 大小
    bool    installed = false;
    char    name[64] = {};              // Hook 名称（调试用）
};

// ============================================================================
// API
// ============================================================================

/// 安装内联 Hook
/// @param target     目标函数地址（ntdll!NtXxx）
/// @param detour_fn  替代函数地址
/// @param name       调试名称
/// @return 跳板地址（调用原始函数用），失败返回 nullptr
void* DetourInstall(BYTE* target, BYTE* detour_fn, const char* name);

/// 卸载单个 hook
bool DetourUninstall(DetourContext* ctx);

/// 卸载所有已安装的 hook（在 DLL_PROCESS_DETACH 调用）
void DetourUninstallAll();

/// 获取指令长度（x64 + x86）
int GetInstructionLen(BYTE* src);

/// 根据模块和函数名查找函数地址
BYTE* FindFunction(const char* module, const char* name);
