// dllmain.cpp — DLL 入口点
//
// 不再 CRT-free！使用完整 MSVC CRT。

#include <windows.h>
#include "hook_engine.h"
#include "file_acl.h"
#include "net_acl.h"
#include "ipc_client.h"
#include "shared_config.h"

static void InitializeSandbox() {
    // 1. 初始化 Hook 引擎
    if (!InitHookEngine()) {
        OutputDebugStringA("[sandbox_hook] InitHookEngine failed\n");
        return;
    }

    // 1.5. ★ 缓存 DLL 路径（从环境变量读取 x64/x86 路径）
    CacheDllPaths();

    // 2. 从共享内存加载配置
    std::string configJson = LoadConfigFromSharedMemory();
    if (!configJson.empty()) {
        InitFileAcl(configJson);
        InitNetAcl(configJson);
    } else {
        OutputDebugStringA("[sandbox_hook] No config from shared memory, using defaults\n");
    }

    // 3. 初始化审计日志
    InitIpcClient();
    AuditLogFileInit();

    // 4. 安装所有 Hook
    InstallAllHooks();

    // 5. 通知父进程初始化完成
    SignalInitComplete();

    OutputDebugStringA("[sandbox_hook] Initialization complete\n");
}

static void ShutdownSandbox() {
    OutputDebugStringA("[sandbox_hook] Shutting down...\n");
    UninstallAllHooks();
    ShutdownIpcClient();
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved) {
    (void)lpReserved;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInstance);
        InitializeSandbox();
        break;

    case DLL_PROCESS_DETACH:
        ShutdownSandbox();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}
