// dllmain.cpp — DLL 入口点

#include <windows.h>
#include "hook_engine.h"
#include "file_acl.h"
#include "net_acl.h"
#include "ipc_client.h"
#include "shared_config.h"

static void InitializeSandbox() {
    if (!InitHookEngine()) {
        OutputDebugStringA("[sandbox_hook] InitHookEngine failed\n");
        return;
    }

    CacheDllPaths();

    std::string configJson = LoadConfigFromSharedMemory();
    if (!configJson.empty()) {
        InitFileAcl(configJson);
        InitNetAcl(configJson);
    } else {
        OutputDebugStringA("[sandbox_hook] No config from shared memory, using defaults\n");
    }

    InitIpcClient();
    AuditLogFileInit();

    InstallAllHooks();

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
