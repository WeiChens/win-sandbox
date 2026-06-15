// inject_helper.exe — WOW64 DLL 注入辅助程序（32-bit）
//
// 问题场景：
//   64-bit 进程调用 GetProcAddress(kernel32, "LoadLibraryW") 返回 64 位地址，
//   该地址在 32-bit WOW64 进程中无效 → CreateRemoteThread 崩溃。
//
// 解决方案：
//   本程序是 32-bit 可执行文件，运行在 WOW64 环境中。
//   它获取的 LoadLibraryW 地址是 32 位的，与目标进程地址空间兼容。
//   由 sandbox-host.exe (64-bit) 在直接注入失败后调用。
//
// 用法:
//   inject_helper.exe <target_pid> <dll_path>
//
// 返回值:
//   0 = 注入成功 (DLL 已加载到目标进程)
//   1 = 注入失败

#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <string>

// ============================================================================
// 主函数
// ============================================================================
int wmain(int argc, wchar_t* argv[]) {
    // ── 参数检查 ──────────────────────────────────────────────────────
    if (argc < 3) {
        wprintf(L"[inject_helper] 用法: %s <target_pid> <dll_path>\n", argv[0]);
        return 1;
    }

    DWORD targetPid = static_cast<DWORD>(_wtoi(argv[1]));
    const wchar_t* dllPath = argv[2];

    wprintf(L"[inject_helper] Target PID=%lu, DLL=%ls\n", targetPid, dllPath);

    // ── 检查 DLL 文件是否存在 ─────────────────────────────────────────
    DWORD attr = GetFileAttributesW(dllPath);
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        wprintf(L"[inject_helper] DLL 文件不存在或无法访问: %ls\n", dllPath);
        return 1;
    }

    // ── 打开目标进程 ──────────────────────────────────────────────────
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
        FALSE, targetPid
    );
    if (!hProcess) {
        wprintf(L"[inject_helper] OpenProcess(%lu) 失败: error=%lu\n",
                targetPid, GetLastError());
        return 1;
    }

    wprintf(L"[inject_helper] 目标进程已打开\n");

    // ── 分配远程内存 ──────────────────────────────────────────────────
    size_t pathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remoteMem = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        wprintf(L"[inject_helper] VirtualAllocEx 失败: error=%lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[inject_helper] 远程内存已分配: %p (size=%zu)\n", remoteMem, pathBytes);

    // ── 写入 DLL 路径 ─────────────────────────────────────────────────
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathBytes, &written)) {
        wprintf(L"[inject_helper] WriteProcessMemory 失败: error=%lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // ── 获取 LoadLibraryW 地址（★ 32-bit！正确的地址！） ────────────
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) {
        wprintf(L"[inject_helper] GetModuleHandle(kernel32) 失败\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryW =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(hK32, "LoadLibraryW"));
    if (!pLoadLibraryW) {
        wprintf(L"[inject_helper] GetProcAddress(LoadLibraryW) 失败\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[inject_helper] LoadLibraryW (32-bit) = %p\n", pLoadLibraryW);

    // ── 创建远程线程 ──────────────────────────────────────────────────
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        pLoadLibraryW, remoteMem, 0, nullptr);

    if (!hThread) {
        wprintf(L"[inject_helper] CreateRemoteThread 失败: error=%lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    wprintf(L"[inject_helper] 远程线程已创建，等待完成...\n");

    // ── 等待 LoadLibraryW 完成 ───────────────────────────────────────
    DWORD waitRet = WaitForSingleObject(hThread, 15000);

    if (waitRet == WAIT_TIMEOUT) {
        wprintf(L"[inject_helper] 等待超时 (15s)\n");
        TerminateThread(hThread, 1);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // ── 检查线程退出码 ────────────────────────────────────────────────
    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        exitCode = 0;
    }

    CloseHandle(hThread);

    // LoadLibraryW 返回模块基址（非零表示成功）
    bool success = (exitCode != 0);

    wprintf(L"[inject_helper] LoadLibraryW 退出码: 0x%08lX (%s)\n",
            exitCode, success ? "成功" : "失败");

    // ── 清理 ──────────────────────────────────────────────────────────
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return success ? 0 : 1;
}
