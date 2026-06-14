// ipc_client.cpp — IPC 客户端（DLL → Host 审计日志上报）
//
// 异步、非阻塞。当 IPC 不可用时回退到文件日志。

#include "ipc_client.h"
#include <windows.h>
#include <cstdio>
#include <string>
#include <ctime>
#include <chrono>

// ============================================================================
// 文件审计日志（回退方案）
// ============================================================================

static HANDLE g_auditFile = INVALID_HANDLE_VALUE;
static bool g_auditFileInit = false;

void AuditLogFileInit() {
    if (g_auditFileInit) return;

    // 从环境变量获取日志目录
    wchar_t logDir[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"SBOX_AUDIT_DIR", logDir, MAX_PATH) == 0) {
        // 默认使用 TEMP
        GetEnvironmentVariableW(L"TEMP", logDir, MAX_PATH);
    }

    // 创建日志目录
    CreateDirectoryW(logDir, nullptr);

    // 生成日志文件名
    DWORD pid = GetCurrentProcessId();
    wchar_t logPath[MAX_PATH];
    swprintf_s(logPath, L"%s\\sandbox_audit_%lu.log", logDir, pid);

    g_auditFile = CreateFileW(logPath, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_auditFileInit = true;

    if (g_auditFile != INVALID_HANDLE_VALUE) {
        // 写入 BOM
        DWORD written;
        char bom[] = "\xEF\xBB\xBF";
        SetFilePointer(g_auditFile, 0, nullptr, FILE_BEGIN);
        DWORD fileSize = GetFileSize(g_auditFile, nullptr);
        if (fileSize == 0) {
            WriteFile(g_auditFile, bom, 3, &written, nullptr);
        }
        SetFilePointer(g_auditFile, 0, nullptr, FILE_END);
    }
}

void AuditLogFileAction(const std::wstring& action, const std::wstring& path,
                        const std::wstring& detail, uint32_t accessMask) {
    if (g_auditFile == INVALID_HANDLE_VALUE) {
        AuditLogFileInit();
    }
    if (g_auditFile == INVALID_HANDLE_VALUE) return;

    // 时间戳
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    char buf[2048];
    int len = snprintf(buf, sizeof(buf),
        "[%04d-%02d-%02d %02d:%02d:%02d.%03lld] [%ls] %ls | %ls | access=0x%08X\n",
        tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
        tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec,
        ms.count(),
        action.c_str(), path.c_str(), detail.c_str(), accessMask);

    if (len > 0) {
        DWORD written;
        WriteFile(g_auditFile, buf, len, &written, nullptr);
    }
}

// ============================================================================
// IPC 审计（TODO: 实现 ring buffer 共享内存方案）
// ============================================================================

bool InitIpcClient() {
    // TODO: 连接到 Rust Host 的审计 ring buffer
    // 当前回退到文件日志
    return true;
}

void AuditLog(AuditEventType type, const std::wstring& target,
              const std::wstring& detail, uint32_t accessMask, int32_t ntStatus) {
    const wchar_t* typeStr = L"UNKNOWN";
    switch (type) {
    case AuditEventType::FileAllow:     typeStr = L"FILE_ALLOW"; break;
    case AuditEventType::FileDeny:      typeStr = L"FILE_DENY"; break;
    case AuditEventType::FileDowngrade: typeStr = L"FILE_DOWNGRADE"; break;
    case AuditEventType::NetAllow:      typeStr = L"NET_ALLOW"; break;
    case AuditEventType::NetDeny:       typeStr = L"NET_DENY"; break;
    case AuditEventType::ProcessCreate: typeStr = L"PROCESS_CREATE"; break;
    case AuditEventType::InjectComplete:typeStr = L"INJECT_DONE"; break;
    case AuditEventType::Error:         typeStr = L"ERROR"; break;
    }

    AuditLogFileAction(typeStr, target, detail, accessMask);
}

void ShutdownIpcClient() {
    if (g_auditFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_auditFile);
        g_auditFile = INVALID_HANDLE_VALUE;
    }
}
