// ipc_client.h — IPC 客户端（DLL → Host）
//
// 异步、非阻塞的审计日志上报通道。
// 使用无锁 ring buffer + 命名事件通知 Host。

#pragma once
#include <windows.h>
#include <string>

/// 审计事件类型
enum class AuditEventType : uint32_t {
    FileAllow = 0,
    FileDeny = 1,
    FileDowngrade = 2,
    NetAllow = 3,
    NetDeny = 4,
    ProcessCreate = 5,
    InjectComplete = 6,
    Error = 7,
};

/// 初始化 IPC 客户端
bool InitIpcClient();

/// 发送审计事件（异步、非阻塞）
void AuditLog(AuditEventType type, const std::wstring& target,
              const std::wstring& detail, uint32_t accessMask, int32_t ntStatus);

/// 关闭 IPC 客户端
void ShutdownIpcClient();

/// 初始化文件审计日志（当 IPC 不可用时回退到文件）
void AuditLogFileInit();
void AuditLogFileAction(const std::wstring& action, const std::wstring& path,
                        const std::wstring& detail, uint32_t accessMask);
