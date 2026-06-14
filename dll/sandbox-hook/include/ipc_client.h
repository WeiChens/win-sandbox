// ipc_client.h — IPC 客户端（DLL → Host 审计 Ring Buffer）
//
// 无锁单生产者单消费者 Ring Buffer。
// C++ DLL 写入，Rust Host 读取。

#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

// ============================================================================
// Ring Buffer 常量
// ============================================================================

#define AUDIT_EVENT_MAX_PATH 260
#define AUDIT_RING_SLOTS      1024
#define AUDIT_RING_MAGIC      0x53424155  // "SBAU"
#define AUDIT_RING_VERSION    1

// ============================================================================
// 审计事件类型
// ============================================================================

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

// ============================================================================
// 二进制审计事件（固定大小，与 Rust AuditEventC 一致）
// 使用自然对齐（与 Rust #[repr(C)] 一致）

struct AuditEventC {
    uint32_t event_type;                       // AuditEventType
    uint32_t pid;
    uint32_t timestamp_ms;
    wchar_t  target[AUDIT_EVENT_MAX_PATH];     // 操作路径/主机名
    wchar_t  detail[128];                      // 附加信息
    uint32_t access_mask;
    int32_t  nt_status;
    uint32_t _padding;
};

struct AuditRingHeader {
    uint32_t magic;           // AUDIT_RING_MAGIC
    uint32_t version;         // AUDIT_RING_VERSION
    uint32_t write_cursor;    // DLL 递增
    uint32_t read_cursor;     // Host 递增
    uint32_t slot_count;      // AUDIT_RING_SLOTS
    uint32_t slot_size;       // sizeof(AuditEventC)
    uint32_t overflow_count;  // 溢出计数
    uint8_t  _reserved[36];
};

// ============================================================================
// API
// ============================================================================

/// 初始化 IPC 客户端（打开 Ring Buffer 共享内存）
bool InitIpcClient();

/// 发送审计事件到 Ring Buffer（异步、非阻塞）
void AuditLog(AuditEventType type, const std::wstring& target,
              const std::wstring& detail, uint32_t accessMask, int32_t ntStatus);

/// 关闭 IPC 客户端
void ShutdownIpcClient();

/// 初始化文件审计日志（当 Ring Buffer 不可用时回退）
void AuditLogFileInit();
void AuditLogFileAction(const std::wstring& action, const std::wstring& path,
                        const std::wstring& detail, uint32_t accessMask);
