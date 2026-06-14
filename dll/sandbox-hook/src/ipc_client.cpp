// ipc_client.cpp — IPC 客户端（DLL → Host 审计 Ring Buffer）
//
// 无锁 Ring Buffer 写入（单生产者）。
// 当 Ring Buffer 不可用时回退到文件日志。

#include "ipc_client.h"
#include <windows.h>
#include <cstdio>
#include <string>
#include <chrono>
#include <atomic>

// ★ 编译期布局验证：确保 C++ 和 Rust 结构体一致
static_assert(sizeof(AuditEventC) == 800, "AuditEventC size mismatch with Rust");
static_assert(sizeof(AuditRingHeader) == 64, "AuditRingHeader size mismatch with Rust");
static_assert(offsetof(AuditEventC, target) == 12, "AuditEventC::target offset mismatch");
static_assert(offsetof(AuditRingHeader, slot_count) == 16, "AuditRingHeader::slot_count offset mismatch");

// ============================================================================
// Ring Buffer 全局状态
// ============================================================================

static HANDLE g_auditShm = nullptr;        // Ring Buffer 共享内存句柄
static AuditRingHeader* g_ringHeader = nullptr;  // 映射视图头部
static AuditEventC* g_ringSlots = nullptr;       // 槽位数组起始
static bool g_ringAvailable = false;

// 回退文件日志
static HANDLE g_auditFile = INVALID_HANDLE_VALUE;
static bool g_auditFileInit = false;

// DLL 加载时刻（用于计算相对时间戳）
static uint32_t g_dllLoadTimeMs = 0;

// ============================================================================
// 初始化
// ============================================================================

bool InitIpcClient() {
    // 记录 DLL 加载时间
    g_dllLoadTimeMs = GetTickCount();

    // 1. 尝试打开 Ring Buffer 共享内存
    wchar_t shmName[128] = {0};
    DWORD len = GetEnvironmentVariableW(L"SBOX_AUDIT_SHM", shmName, 128);
    if (len > 0 && len < 128) {
        g_auditShm = OpenFileMappingW(FILE_MAP_WRITE, FALSE, shmName);
        if (g_auditShm) {
            void* view = MapViewOfFile(g_auditShm, FILE_MAP_WRITE, 0, 0, 0);
            if (view) {
                g_ringHeader = reinterpret_cast<AuditRingHeader*>(view);
                // 验证魔数
                if (g_ringHeader->magic == AUDIT_RING_MAGIC &&
                    g_ringHeader->slot_count > 0) {
                    g_ringSlots = reinterpret_cast<AuditEventC*>(
                        reinterpret_cast<uint8_t*>(view) + sizeof(AuditRingHeader));
                    g_ringAvailable = true;

                    char buf[128];
                    snprintf(buf, sizeof(buf),
                        "[sandbox_hook] Audit ring buffer ready: %u slots\n",
                        g_ringHeader->slot_count);
                    OutputDebugStringA(buf);
                    return true;
                }
                // 魔数不对，回退
                UnmapViewOfFile(view);
                g_ringHeader = nullptr;
            }
            CloseHandle(g_auditShm);
            g_auditShm = nullptr;
        }
    }

    OutputDebugStringA("[sandbox_hook] Audit ring buffer not available, using file fallback\n");
    return false;
}

// ============================================================================
// Ring Buffer 写入
// ============================================================================

void AuditLog(AuditEventType type, const std::wstring& target,
              const std::wstring& detail, uint32_t accessMask, int32_t ntStatus) {
    // 尝试 Ring Buffer
    if (g_ringAvailable && g_ringHeader && g_ringSlots) {
        uint32_t slotCount = g_ringHeader->slot_count;
        if (slotCount == 0 || slotCount > AUDIT_RING_SLOTS) goto fallback;

        // 原子的读取 write_cursor 并递增（单生产者，InterlockedIncrement 即可）
        uint32_t writePos = InterlockedIncrement(&g_ringHeader->write_cursor) - 1;
        uint32_t readPos = g_ringHeader->read_cursor;

        // 检查是否追上读者（buffer full）
        if (writePos - readPos >= slotCount) {
            // 溢出：更新溢出计数，丢弃本次事件
            InterlockedIncrement(&g_ringHeader->overflow_count);
            // 回退 write_cursor（尽力而为）
            InterlockedCompareExchange(&g_ringHeader->write_cursor, readPos + slotCount, writePos + 1);
            return;
        }

        // 写入槽位
        uint32_t slotIdx = writePos % slotCount;
        AuditEventC* slot = &g_ringSlots[slotIdx];

        ZeroMemory(slot, sizeof(AuditEventC));
        slot->event_type = static_cast<uint32_t>(type);
        slot->pid = GetCurrentProcessId();
        slot->timestamp_ms = GetTickCount() - g_dllLoadTimeMs;
        wcsncpy_s(slot->target, AUDIT_EVENT_MAX_PATH, target.c_str(), _TRUNCATE);
        wcsncpy_s(slot->detail, 128, detail.c_str(), _TRUNCATE);
        slot->access_mask = accessMask;
        slot->nt_status = ntStatus;

        return;
    }

fallback:
    // 回退到文件日志
    AuditLogFileAction(
        type == AuditEventType::FileAllow     ? L"FILE_ALLOW" :
        type == AuditEventType::FileDeny      ? L"FILE_DENY" :
        type == AuditEventType::FileDowngrade ? L"FILE_DOWNGRADE" :
        type == AuditEventType::NetAllow      ? L"NET_ALLOW" :
        type == AuditEventType::NetDeny       ? L"NET_DENY" :
        type == AuditEventType::ProcessCreate ? L"PROCESS_CREATE" :
        type == AuditEventType::InjectComplete? L"INJECT_DONE" :
        L"ERROR",
        target, detail, accessMask);
}

// ============================================================================
// 文件日志回退
// ============================================================================

void AuditLogFileInit() {
    if (g_auditFileInit) return;

    wchar_t logDir[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"SBOX_AUDIT_DIR", logDir, MAX_PATH) == 0) {
        GetEnvironmentVariableW(L"TEMP", logDir, MAX_PATH);
    }

    CreateDirectoryW(logDir, nullptr);

    DWORD pid = GetCurrentProcessId();
    wchar_t logPath[MAX_PATH];
    swprintf_s(logPath, L"%s\\sandbox_audit_%lu.log", logDir, pid);

    g_auditFile = CreateFileW(logPath, FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_auditFileInit = true;

    if (g_auditFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        // BOM
        char bom[] = "\xEF\xBB\xBF";
        DWORD fileSize = GetFileSize(g_auditFile, nullptr);
        if (fileSize == 0) {
            WriteFile(g_auditFile, bom, 3, &written, nullptr);
        }
    }
}

void AuditLogFileAction(const std::wstring& action, const std::wstring& path,
                        const std::wstring& detail, uint32_t accessMask) {
    if (g_auditFile == INVALID_HANDLE_VALUE) {
        AuditLogFileInit();
    }
    if (g_auditFile == INVALID_HANDLE_VALUE) return;

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
// 关闭
// ============================================================================

void ShutdownIpcClient() {
    if (g_ringHeader) {
        UnmapViewOfFile(g_ringHeader);
        g_ringHeader = nullptr;
        g_ringSlots = nullptr;
    }
    if (g_auditShm) {
        CloseHandle(g_auditShm);
        g_auditShm = nullptr;
    }
    if (g_auditFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_auditFile);
        g_auditFile = INVALID_HANDLE_VALUE;
    }
    g_ringAvailable = false;
}
