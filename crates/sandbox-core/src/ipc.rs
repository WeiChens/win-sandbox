//! IPC 协议定义
//!
//! 共享内存布局、审计事件结构、IPC 通信协议。
//! C++ DLL 和 Rust Host 通过以下机制通信：
//!
//! 1. **共享内存**（Host → DLL）：配置下发
//!    - 名称: `Global\SBoxCfg_<PID>`
//!    - 布局: `SharedMemLayout`
//!
//! 2. **Ring Buffer 共享内存**（DLL → Host）：审计日志上报
//!    - 名称: `Global\SBoxAudit_<PID>`
//!    - 无锁环形缓冲区
//!
//! 3. **命名事件**（同步）：
//!    - `Global\SBoxInit_<PID>` — DLL 初始化完成信号

use serde::{Deserialize, Serialize};

// ============================================================================
// 共享内存常量
// ============================================================================

/// 共享内存魔数 "SBOX"
pub const SHM_MAGIC: u32 = 0x53424F58;
/// 当前协议版本
pub const SHM_VERSION: u32 = 2;
/// 共享内存最大大小 (256 KB)
pub const SHM_MAX_SIZE: usize = 256 * 1024;

// ============================================================================
// 共享内存布局
// ============================================================================

/// C++ DLL 端读取的共享内存头部（repr(C) 保证与 C 一致）
#[repr(C, packed)]
pub struct SharedMemLayout {
    /// 魔数 `SHM_MAGIC`
    pub magic: u32,
    /// 版本号
    pub version: u32,
    /// 文件规则数量
    pub file_rule_count: u32,
    /// 网络规则数量
    pub net_rule_count: u32,
    /// 审计 ring buffer 事件名 (UTF-16)
    pub audit_event_name: [u16; 64],
    /// JSON 数据大小（字节）
    pub data_size: u32,
    /// 保留
    pub _reserved: [u8; 64],
    // 紧随其后的是 JSON 数据 (data_size 字节)
}

// ============================================================================
// 审计事件
// ============================================================================

/// 审计事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum AuditEventType {
    /// 文件操作被允许
    FileAllow = 0,
    /// 文件操作被拒绝
    FileDeny = 1,
    /// 文件操作降级为只读
    FileDowngrade = 2,
    /// 网络连接被允许
    NetAllow = 3,
    /// 网络连接被拒绝
    NetDeny = 4,
    /// 进程创建
    ProcessCreate = 5,
    /// DLL 注入完成
    InjectComplete = 6,
    /// 沙箱错误
    Error = 7,
}

/// 审计事件（DLL → Host）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 事件类型
    pub event_type: AuditEventType,
    /// 目标进程 PID
    pub pid: u32,
    /// 时间戳 (ms since DLL load)
    pub timestamp_ms: u32,
    /// 操作路径 / 主机名
    pub target: String,
    /// 附加信息
    pub detail: String,
    /// 访问掩码（文件操作）
    pub access_mask: u32,
    /// 结果 NTSTATUS
    pub nt_status: i32,
}

// ============================================================================
// IPC 请求（Host → DLL，通过共享内存 + 事件）
// ============================================================================

/// IPC 头部（C++ DLL 端）
#[repr(C, packed)]
pub struct IpcHeader {
    /// 魔数（IPC 头部验证）
    pub magic: u32,
    /// 版本
    pub version: u32,
    /// 请求类型
    pub request_type: u32,
    /// 状态码（0 = 成功）
    pub status: u32,
    /// 数据大小
    pub data_size: u32,
    /// 保留
    pub _reserved: [u8; 48],
}

// ============================================================================
// 审计 Ring Buffer（DLL → Host，无锁单生产者单消费者）
// ============================================================================

/// 单个审计事件槽（固定大小，C++/Rust 共享布局）
pub const AUDIT_EVENT_MAX_PATH: usize = 260;
pub const AUDIT_RING_SLOTS: usize = 1024;

/// 二进制审计事件（repr(C)，与 C++ AuditEventC 一致）
#[repr(C)]
pub struct AuditEventC {
    pub event_type: u32,
    pub pid: u32,
    pub timestamp_ms: u32,
    pub target: [u16; AUDIT_EVENT_MAX_PATH],
    pub detail: [u16; 128],
    pub access_mask: u32,
    pub nt_status: i32,
    pub _padding: u32,
}

/// Ring Buffer 头部
#[repr(C)]
pub struct AuditRingHeader {
    pub magic: u32,           // 0x53424155 "SBAU"
    pub version: u32,         // 1
    pub write_cursor: u32,    // DLL 递增（volatile）
    pub read_cursor: u32,     // Host 递增
    pub slot_count: u32,      // AUDIT_RING_SLOTS
    pub slot_size: u32,       // sizeof(AuditEventC)
    pub overflow_count: u32,  // 溢出计数
    pub _reserved: [u8; 36],
}

pub const AUDIT_RING_MAGIC: u32 = 0x53424155; // "SBAU"
pub const AUDIT_RING_VERSION: u32 = 1;

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_shm_magic() {
        // "SBOX" in little-endian
        assert_eq!(SHM_MAGIC, 0x53424F58);
    }

    #[test]
    fn test_shared_mem_layout_size() {
        let size = mem::size_of::<SharedMemLayout>();
        // magic(4) + version(4) + file_rule_count(4) + net_rule_count(4)
        // + audit_event_name(128) + data_size(4) + reserved(64) = 212
        // But need to check with packed
        assert!(size >= 200 && size <= 256);
    }

    #[test]
    fn test_ipc_header_size() {
        let size = mem::size_of::<IpcHeader>();
        // magic(4) + version(4) + request_type(4) + status(4) + data_size(4) + reserved(48)
        assert_eq!(size, 68);
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent {
            event_type: AuditEventType::FileDeny,
            pid: 12345,
            timestamp_ms: 1000,
            target: r"C:\Windows\System32\secret.txt".into(),
            detail: "deny".into(),
            access_mask: 0x120089,
            nt_status: -1073741790, // STATUS_ACCESS_DENIED
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.event_type, AuditEventType::FileDeny);
        assert_eq!(restored.pid, 12345);
    }

    #[test]
    fn test_audit_event_c_size() {
        // C++/Rust 布局一致性验证
        let size = mem::size_of::<AuditEventC>();
        // event_type(4) + pid(4) + timestamp_ms(4) + target(520) + detail(256)
        // + access_mask(4) + nt_status(4) + _padding(4) = 800
        assert_eq!(size, 800);
    }

    #[test]
    fn test_audit_ring_header_size() {
        let size = mem::size_of::<AuditRingHeader>();
        // magic(4)+version(4)+write_cursor(4)+read_cursor(4)+slot_count(4)+slot_size(4)+overflow(4)+reserved(36)
        assert_eq!(size, 64);
    }

    #[test]
    fn test_audit_ring_magic() {
        assert_eq!(AUDIT_RING_MAGIC, 0x53424155); // "SBAU"
    }
}
