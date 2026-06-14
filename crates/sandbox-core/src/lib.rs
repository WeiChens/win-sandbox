//! # sandbox-core — Windows 沙箱共享类型库
//!
//! 本 crate 提供：
//! - 沙箱配置模型 (SandboxConfig)
//! - 文件/网络 ACL 规则
//! - IPC 协议定义
//! - Windows FFI 常量

pub mod acl;
pub mod config;
pub mod ffi;
pub mod ipc;

pub use acl::{FilePermission, FileRule, NetRule, NetAction, NetProtocol};
pub use config::SandboxConfig;
pub use ipc::{IpcHeader, AuditEvent, AuditEventType, SharedMemLayout, SHM_MAGIC, SHM_VERSION, SHM_MAX_SIZE};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
