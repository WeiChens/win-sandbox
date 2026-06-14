//! Windows FFI 常量与类型声明（sandbox-core 需要的基础类型）
//!
//! 仅在 sandbox-host 需要直接调用 Windows API 时使用。
//! C++ DLL 不使用此模块。

#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub type HMODULE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
pub const INVALID_HANDLE_VALUE: HANDLE = !0isize as HANDLE;

// 进程创建
pub const CREATE_SUSPENDED: DWORD = 0x0000_0004;
pub const INFINITE: DWORD = 0xFFFF_FFFF;

// 进程访问
pub const PROCESS_ALL_ACCESS: DWORD = 0x1F_0FFF;
pub const PROCESS_CREATE_THREAD: DWORD = 0x0002;
pub const PROCESS_VM_OPERATION: DWORD = 0x0008;
pub const PROCESS_VM_WRITE: DWORD = 0x0020;
pub const PROCESS_VM_READ: DWORD = 0x0010;

// 内存
pub const MEM_COMMIT: DWORD = 0x0000_1000;
pub const MEM_RESERVE: DWORD = 0x0000_2000;
pub const MEM_RELEASE: DWORD = 0x0000_8000;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

// 同步
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 0x0000_0102;
pub const WAIT_FAILED: DWORD = 0xFFFF_FFFF;
pub const EVENT_ALL_ACCESS: DWORD = 0x001F_0003;

// 文件映射
pub const FILE_MAP_ALL_ACCESS: DWORD = 0xF001F;
pub const FILE_MAP_READ: DWORD = 0x0004;
pub const FILE_MAP_WRITE: DWORD = 0x0002;

// 错误码
pub const ERROR_FILE_NOT_FOUND: DWORD = 2;
pub const ERROR_ACCESS_DENIED: DWORD = 5;
pub const ERROR_ALREADY_EXISTS: DWORD = 183;

// ToolHelp
pub const TH32CS_SNAPMODULE: DWORD = 0x0000_0008;
pub const TH32CS_SNAPMODULE32: DWORD = 0x0000_0010;
