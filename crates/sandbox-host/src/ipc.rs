//! IPC 服务模块 — 宿主端共享内存管理
//!
//! Host → 共享内存(配置) → C++ DLL

use sandbox_core::SandboxConfig;
use sandbox_core::ipc::{SharedMemLayout, AuditEvent, SHM_MAGIC, SHM_VERSION, SHM_MAX_SIZE};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;

use std::ffi::c_void;
type HANDLE = *mut c_void;
type DWORD = u32;
type BOOL = i32;

const PAGE_READWRITE: DWORD = 0x04;
const FILE_MAP_ALL_ACCESS: DWORD = 0xF001F;

extern "system" {
    fn CreateFileMappingW(hFile: HANDLE, lpAttr: *const c_void, flProtect: DWORD,
                          dwMaxHigh: DWORD, dwMaxLow: DWORD, lpName: *const u16) -> HANDLE;
    fn MapViewOfFile(hMap: HANDLE, dwAccess: DWORD, dwOffHi: DWORD,
                     dwOffLo: DWORD, dwBytes: usize) -> *mut c_void;
    fn UnmapViewOfFile(lpBase: *const c_void) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetLastError() -> DWORD;
}

fn invalid_handle() -> HANDLE { !0isize as HANDLE }

pub struct IpcServer {
    shm_name: String,
    shm_handle: HANDLE,
    shm_view: *mut u8,
    audit_buffer: Mutex<Vec<AuditEvent>>,
}

impl IpcServer {
    pub fn new(host_pid: u32, config: &SandboxConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let shm_name = format!("Global\\SBoxCfg_{}", host_pid);
        log::info!("创建共享内存: {}", shm_name);

        let name_wide: Vec<u16> = OsStr::new(&shm_name)
            .encode_wide().chain(std::iter::once(0)).collect();

        let shm_handle = unsafe {
            CreateFileMappingW(
                invalid_handle(), std::ptr::null(),
                PAGE_READWRITE, 0, SHM_MAX_SIZE as DWORD,
                name_wide.as_ptr(),
            )
        };

        if shm_handle.is_null() || shm_handle == invalid_handle() {
            return Err(format!("CreateFileMappingW 失败: {}", unsafe { GetLastError() }).into());
        }

        let shm_view = unsafe {
            MapViewOfFile(shm_handle, FILE_MAP_ALL_ACCESS, 0, 0, SHM_MAX_SIZE)
        };

        if shm_view.is_null() {
            unsafe { CloseHandle(shm_handle); }
            return Err(format!("MapViewOfFile 失败: {}", unsafe { GetLastError() }).into());
        }

        // 写入配置
        let config_json = serde_json::to_vec(config)?;

        unsafe {
            let hdr = shm_view as *mut SharedMemLayout;
            std::ptr::write(hdr, SharedMemLayout {
                magic: SHM_MAGIC,
                version: SHM_VERSION,
                file_rule_count: config.file_permissions.len() as u32,
                net_rule_count: config.network_permissions.len() as u32,
                audit_event_name: [0u16; 64],
                data_size: config_json.len() as u32,
                _reserved: [0u8; 64],
            });

            let hdr_size = std::mem::size_of::<SharedMemLayout>();
            std::ptr::copy_nonoverlapping(
                config_json.as_ptr(),
                (shm_view as *mut u8).add(hdr_size),
                config_json.len(),
            );
        }

        log::info!("共享内存已写入: {} 字节", config_json.len());

        Ok(Self {
            shm_name,
            shm_handle,
            shm_view: shm_view as *mut u8,
            audit_buffer: Mutex::new(Vec::new()),
        })
    }

    pub fn shm_name(&self) -> &str { &self.shm_name }

    pub fn record_audit(&self, event: AuditEvent) {
        if let Ok(mut buf) = self.audit_buffer.lock() {
            buf.push(event);
        }
    }

    pub fn flush_audit(&self) {
        if let Ok(buf) = self.audit_buffer.lock() {
            log::debug!("审计: {} 条事件", buf.len());
        }
    }

    pub fn summary(&self) -> String {
        let buf = self.audit_buffer.lock().unwrap_or_else(|e| e.into_inner());
        let denied = buf.iter().filter(|e| matches!(e.event_type,
            sandbox_core::ipc::AuditEventType::FileDeny |
            sandbox_core::ipc::AuditEventType::NetDeny
        )).count();
        format!("=== 审计摘要 ===\n总计: {}\n允许: {}\n拒绝: {}\n",
            buf.len(), buf.len() - denied, denied)
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        unsafe {
            if !self.shm_view.is_null() {
                UnmapViewOfFile(self.shm_view as *const _);
            }
            if !self.shm_handle.is_null() && self.shm_handle != invalid_handle() {
                CloseHandle(self.shm_handle);
            }
        }
    }
}

unsafe impl Send for IpcServer {}
unsafe impl Sync for IpcServer {}
