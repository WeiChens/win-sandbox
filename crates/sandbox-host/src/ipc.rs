//! IPC 服务模块 — 宿主端共享内存管理
//!
//! 两个共享内存区域：
//!   1. 配置 SHM:  Host → DLL (ACL规则)
//!   2. 审计 Ring Buffer: DLL → Host (审计事件)

use sandbox_core::SandboxConfig;
use sandbox_core::ipc::{
    SharedMemLayout, AuditEvent, AuditEventC, AuditRingHeader,
    AuditEventType, SHM_MAGIC, SHM_VERSION, SHM_MAX_SIZE,
    AUDIT_RING_SLOTS, AUDIT_RING_MAGIC, AUDIT_RING_VERSION,
    AUDIT_EVENT_MAX_PATH,
};
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

/// 计算 Ring Buffer 共享内存总大小
fn audit_shm_size() -> usize {
    std::mem::size_of::<AuditRingHeader>() + AUDIT_RING_SLOTS * std::mem::size_of::<AuditEventC>()
}

pub struct IpcServer {
    /// Host PID
    #[allow(dead_code)]
    host_pid: u32,
    /// 配置共享内存名称
    shm_name: String,
    shm_handle: HANDLE,
    shm_view: *mut u8,

    /// 审计 Ring Buffer
    audit_shm_name: String,
    audit_shm_handle: HANDLE,
    audit_shm_view: *mut u8,
    audit_header: *mut AuditRingHeader,
    audit_slots: *mut AuditEventC,

    /// 上次读取位置
    audit_read_pos: Mutex<u32>,

    /// 收集的审计事件
    audit_buffer: Mutex<Vec<AuditEvent>>,
}

/// 创建共享内存，Global\ 失败时自动回退到 Local\（无需管理员权限）
fn create_shm_global_fallback(name: &str, size: DWORD) -> Result<(HANDLE, *mut u8, String), String> {
    // 先尝试 Global\（跨会话，需要管理员）
    let global_name = format!("Global\\{}", name);
    let mut last_err = 0u32;

    let attempts: [(&str, &str); 2] = [("Global", &global_name), ("Local", name)];
    for (attempt, prefix_name) in &attempts {
        let name_wide: Vec<u16> = OsStr::new(prefix_name)
            .encode_wide().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            CreateFileMappingW(invalid_handle(), std::ptr::null(),
                PAGE_READWRITE, 0, size, name_wide.as_ptr())
        };

        if !handle.is_null() && handle != invalid_handle() {
            let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size as usize) };
            if !view.is_null() {
                let ptr = view as *mut u8;
                log::info!("共享内存已创建 ({}) : {}", attempt, prefix_name);
                return Ok((handle, ptr, prefix_name.to_string()));
            }
            unsafe { CloseHandle(handle); }
            return Err(format!("MapViewOfFile 失败: {}", unsafe { GetLastError() }));
        }

        last_err = unsafe { GetLastError() };
        if *attempt == "Global" && last_err == 5 {
            // ACCESS_DENIED → 回退到 Local\
            log::warn!("Global\\ 需要管理员权限，回退到 Local\\ 命名空间");
            continue;
        }
        return Err(format!("CreateFileMappingW({}) 失败: {}", attempt, last_err));
    }

    Err(format!("CreateFileMappingW 失败: {}", last_err))
}

impl IpcServer {
    pub fn new(host_pid: u32, config: &SandboxConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // ================================================================
        // 1. 配置共享内存
        // ================================================================
        let cfg_base_name = format!("SBoxCfg_{}", host_pid);
        let (shm_handle, shm_view, shm_name) = create_shm_global_fallback(
            &cfg_base_name, SHM_MAX_SIZE as DWORD,
        )?;

        // 写入配置 JSON
        let config_json = serde_json::to_vec(config)?;
        unsafe {
            let hdr = shm_view as *mut SharedMemLayout;
            std::ptr::write(hdr, SharedMemLayout {
                magic: SHM_MAGIC, version: SHM_VERSION,
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
        log::info!("配置共享内存已写入: {} 字节", config_json.len());

        // ================================================================
        // 2. 审计 Ring Buffer 共享内存
        // ================================================================
        let audit_base_name = format!("SBoxAudit_{}", host_pid);
        let total_size = audit_shm_size();

        let (audit_shm_handle, audit_shm_view, audit_shm_name) = create_shm_global_fallback(
            &audit_base_name, total_size as DWORD,
        ).map_err(|e| {
            unsafe { UnmapViewOfFile(shm_view as *const _); CloseHandle(shm_handle); }
            e
        })?;

        // 初始化 Ring Buffer 头部
        let audit_header = audit_shm_view as *mut AuditRingHeader;
        let audit_slots = unsafe {
            (audit_shm_view as *mut u8).add(std::mem::size_of::<AuditRingHeader>()) as *mut AuditEventC
        };

        unsafe {
            std::ptr::write(audit_header, AuditRingHeader {
                magic: AUDIT_RING_MAGIC,
                version: AUDIT_RING_VERSION,
                write_cursor: 0,
                read_cursor: 0,
                slot_count: AUDIT_RING_SLOTS as u32,
                slot_size: std::mem::size_of::<AuditEventC>() as u32,
                overflow_count: 0,
                _reserved: [0u8; 36],
            });
        }
        log::info!("审计 Ring Buffer 已初始化: {} 槽位 × {} bytes = {} KB",
            AUDIT_RING_SLOTS, std::mem::size_of::<AuditEventC>(), total_size / 1024);

        Ok(Self {
            host_pid,
            shm_name,
            shm_handle,
            shm_view: shm_view as *mut u8,
            audit_shm_name,
            audit_shm_handle,
            audit_shm_view: audit_shm_view as *mut u8,
            audit_header,
            audit_slots,
            audit_read_pos: Mutex::new(0),
            audit_buffer: Mutex::new(Vec::new()),
        })
    }

    pub fn shm_name(&self) -> &str { &self.shm_name }
    pub fn audit_shm_name(&self) -> &str { &self.audit_shm_name }
    #[allow(dead_code)]
    pub fn host_pid(&self) -> u32 { self.host_pid }

    /// 从 Ring Buffer 消费审计事件（多线程安全）
    ///
    /// ★ 多线程安全设计：
    ///   C++ 写入端使用 _padding 字段作为 valid 标志：
    ///     1. ZeroMemory → _padding = 0（无效）
    ///     2. 写入所有数据字段
    ///     3. MemoryBarrier() + _padding = 1（标记有效）
    ///   本读取端先检查 _padding：
    ///     - _padding != 1 → 槽位正在被写入，跳过（等下一轮 poll）
    ///     - _padding == 1 → 所有字段已完整写入，可安全读取
    pub fn poll_audit(&self) -> Vec<AuditEvent> {
        let header = unsafe { &*self.audit_header };
        let mut read_pos = self.audit_read_pos.lock().unwrap();

        let write_pos = header.write_cursor;
        let mut events = Vec::new();

        while *read_pos < write_pos {
            let slot_idx = (*read_pos % header.slot_count) as usize;
            let slot_ptr = unsafe { self.audit_slots.add(slot_idx) };

            // ★ 多线程安全：先读取 _padding 有效标志
            //   _padding == 0: 槽位正在被写入，跳过（等待下一轮 poll）
            //   _padding == 1: 槽位已完整写入，可以安全读取
            let valid: u32 = unsafe {
                std::ptr::read_unaligned(&(*slot_ptr)._padding)
            };
            if valid != 1 {
                // 槽位尚未完成写入，跳过
                *read_pos += 1;
                continue;
            }

            // ★ 槽位已验证为完整写入，安全读取所有字段
            let slot: AuditEventC = unsafe {
                std::ptr::read_unaligned(slot_ptr)
            };

            // 转换二进制事件 → Rust AuditEvent
            let target_end = slot.target.iter().position(|&c| c == 0).unwrap_or(AUDIT_EVENT_MAX_PATH);
            let detail_end = slot.detail.iter().position(|&c| c == 0).unwrap_or(128);
            let target = String::from_utf16_lossy(&slot.target[..target_end]);
            let detail = String::from_utf16_lossy(&slot.detail[..detail_end]);

            let event_type = match slot.event_type {
                0 => AuditEventType::FileAllow,
                1 => AuditEventType::FileDeny,
                2 => AuditEventType::FileDowngrade,
                3 => AuditEventType::NetAllow,
                4 => AuditEventType::NetDeny,
                5 => AuditEventType::ProcessCreate,
                6 => AuditEventType::InjectComplete,
                _ => AuditEventType::Error,
            };

            events.push(AuditEvent {
                event_type,
                pid: slot.pid,
                timestamp_ms: slot.timestamp_ms,
                target,
                detail,
                access_mask: slot.access_mask,
                nt_status: slot.nt_status,
            });

            *read_pos += 1;
        }

        // 更新 read_cursor（通知 DLL 可以复用槽位）
        if *read_pos > header.read_cursor {
            unsafe {
                (*self.audit_header).read_cursor = *read_pos;
            }
        }

        events
    }

    #[allow(dead_code)]
    pub fn record_audit(&self, event: AuditEvent) {
        if let Ok(mut buf) = self.audit_buffer.lock() {
            buf.push(event);
        }
    }

    /// 刷出所有审计事件
    pub fn flush_audit(&self) {
        let events = self.poll_audit();
        if let Ok(mut buf) = self.audit_buffer.lock() {
            buf.extend(events);
        }
        if let Ok(buf) = self.audit_buffer.lock() {
            log::info!("审计: {} 条事件", buf.len());
        }
    }

    pub fn summary(&self) -> String {
        self.flush_audit();
        let buf = self.audit_buffer.lock().unwrap_or_else(|e| e.into_inner());
        let denied = buf.iter().filter(|e| matches!(e.event_type,
            AuditEventType::FileDeny | AuditEventType::NetDeny
        )).count();

        let mut lines = vec![
            format!("=== 沙箱审计摘要 ==="),
            format!("总计: {}  允许: {}  拒绝: {}  溢出: {}",
                buf.len(), buf.len() - denied, denied,
                unsafe { (*self.audit_header).overflow_count }),
        ];

        // 最近 20 条
        for evt in buf.iter().rev().take(20) {
            lines.push(format!(
                "  [{:?}] PID={} {} | {}",
                evt.event_type, evt.pid, evt.target, evt.detail
            ));
        }
        lines.join("\n")
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        unsafe {
            if !self.shm_view.is_null() { UnmapViewOfFile(self.shm_view as *const _); }
            if !self.shm_handle.is_null() && self.shm_handle != invalid_handle() { CloseHandle(self.shm_handle); }
            if !self.audit_shm_view.is_null() { UnmapViewOfFile(self.audit_shm_view as *const _); }
            if !self.audit_shm_handle.is_null() && self.audit_shm_handle != invalid_handle() { CloseHandle(self.audit_shm_handle); }
        }
    }
}

unsafe impl Send for IpcServer {}
unsafe impl Sync for IpcServer {}
