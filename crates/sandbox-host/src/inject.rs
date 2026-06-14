//! 进程注入模块 — 创建目标进程并注入沙箱 DLL
//!
//! ## 注入策略（关键架构决策）
//!
//! 初始注入（本模块负责）：
//!   Rust Host → CreateProcess(SUSPENDED) → 注入 sandbox_hook.dll → ResumeThread
//!
//! 递归注入（C++ DLL 负责，不再经过 Host）：
//!   子进程中的 sandbox_hook.dll → Hook NtResumeThread → 自注入孙进程
//!
//! 这避免了 Failure-01 的 IPC-to-Host 瓶颈（CLR 崩溃的根因）。

use sandbox_core::SandboxConfig;
use crate::ipc::IpcServer;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

// ============================================================================
// 手动 FFI 声明（避免 windows-sys 类型复杂化）
// ============================================================================

use std::ffi::c_void;
type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;

const FALSE: BOOL = 0;
const TRUE: BOOL = 1;
const CREATE_SUSPENDED: DWORD = 0x0000_0004;
const INFINITE: DWORD = 0xFFFF_FFFF;
const WAIT_OBJECT_0: DWORD = 0;
const PROCESS_ALL_ACCESS: DWORD = 0x1F_0FFF;
const MEM_COMMIT: DWORD = 0x0000_1000;
const MEM_RESERVE: DWORD = 0x0000_2000;
const MEM_RELEASE: DWORD = 0x0000_8000;
const PAGE_READWRITE: DWORD = 0x04;

#[repr(C)]
struct STARTUPINFOW {
    cb: DWORD,
    _pad0: *mut u16, _pad1: *mut u16, _pad2: *mut u16,
    _pad3: DWORD, _pad4: DWORD, _pad5: DWORD, _pad6: DWORD,
    _pad7: DWORD, _pad8: DWORD, _pad9: DWORD,
    wShowWindow: u16, _pad10: u16,
    _pad11: *mut u8,
    hStdInput: HANDLE, hStdOutput: HANDLE, hStdError: HANDLE,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE, hThread: HANDLE,
    dwProcessId: DWORD, dwThreadId: DWORD,
}

extern "system" {
    fn CreateProcessW(
        lpApp: *const u16, lpCmd: *mut u16,
        lpProcAttr: *const c_void, lpThreadAttr: *const c_void,
        bInherit: BOOL, dwFlags: DWORD,
        lpEnv: *const c_void, lpDir: *const u16,
        lpSI: *const STARTUPINFOW, lpPI: *mut PROCESS_INFORMATION,
    ) -> BOOL;

    fn ResumeThread(hThread: HANDLE) -> DWORD;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetLastError() -> DWORD;
    fn WaitForSingleObject(hHandle: HANDLE, dwMs: DWORD) -> DWORD;
    fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *mut DWORD) -> BOOL;

    fn VirtualAllocEx(hProcess: HANDLE, lpAddr: *const c_void, dwSize: usize,
                      flAllocType: DWORD, flProtect: DWORD) -> *mut c_void;
    fn VirtualFreeEx(hProcess: HANDLE, lpAddr: *mut c_void, dwSize: usize,
                     dwFreeType: DWORD) -> BOOL;
    fn WriteProcessMemory(hProcess: HANDLE, lpBase: *const c_void,
                          lpBuf: *const c_void, nSize: usize,
                          lpWritten: *mut usize) -> BOOL;
    fn CreateRemoteThread(hProcess: HANDLE, lpAttr: *const c_void, dwStack: usize,
                          lpStart: *mut c_void, lpParam: *mut c_void,
                          dwFlags: DWORD, lpThreadId: *mut DWORD) -> HANDLE;

    fn GetModuleHandleW(lpName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpName: *const u8) -> *mut c_void;
    fn IsWow64Process(hProcess: HANDLE, Wow64Process: *mut BOOL) -> BOOL;

    fn SetEnvironmentVariableW(lpName: *const u16, lpValue: *const u16) -> BOOL;
}

fn invalid_handle() -> HANDLE { !0isize as HANDLE }

// ============================================================================
// 创建并注入
// ============================================================================

pub fn create_and_inject(
    command: &str,
    args: &[String],
    dll_path_x64: &str,
    dll_path_x86: &str,
    config: &SandboxConfig,
    ipc: &IpcServer,
) -> Result<(HANDLE, u32), Box<dyn std::error::Error>> {
    // 构建命令行
    let cmdline = build_cmdline(command, args);
    let cmdline_wide: Vec<u16> = OsStr::new(&cmdline)
        .encode_wide().chain(std::iter::once(0)).collect();

    // 解析 DLL 路径（绝对路径化）
    let exe_dir = std::env::current_exe()?
        .parent().unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let resolve_dll = |path: &str| -> String {
        let p = std::path::Path::new(path);
        if p.is_absolute() && p.exists() {
            return path.to_string();
        }
        // 尝试相对于 exe 目录
        let abs = exe_dir.join(path);
        if abs.exists() {
            return abs.to_string_lossy().to_string();
        }
        // 返回原始路径（让 DLL 端自行处理）
        path.to_string()
    };

    let dll_x64 = resolve_dll(dll_path_x64);
    let dll_x86 = resolve_dll(dll_path_x86);

    log::info!("DLL x64: {}", dll_x64);
    log::info!("DLL x86: {}", dll_x86);

    // 设置环境变量（传入 DLL 路径给子进程的 sandbox_hook.dll）
    set_hook_env_vars(ipc, config, &dll_x64, &dll_x86);

    // 创建进程（挂起）
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline_wide.as_ptr() as *mut u16,
            std::ptr::null(), std::ptr::null(),
            TRUE,
            CREATE_SUSPENDED,
            std::ptr::null(), std::ptr::null(),
            &si, &mut pi,
        )
    };

    if result == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("CreateProcessW 失败: {}", err).into());
    }

    log::info!("进程已创建 (SUSPENDED): PID={}", pi.dwProcessId);

    // 检测架构
    let is_wow64 = is_process_wow64(pi.hProcess)?;
    let actual_dll: &str = if is_wow64 {
        &dll_x86
    } else {
        &dll_x64
    };

    log::info!("架构: {}, DLL: {}", if is_wow64 { "x86" } else { "x64" }, actual_dll);

    // 注入
    inject_dll(pi.hProcess, actual_dll)?;

    // 恢复
    unsafe { ResumeThread(pi.hThread); CloseHandle(pi.hThread); }

    log::info!("注入完成: PID={}", pi.dwProcessId);

    Ok((pi.hProcess, pi.dwProcessId))
}

fn is_process_wow64(process: HANDLE) -> Result<bool, Box<dyn std::error::Error>> {
    let mut wow64: BOOL = 0;
    let result = unsafe { IsWow64Process(process, &mut wow64) };
    if result == 0 {
        log::warn!("IsWow64Process 失败: {}", unsafe { GetLastError() });
        return Ok(false);
    }
    Ok(wow64 != 0)
}

fn inject_dll(process: HANDLE, dll_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dll_wide: Vec<u16> = OsStr::new(dll_path)
        .encode_wide().chain(std::iter::once(0)).collect();
    let dll_bytes = dll_wide.len() * 2;

    // 1. VirtualAllocEx
    let remote_mem = unsafe {
        VirtualAllocEx(process, std::ptr::null(), dll_bytes,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote_mem.is_null() {
        return Err(format!("VirtualAllocEx 失败: {}", unsafe { GetLastError() }).into());
    }

    // 2. WriteProcessMemory
    let mut written: usize = 0;
    let result = unsafe {
        WriteProcessMemory(process, remote_mem,
                           dll_wide.as_ptr() as *const c_void, dll_bytes,
                           &mut written)
    };
    if result == 0 {
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err(format!("WriteProcessMemory 失败: {}", unsafe { GetLastError() }).into());
    }

    // 3. GetModuleHandleW + GetProcAddress(LoadLibraryW)
    let k32_name: Vec<u16> = OsStr::new("kernel32.dll")
        .encode_wide().chain(std::iter::once(0)).collect();
    let k32 = unsafe { GetModuleHandleW(k32_name.as_ptr()) };
    if k32.is_null() {
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err("GetModuleHandleW(kernel32.dll) 失败".into());
    }

    let loadlib = unsafe { GetProcAddress(k32, b"LoadLibraryW\0".as_ptr()) };
    if loadlib.is_null() {
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err("GetProcAddress(LoadLibraryW) 失败".into());
    }

    // 4. CreateRemoteThread
    let thread = unsafe {
        CreateRemoteThread(process, std::ptr::null(), 0,
                           loadlib, remote_mem, 0, std::ptr::null_mut())
    };
    if thread.is_null() {
        let err = unsafe { GetLastError() };
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err(format!("CreateRemoteThread 失败: {}", err).into());
    }

    // 5. 等待 LoadLibraryW 完成
    let wait_ret = unsafe { WaitForSingleObject(thread, 15000) };
    unsafe { CloseHandle(thread); }

    if wait_ret != WAIT_OBJECT_0 {
        log::warn!("LoadLibraryW 等待超时，继续执行");
    }

    // 6. 清理
    unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }

    Ok(())
}

pub fn wait_for_process(process: HANDLE, _pid: u32) -> Result<u32, Box<dyn std::error::Error>> {
    unsafe {
        WaitForSingleObject(process, INFINITE);
        let mut exit_code: DWORD = 0;
        GetExitCodeProcess(process, &mut exit_code);
        CloseHandle(process);
        Ok(exit_code)
    }
}

fn build_cmdline(command: &str, args: &[String]) -> String {
    let mut cmd = format!("\"{}\"", command);
    for arg in args {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd
}

fn set_hook_env_vars(ipc: &IpcServer, config: &SandboxConfig, dll_x64: &str, dll_x86: &str) {
    let set_env = |key: &str, val: &str| unsafe {
        let k: Vec<u16> = OsStr::new(key).encode_wide().chain(std::iter::once(0)).collect();
        let v: Vec<u16> = OsStr::new(val).encode_wide().chain(std::iter::once(0)).collect();
        SetEnvironmentVariableW(k.as_ptr(), v.as_ptr());
    };

    set_env("SBOX_SHARED_DATA", ipc.shm_name());
    set_env("SBOX_HOST_PID", &std::process::id().to_string());
    set_env("SBOX_RECURSIVE_INJECTION", if config.enable_recursive_injection { "1" } else { "0" });
    set_env("SBOX_NETWORK_ISOLATION", if config.enable_network_isolation { "1" } else { "0" });
    set_env("SBOX_AUDIT_DIR", &config.audit_log_dir.to_string_lossy());
    set_env("SBOX_DLL_PATH_X64", dll_x64);
    set_env("SBOX_DLL_PATH_X86", dll_x86);

    log::info!("沙箱环境变量已设置");
}

fn find_dll() -> Result<String, Box<dyn std::error::Error>> {
    // 尝试多个可能路径
    let candidates = [
        "target/dll/x64/sandbox_hook.dll",
        "../target/dll/x64/sandbox_hook.dll",
        "../../target/dll/x64/sandbox_hook.dll",
        "dll/sandbox-hook/build-x64/Release/sandbox_hook.dll",
    ];
    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    Err("找不到 sandbox_hook.dll".into())
}
