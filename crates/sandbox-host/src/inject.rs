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
const WAIT_TIMEOUT: DWORD = 0x00000102;
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
    _pad7: DWORD, dwFlags: DWORD, _pad9: DWORD,
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
    fn TerminateProcess(hProcess: HANDLE, uExitCode: DWORD) -> BOOL;

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
    fn GetExitCodeThread(hThread: HANDLE, lpExitCode: *mut DWORD) -> BOOL;

    fn SetEnvironmentVariableW(lpName: *const u16, lpValue: *const u16) -> BOOL;

    fn Sleep(dwMilliseconds: DWORD);

    // WOW64 注入辅助 — ToolHelp32 快照
    fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) -> HANDLE;
    fn Module32FirstW(hSnapshot: HANDLE, lpme: *mut MODULEENTRY32W) -> BOOL;
    fn Module32NextW(hSnapshot: HANDLE, lpme: *mut MODULEENTRY32W) -> BOOL;
    fn ReadProcessMemory(hProcess: HANDLE, lpBase: *const c_void,
                         lpBuf: *mut c_void, nSize: usize,
                         lpNumberOfBytesRead: *mut usize) -> BOOL;

    // 管道
    fn CreatePipe(hRead: *mut HANDLE, hWrite: *mut HANDLE,
                  lpAttr: *const c_void, nSize: DWORD) -> BOOL;
    fn ReadFile(hFile: HANDLE, lpBuf: *mut u8, nToRead: DWORD,
                nRead: *mut DWORD, lpOverlapped: *mut c_void) -> BOOL;
    fn PeekNamedPipe(hPipe: HANDLE, lpBuf: *mut u8, nBufSize: DWORD,
                     nRead: *mut DWORD, nAvail: *mut DWORD, nLeft: *mut DWORD) -> BOOL;
}

const STARTF_USESTDHANDLES: DWORD = 0x0000_0100;

// ToolHelp32 标志
const TH32CS_SNAPMODULE: DWORD = 0x00000008;
const TH32CS_SNAPMODULE32: DWORD = 0x00000010;

// PE 常量
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;   // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

// WOW64 辅助进程超时
const WOW64_HELPER_TIMEOUT_MS: DWORD = 3000;

#[repr(C)]
struct MODULEENTRY32W {
    dwSize: DWORD,
    th32ModuleID: DWORD,
    th32ProcessID: DWORD,
    GlblcntUsage: DWORD,
    ProccntUsage: DWORD,
    modBaseAddr: *mut u8,
    modBaseSize: DWORD,
    hModule: HANDLE,
    szModule: [u16; 256],
    szExePath: [u16; 260],
}

// PE 头部结构（32 位）
#[repr(C, packed)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER32 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_NT_HEADERS32 {
    signature: u32,
    file_header: [u8; 20],  // IMAGE_FILE_HEADER (we don't need individual fields)
    optional_header: IMAGE_OPTIONAL_HEADER32,
}

fn invalid_handle() -> HANDLE { !0isize as HANDLE }

// ============================================================================
// 管道辅助函数
// ============================================================================

/// 创建一对管道 (读端, 写端) 用于捕获子进程输出
pub fn create_pipe_pair() -> Result<((HANDLE, HANDLE), (HANDLE, HANDLE)), Box<dyn std::error::Error>> {
    let mut stdout_read: HANDLE = std::ptr::null_mut();
    let mut stdout_write: HANDLE = std::ptr::null_mut();
    let mut stderr_read: HANDLE = std::ptr::null_mut();
    let mut stderr_write: HANDLE = std::ptr::null_mut();

    unsafe {
        if CreatePipe(&mut stdout_read, &mut stdout_write, std::ptr::null(), 0) == 0 {
            return Err(format!("CreatePipe(stdout) 失败: {}", GetLastError()).into());
        }
        if CreatePipe(&mut stderr_read, &mut stderr_write, std::ptr::null(), 0) == 0 {
            CloseHandle(stdout_read); CloseHandle(stdout_write);
            return Err(format!("CreatePipe(stderr) 失败: {}", GetLastError()).into());
        }
    }

    // 返回：(读端对, 写端对)
    // 读端给 Host 读取；(写端对)传给子进程
    Ok(((stdout_read, stderr_read), (stdout_write, stderr_write)))
}

/// 从管道读取所有数据直到 EOF
pub fn read_pipe_to_end(hPipe: HANDLE) -> String {
    let mut result = Vec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        let mut nread: DWORD = 0;
        let ret = unsafe {
            ReadFile(hPipe, buf.as_mut_ptr(), buf.len() as DWORD, &mut nread, std::ptr::null_mut())
        };
        if ret == 0 || nread == 0 {
            break;
        }
        result.extend_from_slice(&buf[..nread as usize]);
    }

    unsafe { CloseHandle(hPipe); }
    String::from_utf8_lossy(&result).to_string()
}

// ============================================================================
// ★ WOW64 LoadLibraryW 地址解析
//
// 在 64 位 Windows 上，32 位进程的 kernel32.dll 基址不同于 64 位进程。
// 使用 64 位 GetProcAddress 获取的 LoadLibraryW 地址在 32 位进程中无效。
// 必须通过 32 位辅助进程 + PE 导出表解析获取正确的 32 位地址。
// ============================================================================

/// 从 32 位辅助进程获取 kernel32!LoadLibraryW 地址
/// 方法：创建 keep-alive 辅助进程 → ToolHelp32 快照 → PE 导出表解析
fn get_wow64_loadlibraryw() -> Result<u32, Box<dyn std::error::Error>> {
    use std::sync::OnceLock;
    static CACHED: OnceLock<u32> = OnceLock::new();

    if let Some(&addr) = CACHED.get() {
        return Ok(addr);
    }

    // 创建 32 位辅助进程（ping 保持运行 ~2 秒，给我们足够时间）
    let helper_path: Vec<u16> = OsStr::new("C:\\Windows\\SysWOW64\\ping.exe")
        .encode_wide().chain(std::iter::once(0)).collect();
    let mut helper_cmd: Vec<u16> = OsStr::new("ping.exe -n 2 127.0.0.1 > NUL")
        .encode_wide().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            helper_path.as_ptr(),
            helper_cmd.as_mut_ptr(),
            std::ptr::null(), std::ptr::null(),
            FALSE, 0, std::ptr::null(), std::ptr::null(),
            &si, &mut pi,
        )
    };
    if result == 0 {
        return Err(format!("CreateProcess(SysWOW64\\ping) 失败: {}", unsafe { GetLastError() }).into());
    }

    unsafe { CloseHandle(pi.hThread); }

    // 给辅助进程时间初始化
    unsafe { Sleep(300); }

    // 用 PSAPI (K32EnumProcessModules) 枚举模块
    // 比 ToolHelp32 更可靠，无需 SE_DEBUG 权限
    type PFN_EnumProcessModules = unsafe extern "system" fn(
        HANDLE, *mut HANDLE, u32, *mut u32,
    ) -> BOOL;
    type PFN_GetModuleBaseNameW = unsafe extern "system" fn(
        HANDLE, HANDLE, *mut u16, u32,
    ) -> u32;
    type PFN_GetModuleInformation = unsafe extern "system" fn(
        HANDLE, HANDLE, *mut MODULEINFO, u32,
    ) -> BOOL;

    #[repr(C)]
    struct MODULEINFO {
        lp_base_of_dll: *mut c_void,
        size_of_image: u32,
        entry_point: *mut c_void,
    }

    let kernel32: Vec<u16> = OsStr::new("kernel32.dll")
        .encode_wide().chain(std::iter::once(0)).collect();

    let psapi_name: Vec<u16> = OsStr::new("psapi.dll")
        .encode_wide().chain(std::iter::once(0)).collect();
    let k32_name: Vec<u16> = OsStr::new("kernel32.dll")
        .encode_wide().chain(std::iter::once(0)).collect();

    // PSAPI functions are in kernel32.dll (K32* prefix) or psapi.dll
    let h_k32 = unsafe { GetModuleHandleW(k32_name.as_ptr()) };
    let enum_mod: Option<PFN_EnumProcessModules> = if !h_k32.is_null() {
        let ptr = unsafe { GetProcAddress(h_k32, b"K32EnumProcessModules\0".as_ptr()) };
        if !ptr.is_null() {
            Some(unsafe { std::mem::transmute(ptr) })
        } else { None }
    } else { None };
    let get_name: Option<PFN_GetModuleBaseNameW> = if !h_k32.is_null() {
        let ptr = unsafe { GetProcAddress(h_k32, b"K32GetModuleBaseNameW\0".as_ptr()) };
        if !ptr.is_null() {
            Some(unsafe { std::mem::transmute(ptr) })
        } else { None }
    } else { None };

    if enum_mod.is_none() || get_name.is_none() {
        unsafe { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); }
        return Err("PSAPI functions not available".into());
    }
    let enum_mod = enum_mod.unwrap();
    let get_name = get_name.unwrap();

    // 枚举模块（最多 1024 个句柄）
    let mut modules = [std::ptr::null_mut::<c_void>(); 1024];
    let mut needed: u32 = 0;
    if unsafe { enum_mod(pi.hProcess, modules.as_mut_ptr(),
                         (modules.len() * std::mem::size_of::<HANDLE>()) as u32,
                         &mut needed) } == 0 {
        unsafe { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); }
        return Err("K32EnumProcessModules 失败".into());
    }

    let count = (needed as usize / std::mem::size_of::<HANDLE>()).min(modules.len());
    let mut k32base: u32 = 0;

    for i in 0..count {
        let mut name_buf = [0u16; 64];
        let name_len = unsafe { get_name(pi.hProcess, modules[i], name_buf.as_mut_ptr(), 64) };
        if name_len > 0 {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]).to_lowercase();
            if name == "kernel32.dll" {
                let mut info: MODULEINFO = unsafe { std::mem::zeroed() };
                let h_psapi = unsafe { GetModuleHandleW(psapi_name.as_ptr()) };
                let get_info: Option<PFN_GetModuleInformation> = if !h_psapi.is_null() {
                    let ptr = unsafe { GetProcAddress(h_psapi, b"GetModuleInformation\0".as_ptr()) };
                    if !ptr.is_null() {
                        Some(unsafe { std::mem::transmute(ptr) })
                    } else { None }
                } else { None };
                if let Some(get_info_fn) = get_info {
                    unsafe { get_info_fn(pi.hProcess, modules[i], &mut info,
                                      std::mem::size_of::<MODULEINFO>() as u32); }
                    k32base = info.lp_base_of_dll as u32;
                }
                if k32base == 0 {
                    // 备用：直接使用模块句柄值作为基址（In Windows, HMODULE == base address）
                    k32base = modules[i] as u32;
                }
                break;
            }
        }
    }

    if k32base == 0 {
        unsafe { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); }
        return Err("kernel32.dll not found in helper process".into());
    }

    log::info!("WOW64 kernel32 base = 0x{:08X}", k32base);

    // PE 导出表解析（在清理辅助进程之前！）
    let mut bytes_read: usize = 0;
    let mut dos_hdr: IMAGE_DOS_HEADER = unsafe { std::mem::zeroed() };
    unsafe {
        ReadProcessMemory(pi.hProcess, k32base as *const c_void,
            &mut dos_hdr as *mut _ as *mut c_void,
            std::mem::size_of::<IMAGE_DOS_HEADER>(), &mut bytes_read);
    }
    if dos_hdr.e_magic != IMAGE_DOS_SIGNATURE {
        return Err("Invalid DOS header".into());
    }

    let nt_offset = (k32base as i32 + dos_hdr.e_lfanew) as u32;
    let mut nt_hdr = unsafe { std::mem::zeroed::<IMAGE_NT_HEADERS32>() };
    unsafe {
        ReadProcessMemory(pi.hProcess, nt_offset as *const c_void,
            &mut nt_hdr as *mut _ as *mut c_void,
            std::mem::size_of::<IMAGE_NT_HEADERS32>(), &mut bytes_read);
    }
    if nt_hdr.signature != IMAGE_NT_SIGNATURE {
        return Err("Invalid NT header".into());
    }

    let export_dir_rva = nt_hdr.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
    if export_dir_rva == 0 { return Err("No export directory".into()); }

    let export_dir_addr = k32base + export_dir_rva;
    let mut export_dir: IMAGE_EXPORT_DIRECTORY = unsafe { std::mem::zeroed() };
    unsafe {
        ReadProcessMemory(pi.hProcess, export_dir_addr as *const c_void,
            &mut export_dir as *mut _ as *mut c_void,
            std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>(), &mut bytes_read);
    }

    let names_rva = k32base + export_dir.address_of_names;
    let ordinals_rva = k32base + export_dir.address_of_name_ordinals;
    let funcs_rva = k32base + export_dir.address_of_functions;
    let name_count = export_dir.number_of_names.min(4096) as usize;
    let func_count = export_dir.number_of_functions.min(4096) as usize;

    let mut names = vec![0u32; name_count];
    let mut ordinals = vec![0u16; name_count];
    let mut funcs = vec![0u32; func_count];
    unsafe {
        ReadProcessMemory(pi.hProcess, names_rva as *const c_void,
            names.as_mut_ptr() as *mut c_void, name_count * 4, &mut bytes_read);
        ReadProcessMemory(pi.hProcess, ordinals_rva as *const c_void,
            ordinals.as_mut_ptr() as *mut c_void, name_count * 2, &mut bytes_read);
        ReadProcessMemory(pi.hProcess, funcs_rva as *const c_void,
            funcs.as_mut_ptr() as *mut c_void, func_count * 4, &mut bytes_read);
    }

    let mut llw_rva: u32 = 0;
    for i in 0..name_count {
        let mut name_buf = [0u8; 64];
        unsafe {
            ReadProcessMemory(pi.hProcess, (k32base + names[i]) as *const c_void,
                name_buf.as_mut_ptr() as *mut c_void, 63, &mut bytes_read);
        }
        if String::from_utf8_lossy(&name_buf[..]).trim_matches('\0') == "LoadLibraryW" {
            let ordinal = ordinals[i] as usize;
            if ordinal < func_count { llw_rva = funcs[ordinal]; }
            break;
        }
    }

    if llw_rva == 0 { 
        unsafe { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); }
        return Err("LoadLibraryW not found".into()); 
    }

    let address = k32base + llw_rva;
    
    // 清理辅助进程
    unsafe { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); }
    
    let _ = CACHED.set(address);
    log::info!("WOW64 LoadLibraryW = 0x{:08X}", address);
    Ok(address)
}

pub fn create_and_inject(
    command: &str,
    args: &[String],
    dll_path_x64: &str,
    dll_path_x86: &str,
    config: &SandboxConfig,
    ipc: &IpcServer,
    pipes: Option<(HANDLE, HANDLE)>,  // (stdout_write, stderr_write)
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

    // 设置管道句柄
    if let Some((stdout_write, stderr_write)) = pipes {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = stdout_write;
        si.hStdError = stderr_write;
        si.hStdInput = std::ptr::null_mut();
    }

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

    // 关闭写端（子进程已继承）
    if let Some((stdout_write, stderr_write)) = pipes {
        unsafe {
            CloseHandle(stdout_write);
            CloseHandle(stderr_write);
        }
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

    // 注入（自动选择正确的 LoadLibraryW 地址）
    inject_dll(pi.hProcess, actual_dll, is_wow64, pi.dwProcessId)?;

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

fn inject_dll(process: HANDLE, dll_path: &str, is_wow64: bool, target_pid: DWORD) -> Result<(), Box<dyn std::error::Error>> {
    if is_wow64 {
        // ★ WOW64 注入: 使用 32-bit 辅助进程（Trae 方案）
        // 64-bit GetProcAddress(LoadLibraryW) 返回的地址在 32-bit 进程中无效
        // 改用 32-bit 辅助进程（sandbox_helper_x86.exe）执行注入
        return inject_via_helper(dll_path, target_pid);
    }

    // ★ x64 注入: 直接 CreateRemoteThread（64-bit LoadLibraryW 地址正确）
    let dll_wide: Vec<u16> = OsStr::new(dll_path)
        .encode_wide().chain(std::iter::once(0)).collect();
    let dll_bytes = dll_wide.len() * 2;

    let remote_mem = unsafe {
        VirtualAllocEx(process, std::ptr::null(), dll_bytes,
                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote_mem.is_null() {
        return Err(format!("VirtualAllocEx 失败: {}", unsafe { GetLastError() }).into());
    }

    let mut written: usize = 0;
    if unsafe { WriteProcessMemory(process, remote_mem,
            dll_wide.as_ptr() as *const c_void, dll_bytes, &mut written) } == 0 {
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err(format!("WriteProcessMemory 失败: {}", unsafe { GetLastError() }).into());
    }

    // 64-bit LoadLibraryW 地址（对 x64 目标有效）
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

    log::info!("x64 LoadLibraryW 地址: {:p}", loadlib);

    let thread = unsafe {
        CreateRemoteThread(process, std::ptr::null(), 0,
                           loadlib, remote_mem, 0, std::ptr::null_mut())
    };
    if thread.is_null() {
        let err = unsafe { GetLastError() };
        unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err(format!("CreateRemoteThread 失败: {}", err).into());
    }

    let wait_ret = unsafe { WaitForSingleObject(thread, 15000) };
    if wait_ret != WAIT_OBJECT_0 {
        unsafe { CloseHandle(thread); VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }
        return Err("LoadLibraryW 远程线程超时".into());
    }

    let mut thread_exit: DWORD = 0;
    unsafe { GetExitCodeThread(thread, &mut thread_exit); }
    unsafe { CloseHandle(thread); }
    unsafe { VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE); }

    if thread_exit == 0 {
        return Err(format!("LoadLibraryW 失败 (exit=0), DLL 可能无法加载: {}", dll_path).into());
    }

    log::info!("DLL 加载成功: 模块基址=0x{:08X}", thread_exit);
    Ok(())
}

/// ★ 通过 32-bit 辅助进程注入 WOW64 目标
///
/// Trae 方案：64-bit 进程无法获取正确的 32-bit LoadLibraryW 地址，
/// 因此创建一个 32-bit 辅助进程来执行注入。
/// 32-bit 进程的 GetProcAddress(kernel32, "LoadLibraryW") 返回正确的 32-bit 地址。
fn inject_via_helper(dll_path: &str, target_pid: DWORD) -> Result<(), Box<dyn std::error::Error>> {
    // 辅助程序路径（与 sandbox-host.exe 同目录）
    let exe_dir = std::env::current_exe()?
        .parent().unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    let helper_path = exe_dir.join("sandbox_helper_x86.exe");

    if !helper_path.exists() {
        // 回退：尝试直接注入（使用 64-bit 地址，虽然会失败）
        log::warn!("sandbox_helper_x86.exe 未找到！WOW64 注入不可用");
        return Err("sandbox_helper_x86.exe not found, WOW64 injection unavailable".into());
    }

    // 构建命令行: helper.exe <target_pid> <dll_path>
    let cmdline = format!(
        "\"{}\" {} \"{}\"",
        helper_path.to_string_lossy(),
        target_pid,
        dll_path,
    );
    let cmdline_wide: Vec<u16> = OsStr::new(&cmdline)
        .encode_wide().chain(std::iter::once(0)).collect();

    log::info!("启动 WOW64 注入辅助进程: {}", cmdline);

    // 创建辅助进程（32-bit）
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmdline_wide.as_ptr() as *mut u16,
            std::ptr::null(), std::ptr::null(),
            FALSE, 0,
            std::ptr::null(), std::ptr::null(),
            &si, &mut pi,
        )
    };
    if result == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("创建辅助注入进程失败: error={}", err).into());
    }

    unsafe { CloseHandle(pi.hThread); }

    // 等待辅助进程完成
    let wait_ret = unsafe { WaitForSingleObject(pi.hProcess, 30000) };
    let mut exit_code: DWORD = 0;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code); }
    unsafe { CloseHandle(pi.hProcess); }

    if wait_ret == WAIT_TIMEOUT {
        return Err("辅助注入进程超时".into());
    }

    log::info!("辅助注入进程退出码: {}", exit_code);

    if exit_code == 0 {
        log::info!("WOW64 辅助注入成功: PID={}", target_pid);
        Ok(())
    } else {
        Err(format!("WOW64 辅助注入失败 (exit={}): PID={}", exit_code, target_pid).into())
    }
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

/// 等待进程退出，超时则强制终止
pub fn wait_for_process_timeout(process: HANDLE, pid: u32, timeout_ms: u32) -> Result<u32, Box<dyn std::error::Error>> {
    unsafe {
        let ret = WaitForSingleObject(process, timeout_ms);
        let exit_code = if ret == WAIT_OBJECT_0 {
            let mut code: DWORD = 0;
            GetExitCodeProcess(process, &mut code);
            code
        } else {
            // 超时 → 强制终止
            log::warn!("PID={} 超时 ({}ms)，强制终止", pid, timeout_ms);
            TerminateProcess(process, 1);
            WaitForSingleObject(process, 3000); // 等待终止完成
            let mut code: DWORD = 0;
            GetExitCodeProcess(process, &mut code);
            code
        };
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
    set_env("SBOX_AUDIT_SHM", ipc.audit_shm_name());  // ★ Ring Buffer 名称

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
