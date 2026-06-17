//! # sandbox_host — Windows 沙箱宿主进程库
//!
//! 提供 [SandboxHost] 结构体，用于在沙箱中执行受控命令。
//! 支持文件系统 ACL、网络 ACL、递归注入等安全特性。
//!
//! ## 快速开始
//!
//! ```no_run
//! use sandbox_host::SandboxHost;
//! use std::path::PathBuf;
//!
//! let host = SandboxHost::new(
//!     PathBuf::from("output/sandbox_hook_x64.dll"),
//!     PathBuf::from("output/sandbox_hook_x86.dll"),
//!     PathBuf::from("output/sandbox_helper_x86.exe"),
//! );
//!
//! let args: Vec<String> = vec!["/c".into(), "echo hello".into()];
//! let result = host.exec(
//!     "cmd.exe",
//!     &args,
//!     None::<PathBuf>,
//!     Some(30),
//! ).expect("沙箱执行失败");
//!
//! println!("exit_code={}", result.exit_code);
//! ```

mod cli;
pub mod config;
mod inject;
pub mod ipc;
pub mod audit;

use std::path::{Path, PathBuf};

/// 沙箱执行结果
#[derive(Clone, Debug, serde::Serialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub audit_summary: String,
    pub pid: u32,
}

/// 沙箱依赖文件路径配置
///
/// 指定三个外部文件的路径，它们是沙箱正常运行所必需的：
///
/// | 文件 | 用途 |
/// |------|------|
/// | `dll_x64` | 64 位 Hook DLL (`sandbox_hook_x64.dll`) |
/// | `dll_x86` | 32 位 Hook DLL (`sandbox_hook_x86.dll`) |
/// | `helper_x86` | WOW64 注入辅助程序 (`sandbox_helper_x86.exe`) |
#[derive(Clone, Debug)]
pub struct SandboxPaths {
    pub dll_x64: PathBuf,
    pub dll_x86: PathBuf,
    pub helper_x86: PathBuf,
}

/// 沙箱宿主 — 创建沙箱化进程
///
/// 管理依赖文件路径，提供沙箱执行入口。
#[derive(Clone, Debug)]
pub struct SandboxHost {
    paths: SandboxPaths,
}

impl SandboxHost {
    /// 创建沙箱宿主，指定三个依赖文件路径
    pub fn new(
        dll_x64: impl Into<PathBuf>,
        dll_x86: impl Into<PathBuf>,
        helper_x86: impl Into<PathBuf>,
    ) -> Self {
        Self {
            paths: SandboxPaths {
                dll_x64: dll_x64.into(),
                dll_x86: dll_x86.into(),
                helper_x86: helper_x86.into(),
            },
        }
    }

    /// 使用已有的路径配置创建沙箱宿主
    pub fn with_paths(paths: SandboxPaths) -> Self {
        Self { paths }
    }

    /// 获取当前路径配置
    pub fn paths(&self) -> &SandboxPaths {
        &self.paths
    }

    /// 在沙箱中执行命令（从配置文件加载规则）
    ///
    /// - `config_path`: 配置文件路径，`None` 则自动检测（同 `config::load_config`）
    /// - `timeout_secs`: 超时秒数，`None` 或 `0` 表示无超时
    pub fn exec(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        config_path: Option<impl AsRef<Path>>,
        timeout_secs: Option<u64>,
    ) -> Result<SandboxResult, Box<dyn std::error::Error>> {
        let cfg_path = config_path.map(|p| p.as_ref().to_path_buf());
        let sandbox_config = config::load_config(cfg_path)?;
        self.run_with_config(command, args, &sandbox_config, timeout_secs)
    }

    /// 在沙箱中执行命令（直接传入配置对象）
    ///
    /// 相比 `exec` 跳过了文件加载步骤，适用于编程方式创建配置的场景。
    pub fn exec_with_config(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        config: &sandbox_core::SandboxConfig,
        timeout_secs: Option<u64>,
    ) -> Result<SandboxResult, Box<dyn std::error::Error>> {
        let sandbox_config = config::use_config(config.clone());
        self.run_with_config(command, args, &sandbox_config, timeout_secs)
    }

    /// 内部：核心执行逻辑
    fn run_with_config(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        sandbox_config: &sandbox_core::SandboxConfig,
        timeout_param: Option<u64>,
    ) -> Result<SandboxResult, Box<dyn std::error::Error>> {
        let command = command.into();
        let cmd_args = args.as_ref().to_vec();

        log::info!("沙箱: {}", sandbox_config.name);

        let ipc_server = ipc::IpcServer::new(std::process::id(), sandbox_config)?;

        // 管道捕获 stdout/stderr
        let (stdout_reader, stderr_reader) = inject::create_pipe_pair()?;

        let (process_handle, process_id) = inject::create_and_inject(
            &command,
            &cmd_args,
            &self.paths.dll_x64.to_string_lossy(),
            &self.paths.dll_x86.to_string_lossy(),
            &self.paths.helper_x86.to_string_lossy(),
            sandbox_config,
            &ipc_server,
            Some((stdout_reader.1, stderr_reader.1)),
        )?;

        log::info!("PID={} 已启动", process_id);

        let stdout_h = stdout_reader.0 as usize;
        let stderr_h = stderr_reader.0 as usize;

        let stdout_thread = std::thread::spawn(move || {
            inject::read_pipe_to_end(stdout_h as *mut std::ffi::c_void)
        });
        let stderr_thread = std::thread::spawn(move || {
            inject::read_pipe_to_end(stderr_h as *mut std::ffi::c_void)
        });

        let timeout_ms = timeout_param.unwrap_or(0).max(1) * 1000;
        let exit_code = if timeout_ms > 0 {
            inject::wait_for_process_timeout(process_handle, process_id, timeout_ms as u32)?
        } else {
            inject::wait_for_process(process_handle, process_id)?
        };

        log::info!("PID={} 退出: {}", process_id, exit_code);

        let stdout = stdout_thread.join().unwrap_or_default();
        let stderr = stderr_thread.join().unwrap_or_default();

        ipc_server.flush_audit();
        let audit_summary = ipc_server.summary();

        Ok(SandboxResult {
            exit_code: exit_code as i32,
            stdout,
            stderr,
            audit_summary,
            pid: process_id,
        })
    }
}

/// 便捷函数：一键沙箱执行
///
/// 等效于使用默认路径创建 `SandboxHost` 并调用 `exec`。
/// 路径从可执行文件所在目录自动查找。
pub fn run_sandbox(
    command: impl Into<String>,
    args: impl AsRef<[String]>,
    config_path: Option<impl AsRef<Path>>,
    timeout_secs: Option<u64>,
) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let host = SandboxHost::new(
        exe_dir.join("sandbox_hook_x64.dll"),
        exe_dir.join("sandbox_hook_x86.dll"),
        exe_dir.join("sandbox_helper_x86.exe"),
    );
    host.exec(command, args, config_path, timeout_secs)
}

// 为测试代码重新导出
#[doc(hidden)]
pub use cli::*;
