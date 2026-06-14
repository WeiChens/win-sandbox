//! sandbox-host — Windows 沙箱宿主进程
//!
//! 负责：
//! - CLI 解析
//! - 沙箱配置加载
//! - 目标进程创建 & 初始 DLL 注入
//! - IPC 服务（审计日志收集）
//! - AI 调用接口（HTTP JSON-RPC）

mod cli;
mod config;
mod inject;
mod ipc;
mod audit;
mod ai_server;

use sandbox_core::SandboxConfig;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = cli::parse_args();

    match args.command {
        cli::Command::Exec { command, cmd_args, config_path, timeout } => {
            run_sandbox(command, cmd_args, config_path, timeout)?;
        }
        cli::Command::Config { action } => {
            handle_config(action)?;
        }
        cli::Command::Audit { log_dir, format } => {
            audit::show_audit(log_dir, format)?;
        }
        cli::Command::Serve { port } => {
            ai_server::serve(port)?;
        }
    }

    Ok(())
}

/// 执行沙箱化命令
fn run_sandbox(
    command: String,
    cmd_args: Vec<String>,
    config_path: Option<PathBuf>,
    _timeout: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 加载配置
    let sandbox_config = config::load_config(config_path)?;
    log::info!("沙箱配置已加载: {}", sandbox_config.name);

    // 2. 准备 DLL 路径
    let exe_dir = std::env::current_exe()?
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let dll_x64 = exe_dir.join("target").join("dll").join("x64").join("sandbox_hook.dll");
    let dll_x86 = exe_dir.join("target").join("dll").join("x86").join("sandbox_hook.dll");

    if !dll_x64.exists() {
        log::warn!("x64 DLL 未找到: {:?}，尝试从源码目录查找", dll_x64);
    }
    if !dll_x86.exists() {
        log::warn!("x86 DLL 未找到: {:?}，尝试从源码目录查找", dll_x86);
    }

    // 3. 创建 IPC 服务（在注入前初始化共享内存）
    let ipc_server = ipc::IpcServer::new(
        std::process::id(),
        &sandbox_config,
    )?;

    // 4. 创建并注入目标进程
    let (process_handle, process_id) = inject::create_and_inject(
        &command,
        &cmd_args,
        &dll_x64.to_string_lossy(),
        &dll_x86.to_string_lossy(),
        &sandbox_config,
        &ipc_server,
    )?;

    log::info!("目标进程已启动: PID={}", process_id);

    // 5. 等待进程退出
    let exit_code = inject::wait_for_process(process_handle, process_id)?;
    log::info!("进程退出: PID={}, exit_code={}", process_id, exit_code);

    // 6. 输出审计报告
    ipc_server.flush_audit();
    let summary = ipc_server.summary();
    println!("{}", summary);

    Ok(())
}

/// 处理配置子命令
fn handle_config(action: cli::ConfigAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        cli::ConfigAction::Show { path } => {
            let cfg = config::load_config(path)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        cli::ConfigAction::Init { output } => {
            let cfg = SandboxConfig::default();
            let path = output.unwrap_or_else(|| PathBuf::from("sandbox.json"));
            std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
            println!("默认配置已写入: {:?}", path);
        }
        cli::ConfigAction::Validate { path } => {
            match config::load_config(Some(path)) {
                Ok(cfg) => println!("配置有效: {}", cfg.name),
                Err(e) => eprintln!("配置无效: {}", e),
            }
        }
    }
    Ok(())
}
