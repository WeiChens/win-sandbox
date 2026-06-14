//! sandbox-host — Windows 沙箱宿主进程

mod cli;
mod config;
mod inject;
mod ipc;
mod audit;
mod ai_server;

use sandbox_core::SandboxConfig;
use std::path::PathBuf;

/// 沙箱执行结果
#[derive(serde::Serialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub audit_summary: String,
    pub pid: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = cli::parse_args();

    match args.command {
        cli::Command::Exec { command, cmd_args, config_path, timeout } => {
            let result = run_sandbox(command, cmd_args, config_path, timeout)?;
            println!("exit_code={}", result.exit_code);
            if !result.stdout.is_empty() { println!("[stdout]\n{}", result.stdout); }
            if !result.stderr.is_empty() { println!("[stderr]\n{}", result.stderr); }
            println!("{}", result.audit_summary);
        }
        cli::Command::Config { action } => {
            handle_config(action)?;
        }
        cli::Command::Audit { log_dir, format } => {
            audit::show_audit(log_dir, format)?;
        }
        cli::Command::Serve { port } => {
            ai_server::serve(port, run_sandbox)?;
        }
    }

    Ok(())
}

/// 执行沙箱化命令（可复用，CLI 和 AI 共用）
pub fn run_sandbox(
    command: String,
    cmd_args: Vec<String>,
    config_path: Option<PathBuf>,
    _timeout: Option<u64>,
) -> Result<SandboxResult, Box<dyn std::error::Error>> {
    let sandbox_config = config::load_config(config_path)?;
    log::info!("沙箱: {}", sandbox_config.name);

    let exe_dir = std::env::current_exe()?
        .parent().unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let dll_x64 = exe_dir.join("target").join("dll").join("x64").join("sandbox_hook.dll");
    let dll_x86 = exe_dir.join("target").join("dll").join("x86").join("sandbox_hook.dll");

    let ipc_server = ipc::IpcServer::new(std::process::id(), &sandbox_config)?;

    // ★ 管道捕获 stdout/stderr
    let (stdout_reader, stderr_reader) = inject::create_pipe_pair()?;

    let (process_handle, process_id) = inject::create_and_inject(
        &command, &cmd_args,
        &dll_x64.to_string_lossy(), &dll_x86.to_string_lossy(),
        &sandbox_config, &ipc_server,
        Some((stdout_reader.1, stderr_reader.1)), // 传入写端
    )?;

    log::info!("PID={} 已启动", process_id);

    // 读取管道输出
    let stdout = inject::read_pipe_to_end(stdout_reader.0);
    let stderr = inject::read_pipe_to_end(stderr_reader.0);

    let exit_code = inject::wait_for_process(process_handle, process_id)?;
    log::info!("PID={} 退出: {}", process_id, exit_code);

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
