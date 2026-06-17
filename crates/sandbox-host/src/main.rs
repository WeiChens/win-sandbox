//! sandbox-host — Windows 沙箱宿主进程（CLI 入口）
//!
//! 这是一个薄壳 CLI，核心逻辑在 `sandbox_host` 库中。
//! 第三方开发者应直接依赖 `sandbox_host` 库而非此二进制。

use sandbox_host::{SandboxHost, SandboxResult};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args = sandbox_host::parse_args();

    match args.command {
        sandbox_host::Command::Exec { command, cmd_args, config_path, timeout } => {
            // 默认从 exe 同目录查找依赖文件
            let exe_dir = std::env::current_exe()?
                .parent().unwrap_or(std::path::Path::new("."))
                .to_path_buf();
            let host = SandboxHost::new(
                exe_dir.join("sandbox_hook_x64.dll"),
                exe_dir.join("sandbox_hook_x86.dll"),
                exe_dir.join("sandbox_helper_x86.exe"),
            );
            let result = host.exec(command, &cmd_args, config_path, timeout)?;
            print_result(&result);
        }
        sandbox_host::Command::Config { action } => {
            handle_config(action)?;
        }
        sandbox_host::Command::Audit { log_dir, format } => {
            sandbox_host::audit::show_audit(log_dir, format)?;
        }
    }

    Ok(())
}

fn print_result(result: &SandboxResult) {
    println!("exit_code={}", result.exit_code);
    if !result.stdout.is_empty() { println!("[stdout]\n{}", result.stdout); }
    if !result.stderr.is_empty() { println!("[stderr]\n{}", result.stderr); }
    println!("{}", result.audit_summary);
}

fn handle_config(action: sandbox_host::ConfigAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        sandbox_host::ConfigAction::Show { path } => {
            let cfg = sandbox_host::config::load_config(path)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        sandbox_host::ConfigAction::Init { output } => {
            let cfg = sandbox_core::SandboxConfig::default();
            let path = output.unwrap_or_else(|| PathBuf::from("sandbox.json"));
            std::fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
            println!("默认配置已写入: {:?}", path);
        }
        sandbox_host::ConfigAction::Validate { path } => {
            match sandbox_host::config::load_config(Some(path)) {
                Ok(cfg) => println!("配置有效: {}", cfg.name),
                Err(e) => eprintln!("配置无效: {}", e),
            }
        }
    }
    Ok(())
}
