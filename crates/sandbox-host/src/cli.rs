//! CLI 接口定义

use std::path::PathBuf;

#[derive(Debug)]
pub struct CliArgs {
    pub command: Command,
    pub verbose: bool,
}

#[derive(Debug)]
pub enum Command {
    /// 在沙箱中执行命令
    Exec {
        command: String,
        cmd_args: Vec<String>,
        config_path: Option<PathBuf>,
        timeout: Option<u64>,
    },
    /// 配置管理
    Config {
        action: ConfigAction,
    },
    /// 查看审计日志
    Audit {
        log_dir: Option<PathBuf>,
        format: AuditFormat,
    },
    /// 启动 AI 调用服务
    Serve {
        port: u16,
    },
}

#[derive(Debug)]
pub enum ConfigAction {
    /// 显示当前配置
    Show { path: Option<PathBuf> },
    /// 生成默认配置
    Init { output: Option<PathBuf> },
    /// 验证配置文件
    Validate { path: PathBuf },
}

#[derive(Debug, Clone, Copy)]
pub enum AuditFormat {
    Json,
    Text,
}

/// 解析命令行参数
pub fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    parse_from(&args)
}

fn parse_from(args: &[String]) -> CliArgs {
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    match args[1].as_str() {
        "exec" | "run" | "e" => parse_exec(args, verbose),
        "config" | "cfg" | "c" => parse_config(args, verbose),
        "audit" | "log" | "a" => parse_audit(args, verbose),
        "serve" | "s" => parse_serve(args, verbose),
        "help" | "--help" | "-h" => {
            print_usage();
            std::process::exit(0);
        }
        _ => {
            // 如果第一个参数不是子命令，当作 exec 简写：
            // sandbox-host cmd.exe /c dir
            parse_exec_implicit(args, verbose)
        }
    }
}

fn parse_exec(args: &[String], verbose: bool) -> CliArgs {
    let mut command = String::new();
    let mut cmd_args = Vec::new();
    let mut config_path = None;
    let mut timeout = None;
    let mut i = 2;

    while i < args.len() {
        if command.is_empty() {
            match args[i].as_str() {
                "--config" | "-c" => { i += 1; if i < args.len() { config_path = Some(PathBuf::from(&args[i])); } }
                "--timeout" | "-t" => { i += 1; if i < args.len() { timeout = args[i].parse().ok(); } }
                "--verbose" | "-v" => {}
                "--" => {
                    let rest: Vec<String> = args[i + 1..].to_vec();
                    if let Some((first, remaining)) = rest.split_first() {
                        command = first.clone();
                        cmd_args = remaining.to_vec();
                    }
                    break;
                }
                _ => { command = args[i].clone(); }
            }
        } else {
            cmd_args.push(args[i].clone());
        }
        i += 1;
    }

    if command.is_empty() {
        eprintln!("错误: exec 需要指定命令");
        std::process::exit(1);
    }

    CliArgs {
        command: Command::Exec { command, cmd_args, config_path, timeout },
        verbose,
    }
}

/// 隐式 exec：无子命令时自动识别
fn parse_exec_implicit(args: &[String], verbose: bool) -> CliArgs {
    let command = args[1].clone();
    let cmd_args = args[2..].to_vec();
    CliArgs {
        command: Command::Exec {
            command, cmd_args,
            config_path: None,
            timeout: None,
        },
        verbose,
    }
}

fn parse_config(args: &[String], verbose: bool) -> CliArgs {
    let action = if args.len() < 3 {
        ConfigAction::Show { path: None }
    } else {
        match args[2].as_str() {
            "show" => {
                let path = args.get(3).map(PathBuf::from);
                ConfigAction::Show { path }
            }
            "init" => {
                let output = args.get(3).map(PathBuf::from);
                ConfigAction::Init { output }
            }
            "validate" => {
                let path = args.get(3)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("sandbox.json"));
                ConfigAction::Validate { path }
            }
            _ => {
                // 如果没有子子命令，当作显示
                let path = Some(PathBuf::from(&args[2]));
                ConfigAction::Show { path }
            }
        }
    };
    CliArgs { command: Command::Config { action }, verbose }
}

fn parse_audit(args: &[String], verbose: bool) -> CliArgs {
    let mut log_dir = None;
    let mut format = AuditFormat::Text;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" | "-d" => { i += 1; if i < args.len() { log_dir = Some(PathBuf::from(&args[i])); } }
            "--json" => { format = AuditFormat::Json; }
            _ => {}
        }
        i += 1;
    }
    CliArgs { command: Command::Audit { log_dir, format }, verbose }
}

fn parse_serve(args: &[String], verbose: bool) -> CliArgs {
    let port = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(9800);
    CliArgs { command: Command::Serve { port }, verbose }
}

fn print_usage() {
    println!(r#"Windows Sandbox — AI 可调用的沙盒终端

用法:
  sandbox-host [exec] <命令> [参数...]  [选项]    在沙箱中执行命令
  sandbox-host config show [配置文件]              显示配置
  sandbox-host config init [输出文件]              生成默认配置
  sandbox-host config validate <配置文件>          验证配置
  sandbox-host audit [--dir <目录>] [--json]       查看审计日志
  sandbox-host serve [端口]                        启动 AI 调用服务
  sandbox-host help                                显示帮助

选项:
  --config, -c <文件>   沙箱配置文件 (默认: sandbox.json)
  --timeout, -t <秒>    超时时间
  --verbose, -v         详细输出

示例:
  sandbox-host exec cmd.exe /c dir C:\
  sandbox-host cmd.exe /c whoami
  sandbox-host --config strict.json python script.py
  sandbox-host serve 9800
"#);
}
