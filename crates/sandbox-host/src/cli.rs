//! CLI 接口定义

use std::path::PathBuf;

#[derive(Debug)]
pub struct CliArgs {
    pub command: Command,
    #[allow(dead_code)]
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

    // 预扫描：提取全局选项 + 找到子命令位置
    let mut subcmd_idx = 1;
    let mut global_config: Option<PathBuf> = None;
    let mut global_timeout: Option<u64> = None;

    while subcmd_idx < args.len() {
        let a = args[subcmd_idx].as_str();
        match a {
            "--config" | "-c" => {
                subcmd_idx += 1;
                if subcmd_idx < args.len() {
                    global_config = Some(PathBuf::from(&args[subcmd_idx]));
                }
            }
            "--timeout" | "-t" => {
                subcmd_idx += 1;
                if subcmd_idx < args.len() {
                    global_timeout = args[subcmd_idx].parse().ok();
                }
            }
            "--verbose" | "-v" => {}
            a if a.starts_with("--") || a.starts_with('-') => {
                // 未知选项，跳过
            }
            _ => break, // 子命令
        }
        subcmd_idx += 1;
    }

    if subcmd_idx >= args.len() {
        // 所有参数都是选项，没有子命令 → exec 简写
        return parse_exec_implicit(args, verbose);
    }

    match args[subcmd_idx].as_str() {
        "exec" | "run" | "e" => parse_exec_from(args, verbose, subcmd_idx + 1, global_config, global_timeout),
        "config" | "cfg" | "c" => parse_config_from(args, verbose, subcmd_idx + 1),
        "audit" | "log" | "a" => parse_audit_from(args, verbose, subcmd_idx + 1),
        "help" | "--help" | "-h" => {
            print_usage();
            std::process::exit(0);
        }
        _ => parse_exec_implicit(args, verbose),
    }
}

fn parse_exec_from(args: &[String], verbose: bool, start: usize,
                    global_config: Option<PathBuf>, global_timeout: Option<u64>) -> CliArgs {
    let mut command = String::new();
    let mut cmd_args = Vec::new();
    let mut config_path = global_config;
    let mut timeout = global_timeout;
    let mut i = start;

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

fn parse_config_from(args: &[String], verbose: bool, start: usize) -> CliArgs {
    let action = if start >= args.len() {
        ConfigAction::Show { path: None }
    } else {
        match args[start].as_str() {
            "show" => {
                let path = args.get(start + 1).map(PathBuf::from);
                ConfigAction::Show { path }
            }
            "init" => {
                let output = args.get(start + 1).map(PathBuf::from);
                ConfigAction::Init { output }
            }
            "validate" => {
                let path = args.get(start + 1)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("sandbox.json"));
                ConfigAction::Validate { path }
            }
            _ => {
                let path = Some(PathBuf::from(&args[start]));
                ConfigAction::Show { path }
            }
        }
    };
    CliArgs { command: Command::Config { action }, verbose }
}

fn parse_audit_from(args: &[String], verbose: bool, start: usize) -> CliArgs {
    let mut log_dir = None;
    let mut format = AuditFormat::Text;
    let mut i = start;
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

fn print_usage() {
    println!(r#"Windows Sandbox — 本地沙盒终端

用法:
  sandbox-host [exec] <命令> [参数...]  [选项]    在沙箱中执行命令
  sandbox-host config show [配置文件]              显示配置
  sandbox-host config init [输出文件]              生成默认配置
  sandbox-host config validate <配置文件>          验证配置
  sandbox-host audit [--dir <目录>] [--json]       查看审计日志
  sandbox-host help                                显示帮助

选项:
  --config, -c <文件>   沙箱配置文件 (默认: sandbox.json)
  --timeout, -t <秒>    超时时间
  --verbose, -v         详细输出

示例:
  sandbox-host exec cmd.exe /c dir C:\
  sandbox-host cmd.exe /c whoami
  sandbox-host --config strict.json python script.py
"#);
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        std::iter::once("sandbox-host.exe".to_string())
            .chain(s.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn test_exec_basic() {
        let a = args(&["exec", "cmd.exe", "/c", "dir"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Exec { command, cmd_args, .. } => {
                assert_eq!(command, "cmd.exe");
                assert_eq!(cmd_args, vec!["/c", "dir"]);
            }
            _ => panic!("Expected Exec"),
        }
    }

    #[test]
    fn test_exec_with_config() {
        let a = args(&["exec", "--config", "my.json", "python", "script.py"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Exec { command, cmd_args, config_path, .. } => {
                assert_eq!(command, "python");
                assert_eq!(cmd_args, vec!["script.py"]);
                assert!(config_path.is_some());
            }
            _ => panic!("Expected Exec"),
        }
    }

    #[test]
    fn test_exec_with_timeout() {
        let a = args(&["exec", "--timeout", "30", "cmd.exe"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Exec { command, timeout, .. } => {
                assert_eq!(command, "cmd.exe");
                assert_eq!(timeout, Some(30));
            }
            _ => panic!("Expected Exec"),
        }
    }

    #[test]
    fn test_exec_with_double_dash() {
        let a = args(&["exec", "--config", "cfg.json", "--", "cmd.exe", "/c", "echo hello"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Exec { command, cmd_args, config_path, .. } => {
                assert_eq!(command, "cmd.exe");
                assert_eq!(cmd_args, vec!["/c", "echo hello"]);
                assert!(config_path.is_some());
            }
            _ => panic!("Expected Exec"),
        }
    }

    #[test]
    fn test_implicit_exec() {
        let a = args(&["cmd.exe", "/c", "whoami"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Exec { command, cmd_args, .. } => {
                assert_eq!(command, "cmd.exe");
                assert_eq!(cmd_args, vec!["/c", "whoami"]);
            }
            _ => panic!("Expected Exec (implicit)"),
        }
    }

    #[test]
    fn test_config_show() {
        let a = args(&["config", "show"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Config { action: ConfigAction::Show { path } } => {
                assert!(path.is_none());
            }
            _ => panic!("Expected Config::Show"),
        }
    }

    #[test]
    fn test_config_init() {
        let a = args(&["config", "init", "output.json"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Config { action: ConfigAction::Init { output } } => {
                assert_eq!(output, Some(PathBuf::from("output.json")));
            }
            _ => panic!("Expected Config::Init"),
        }
    }

    #[test]
    fn test_config_validate() {
        let a = args(&["config", "validate", "sandbox.json"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Config { action: ConfigAction::Validate { path } } => {
                assert_eq!(path, PathBuf::from("sandbox.json"));
            }
            _ => panic!("Expected Config::Validate"),
        }
    }

    #[test]
    fn test_audit_text() {
        let a = args(&["audit"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Audit { format, .. } => {
                assert!(matches!(format, AuditFormat::Text));
            }
            _ => panic!("Expected Audit"),
        }
    }

    #[test]
    fn test_audit_json() {
        let a = args(&["audit", "--json"]);
        let cli = parse_from(&a);
        match cli.command {
            Command::Audit { format, .. } => {
                assert!(matches!(format, AuditFormat::Json));
            }
            _ => panic!("Expected Audit::Json"),
        }
    }

    #[test]
    fn test_verbose_flag() {
        let a = args(&["--verbose", "exec", "cmd.exe"]);
        let cli = parse_from(&a);
        assert!(cli.verbose);
    }

    #[test]
    fn test_verbose_short_flag() {
        let a = args(&["-v", "exec", "cmd.exe"]);
        let cli = parse_from(&a);
        assert!(cli.verbose);
    }
}
