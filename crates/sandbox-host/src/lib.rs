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
use std::sync::mpsc::{self, Receiver};

/// 沙箱执行结果
#[derive(Clone, Debug, serde::Serialize)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub audit_summary: String,
    pub pid: u32,
}

/// 流式输出事件
///
/// 通过 [`SandboxHost::exec_streaming`] 返回的 `Receiver` 接收。
/// 先收到零个或多个 `Stdout`/`Stderr` 数据块，最后收到 `Done` 事件。
#[derive(Debug)]
pub enum StreamEvent {
    /// stdout 数据块（原始字节，转为 UTF-8 lossy）
    Stdout(String),
    /// stderr 数据块
    Stderr(String),
    /// 进程执行完毕，携带最终结果
    Done(SandboxResult),
}

/// 流式沙箱执行句柄
///
/// 提供两种消费方式：
/// - 直接迭代 `receiver()` — 实时处理每块输出
/// - 调用 `collect()` — 等待执行完毕，收集完整结果
#[derive(Debug)]
pub struct SandboxStream {
    rx: Receiver<StreamEvent>,
}

impl SandboxStream {
    /// 获取事件接收器引用
    pub fn receiver(&self) -> &Receiver<StreamEvent> {
        &self.rx
    }

    /// 消费接收器（取走所有权）
    pub fn into_receiver(self) -> Receiver<StreamEvent> {
        self.rx
    }

    /// 等待执行完毕，收集所有输出为完整结果
    ///
    /// 等效于传统的阻塞式 `exec()`，但底层是流式的。
    /// 返回 `None` 表示通道在收到 `Done` 事件前已关闭（不应发生，除非进程被强制终止）。
    pub fn collect(self) -> Option<SandboxResult> {
        let mut stdout = String::new();
        let mut stderr = String::new();
        for event in self.rx {
            match event {
                StreamEvent::Stdout(s) => stdout.push_str(&s),
                StreamEvent::Stderr(s) => stderr.push_str(&s),
                StreamEvent::Done(mut r) => {
                    r.stdout = stdout;
                    r.stderr = stderr;
                    return Some(r);
                }
            }
        }
        None
    }
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
        let stream = self.exec_streaming(command, args, config_path, timeout_secs)?;
        stream.collect().ok_or_else(|| "沙箱流意外结束（未收到 Done 事件）".into())
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
        let stream = self.exec_with_config_streaming(command, args, config, timeout_secs)?;
        stream.collect().ok_or_else(|| "沙箱流意外结束（未收到 Done 事件）".into())
    }

    /// 在沙箱中执行命令，实时输出流
    ///
    /// 返回 [`SandboxStream`]，通过 `Receiver<StreamEvent>` 实时获取输出。
    /// 最后一条事件一定是 `StreamEvent::Done(SandboxResult)`。
    ///
    /// ```no_run
    /// use sandbox_host::SandboxHost;
    /// use std::path::PathBuf;
    ///
    /// let host = SandboxHost::new(
    ///     PathBuf::from("output/sandbox_hook_x64.dll"),
    ///     PathBuf::from("output/sandbox_hook_x86.dll"),
    ///     PathBuf::from("output/sandbox_helper_x86.exe"),
    /// );
    ///
    /// let stream = host.exec_streaming(
    ///     "cmd.exe",
    ///     &vec!["/c".into(), "echo hello".into()],
    ///     None::<PathBuf>,
    ///     Some(30),
    /// ).unwrap();
    ///
    /// for event in stream.into_receiver() {
    ///     match event {
    ///         sandbox_host::StreamEvent::Stdout(s) => print!("{}", s),
    ///         sandbox_host::StreamEvent::Stderr(s) => eprint!("{}", s),
    ///         sandbox_host::StreamEvent::Done(r) => {
    ///             println!("\n--- exit_code={} ---", r.exit_code);
    ///             break;
    ///         }
    ///     }
    /// }
    /// ```
    pub fn exec_streaming(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        config_path: Option<impl AsRef<Path>>,
        timeout_secs: Option<u64>,
    ) -> Result<SandboxStream, Box<dyn std::error::Error>> {
        let cfg_path = config_path.map(|p| p.as_ref().to_path_buf());
        let sandbox_config = config::load_config(cfg_path)?;
        self.run_streaming(command, args, &sandbox_config, timeout_secs)
    }

    /// 在沙箱中执行命令，实时输出流（直接传入配置对象）
    pub fn exec_with_config_streaming(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        config: &sandbox_core::SandboxConfig,
        timeout_secs: Option<u64>,
    ) -> Result<SandboxStream, Box<dyn std::error::Error>> {
        log::info!("沙箱配置: {}", config.name);
        self.run_streaming(command, args, config, timeout_secs)
    }

    /// 内部：流式执行核心逻辑
    fn run_streaming(
        &self,
        command: impl Into<String>,
        args: impl AsRef<[String]>,
        sandbox_config: &sandbox_core::SandboxConfig,
        timeout_param: Option<u64>,
    ) -> Result<SandboxStream, Box<dyn std::error::Error>> {
        let command = command.into();
        let cmd_args = args.as_ref().to_vec();

        log::info!("沙箱(流式): {}", sandbox_config.name);

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

        log::info!("流式 PID={} 已启动", process_id);

        // 创建通道：实时推送输出事件
        let (tx, rx) = mpsc::channel::<StreamEvent>();

        // HANDLE 不是 Send，转为 usize 传递
        let stdout_h = stdout_reader.0 as usize;
        let stderr_h = stderr_reader.0 as usize;

        // ── stdout 读取线程（实时推送） ──
        let tx_out = tx.clone();
        let stdout_thread = std::thread::spawn(move || {
            inject::read_pipe_stream(stdout_h, |data| {
                let text = String::from_utf8_lossy(data).to_string();
                tx_out.send(StreamEvent::Stdout(text)).map_err(|_| ())
            });
        });

        // ── stderr 读取线程（实时推送） ──
        let tx_err = tx.clone();
        let stderr_thread = std::thread::spawn(move || {
            inject::read_pipe_stream(stderr_h, |data| {
                let text = String::from_utf8_lossy(data).to_string();
                tx_err.send(StreamEvent::Stderr(text)).map_err(|_| ())
            });
        });

        // ── 等待/超时线程 ──
        // 负责：等待进程退出 → join reader 确保输出完整 → 刷审计 → 发送 Done 事件
        // IpcServer 已 impl Send，JoinHandle<()> 也是 Send，可安全移入线程
        // process_handle 是 HANDLE(*mut c_void)，不是 Send，转为 usize
        let process_h = process_handle as usize;
        let timeout_ms = timeout_param.unwrap_or(0).max(1) * 1000;
        std::thread::spawn(move || {
            // 1) 等待进程退出
            let process = process_h as *mut std::ffi::c_void;
            let exit_result = if timeout_ms > 0 {
                inject::wait_for_process_timeout(process, process_id, timeout_ms as u32)
                    .map(|code| code as i32)
            } else {
                inject::wait_for_process(process, process_id)
                    .map(|code| code as i32)
            };

            // 2) join reader 线程（确保所有输出已被消费完再发 Done）
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();

            // 3) 刷出审计事件并发送结果
            match exit_result {
                Ok(exit_code) => {
                    log::info!("流式 PID={} 退出: {}", process_id, exit_code);
                    ipc_server.flush_audit();
                    let audit_summary = ipc_server.summary();

                    let _ = tx.send(StreamEvent::Done(SandboxResult {
                        exit_code,
                        stdout: String::new(),
                        stderr: String::new(),
                        audit_summary,
                        pid: process_id,
                    }));
                }
                Err(e) => {
                    log::error!("流式 PID={} 异常: {}", process_id, e);
                    let _ = tx.send(StreamEvent::Done(SandboxResult {
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: String::new(),
                        audit_summary: format!("进程异常: {}", e),
                        pid: process_id,
                    }));
                }
            }
        });

        Ok(SandboxStream { rx })
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

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    // ── SandboxStream 测试 ────────────────────────────────────────────

    #[test]
    fn test_stream_collect_basic() {
        let (tx, rx) = mpsc::channel();
        tx.send(StreamEvent::Stdout("hello ".into())).unwrap();
        tx.send(StreamEvent::Stdout("world\n".into())).unwrap();
        tx.send(StreamEvent::Stderr("err log\n".into())).unwrap();
        tx.send(StreamEvent::Done(SandboxResult {
            exit_code: 0, stdout: String::new(), stderr: String::new(),
            audit_summary: "audit ok".into(), pid: 1234,
        })).unwrap();

        let result = SandboxStream { rx }.collect().expect("should have result");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello world\n");
        assert_eq!(result.stderr, "err log\n");
        assert_eq!(result.audit_summary, "audit ok");
        assert_eq!(result.pid, 1234);
    }

    #[test]
    fn test_stream_collect_no_stdout() {
        let (tx, rx) = mpsc::channel();
        tx.send(StreamEvent::Stderr("only err".into())).unwrap();
        tx.send(StreamEvent::Done(SandboxResult {
            exit_code: 1, stdout: String::new(), stderr: String::new(),
            audit_summary: "".into(), pid: 1,
        })).unwrap();

        let result = SandboxStream { rx }.collect().expect("should have result");
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.stdout, "");
        assert_eq!(result.stderr, "only err");
    }

    #[test]
    fn test_stream_collect_only_done() {
        let (tx, rx) = mpsc::channel();
        tx.send(StreamEvent::Done(SandboxResult {
            exit_code: 42, stdout: String::new(), stderr: String::new(),
            audit_summary: "direct".into(), pid: 99,
        })).unwrap();

        let result = SandboxStream { rx }.collect().expect("should have result");
        assert_eq!(result.exit_code, 42);
        assert_eq!(result.audit_summary, "direct");
        assert_eq!(result.pid, 99);
    }

    #[test]
    fn test_stream_collect_empty_channel() {
        let (_tx, rx) = mpsc::channel::<StreamEvent>();
        drop(_tx);
        assert!(SandboxStream { rx }.collect().is_none());
    }

    #[test]
    fn test_stream_collect_first_done_wins() {
        let (tx, rx) = mpsc::channel();
        tx.send(StreamEvent::Done(SandboxResult {
            exit_code: 7, stdout: String::new(), stderr: String::new(),
            audit_summary: "first".into(), pid: 1,
        })).unwrap();
        tx.send(StreamEvent::Done(SandboxResult {
            exit_code: 8, stdout: String::new(), stderr: String::new(),
            audit_summary: "second".into(), pid: 2,
        })).unwrap();

        let result = SandboxStream { rx }.collect().expect("should have result");
        assert_eq!(result.exit_code, 7, "should stop at first Done");
        assert_eq!(result.audit_summary, "first");
    }

    #[test]
    fn test_stream_into_receiver() {
        let (tx, rx) = mpsc::channel();
        tx.send(StreamEvent::Stdout("x".into())).unwrap();
        drop(tx);

        let stream = SandboxStream { rx };
        let rx2 = stream.into_receiver();
        let events: Vec<_> = rx2.iter().collect();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_stream_receiver_ref() {
        let (_tx, rx) = mpsc::channel::<StreamEvent>();
        let stream = SandboxStream { rx };
        let _ = stream.receiver();
    }

    // ── SandboxHost 构建测试 ─────────────────────────────────────

    #[test]
    fn test_host_new_with_paths() {
        let host = SandboxHost::new(
            PathBuf::from("a.dll"),
            PathBuf::from("b.dll"),
            PathBuf::from("c.exe"),
        );
        assert_eq!(host.paths().dll_x64, PathBuf::from("a.dll"));
        assert_eq!(host.paths().dll_x86, PathBuf::from("b.dll"));
        assert_eq!(host.paths().helper_x86, PathBuf::from("c.exe"));
    }

    #[test]
    fn test_host_with_paths_struct() {
        let paths = SandboxPaths {
            dll_x64: "x64.dll".into(),
            dll_x86: "x86.dll".into(),
            helper_x86: "helper.exe".into(),
        };
        let host = SandboxHost::with_paths(paths.clone());
        assert_eq!(host.paths().dll_x64, PathBuf::from("x64.dll"));
        assert_eq!(host.paths().dll_x86, PathBuf::from("x86.dll"));
        assert_eq!(host.paths().helper_x86, PathBuf::from("helper.exe"));
    }

    #[test]
    fn test_host_paths_read() {
        let host = SandboxHost::new("a.dll", "b.dll", "c.exe");
        let p = host.paths();
        let _ = (&p.dll_x64, &p.dll_x86, &p.helper_x86);
    }

    // ── SandboxResult 序列化测试 ─────────────────────────────

    #[test]
    fn test_result_serialization() {
        let r = SandboxResult {
            exit_code: 42,
            stdout: "out".into(),
            stderr: "err".into(),
            audit_summary: "audit".into(),
            pid: 999,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"exit_code\":42"));
        assert!(json.contains("\"pid\":999"));
        assert!(json.contains("\"stdout\":\"out\""));
    }

    #[test]
    fn test_result_clone_and_debug() {
        let r = SandboxResult {
            exit_code: 1, stdout: "a".into(), stderr: "b".into(),
            audit_summary: "c".into(), pid: 2,
        };
        let r2 = r.clone();
        assert_eq!(r2.exit_code, 1);
        let _ = format!("{:?}", r2);
    }

    // ── 流事件类型测试 ─────────────────────────────────────────

    #[test]
    fn test_stream_event_variants() {
        let s = StreamEvent::Stdout("out".into());
        let e = StreamEvent::Stderr("err".into());
        let d = StreamEvent::Done(SandboxResult {
            exit_code: 0, stdout: String::new(), stderr: String::new(),
            audit_summary: String::new(), pid: 0,
        });
        assert!(format!("{:?}", s).contains("Stdout"));
        assert!(format!("{:?}", e).contains("Stderr"));
        assert!(format!("{:?}", d).contains("Done"));
    }

    // ── 错误路径测试（不启动实际沙箱进程） ─────────────────────

    #[test]
    fn test_exec_nonexistent_config_returns_error() {
        let host = SandboxHost::new("x.dll", "x.dll", "x.exe");
        let result = host.exec(
            "cmd.exe",
            &Vec::<String>::new(),
            Some(PathBuf::from("__no_such_config_file__.json")),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("不存在") || err.contains("__no_such_config_file__"));
    }

    #[test]
    fn test_exec_streaming_nonexistent_config_returns_error() {
        let host = SandboxHost::new("x.dll", "x.dll", "x.exe");
        let result = host.exec_streaming(
            "cmd.exe",
            &Vec::<String>::new(),
            Some(PathBuf::from("__no_such_config__.json")),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_exec_with_config_nonexistent_dll_returns_error() {
        let host = SandboxHost::new(
            PathBuf::from("C:\\__nonexistent_hook_x64__.dll"),
            PathBuf::from("C:\\__nonexistent_hook_x86__.dll"),
            PathBuf::from("C:\\__nonexistent_helper__.exe"),
        );
        let config = sandbox_core::SandboxConfig::default();
        let result = host.exec_with_config(
            "cmd.exe",
            &vec!["/c".into(), "echo test".into()],
            &config,
            Some(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_run_sandbox_free_function_nonexistent_config() {
        let result = run_sandbox(
            "cmd.exe",
            &Vec::<String>::new(),
            Some(PathBuf::from("__no_such_config__.json")),
            None,
        );
        assert!(result.is_err());
    }
}
