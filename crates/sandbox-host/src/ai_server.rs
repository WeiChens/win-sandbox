//! AI 调用接口 — HTTP JSON-RPC 服务
//!
//! POST /exec  {"command":"cmd.exe","args":["/c","dir"],"timeout_secs":30}
//! GET  /health
//! GET  /audit?last_n=50

use crate::SandboxResult;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Mutex;

/// 最近一次沙箱执行结果（用于 /audit 查询）
static LAST_RESULT: Mutex<Option<SandboxResult>> = Mutex::new(None);

pub fn serve(
    port: u16,
    run_fn: fn(String, Vec<String>, Option<PathBuf>, Option<u64>) -> Result<SandboxResult, Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    log::info!("AI 沙箱服务: http://{}", addr);
    println!("AI Sandbox API: http://{}", addr);
    println!("  POST /exec  — 沙箱执行命令");
    println!("  GET  /health — 健康检查");
    println!("  GET  /audit  — 最近审计摘要");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    handle_client(stream, run_fn);
                });
            }
            Err(e) => log::error!("连接错误: {}", e),
        }
    }

    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    run_fn: fn(String, Vec<String>, Option<PathBuf>, Option<u64>) -> Result<SandboxResult, Box<dyn std::error::Error>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, r#"{"error":"bad request"}"#);
        return;
    }

    let method = parts[0];
    let path = parts[1];

    // 读取 headers
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() { break; }
        if line.trim().is_empty() { break; }
        if line.to_lowercase().starts_with("content-length:") {
            content_length = line["content-length:".len()..].trim().parse().unwrap_or(0);
        }
    }

    // 读取 body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        use std::io::Read;
        let _ = reader.read_exact(&mut body);
    }

    match (method, path.split('?').next().unwrap_or("/")) {
        ("GET", "/health") => {
            send_response(&mut stream, 200, r#"{"status":"ok","service":"sandbox-ai"}"#);
        }
        ("GET", "/audit") => {
            let summary = LAST_RESULT.lock().unwrap()
                .as_ref()
                .map(|r| r.audit_summary.clone())
                .unwrap_or_else(|| "暂无审计数据".to_string());
            let json = serde_json::json!({"audit_summary": summary});
            send_response(&mut stream, 200, &json.to_string());
        }
        ("POST", "/exec") => {
            let body_str = String::from_utf8_lossy(&body);
            match handle_exec(&body_str, run_fn) {
                Ok(response) => send_response(&mut stream, 200, &response),
                Err(e) => send_response(&mut stream, 500, &format!(r#"{{"error":"{}"}}"#, e)),
            }
        }
        _ => {
            send_response(&mut stream, 404, r#"{"error":"not found"}"#);
        }
    }
}

fn handle_exec(
    body: &str,
    run_fn: fn(String, Vec<String>, Option<PathBuf>, Option<u64>) -> Result<SandboxResult, Box<dyn std::error::Error>>,
) -> Result<String, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct ExecRequest {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        timeout_secs: u64,
    }

    let req: ExecRequest = serde_json::from_str(body)?;
    log::info!("AI exec: {} {:?}", req.command, req.args);

    // ★ 使用沙箱执行
    let result = run_fn(req.command, req.args, None, Some(req.timeout_secs))?;

    // 缓存审计结果
    *LAST_RESULT.lock().unwrap() = Some(SandboxResult {
        exit_code: result.exit_code,
        stdout: String::new(), // 不缓存大段输出
        stderr: String::new(),
        audit_summary: result.audit_summary.clone(),
        pid: result.pid,
    });

    let response = serde_json::json!({
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "pid": result.pid,
        "audit_summary": result.audit_summary,
    });

    Ok(serde_json::to_string(&response)?)
}

fn send_response(stream: &mut TcpStream, status: u16, body: &str) {
    let status_text = match status {
        200 => "OK", 400 => "Bad Request", 404 => "Not Found",
        500 => "Internal Server Error", _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, status_text, body.len(), body
    );
    let _ = stream.write_all(response.as_bytes());
}
