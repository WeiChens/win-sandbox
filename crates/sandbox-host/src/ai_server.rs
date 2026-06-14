//! AI 调用接口 — HTTP JSON-RPC 服务
//!
//! AI 通过 HTTP 调用沙箱执行命令：
//!
//! POST /exec
//! {
//!   "command": "cmd.exe",
//!   "args": ["/c", "dir"],
//!   "timeout_secs": 30
//! }
//!
//! 响应：
//! {
//!   "exit_code": 0,
//!   "stdout": "...",
//!   "stderr": "...",
//!   "audit_summary": "..."
//! }

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

/// 启动 AI HTTP 服务
pub fn serve(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;
    log::info!("AI 沙箱服务已启动: http://{}", addr);
    println!("AI 沙箱服务已启动: http://{}", addr);
    println!("API 端点:");
    println!("  POST /exec  — 执行命令");
    println!("  GET  /health — 健康检查");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| handle_client(stream));
            }
            Err(e) => {
                log::error!("连接错误: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap_or_else(|_| {
        panic!("stream clone failed");
    }));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, r#"{"error": "bad request"}"#);
        return;
    }

    let method = parts[0];
    let path = parts[1];

    // 读取 headers
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() { break; }
        let line = line.trim().to_lowercase();
        if line.is_empty() { break; }
        if line.starts_with("content-length:") {
            content_length = line["content-length:".len()..]
                .trim().parse().unwrap_or(0);
        }
    }

    // 读取 body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        use std::io::Read;
        let _ = reader.read_exact(&mut body);
    }

    match (method, path) {
        ("GET", "/health") => {
            send_response(&mut stream, 200, r#"{"status":"ok","service":"sandbox-ai"}"#);
        }
        ("POST", "/exec") => {
            let body_str = String::from_utf8_lossy(&body);
            match handle_exec(&body_str) {
                Ok(response) => send_response(&mut stream, 200, &response),
                Err(e) => send_response(&mut stream, 500, &format!(r#"{{"error":"{}"}}"#, e)),
            }
        }
        _ => {
            send_response(&mut stream, 404, r#"{"error":"not found"}"#);
        }
    }
}

fn handle_exec(body: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct ExecRequest {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        timeout_secs: u64,
    }

    let req: ExecRequest = serde_json::from_str(body)?;

    log::info!("AI exec 请求: {} {:?}", req.command, req.args);

    // 使用 cmd /c 作为包装
    let mut cmd_args = vec!["/c".to_string(), req.command.clone()];
    cmd_args.extend(req.args.clone());

    let output = std::process::Command::new("cmd.exe")
        .args(&cmd_args)
        .output();

    match output {
        Ok(out) => {
            let response = serde_json::json!({
                "exit_code": out.status.code().unwrap_or(-1),
                "stdout": String::from_utf8_lossy(&out.stdout).to_string(),
                "stderr": String::from_utf8_lossy(&out.stderr).to_string(),
                "audit_summary": "no sandbox in AI direct mode"
            });
            Ok(serde_json::to_string(&response)?)
        }
        Err(e) => {
            Err(format!("命令执行失败: {}", e).into())
        }
    }
}

fn send_response(stream: &mut TcpStream, status: u16, body: &str) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status, status_text,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}
