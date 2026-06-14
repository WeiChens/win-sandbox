//! 审计日志查看模块

use crate::cli::AuditFormat;
use std::path::PathBuf;

/// 显示审计日志
pub fn show_audit(
    log_dir: Option<PathBuf>,
    format: AuditFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = log_dir.unwrap_or_else(|| PathBuf::from(".\\sandbox-logs"));

    if !dir.exists() {
        println!("审计日志目录不存在: {:?}", dir);
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "log" || ext == "json"))
        .collect();

    entries.sort_by_key(|e| e.path());

    match format {
        AuditFormat::Json => {
            println!("[");
            for (i, entry) in entries.iter().enumerate() {
                let content = std::fs::read_to_string(entry.path())?;
                print!("{}", content.trim());
                if i < entries.len() - 1 { println!(","); }
            }
            println!("\n]");
        }
        AuditFormat::Text => {
            println!("=== 审计日志 ({} 个文件) ===", entries.len());
            for entry in &entries {
                let meta = entry.metadata()?;
                println!("\n--- {:?} ({} bytes) ---", entry.file_name(), meta.len());
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    println!("{}", content);
                }
            }
        }
    }

    Ok(())
}
