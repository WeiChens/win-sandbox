//! 配置加载模块

use sandbox_core::SandboxConfig;
use std::path::PathBuf;

/// 直接使用提供的配置对象（库 API 使用）
pub fn use_config(config: SandboxConfig) -> SandboxConfig {
    log::info!("使用直接提供的沙箱配置: {}", config.name);
    config
}

/// 加载沙箱配置
///
/// 查找顺序：
/// 1. 显式指定的路径
/// 2. 当前目录 `sandbox.json`
/// 3. 可执行文件目录 `sandbox.json`
/// 4. 默认配置
pub fn load_config(explicit_path: Option<PathBuf>) -> Result<SandboxConfig, Box<dyn std::error::Error>> {
    // 1. 显式路径
    if let Some(ref path) = explicit_path {
        if path.exists() {
            log::info!("从指定路径加载配置: {:?}", path);
            return SandboxConfig::from_file(path);
        } else {
            return Err(format!("配置文件不存在: {:?}", path).into());
        }
    }

    // 2. 当前目录
    let cwd_config = PathBuf::from("sandbox.json");
    if cwd_config.exists() {
        log::info!("从当前目录加载配置: {:?}", cwd_config);
        return SandboxConfig::from_file(&cwd_config);
    }

    // 3. 可执行文件目录
    if let Ok(exe_path) = std::env::current_exe() {
        let exe_dir = exe_path.parent().unwrap_or(std::path::Path::new("."));
        let exe_config = exe_dir.join("sandbox.json");
        if exe_config.exists() {
            log::info!("从可执行目录加载配置: {:?}", exe_config);
            return SandboxConfig::from_file(&exe_config);
        }
    }

    // 4. 默认
    log::warn!("未找到配置文件，使用默认配置");
    Ok(SandboxConfig::default())
}
