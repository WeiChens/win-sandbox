//! 沙箱配置模型

use serde::{Deserialize, Serialize};
use crate::acl::{FileRule, NetRule};
use std::path::PathBuf;

/// 完整沙箱配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// 配置名称
    #[serde(default = "default_name")]
    pub name: String,

    /// 文件系统权限规则列表（按顺序匹配，第一个匹配生效）
    #[serde(default)]
    pub file_permissions: Vec<FileRule>,

    /// 网络权限规则列表
    #[serde(default)]
    pub network_permissions: Vec<NetRule>,

    /// 沙箱工作根目录
    #[serde(default = "default_sandbox_root")]
    pub sandbox_root: PathBuf,

    /// Shell 路径
    #[serde(default = "default_shell")]
    pub shell_path: PathBuf,

    /// 是否启用网络隔离
    #[serde(default = "default_true")]
    pub enable_network_isolation: bool,

    /// 是否启用递归注入（子进程自动注入沙箱 DLL）
    #[serde(default = "default_true")]
    pub enable_recursive_injection: bool,

    /// 审计日志目录
    #[serde(default = "default_audit_dir")]
    pub audit_log_dir: PathBuf,

    /// 详细审计模式
    #[serde(default)]
    pub verbose_audit: bool,

    /// 超时秒数（0 = 无超时）
    #[serde(default)]
    pub timeout_secs: u64,
}

fn default_name() -> String { "default-sandbox".into() }
fn default_sandbox_root() -> PathBuf { PathBuf::from(".\\sandbox-workdir") }
fn default_shell() -> PathBuf { PathBuf::from("C:\\Windows\\System32\\cmd.exe") }
fn default_true() -> bool { true }
fn default_audit_dir() -> PathBuf { PathBuf::from(".\\sandbox-logs") }

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            name: default_name(),
            file_permissions: vec![
                FileRule {
                    pattern: "C:\\Users\\*\\**".into(),
                    permission: crate::acl::FilePermission::ReadOnly,
                },
                FileRule {
                    pattern: "C:\\Windows\\**".into(),
                    permission: crate::acl::FilePermission::ReadOnly,
                },
            ],
            network_permissions: vec![
                NetRule {
                    host: "127.0.0.1".into(),
                    port: 0,
                    protocol: crate::acl::NetProtocol::Any,
                    action: crate::acl::NetAction::Allow,
                },
                NetRule {
                    host: "localhost".into(),
                    port: 0,
                    protocol: crate::acl::NetProtocol::Any,
                    action: crate::acl::NetAction::Allow,
                },
                NetRule {
                    host: "*".into(),
                    port: 0,
                    protocol: crate::acl::NetProtocol::Tcp,
                    action: crate::acl::NetAction::Allow,
                },
            ],
            sandbox_root: default_sandbox_root(),
            shell_path: default_shell(),
            enable_network_isolation: true,
            enable_recursive_injection: true,
            audit_log_dir: default_audit_dir(),
            verbose_audit: false,
            timeout_secs: 0,
        }
    }
}

impl SandboxConfig {
    /// 从 JSON 文件加载配置
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// 开发默认配置（宽松）
    pub fn dev_config() -> Self {
        Self::default()
    }

    /// 严格配置（最小权限）
    pub fn strict_config() -> Self {
        Self {
            name: "strict-sandbox".into(),
            file_permissions: vec![
                FileRule {
                    pattern: "C:\\Users\\*\\**".into(),
                    permission: crate::acl::FilePermission::ReadOnly,
                },
                FileRule {
                    pattern: "C:\\Windows\\**".into(),
                    permission: crate::acl::FilePermission::ReadOnly,
                },
                FileRule {
                    pattern: "*".into(),
                    permission: crate::acl::FilePermission::Deny,
                },
            ],
            network_permissions: vec![
                NetRule {
                    host: "*".into(),
                    port: 0,
                    protocol: crate::acl::NetProtocol::Any,
                    action: crate::acl::NetAction::Deny,
                },
            ],
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let config = SandboxConfig::default();
        assert_eq!(config.name, "default-sandbox");
        assert!(config.enable_network_isolation);
        assert!(config.enable_recursive_injection);
        assert_eq!(config.file_permissions.len(), 2);
    }

    #[test]
    fn test_strict_config_denies_network() {
        let config = SandboxConfig::strict_config();
        let first_net = &config.network_permissions[0];
        assert_eq!(first_net.action, crate::acl::NetAction::Deny);
    }

    #[test]
    fn test_strict_config_denies_all_files() {
        let config = SandboxConfig::strict_config();
        let last_rule = config.file_permissions.last().unwrap();
        assert_eq!(last_rule.pattern, "*");
        assert_eq!(last_rule.permission, crate::acl::FilePermission::Deny);
    }

    #[test]
    fn test_deserialize_minimal_config() {
        let json = r#"{"name": "test"}"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "test");
    }

    #[test]
    fn test_deserialize_full_config() {
        let json = r#"{
            "name": "full-test",
            "file_permissions": [
                {"pattern": "C:\\Users\\*\\**", "permission": "read_only"}
            ],
            "network_permissions": [
                {"host": "127.0.0.1", "port": 8080, "protocol": "tcp", "action": "allow"}
            ],
            "enable_network_isolation": false,
            "enable_recursive_injection": false,
            "timeout_secs": 60
        }"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "full-test");
        assert!(!config.enable_network_isolation);
        assert!(!config.enable_recursive_injection);
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.file_permissions.len(), 1);
        assert_eq!(config.network_permissions.len(), 1);
    }

    #[test]
    fn test_deserialize_dev_config() {
        let config = SandboxConfig::dev_config();
        let dev_json = serde_json::to_string(&config).unwrap();
        let restored: SandboxConfig = serde_json::from_str(&dev_json).unwrap();
        assert_eq!(restored.name, config.name);
        assert_eq!(restored.file_permissions.len(), config.file_permissions.len());
    }

    #[test]
    fn test_config_defaults_on_missing_fields() {
        // 空 JSON 对象应使用所有默认值
        let json = r#"{}"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "default-sandbox");
        assert_eq!(config.sandbox_root, PathBuf::from(".\\sandbox-workdir"));
        assert!(config.enable_network_isolation);
        assert_eq!(config.timeout_secs, 0);
    }

    #[test]
    fn test_timeout_serialization() {
        let mut config = SandboxConfig::default();
        config.timeout_secs = 300;
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("300"));
        let restored: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.timeout_secs, 300);
    }

    #[test]
    fn test_file_rule_order_is_preserved() {
        let json = r#"{
            "name": "order-test",
            "file_permissions": [
                {"pattern": "first", "permission": "deny"},
                {"pattern": "second", "permission": "read_only"},
                {"pattern": "third", "permission": "inherit"}
            ]
        }"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.file_permissions[0].pattern, "first");
        assert_eq!(config.file_permissions[1].pattern, "second");
        assert_eq!(config.file_permissions[2].pattern, "third");
    }
}
