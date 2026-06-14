//! ACL 规则模型 — 文件权限 + 网络权限

use serde::{Deserialize, Serialize};

// ============================================================================
// 文件权限
// ============================================================================

/// 文件系统操作权限
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilePermission {
    /// 完全放行（继承父目录权限）
    #[serde(alias = "inherit")]
    Inherit,
    /// 只读（拒绝写入、删除、重命名）
    #[serde(alias = "read_only")]
    ReadOnly,
    /// 完全拒绝
    Deny,
}

impl Default for FilePermission {
    fn default() -> Self { Self::Inherit }
}

/// 单条文件 ACL 规则
///
/// `pattern` 使用 glob 语法，例如：
/// - `C:\Users\*\Projects\**` — 匹配所有用户下的 Projects 目录树
/// - `C:\Windows\**` — 匹配整个 Windows 目录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRule {
    /// Glob 匹配模式
    pub pattern: String,
    /// 匹配后的权限
    pub permission: FilePermission,
}

// ============================================================================
// 网络权限
// ============================================================================

/// 网络协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetProtocol {
    Tcp,
    Udp,
    #[serde(alias = "any")]
    Any,
}

/// 网络动作
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetAction {
    Allow,
    Deny,
}

/// 单条网络 ACL 规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRule {
    /// 目标主机（支持 `*` 通配符、IP 地址、域名）
    pub host: String,
    /// 目标端口（0 = 任意端口）
    pub port: u16,
    /// 协议
    pub protocol: NetProtocol,
    /// 动作
    pub action: NetAction,
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_file_permission() {
        let perm: FilePermission = serde_json::from_str(r#""inherit""#).unwrap();
        assert_eq!(perm, FilePermission::Inherit);

        let perm: FilePermission = serde_json::from_str(r#""read_only""#).unwrap();
        assert_eq!(perm, FilePermission::ReadOnly);

        let perm: FilePermission = serde_json::from_str(r#""deny""#).unwrap();
        assert_eq!(perm, FilePermission::Deny);
    }

    #[test]
    fn test_file_permission_default() {
        assert_eq!(FilePermission::default(), FilePermission::Inherit);
    }

    #[test]
    fn test_deserialize_file_rule() {
        let json = r#"{"pattern": "C:\\Users\\*\\**", "permission": "read_only"}"#;
        let rule: FileRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.pattern, r"C:\Users\*\**");
        assert_eq!(rule.permission, FilePermission::ReadOnly);
    }

    #[test]
    fn test_deserialize_file_rule_with_aliases() {
        // "inherit" 别名为 Inherit (serde alias)
        let json = r#"{"pattern": "**", "permission": "inherit"}"#;
        let rule: FileRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.permission, FilePermission::Inherit);
    }

    #[test]
    fn test_deserialize_net_rule() {
        let json = r#"{"host": "*.github.com", "port": 443, "protocol": "tcp", "action": "allow"}"#;
        let rule: NetRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.host, "*.github.com");
        assert_eq!(rule.port, 443);
        assert_eq!(rule.protocol, NetProtocol::Tcp);
        assert_eq!(rule.action, NetAction::Allow);
    }

    #[test]
    fn test_deserialize_net_rule_any_protocol() {
        let json = r#"{"host": "*", "port": 0, "protocol": "any", "action": "deny"}"#;
        let rule: NetRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.protocol, NetProtocol::Any);
        assert_eq!(rule.action, NetAction::Deny);
        assert_eq!(rule.port, 0);
    }

    #[test]
    fn test_net_protocol_serialization_roundtrip() {
        for proto in &[NetProtocol::Tcp, NetProtocol::Udp, NetProtocol::Any] {
            let json = serde_json::to_string(proto).unwrap();
            let restored: NetProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(*proto, restored);
        }
    }

    #[test]
    fn test_net_action_serialization() {
        let allow = serde_json::to_string(&NetAction::Allow).unwrap();
        assert!(allow.contains("allow"));
        let deny = serde_json::to_string(&NetAction::Deny).unwrap();
        assert!(deny.contains("deny"));
    }
}
