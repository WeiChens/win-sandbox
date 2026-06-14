// net_acl.h — 网络 ACL 检查
//
// Hook Winsock connect/getaddrinfo/DNS 函数，
// 按规则放行/拒绝网络连接。

#pragma once
#include <string>
#include <vector>

/// 网络协议
enum class NetProtocol : int {
    Tcp = 0,
    Udp = 1,
    Any = 2,
};

/// 网络动作
enum class NetAction : int {
    Allow = 0,
    Deny = 1,
};

/// 单条网络 ACL 规则
struct NetRule {
    std::string host;       // 主机名/IP（支持 * 通配符）
    uint16_t    port;       // 端口（0 = 任意）
    NetProtocol protocol;   // 协议
    NetAction   action;     // 动作
};

/// 从 JSON 配置初始化网络 ACL
bool InitNetAcl(const std::string& json);

/// 检查网络连接是否允许
/// @param host  目标主机名或 IP
/// @param port  目标端口
/// @param proto 协议
/// @return true=允许，false=拒绝
bool CheckNetPermission(const std::string& host, uint16_t port, NetProtocol proto);

/// 安装网络 Hook（Winsock API）
void InstallNetHooks();
