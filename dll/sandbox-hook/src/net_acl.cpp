// net_acl.cpp — 网络 ACL 实现
//
// Hook Winsock connect/getaddrinfo/DNS 查询。

#include "net_acl.h"
#include "detour.h"
#include "ipc_client.h"
#include "utils.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

// NTSTATUS codes
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif

// ============================================================================
// 规则存储
// ============================================================================

static std::vector<NetRule> g_netRules;
static std::mutex g_netMutex;
static bool g_netInitialized = false;

// ============================================================================
// 原始函数指针
// ============================================================================

typedef int (WSAAPI *PFN_connect)(SOCKET, const sockaddr*, int);
typedef int (WSAAPI *PFN_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI *PFN_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_W)(PCWSTR, WORD, DWORD, PVOID, PDNS_RECORD*, PVOID*);

static PFN_connect Real_connect = nullptr;
static PFN_getaddrinfo Real_getaddrinfo = nullptr;
static PFN_GetAddrInfoW Real_GetAddrInfoW = nullptr;
static PFN_DnsQuery_W Real_DnsQuery_W = nullptr;

// ============================================================================
// 配置解析
// ============================================================================

static NetProtocol ParseNetProtocol(const std::string& prot) {
    if (prot == "tcp" || prot == "TCP") return NetProtocol::Tcp;
    if (prot == "udp" || prot == "UDP") return NetProtocol::Udp;
    return NetProtocol::Any;
}

static NetAction ParseNetAction(const std::string& act) {
    if (act == "deny" || act == "DENY") return NetAction::Deny;
    return NetAction::Allow;
}

bool InitNetAcl(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_netMutex);
    g_netRules.clear();

    // 查找 "network_permissions"
    size_t arrStart = json.find("\"network_permissions\"");
    if (arrStart == std::string::npos) {
        g_netInitialized = true;
        return true;
    }

    arrStart = json.find('[', arrStart);
    if (arrStart == std::string::npos) {
        g_netInitialized = true;
        return true;
    }

    size_t arrEnd = json.find(']', arrStart);
    if (arrEnd == std::string::npos) arrEnd = json.length();

    size_t pos = arrStart + 1;
    while (pos < arrEnd) {
        size_t objStart = json.find('{', pos);
        if (objStart == std::string::npos || objStart >= arrEnd) break;
        size_t objEnd = json.find('}', objStart);
        if (objEnd == std::string::npos || objEnd >= arrEnd) break;

        NetRule rule;
        size_t innerPos = objStart;

        // 简易 JSON 解析
        auto getStr = [&](const char* key) -> std::string {
            std::string search = std::string("\"") + key + "\"";
            size_t kp = json.find(search, innerPos);
            if (kp == std::string::npos || kp >= objEnd) return "";
            size_t vs = json.find('"', kp + search.length() + 1);
            if (vs == std::string::npos || vs >= objEnd) return "";
            vs++;
            size_t ve = json.find('"', vs);
            if (ve == std::string::npos || ve >= objEnd) return "";
            return json.substr(vs, ve - vs);
        };

        auto getInt = [&](const char* key) -> int {
            std::string s = getStr(key);
            if (s.empty()) {
                std::string search = std::string("\"") + key + "\"";
                size_t kp = json.find(search, innerPos);
                if (kp == std::string::npos || kp >= objEnd) return 0;
                size_t vs = json.find(':', kp);
                if (vs == std::string::npos || vs >= objEnd) return 0;
                vs++;
                while (vs < objEnd && (json[vs] == ' ' || json[vs] == '\t')) vs++;
                size_t ve = vs;
                while (ve < objEnd && json[ve] >= '0' && json[ve] <= '9') ve++;
                if (ve == vs) return 0;
                return std::stoi(json.substr(vs, ve - vs));
            }
            return std::stoi(s);
        };

        rule.host = getStr("host");
        rule.port = static_cast<uint16_t>(getInt("port"));
        rule.protocol = ParseNetProtocol(getStr("protocol"));
        rule.action = ParseNetAction(getStr("action"));

        if (!rule.host.empty()) {
            g_netRules.push_back(rule);
        }

        pos = objEnd + 1;
    }

    g_netInitialized = true;
    return true;
}

// ============================================================================
// 权限检查
// ============================================================================

static bool GlobMatchSimple(const std::string& pattern, const std::string& target) {
    // 简化版 glob 匹配
    if (pattern == "*") return true;

    size_t pi = 0, ti = 0;
    size_t pLen = pattern.length(), tLen = target.length();

    while (pi < pLen && ti < tLen) {
        if (pattern[pi] == '*') {
            pi++;
            if (pi == pLen) return true;
            // 贪婪匹配：找到 pattern 下一段
            while (ti < tLen) {
                if (toupper(target[ti]) == toupper(pattern[pi])) {
                    if (GlobMatchSimple(pattern.substr(pi), target.substr(ti)))
                        return true;
                }
                ti++;
            }
            return false;
        }
        if (toupper(pattern[pi]) != toupper(target[ti])) return false;
        pi++; ti++;
    }

    while (pi < pLen && pattern[pi] == '*') pi++;
    return pi == pLen && ti == tLen;
}

bool CheckNetPermission(const std::string& host, uint16_t port, NetProtocol proto) {
    if (!g_netInitialized) return true;

    std::lock_guard<std::mutex> lock(g_netMutex);

    for (const auto& rule : g_netRules) {
        // 主机匹配
        if (!GlobMatchSimple(rule.host, host)) continue;

        // 端口匹配（0 = 任意）
        if (rule.port != 0 && rule.port != port) continue;

        // 协议匹配
        if (rule.protocol != NetProtocol::Any && rule.protocol != proto) continue;

        // 匹配！返回动作
        return rule.action == NetAction::Allow;
    }

    // 无匹配规则：默认允许
    return true;
}

// ============================================================================
// Hook 函数
// ============================================================================

static int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (name && namelen >= sizeof(sockaddr_in)) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(name);
        if (sin->sin_family == AF_INET) {
            char ipBuf[64];
            inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
            uint16_t port = ntohs(sin->sin_port);

            if (!CheckNetPermission(ipBuf, port, NetProtocol::Tcp)) {
                AuditLog(AuditEventType::NetDeny, Utf8ToWide(ipBuf),
                         L"deny_connect", port, STATUS_ACCESS_DENIED);
                WSASetLastError(WSAEACCES);
                return SOCKET_ERROR;
            }

            AuditLog(AuditEventType::NetAllow, Utf8ToWide(ipBuf),
                     L"allow_connect", port, 0);
        }
    }
    return Real_connect(s, name, namelen);
}

static int WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
                                    const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    if (pNodeName) {
        if (!CheckNetPermission(pNodeName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, Utf8ToWide(pNodeName),
                     L"deny_dns", 0, STATUS_ACCESS_DENIED);
            return WSAHOST_NOT_FOUND;
        }
    }
    return Real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

static int WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                                     const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    if (pNodeName) {
        std::string nodeName = WideToUtf8(pNodeName);
        if (!CheckNetPermission(nodeName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, pNodeName,
                     L"deny_dns_w", 0, STATUS_ACCESS_DENIED);
            return WSAHOST_NOT_FOUND;
        }
    }
    return Real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

// ============================================================================
// 安装网络 Hook
// ============================================================================

void InstallNetHooks() {
    HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryW(L"ws2_32.dll");

    if (hWs2) {
        auto* connectTarget = (BYTE*)GetProcAddress(hWs2, "connect");
        if (connectTarget) {
            auto* tramp = (BYTE*)DetourInstall(connectTarget, (BYTE*)Hook_connect, "connect");
            if (tramp) Real_connect = (PFN_connect)tramp;
        }

        auto* gaiTarget = (BYTE*)GetProcAddress(hWs2, "getaddrinfo");
        if (gaiTarget) {
            auto* tramp = (BYTE*)DetourInstall(gaiTarget, (BYTE*)Hook_getaddrinfo, "getaddrinfo");
            if (tramp) Real_getaddrinfo = (PFN_getaddrinfo)tramp;
        }

        auto* gaiwTarget = (BYTE*)GetProcAddress(hWs2, "GetAddrInfoW");
        if (gaiwTarget) {
            auto* tramp = (BYTE*)DetourInstall(gaiwTarget, (BYTE*)Hook_GetAddrInfoW, "GetAddrInfoW");
            if (tramp) Real_GetAddrInfoW = (PFN_GetAddrInfoW)tramp;
        }
    }
}
