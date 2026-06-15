// net_acl.cpp — 网络 ACL 实现
//
// 按 Trae 的方式重构：
// - 不在 DllMain 中 LoadLibrary（避免 Loader Lock 死锁）
// - 只 Hook 已加载的 DLL（GetModuleHandle），未加载则跳过
// - Hook WSAStartup 做延迟初始化

#include "net_acl.h"
#include "detour.h"
#include "ipc_client.h"
#include "utils.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

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

typedef int (WSAAPI *PFN_WSAStartup)(WORD, LPWSADATA);
typedef int (WSAAPI *PFN_connect)(SOCKET, const sockaddr*, int);
typedef int (WSAAPI *PFN_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI *PFN_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);

static PFN_WSAStartup Real_WSAStartup = nullptr;
static PFN_connect Real_connect = nullptr;
static PFN_getaddrinfo Real_getaddrinfo = nullptr;
static PFN_GetAddrInfoW Real_GetAddrInfoW = nullptr;

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

// 简易 JSON 取值（同 file_acl.cpp 模式）
static std::string JsonGetString(const std::string& json, const char* key, size_t& pos) {
    std::string search = std::string("\"") + key + "\"";
    size_t keyPos = json.find(search, pos);
    if (keyPos == std::string::npos) return "";

    size_t valStart = json.find(':', keyPos + search.length());
    if (valStart == std::string::npos) return "";

    valStart = json.find('"', valStart + 1);
    if (valStart == std::string::npos) return "";
    valStart++;

    size_t valEnd = json.find('"', valStart);
    if (valEnd == std::string::npos) return "";

    pos = valEnd + 1;
    return json.substr(valStart, valEnd - valStart);
}

static int JsonGetInt(const std::string& json, const char* key, size_t& pos) {
    // 先尝试引号内的值（如 "port": "443"）
    size_t savedPos = pos;
    std::string s = JsonGetString(json, key, pos);
    if (!s.empty()) {
        try { return std::stoi(s); } catch (...) { pos = savedPos; }
    }

    // 回退：无引号数字（如 "port": 443）
    pos = savedPos;
    std::string search = std::string("\"") + key + "\"";
    size_t keyPos = json.find(search, pos);
    if (keyPos == std::string::npos) return 0;

    size_t vs = json.find(':', keyPos + search.length());
    if (vs == std::string::npos) return 0;
    vs++;
    while (vs < json.length() && (json[vs] == ' ' || json[vs] == '\t')) vs++;
    size_t ve = vs;
    while (ve < json.length() && json[ve] >= '0' && json[ve] <= '9') ve++;
    if (ve == vs) return 0;
    pos = ve;
    return std::stoi(json.substr(vs, ve - vs));
}

bool InitNetAcl(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_netMutex);
    g_netRules.clear();

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

        rule.host = JsonGetString(json, "host", innerPos);
        rule.port = static_cast<uint16_t>(JsonGetInt(json, "port", innerPos));
        rule.protocol = ParseNetProtocol(JsonGetString(json, "protocol", innerPos));
        rule.action = ParseNetAction(JsonGetString(json, "action", innerPos));

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
    if (pattern == "*") return true;

    size_t pi = 0, ti = 0;
    size_t pLen = pattern.length(), tLen = target.length();

    while (pi < pLen && ti < tLen) {
        if (pattern[pi] == '*') {
            pi++;
            if (pi == pLen) return true;
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
        if (!GlobMatchSimple(rule.host, host)) continue;
        if (rule.port != 0 && rule.port != port) continue;
        if (rule.protocol != NetProtocol::Any && rule.protocol != proto) continue;
        return rule.action == NetAction::Allow;
    }

    return true; // 默认允许
}

// ============================================================================
// Hook 函数
// ============================================================================

static int WSAAPI Hook_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (name && namelen >= (int)sizeof(sockaddr_in)) {
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

// ★ WSAStartup Hook — 延迟安装真正的网络 Hook
//
// 如果 ws2_32.dll 在 DllMain 时尚未加载，我们无法 Hook connect/getaddrinfo。
// 但任何使用 Winsock 的程序都会先调用 WSAStartup，此时 ws2_32 已加载，
// 我们可以安全地安装剩余 Hook。
static int WSAAPI Hook_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    if (!Real_WSAStartup) return WSASYSNOTREADY;

    // 首次调用 WSAStartup 时，安装 connect/getaddrinfo Hook
    static bool ws2HooksInstalled = false;
    if (!ws2HooksInstalled) {
        ws2HooksInstalled = true;

        HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
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

    return Real_WSAStartup(wVersionRequested, lpWSAData);
}

// ============================================================================
// 安装网络 Hook
// ============================================================================

void InstallNetHooks() {
    // ★ 只用 GetModuleHandle，不用 LoadLibraryW（避免 Loader Lock 死锁）
    HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2) {
        OutputDebugStringA("[sandbox_hook] ws2_32 not loaded, net hooks unavailable\n");
        return;
    }

    // 只 Hook WSAStartup，由它延迟安装 connect/getaddrinfo
    // ★ 不在 DllMain 中调 WSAStartup！ Windows 可能在 Loader Lock 下
    //   触发网络栈加载，导致死锁。
    auto* wsastartup = (BYTE*)GetProcAddress(hWs2, "WSAStartup");
    if (wsastartup) {
        auto* tramp = (BYTE*)DetourInstall(wsastartup, (BYTE*)Hook_WSAStartup, "WSAStartup");
        if (tramp) Real_WSAStartup = (PFN_WSAStartup)tramp;
    }

    // ★ 注意：connect/getaddrinfo 由 Hook_WSAStartup 在首次调用时安装
    //   这确保了它们不在 DllMain 上下文中安装
}
