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
// DNS API 类型（最小定义，避免 windns.h 的复杂依赖）
// ============================================================================

typedef DWORD DNS_STATUS;

// DNS_RECORDW — DNS 记录（最小定义）
typedef struct _MY_DNS_RECORDW {
    struct _MY_DNS_RECORDW* pNext;     // 链表下一项
    PCWSTR pName;                       // 查询名
    WORD   wType;                       // 记录类型 (DNS_TYPE_A=1, DNS_TYPE_AAAA=28)
    WORD   wDataLength;                 // 数据长度
    DWORD  Flags;
    DWORD  dwTtl;
    DWORD  dwReserved;
    union {
        struct { DWORD bData[1]; } A;   // A 记录 (IPv4)
        struct { DWORD bData[2]; } AAAA; // AAAA 记录 (IPv6)
    } Data;
} MY_DNS_RECORDW, *PMY_DNS_RECORDW;

typedef MY_DNS_RECORDW* PDNS_RECORDW;

// DnsQueryEx 请求/结果结构
typedef struct _MY_DNS_QUERY_REQUEST {
    ULONG Version;                              // 必须为 0
    PCWSTR QueryName;                           // 查询名
    WORD   Type;                                // 记录类型
    DWORD  Options;                             // 查询选项
    PVOID  pDnsServerList;                      // 可选 DNS 服务器列表
    ULONG  InterfaceIndex;                      // 网络接口索引
    PVOID  pQueryCompletionRoutine;             // 完成回调（异步用）
    PVOID  pQueryContext;                       // 回调上下文
} MY_DNS_QUERY_REQUEST, *PMY_DNS_QUERY_REQUEST;

typedef struct _MY_DNS_QUERY_RESULT {
    ULONG     Version;                          // 必须为 0
    DNS_STATUS QueryStatus;                     // 查询结果状态
    PVOID     QueryOptions;                     // 保留
    PDNS_RECORDW QueryRecords;                  // 结果记录链表
    PVOID     Reserved;                         // 保留
} MY_DNS_QUERY_RESULT, *PMY_DNS_QUERY_RESULT;

typedef PVOID PDNS_SERVICE_CANCEL;

// DNS 函数指针类型
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_W)(
    PCWSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(
    PCSTR, WORD, DWORD, PVOID, PVOID*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_UTF8)(
    PCSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQueryEx)(
    PMY_DNS_QUERY_REQUEST, PMY_DNS_QUERY_RESULT, PDNS_SERVICE_CANCEL*);

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
typedef SOCKET (WSAAPI *PFN_WSASocketW)(int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags);
typedef int (WSAAPI *PFN_WSAConnect)(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

static PFN_WSAStartup Real_WSAStartup = nullptr;
static PFN_connect Real_connect = nullptr;
static PFN_getaddrinfo Real_getaddrinfo = nullptr;
static PFN_GetAddrInfoW Real_GetAddrInfoW = nullptr;
static PFN_WSASocketW Real_WSASocketW = nullptr;
static PFN_WSAConnect Real_WSAConnect = nullptr;

// DNS 原始函数指针
static PFN_DnsQuery_W Real_DnsQuery_W = nullptr;
static PFN_DnsQuery_A Real_DnsQuery_A = nullptr;
static PFN_DnsQuery_UTF8 Real_DnsQuery_UTF8 = nullptr;
static PFN_DnsQueryEx Real_DnsQueryEx = nullptr;
static bool g_dnsHooksInstalled = false;

// DNS 错误码（dnsapi.dll 返回值）
#define DNS_ERROR_HOST_NOT_FOUND 11001L  // 同 WSAHOST_NOT_FOUND

// 前向声明
static void TryInstallDnsHooks();

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
    // 尝试安装 DNS Hook（如果 dnsapi.dll 刚被加载）
    TryInstallDnsHooks();

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
    // 尝试安装 DNS Hook（如果 dnsapi.dll 刚被加载）
    TryInstallDnsHooks();

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
// WSASocketW + WSAConnect Hook — 防止重叠 I/O 绕过 connect()
// ============================================================================

static SOCKET WSAAPI Hook_WSASocketW(int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags) {
    if (!Real_WSASocketW) {
        WSASetLastError(WSAEACCES);
        return INVALID_SOCKET;
    }
    // 套接字创建本身不需要权限检查，直接放行
    return Real_WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
}

static int WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    if (!Real_WSAConnect) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }

    if (name && namelen >= (int)sizeof(sockaddr_in)) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(name);
        if (sin->sin_family == AF_INET) {
            char ipBuf[64];
            inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
            uint16_t port = ntohs(sin->sin_port);

            if (!CheckNetPermission(ipBuf, port, NetProtocol::Tcp)) {
                AuditLog(AuditEventType::NetDeny, Utf8ToWide(ipBuf),
                         L"deny_wsaconnect", port, STATUS_ACCESS_DENIED);
                WSASetLastError(WSAEACCES);
                return SOCKET_ERROR;
            }

            AuditLog(AuditEventType::NetAllow, Utf8ToWide(ipBuf),
                     L"allow_wsaconnect", port, 0);
        }
    }
    return Real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

// ============================================================================
// WSAIoctl Hook — 拦截 SIO_GET_EXTENSION_FUNCTION_POINTER (ConnectEx)
// ============================================================================

// WSAID_CONNECTEX GUID
const GUID GUID_CONNECTEX = {0x25a207b9, 0xdbb3, 0x4a90, {0xb0, 0x4b, 0x87, 0x4e, 0x6f, 0x6e, 0xd0, 0x17}};

#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER
#define SIO_GET_EXTENSION_FUNCTION_POINTER 0xC8000006
#endif

// ConnectEx 函数指针类型
typedef BOOL (WINAPI *PFN_CONNECTEX)(SOCKET s, const sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPWSAOVERLAPPED lpOverlapped);

static PFN_CONNECTEX Real_ConnectEx = nullptr;

/// 包装的 ConnectEx — 在连接前检查 ACL
static BOOL WINAPI Hook_ConnectEx(SOCKET s, const sockaddr* name, int namelen,
    PVOID lpSendBuffer, DWORD dwSendDataLength, LPDWORD lpdwBytesSent,
    LPWSAOVERLAPPED lpOverlapped)
{
    if (!Real_ConnectEx) {
        WSASetLastError(WSAEACCES);
        return FALSE;
    }

    if (name && namelen >= (int)sizeof(sockaddr_in)) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(name);
        if (sin->sin_family == AF_INET) {
            char ipBuf[64];
            inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
            uint16_t port = ntohs(sin->sin_port);

            if (!CheckNetPermission(ipBuf, port, NetProtocol::Tcp)) {
                AuditLog(AuditEventType::NetDeny, Utf8ToWide(ipBuf),
                         L"deny_connectex", port, STATUS_ACCESS_DENIED);
                WSASetLastError(WSAEACCES);
                return FALSE;
            }

            AuditLog(AuditEventType::NetAllow, Utf8ToWide(ipBuf),
                     L"allow_connectex", port, 0);
        }
    }

    return Real_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength,
                          lpdwBytesSent, lpOverlapped);
}

typedef int (WSAAPI *PFN_WSAIoctl)(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
    DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static PFN_WSAIoctl Real_WSAIoctl = nullptr;

/// 检查是否是 ConnectEx 的 GUID 查询（安全版，带空指针和长度检查）
static bool IsConnectExRequest(const void* inBuf, DWORD inBufLen) {
    if (!inBuf || inBufLen < (DWORD)sizeof(GUID)) return false;
    __try {
        return memcmp(inBuf, &GUID_CONNECTEX, sizeof(GUID)) == 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;  // 非法内存访问，安全降级
    }
}

static int WSAAPI Hook_WSAIoctl(
    SOCKET s, DWORD dwIoControlCode, LPVOID lpvInBuffer,
    DWORD cbInBuffer, LPVOID lpvOutBuffer, DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (!Real_WSAIoctl) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }

    // ★ 拦截 SIO_GET_EXTENSION_FUNCTION_POINTER 请求
    //    仅在所有参数有效时才介入，否则透传
    if (dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer && cbInBuffer >= sizeof(GUID) &&
        lpvOutBuffer && cbOutBuffer >= sizeof(PVOID) &&
        IsConnectExRequest(lpvInBuffer, cbInBuffer)) {

        // 先调用原始的 WSAIoctl 获取真实的 ConnectEx 指针
        int ret = Real_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                                lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,
                                lpOverlapped, lpCompletionRoutine);

        if (ret == 0 && lpcbBytesReturned && *lpcbBytesReturned >= sizeof(PVOID)) {
            // 保存真实的 ConnectEx 指针
            Real_ConnectEx = *(PFN_CONNECTEX*)lpvOutBuffer;

            // ★ 返回我们的包装函数指针
            *(PFN_CONNECTEX*)lpvOutBuffer = Hook_ConnectEx;

            OutputDebugStringA("[sandbox_hook] WSAIoctl: ConnectEx hooked\n");
        }

        return ret;
    }

    // 其他 IOCTL 请求透传
    return Real_WSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                         lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,
                         lpOverlapped, lpCompletionRoutine);
}

// ============================================================================
// DNS Hook 函数 — 防止 DnsQuery_* 绕过 getaddrinfo
// ============================================================================

static DNS_STATUS WINAPI Hook_DnsQuery_W(
    PCWSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORDW* ppQueryResults, PVOID* pReserved)
{
    if (!Real_DnsQuery_W) {
        SetLastError(DNS_ERROR_HOST_NOT_FOUND);
        return DNS_ERROR_HOST_NOT_FOUND;
    }

    if (pName) {
        std::string nodeName = WideToUtf8(pName);
        if (!CheckNetPermission(nodeName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, pName,
                     L"deny_dns_query_w", 0, STATUS_ACCESS_DENIED);
            SetLastError(DNS_ERROR_HOST_NOT_FOUND);
            return DNS_ERROR_HOST_NOT_FOUND;
        }
    }

    return Real_DnsQuery_W(pName, wType, Options, pExtra, ppQueryResults, pReserved);
}

static DNS_STATUS WINAPI Hook_DnsQuery_A(
    PCSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PVOID* ppQueryResults, PVOID* pReserved)
{
    if (!Real_DnsQuery_A) {
        SetLastError(DNS_ERROR_HOST_NOT_FOUND);
        return DNS_ERROR_HOST_NOT_FOUND;
    }

    if (pName) {
        if (!CheckNetPermission(pName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, Utf8ToWide(pName),
                     L"deny_dns_query_a", 0, STATUS_ACCESS_DENIED);
            SetLastError(DNS_ERROR_HOST_NOT_FOUND);
            return DNS_ERROR_HOST_NOT_FOUND;
        }
    }

    return Real_DnsQuery_A(pName, wType, Options, pExtra, ppQueryResults, pReserved);
}

static DNS_STATUS WINAPI Hook_DnsQuery_UTF8(
    PCSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORDW* ppQueryResults, PVOID* pReserved)
{
    if (!Real_DnsQuery_UTF8) {
        SetLastError(DNS_ERROR_HOST_NOT_FOUND);
        return DNS_ERROR_HOST_NOT_FOUND;
    }

    if (pName) {
        if (!CheckNetPermission(pName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, Utf8ToWide(pName),
                     L"deny_dns_query_utf8", 0, STATUS_ACCESS_DENIED);
            SetLastError(DNS_ERROR_HOST_NOT_FOUND);
            return DNS_ERROR_HOST_NOT_FOUND;
        }
    }

    return Real_DnsQuery_UTF8(pName, wType, Options, pExtra, ppQueryResults, pReserved);
}

static DNS_STATUS WINAPI Hook_DnsQueryEx(
    PMY_DNS_QUERY_REQUEST pQueryRequest,
    PMY_DNS_QUERY_RESULT pQueryResult,
    PDNS_SERVICE_CANCEL* pCancelHandle)
{
    if (!Real_DnsQueryEx) {
        SetLastError(DNS_ERROR_HOST_NOT_FOUND);
        return DNS_ERROR_HOST_NOT_FOUND;
    }

    if (pQueryRequest && pQueryRequest->QueryName) {
        std::string nodeName = WideToUtf8(pQueryRequest->QueryName);
        if (!CheckNetPermission(nodeName, 0, NetProtocol::Any)) {
            AuditLog(AuditEventType::NetDeny, pQueryRequest->QueryName,
                     L"deny_dns_query_ex", 0, STATUS_ACCESS_DENIED);
            SetLastError(DNS_ERROR_HOST_NOT_FOUND);
            if (pQueryResult) {
                pQueryResult->QueryStatus = DNS_ERROR_HOST_NOT_FOUND;
                pQueryResult->QueryRecords = nullptr;
            }
            return DNS_ERROR_HOST_NOT_FOUND;
        }
    }

    return Real_DnsQueryEx(pQueryRequest, pQueryResult, pCancelHandle);
}

/// 尝试安装 DNS Hook（如果 dnsapi.dll 已加载）
/// 可在多个入口点安全调用（内部有 g_dnsHooksInstalled 标志保护）
static void TryInstallDnsHooks() {
    if (g_dnsHooksInstalled) return;

    HMODULE hDns = GetModuleHandleW(L"dnsapi.dll");
    if (!hDns) return;  // dnsapi.dll 尚未加载，稍后再试

    g_dnsHooksInstalled = true;

    auto* dqW = (BYTE*)GetProcAddress(hDns, "DnsQuery_W");
    if (dqW) {
        auto* tramp = (BYTE*)DetourInstall(dqW, (BYTE*)Hook_DnsQuery_W, "DnsQuery_W");
        if (tramp) Real_DnsQuery_W = (PFN_DnsQuery_W)tramp;
    }

    auto* dqA = (BYTE*)GetProcAddress(hDns, "DnsQuery_A");
    if (dqA) {
        auto* tramp = (BYTE*)DetourInstall(dqA, (BYTE*)Hook_DnsQuery_A, "DnsQuery_A");
        if (tramp) Real_DnsQuery_A = (PFN_DnsQuery_A)tramp;
    }

    auto* dqU = (BYTE*)GetProcAddress(hDns, "DnsQuery_UTF8");
    if (dqU) {
        auto* tramp = (BYTE*)DetourInstall(dqU, (BYTE*)Hook_DnsQuery_UTF8, "DnsQuery_UTF8");
        if (tramp) Real_DnsQuery_UTF8 = (PFN_DnsQuery_UTF8)tramp;
    }

    auto* dqE = (BYTE*)GetProcAddress(hDns, "DnsQueryEx");
    if (dqE) {
        auto* tramp = (BYTE*)DetourInstall(dqE, (BYTE*)Hook_DnsQueryEx, "DnsQueryEx");
        if (tramp) Real_DnsQueryEx = (PFN_DnsQueryEx)tramp;
    }

    OutputDebugStringA("[sandbox_hook] DNS hooks installed (DnsQuery_W/A/UTF8/Ex)\n");
}

// ★ WSAStartup Hook — 延迟安装真正的网络 Hook
//
// 如果 ws2_32.dll 在 DllMain 时尚未加载，我们无法 Hook connect/getaddrinfo。
// 但任何使用 Winsock 的程序都会先调用 WSAStartup，此时 ws2_32 已加载，
// 我们可以安全地安装剩余 Hook。
static int WSAAPI Hook_WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData) {
    if (!Real_WSAStartup) return WSASYSNOTREADY;

    // 首次调用 WSAStartup 时，安装所有 ws2_32 Hook
    // ★ 使用 Real_connect 判断而非静态标志，以处理 ws2_32.dll 卸载重载的情况
    if (Real_connect == nullptr) {
        HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
        if (hWs2) {
            // connect
            auto* connectTarget = (BYTE*)GetProcAddress(hWs2, "connect");
            if (connectTarget) {
                auto* tramp = (BYTE*)DetourInstall(connectTarget, (BYTE*)Hook_connect, "connect");
                if (tramp) Real_connect = (PFN_connect)tramp;
            }

            // getaddrinfo
            auto* gaiTarget = (BYTE*)GetProcAddress(hWs2, "getaddrinfo");
            if (gaiTarget) {
                auto* tramp = (BYTE*)DetourInstall(gaiTarget, (BYTE*)Hook_getaddrinfo, "getaddrinfo");
                if (tramp) Real_getaddrinfo = (PFN_getaddrinfo)tramp;
            }

            // GetAddrInfoW
            auto* gaiwTarget = (BYTE*)GetProcAddress(hWs2, "GetAddrInfoW");
            if (gaiwTarget) {
                auto* tramp = (BYTE*)DetourInstall(gaiwTarget, (BYTE*)Hook_GetAddrInfoW, "GetAddrInfoW");
                if (tramp) Real_GetAddrInfoW = (PFN_GetAddrInfoW)tramp;
            }

            // ★ WSASocketW — 防止 WSASocketW + WSAConnect 绕过 connect()
            auto* wsaSocketTarget = (BYTE*)GetProcAddress(hWs2, "WSASocketW");
            if (wsaSocketTarget) {
                auto* tramp = (BYTE*)DetourInstall(wsaSocketTarget, (BYTE*)Hook_WSASocketW, "WSASocketW");
                if (tramp) Real_WSASocketW = (PFN_WSASocketW)tramp;
            }

            // ★ WSAConnect — 重叠 I/O connect 权限检查
            auto* wsaConnectTarget = (BYTE*)GetProcAddress(hWs2, "WSAConnect");
            if (wsaConnectTarget) {
                auto* tramp = (BYTE*)DetourInstall(wsaConnectTarget, (BYTE*)Hook_WSAConnect, "WSAConnect");
                if (tramp) Real_WSAConnect = (PFN_WSAConnect)tramp;
            }

            // ★ WSAIoctl — 拦截 ConnectEx 获取，防止绕过 connect/WSAConnect
            auto* wsaIoctlTarget = (BYTE*)GetProcAddress(hWs2, "WSAIoctl");
            if (wsaIoctlTarget) {
                auto* tramp = (BYTE*)DetourInstall(wsaIoctlTarget, (BYTE*)Hook_WSAIoctl, "WSAIoctl");
                if (tramp) Real_WSAIoctl = (PFN_WSAIoctl)tramp;
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

    // 首次安装网络 Hook 时，也尝试安装 DNS Hook（如果 dnsapi.dll 已加载）
    TryInstallDnsHooks();
}
