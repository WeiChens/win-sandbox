// file_acl.cpp — 文件系统 ACL 实现
//
// 从 Failure-01 acl.c 移植，使用 C++ STL 重写。

#include "file_acl.h"
#include "ipc_client.h"
#include "utils.h"
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <mutex>

// ============================================================================
// NT 类型（共享定义）
// ============================================================================

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    MY_UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES;

// ============================================================================
// ACL 规则存储
// ============================================================================

static std::vector<FileRule> g_fileRules;
static std::mutex g_aclMutex;
static bool g_initialized = false;
static std::wstring g_lastMatchedRule;

// ============================================================================
// 从 JSON 解析文件规则
// ============================================================================

// 简易 JSON 解析（不依赖第三方库）
// 支持格式: [{"pattern":"...","permission":"deny|read_only|inherit"}]

static std::string JsonGetString(const std::string& json, const char* key, size_t& pos) {
    std::string search = std::string("\"") + key + "\"";
    size_t keyPos = json.find(search, pos);
    if (keyPos == std::string::npos) return "";

    // 跳过 key 和冒号
    size_t valStart = json.find(':', keyPos + search.length());
    if (valStart == std::string::npos) return "";

    // 跳过空白和引号
    valStart = json.find('"', valStart + 1);
    if (valStart == std::string::npos) return "";
    valStart++;

    size_t valEnd = json.find('"', valStart);
    if (valEnd == std::string::npos) return "";

    pos = valEnd + 1;
    return json.substr(valStart, valEnd - valStart);
}

static FilePermission ParsePermission(const std::string& perm) {
    if (perm == "deny" || perm == "DENY") return FilePermission::Deny;
    if (perm == "read_only" || perm == "read_only" || perm == "READ_ONLY") return FilePermission::ReadOnly;
    return FilePermission::Inherit;
}

bool InitFileAcl(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_aclMutex);
    g_fileRules.clear();

    size_t arrStart = json.find("\"file_permissions\"");
    if (arrStart == std::string::npos) {
        g_initialized = true;
        return true;
    }

    arrStart = json.find('[', arrStart);
    if (arrStart == std::string::npos) {
        g_initialized = true;
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

        FileRule rule;
        size_t innerPos = objStart;

        std::string pattern = JsonGetString(json, "pattern", innerPos);
        if (!pattern.empty()) {
            // JSON unescape: replace double backslash with single
            std::string unesc;
            for (size_t ci = 0; ci < pattern.size(); ci++) {
                if (pattern[ci] == '\\' && ci + 1 < pattern.size() && pattern[ci + 1] == '\\') {
                    unesc += '\\';
                    ci++;
                } else {
                    unesc += pattern[ci];
                }
            }
            rule.pattern = Utf8ToWide(unesc);

            innerPos = objStart;
            std::string permission = JsonGetString(json, "permission", innerPos);
            rule.permission = ParsePermission(permission);

            g_fileRules.push_back(rule);
        }

        pos = objEnd + 1;
    }

    g_initialized = true;
    return true;
}

// ============================================================================
// 权限检查
// ============================================================================

FilePermission CheckFilePermission(const std::wstring& path) {
    if (!g_initialized) return FilePermission::Inherit;

    std::lock_guard<std::mutex> lock(g_aclMutex);

    // 第一个匹配的规则生效
    for (const auto& rule : g_fileRules) {
        if (GlobMatch(rule.pattern, path)) {
            g_lastMatchedRule = rule.pattern;
            return rule.permission;
        }
    }

    // 无匹配规则：默认 ReadOnly（安全优先）
    return FilePermission::ReadOnly;
}

// ============================================================================
// 硬链接/符号链接 ACL 绕过防护
//
// NTFS 上一个文件可以有多个路径（硬链接）。如果规则是：
//   C:\Secret\**  → deny
//   C:\Public\**  → inherit
// 攻击者可以通过 `mklink /H C:\Public\link.txt C:\Secret\file.txt`
// 创建硬链接，然后通过 C:\Public\link.txt 绕过 deny。
//
// 修复：检查文件的所有硬链接路径，只要有一个路径被拒绝就拒绝。
// ============================================================================

// ★ 重入守卫 TLS
static DWORD g_tls_hardlink = TLS_OUT_OF_INDEXES;

static bool EnterHardLinkCheck() {
    if (g_tls_hardlink == TLS_OUT_OF_INDEXES) {
        g_tls_hardlink = TlsAlloc();
        if (g_tls_hardlink == TLS_OUT_OF_INDEXES) return false;
    }
    if (TlsGetValue(g_tls_hardlink) != 0) return false;
    TlsSetValue(g_tls_hardlink, (LPVOID)1);
    return true;
}

static void LeaveHardLinkCheck() {
    if (g_tls_hardlink != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_hardlink, (LPVOID)0);
}

/// 获取文件的所有硬链接路径（排除自身）
static std::vector<std::wstring> GetHardLinkPaths(const std::wstring& path) {
    std::vector<std::wstring> links;
    if (path.empty()) return links;
    if (!EnterHardLinkCheck()) return links;

    wchar_t linkBuf[1024] = {0};
    DWORD bufLen = 1024;

    HANDLE hFind = FindFirstFileNameW(path.c_str(), 0, &bufLen, linkBuf);
    if (hFind == INVALID_HANDLE_VALUE) {
        LeaveHardLinkCheck();
        return links;
    }

    // 提取盘符（如 "C:"）
    std::wstring drivePrefix;
    if (path.length() >= 2 && path[1] == L':') {
        drivePrefix = path.substr(0, 2);
    }

    // 第一条硬链接
    if (bufLen > 0 && linkBuf[0]) {
        std::wstring fullPath = drivePrefix + linkBuf;
        std::transform(fullPath.begin(), fullPath.end(), fullPath.begin(), ::towupper);
        if (fullPath != path) {
            links.push_back(fullPath);
        }
    }

    // 后续硬链接
    while (true) {
        bufLen = 1024;
        linkBuf[0] = L'\0';
        if (!FindNextFileNameW(hFind, &bufLen, linkBuf)) {
            break;
        }
        if (bufLen > 0 && linkBuf[0]) {
            std::wstring fullPath = drivePrefix + linkBuf;
            std::transform(fullPath.begin(), fullPath.end(), fullPath.begin(), ::towupper);
            if (fullPath != path) {
                links.push_back(fullPath);
            }
        }
    }

    FindClose(hFind);
    LeaveHardLinkCheck();
    return links;
}

/// 检查文件权限（含硬链接绕过检测）
/// 除了检查 path 本身的权限，还检查该文件的所有硬链接路径。
/// 如果任一硬链接路径被 deny 或更严格的权限，返回该权限。
FilePermission CheckFilePermissionWithHardLinks(const std::wstring& path) {
    FilePermission perm = CheckFilePermission(path);

    // 如果已被 deny，无需进一步检查
    if (perm == FilePermission::Deny) {
        return perm;
    }

    // 检查硬链接：所有指向同一文件数据的路径都要检查
    auto hardLinks = GetHardLinkPaths(path);
    for (const auto& link : hardLinks) {
        FilePermission linkPerm = CheckFilePermission(link);
        // 取最严格权限
        if (linkPerm == FilePermission::Deny) {
            return FilePermission::Deny;
        }
        if (linkPerm == FilePermission::ReadOnly && perm == FilePermission::Inherit) {
            perm = FilePermission::ReadOnly;
        }
    }

    return perm;
}

bool IsAclInitialized() {
    return g_initialized;
}

// ============================================================================
// 路径规范化
// ============================================================================

void NormalizeNtPath(const wchar_t* ntPath, wchar_t* out, size_t outSize) {
    if (!ntPath || !out || outSize == 0) return;

    std::wstring path(ntPath);

    // \\??\\C:... → C:...
    if (path.find(L"\\\\?\\") == 0) {
        path = path.substr(4);
    }
    // \\??\\C:... (另类格式)
    else if (path.find(L"\\??\\") == 0) {
        path = path.substr(4);
    }
    // \Device\HarddiskVolume... → 无法直接转换，保留原样

    // 转换为大写（Windows 路径不区分大小写）
    std::transform(path.begin(), path.end(), path.begin(), ::towupper);

    wcsncpy_s(out, outSize, path.c_str(), _TRUNCATE);
}

// ★ 重入守卫 TLS：GetFinalPathNameByHandleW 可能间接触发 NtCreateFile
// 导致递归。使用 TLS 标志检测并切断递归链。
static DWORD g_tls_resolving_relative = TLS_OUT_OF_INDEXES;

static bool EnterResolveRelative() {
    if (g_tls_resolving_relative == TLS_OUT_OF_INDEXES) {
        g_tls_resolving_relative = TlsAlloc();
        if (g_tls_resolving_relative == TLS_OUT_OF_INDEXES) return false;
    }
    if (TlsGetValue(g_tls_resolving_relative) != 0) return false;
    TlsSetValue(g_tls_resolving_relative, (LPVOID)1);
    return true;
}

static void LeaveResolveRelative() {
    if (g_tls_resolving_relative != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_resolving_relative, (LPVOID)0);
}

bool ExtractPathFromOA(void* ObjectAttributes, wchar_t* out, size_t outSize) {
    if (!ObjectAttributes || !out || outSize == 0) return false;

    auto* oa = reinterpret_cast<MY_OBJECT_ATTRIBUTES*>(ObjectAttributes);

    if (!oa->ObjectName || !oa->ObjectName->Buffer || oa->ObjectName->Length == 0)
        return false;

    if (oa->RootDirectory) {
        if (!EnterResolveRelative()) {
            return false;
        }

        wchar_t dirPath[1024] = {0};
        DWORD dirLen = GetFinalPathNameByHandleW(oa->RootDirectory, dirPath, 1024, 0);
        if (dirLen == 0 || dirLen >= 1024) {
            LeaveResolveRelative();

            wchar_t cwd[1024] = {0};
            DWORD cwdLen = GetCurrentDirectoryW(1024, cwd);
            if (cwdLen == 0 || cwdLen >= 1024) return false;

            size_t cwdLen2 = wcslen(cwd);
            if (cwdLen2 > 0 && cwd[cwdLen2 - 1] != L'\\') {
                if (cwdLen2 < 1023) { cwd[cwdLen2] = L'\\'; cwd[cwdLen2 + 1] = L'\0'; }
            }

            USHORT nameLen = oa->ObjectName->Length / 2;
            size_t offset = wcslen(cwd);
            if (nameLen > 1023 - offset) nameLen = static_cast<USHORT>(1023 - offset);
            wcsncpy_s(cwd + offset, 1024 - offset, oa->ObjectName->Buffer, nameLen);
            cwd[offset + nameLen] = L'\0';

            wchar_t normalized[1024];
            NormalizeNtPath(cwd, normalized, 1024);
            wcsncpy_s(out, outSize, normalized, _TRUNCATE);
            return out[0] != L'\0';
        }

        // 去掉 \\?\ 前缀
        int pos = 0;
        if (wcsncmp(dirPath, L"\\\\?\\", 4) == 0) pos = 4;

        // 确保目录路径末尾有反斜杠
        int j = (int)wcslen(dirPath);
        if (j > pos && dirPath[j - 1] != L'\\') {
            if (j < 1023) dirPath[j++] = L'\\';
            dirPath[j] = L'\0';
        }

        // 拼接 ObjectName（相对名）
        USHORT nameLen = oa->ObjectName->Length / 2;
        if (nameLen > 1023 - j) nameLen = static_cast<USHORT>(1023 - j);
        wcsncpy_s(dirPath + j, 1024 - j, oa->ObjectName->Buffer, nameLen);
        dirPath[j + nameLen] = L'\0';

        LeaveResolveRelative();

        // 规范化并输出
        wchar_t normalized[1024];
        NormalizeNtPath(dirPath + pos, normalized, 1024);
        wcsncpy_s(out, outSize, normalized, _TRUNCATE);
        return out[0] != L'\0';
    }

    // 绝对路径：直接提取 ObjectName
    USHORT len = oa->ObjectName->Length;
    if (len >= outSize * 2) len = static_cast<USHORT>(outSize * 2 - 2);

    wcsncpy_s(out, outSize, oa->ObjectName->Buffer, len / 2);
    out[len / 2] = L'\0';

    // 规范化
    wchar_t normalized[1024];
    NormalizeNtPath(out, normalized, 1024);
    wcscpy_s(out, outSize, normalized);
    return out[0] != L'\0';
}

// ============================================================================
// 符号链接解析 — 在检查 ACL 前追踪符号链接/交接点至最终目标
// ============================================================================

/// TLS 守卫防止符号链接解析中的递归
static DWORD g_tls_symlink_resolve = TLS_OUT_OF_INDEXES;

static bool EnterSymlinkResolve() {
    if (g_tls_symlink_resolve == TLS_OUT_OF_INDEXES) {
        g_tls_symlink_resolve = TlsAlloc();
        if (g_tls_symlink_resolve == TLS_OUT_OF_INDEXES) return false;
    }
    if (TlsGetValue(g_tls_symlink_resolve) != 0) return false;
    TlsSetValue(g_tls_symlink_resolve, (LPVOID)1);
    return true;
}

static void LeaveSymlinkResolve() {
    if (g_tls_symlink_resolve != TLS_OUT_OF_INDEXES)
        TlsSetValue(g_tls_symlink_resolve, (LPVOID)0);
}

/// 检查路径是否为重解析点（符号链接/交接点/挂载点）
static bool IsReparsePoint(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

/// 解析符号链接/交接点至最终目标路径
/// 通过打开重解析点本身（不追踪它）获取其目标，然后递归解析
/// @param path      原始路径
/// @param depth     递归深度（防循环，最大 16 层）
/// @return 解析后的最终路径，如果无法解析则返回原始路径
static std::wstring ResolveSymbolicLink(const std::wstring& path, int depth = 0) {
    if (depth > 16) return path;      // 防循环链接
    if (!EnterSymlinkResolve()) return path;

    // 先检查是否为重解析点
    if (!IsReparsePoint(path)) {
        LeaveSymlinkResolve();
        return path;
    }

    // 以最小权限打开重解析点（不追踪它）
    HANDLE hFile = CreateFileW(path.c_str(),
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        LeaveSymlinkResolve();
        return path;
    }

    // 获取最终路径
    wchar_t finalPath[1024] = {0};
    DWORD ret = GetFinalPathNameByHandleW(hFile, finalPath, 1024, FILE_NAME_NORMALIZED);
    CloseHandle(hFile);

    if (ret == 0 || ret >= 1024) {
        LeaveSymlinkResolve();
        return path;
    }

    // 去掉 \\?\ 前缀
    std::wstring resolved(finalPath);
    if (resolved.find(L"\\\\?\\") == 0) {
        resolved = resolved.substr(4);
    }

    // 大写归一化
    std::transform(resolved.begin(), resolved.end(), resolved.begin(), ::towupper);

    // 如果解析后路径与原路径相同，说明无符号链接
    if (resolved == path) {
        LeaveSymlinkResolve();
        return path;
    }

    LeaveSymlinkResolve();

    // 递归解析（目标可能本身也是符号链接）
    return ResolveSymbolicLink(resolved, depth + 1);
}

/// 检查文件权限（含符号链接 + WOW64 重定向 + 硬链接防护）
/// 先解析符号链接至最终目标，再对 WOW64 路径做逆向映射，
/// 最后对最终目标做 ACL 检查（含硬链接防护）
FilePermission CheckFilePermissionWithSymlink(const std::wstring& path) {
    // 先解析符号链接
    std::wstring resolvedPath = ResolveSymbolicLink(path);

    // 对 WOW64 进程做 SysWOW64→System32 逆向映射
    std::wstring normalizedPath = WowPathRedirectIfNeed(resolvedPath);

    // 对解析后的路径做 ACL 检查（含硬链接防护）
    return CheckFilePermissionWithHardLinks(normalizedPath);
}

// ============================================================================
// WOW64 路径重定向修复
//
// x86 (WOW64) 进程访问 C:\Windows\System32\... 时，
// WOW64 文件系统重定向器自动将路径重定向到 C:\Windows\SysWOW64\...
// 这意味着 ACL 规则中的 System32 路径对 x86 进程不生效。
//
// 修复：在检查 ACL 前，将重定向后的路径映射回原始路径。
// ============================================================================

/// WOW64 路径映射规则
struct Wow64RedirectRule {
    const wchar_t* redirected;   // 重定向后的前缀（如 SysWOW64）
    const wchar_t* original;     // 原始前缀（如 System32）
};

static const Wow64RedirectRule g_wow64Rules[] = {
    { L"C:\\WINDOWS\\SYSWOW64\\", L"C:\\WINDOWS\\SYSTEM32\\" },
    { L"C:\\WINDOWS\\SYSNATIVE\\", L"C:\\WINDOWS\\SYSTEM32\\" },
    { L"C:\\PROGRAM FILES (X86)\\", L"C:\\PROGRAM FILES\\" },
};

/// 如果当前进程是 WOW64 (x86)，将路径从重定向后的格式映射回原始格式
/// 以匹配 ACL 规则中的路径
std::wstring WowPathRedirectIfNeed(const std::wstring& path) {
    // 检查当前进程是否为 WOW64
    static bool s_isWow64Checked = false;
    static bool s_isWow64 = false;
    
    if (!s_isWow64Checked) {
        BOOL isWow64 = FALSE;
        if (IsWow64Process(GetCurrentProcess(), &isWow64)) {
            s_isWow64 = (isWow64 != FALSE);
        }
        s_isWow64Checked = true;
    }
    
    if (!s_isWow64) {
        return path;  // x64 进程，不需要重定向
    }

    // 对 WOW64 进程：将重定向路径映射回原始路径
    for (const auto& rule : g_wow64Rules) {
        size_t prefixLen = wcslen(rule.redirected);
        if (_wcsnicmp(path.c_str(), rule.redirected, prefixLen) == 0) {
            // 替换前缀
            std::wstring result = rule.original;
            result += path.substr(prefixLen);
            return result;
        }
    }

    return path;
}


