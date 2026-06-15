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
