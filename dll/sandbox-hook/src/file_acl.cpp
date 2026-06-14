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

    // 查找 "file_permissions" 数组
    size_t arrStart = json.find("\"file_permissions\"");
    if (arrStart == std::string::npos) {
        // 没有文件规则不是错误，使用空规则（全部 Inherit）
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

    // 逐对象解析
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
            rule.pattern = Utf8ToWide(pattern);

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

bool ExtractPathFromOA(void* ObjectAttributes, wchar_t* out, size_t outSize) {
    if (!ObjectAttributes || !out || outSize == 0) return false;

    // OBJECT_ATTRIBUTES 结构:
    //   ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ...
    auto* oa = reinterpret_cast<MY_OBJECT_ATTRIBUTES*>(ObjectAttributes);

    if (!oa->ObjectName || !oa->ObjectName->Buffer) return false;

    USHORT len = oa->ObjectName->Length;
    if (len >= outSize * 2) len = static_cast<USHORT>(outSize * 2 - 2);

    // 相对路径（有 RootDirectory）：需要通过 GetFinalPathNameByHandle 解析
    // 这里简化处理：直接复制缓冲区（大多数情况是绝对路径）
    wcsncpy_s(out, outSize, oa->ObjectName->Buffer, len / 2);
    out[len / 2] = L'\0';

    // 规范化
    wchar_t normalized[1024];
    NormalizeNtPath(out, normalized, 1024);
    wcscpy_s(out, outSize, normalized);

    return out[0] != L'\0';
}
