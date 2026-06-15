// file_acl.h — 文件系统 ACL 检查
//
// 基于 glob 模式匹配，检查文件路径的读写权限。
// 权限级别: Inherit(完全放行) / ReadOnly(只读) / Deny(完全拒绝)

#pragma once
#include <windows.h>
#include <string>
#include <vector>

/// 文件权限级别
enum class FilePermission : int {
    Inherit = 0,   // 完全放行（继承父目录权限）
    ReadOnly = 1,  // 只读（拒绝写入/删除/重命名）
    Deny = 2,      // 完全拒绝
};

/// 单条文件 ACL 规则
struct FileRule {
    std::wstring pattern;       // Glob 模式（如 L"C:\\Users\\*\\**"）
    FilePermission permission;  // 匹配后的权限
};

/// 从 JSON 配置初始化文件 ACL
/// @param json  JSON 字符串（来自共享内存）
/// @return 解析成功返回 true
bool InitFileAcl(const std::string& json);

/// 检查文件路径的权限
/// @param path  规范化后的 Win32 路径
/// @return 权限级别
FilePermission CheckFilePermission(const std::wstring& path);

/// 检查文件权限（含硬链接绕过检测）
/// 除了检查 path 本身的权限，还会检查该文件的所有硬链接路径。
/// 如果任一硬链接路径被拒绝，返回该权限（防御 mklink /H 绕过）。
FilePermission CheckFilePermissionWithHardLinks(const std::wstring& path);

/// ACL 是否已初始化
bool IsAclInitialized();

/// 规范化 NT 路径为 Win32 路径
/// @param ntPath  输入 NT 路径（如 \??\C:\...）
/// @param out     输出 Win32 路径
/// @param outSize 输出缓冲区大小
void NormalizeNtPath(const wchar_t* ntPath, wchar_t* out, size_t outSize);

/// 从 OBJECT_ATTRIBUTES 提取路径字符串
bool ExtractPathFromOA(void* ObjectAttributes, wchar_t* out, size_t outSize);
