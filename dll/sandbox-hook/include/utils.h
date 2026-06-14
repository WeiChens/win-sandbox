// utils.h — 工具函数

#pragma once
#include <windows.h>
#include <string>
#include <vector>

/// 宽字符转 UTF-8
std::string WideToUtf8(const std::wstring& wstr);
std::wstring Utf8ToWide(const std::string& str);

/// Glob 模式匹配（简化版，支持 * 和 **）
/// @param pattern  Glob 模式
/// @param path     待匹配路径（大小写不敏感）
bool GlobMatch(const std::wstring& pattern, const std::wstring& path);

/// 获取当前进程的 DLL 路径
std::wstring GetCurrentModulePath(HMODULE hModule = nullptr);

/// 获取环境变量（宽字符版）
std::wstring GetEnvWide(const std::wstring& name);

/// 检查是否为设备路径（\Device\...）或 DOS 设备名（NUL, CON 等）
bool IsDevicePath(const std::wstring& path);
