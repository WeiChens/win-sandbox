// hook_memory.cpp — 内存映射 Hook（NtMapViewOfSection / NtOpenSection）
//
// 防止通过 CreateFileMapping + MapViewOfFile 绕过文件 ACL。
//
// 攻击路径:
//   1. CreateFileMapping(INVALID_HANDLE_VALUE, ..., PAGE_READWRITE, 0, 4096, "Local\\S")
//      → 创建文件-backed section 时，CreateFileMapping 内部调用 NtCreateFile + NtCreateSection
//      → NtCreateFile 已被我们 Hook
//
//   2. CreateFileMapping(INVALID_HANDLE_VALUE, ...) — 页面文件-backed（无文件路径）
//      → 不需要检查
//
//   3. OpenFileMapping → NtOpenSection + MapViewOfFile → NtMapViewOfSection
//      → 如果 section 是文件-backed，需要检查文件 ACL
//
// 我们 Hook 的位置:
//   - NtMapViewOfSection: 在映射时检查 section 对应的文件路径

#include "hook_engine.h"
#include "detour.h"
#include "file_acl.h"
#include "ipc_client.h"
#include "utils.h"

#include <windows.h>
#include <cstdio>
#include <string>
#include <algorithm>

// ============================================================================
// NT 类型和常量
// ============================================================================

typedef LONG NTSTATUS;
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)

// ============================================================================
// 原始函数指针
// ============================================================================

typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (NTAPI *PFN_NtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes
);

static PFN_NtMapViewOfSection Real_NtMapViewOfSection = nullptr;
static PFN_NtOpenSection Real_NtOpenSection = nullptr;

// ============================================================================
// 辅助: 判断内存保护标志是否为写操作
// ============================================================================

static bool IsWriteProtect(ULONG protect) {
    // 以下保护标志允许写入
    return (protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                       PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// ============================================================================
// 辅助: 从 Section 句柄获取文件路径（通过 NtQueryObject）
// ============================================================================

/// 从 Section 句柄获取文件路径
/// Section 对象有两种类型:
///   1. 文件-backed: Name 为 "\Device\HarddiskVolume2\..."
///   2. 页面文件-backed (匿名): Name 为空
/// 本函数只对类型 1 返回有效路径
static bool GetSectionFilePath(HANDLE hSection, wchar_t* out, size_t outSize) {
    if (!hSection || hSection == INVALID_HANDLE_VALUE || !out || outSize == 0)
        return false;

    // 复用已有的 NtQueryObject 路径解析
    return GetPathFromHandleNt(hSection, out, outSize);
}

// ============================================================================
// NtMapViewOfSection Hook
// ============================================================================

static NTSTATUS NTAPI Hook_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect)
{
    if (!Real_NtMapViewOfSection) {
        return STATUS_ACCESS_DENIED;
    }

    // ★ 只拦截写映射（读映射不需要权限检查）
    //    注意: 即使 Win32Protect 是只读，调用者之后可能用 VirtualProtect 改为读写。
    //    但那是 VirtualProtect 的问题，我们不在那里 Hook。
    if (!IsWriteProtect(Win32Protect)) {
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle,
            BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect);
    }

    // ★ 只拦截当前进程的映射（跨进程映射较少见，且复杂度高）
    if (ProcessHandle != GetCurrentProcess()) {
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle,
            BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect);
    }

    // 获取 Section 对应的文件路径
    wchar_t path[1024] = {0};
    bool hasPath = GetSectionFilePath(SectionHandle, path, 1024);

    if (!hasPath || !path[0]) {
        // 匿名 section（页面文件-backed）或无法解析路径 → 放行
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle,
            BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
            InheritDisposition, AllocationType, Win32Protect);
    }

    // 检查文件 ACL
    std::wstring pathStr(path);
    FilePermission perm = CheckFilePermissionWithSymlink(pathStr);

    if (perm == FilePermission::Deny) {
        // Deny 路径: 禁止任何形式的映射（包括只读映射）
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_map_view_section",
                 Win32Protect, STATUS_ACCESS_DENIED);
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    if (perm == FilePermission::ReadOnly && IsWriteProtect(Win32Protect)) {
        // ReadOnly 路径: 禁止写映射
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_map_view_section_readonly",
                 Win32Protect, STATUS_ACCESS_DENIED);
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    // 允许映射
    return Real_NtMapViewOfSection(SectionHandle, ProcessHandle,
        BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
        InheritDisposition, AllocationType, Win32Protect);
}

// ============================================================================
// NtOpenSection Hook — 可选（用于审计跟踪）
// ============================================================================

static NTSTATUS NTAPI Hook_NtOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes)
{
    if (!Real_NtOpenSection) {
        return STATUS_ACCESS_DENIED;
    }

    // ★ 注意: Section 对象名是 NT 对象命名空间路径（如 \BaseNamedObjects\Local\MySection）
    //   不是文件系统路径。我们无法在这里检查文件 ACL。
    //   文件 ACL 检查在 NtMapViewOfSection 中完成。
    //
    // 但我们仍可以记录审计：打开 section 的行为。
    // 如果 DesiredAccess 包含 SECTION_MAP_WRITE，记录下来。
    if (DesiredAccess & SECTION_MAP_WRITE) {
        wchar_t objName[256] = {0};
        ExtractPathFromOA(ObjectAttributes, objName, 256);
        if (objName[0]) {
            AuditLog(AuditEventType::FileAllow, objName,
                     L"open_section_write", DesiredAccess, 0);
        }
    }

    return Real_NtOpenSection(SectionHandle, DesiredAccess, ObjectAttributes);
}

// ============================================================================
// 安装函数
// ============================================================================

void InstallNtMapViewOfSectionHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtMapViewOfSection");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtMapViewOfSection, "NtMapViewOfSection");
        if (tramp) Real_NtMapViewOfSection = (PFN_NtMapViewOfSection)tramp;
    }
}

void InstallNtOpenSectionHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtOpenSection");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtOpenSection, "NtOpenSection");
        if (tramp) Real_NtOpenSection = (PFN_NtOpenSection)tramp;
    }
}
