// hook_file.cpp — 文件系统 NT API Hook（NtCreateFile/NtOpenFile/NtDeleteFile/
//                                       NtSetInformationFile/NtWriteFile）
//
// 从 hook_engine.cpp 拆分而来，原文件缩小 ~490 行。

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

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} MY_UNICODE_STRING, *PMY_UNICODE_STRING;

typedef struct _MY_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PMY_UNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} MY_OBJECT_ATTRIBUTES, *PMY_OBJECT_ATTRIBUTES;

#define FILE_SUPERSEDE       0x00000000
#define FILE_OPEN            0x00000001
#define FILE_CREATE          0x00000002
#define FILE_OPEN_IF         0x00000003
#define FILE_OVERWRITE       0x00000004
#define FILE_OVERWRITE_IF    0x00000005
#define FILE_DIRECTORY_FILE  0x00000001
#ifndef FILE_DISPOSITION_DELETE
#define FILE_DISPOSITION_DELETE 0x00000001
#endif

// ============================================================================
// 原始函数指针
// ============================================================================

static NTSTATUS (WINAPI *Real_NtCreateFile)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, PLARGE_INTEGER,
    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = nullptr;

static NTSTATUS (WINAPI *Real_NtOpenFile)(
    PHANDLE, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG) = nullptr;

static NTSTATUS (WINAPI *Real_NtDeleteFile)(PVOID) = nullptr;

static NTSTATUS (WINAPI *Real_NtSetInformationFile)(
    HANDLE, PVOID, PVOID, ULONG, ULONG) = nullptr;

static NTSTATUS (WINAPI *Real_NtWriteFile)(
    HANDLE, HANDLE, PVOID, PVOID, PVOID,
    PVOID, ULONG, PLARGE_INTEGER, PULONG) = nullptr;

// ============================================================================
// Handle → 路径 辅助
// ============================================================================

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

// ============================================================================
// NtCreateFile Hook
// ============================================================================

static NTSTATUS WINAPI Hook_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (!Real_NtCreateFile) {
        if (FileHandle) *FileHandle = nullptr;
        return STATUS_ACCESS_DENIED;
    }

    wchar_t path[1024] = {0};
    if (!ExtractPathFromOA(ObjectAttributes, path, 1024) || !path[0]) {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    std::wstring pathStr(path);
    if (IsDevicePath(pathStr)) {
        return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
            IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    FilePermission perm;
    if (IsAclInitialized()) {
        bool existingFile = (CreateDisposition != FILE_CREATE);
        perm = existingFile
            ? CheckFilePermissionWithHardLinks(pathStr)
            : CheckFilePermission(pathStr);
    } else {
        perm = FilePermission::Inherit;
    }

    if (perm == FilePermission::Deny) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_create", DesiredAccess, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    // ★ Deny 路径也要检查 FILE_DELETE_ON_CLOSE（防 DeleteFileW 绕过）
    if (perm == FilePermission::Deny && (CreateOptions & 0x00001000)) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_delete_on_close",
                 CreateOptions, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    if (perm == FilePermission::ReadOnly) {
        DWORD writeFlags = GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA
                         | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE;
        DWORD dirWriteFlags = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD;
        DWORD allWriteFlags = writeFlags | dirWriteFlags;

        if (DesiredAccess & allWriteFlags) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_write_readonly", DesiredAccess, STATUS_ACCESS_DENIED);
            if (FileHandle) *FileHandle = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }

        if (CreateOptions & 0x00001000) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_delete_on_close_readonly",
                     CreateOptions, STATUS_ACCESS_DENIED);
            if (FileHandle) *FileHandle = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }

        if ((CreateOptions & FILE_DIRECTORY_FILE) &&
            (CreateDisposition == FILE_CREATE || CreateDisposition == FILE_SUPERSEDE ||
             CreateDisposition == FILE_OPEN_IF || CreateDisposition == FILE_OVERWRITE_IF)) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_mkdir_readonly", DesiredAccess, STATUS_ACCESS_DENIED);
            if (FileHandle) *FileHandle = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

// ============================================================================
// NtOpenFile Hook
// ============================================================================

static NTSTATUS WINAPI Hook_NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions)
{
    if (!Real_NtOpenFile) {
        if (FileHandle) *FileHandle = nullptr;
        return STATUS_ACCESS_DENIED;
    }

    wchar_t path[1024] = {0};
    if (!ExtractPathFromOA(ObjectAttributes, path, 1024) || !path[0]) {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, ShareAccess, OpenOptions);
    }

    std::wstring pathStr(path);
    if (IsDevicePath(pathStr)) {
        return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                               IoStatusBlock, ShareAccess, OpenOptions);
    }

    FilePermission perm = CheckFilePermissionWithHardLinks(pathStr);
    if (perm == FilePermission::Deny) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_open", DesiredAccess, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }
    if (perm == FilePermission::ReadOnly) {
        DWORD writeFlags = GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA
                         | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE;
        if (DesiredAccess & writeFlags) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_open_readonly", DesiredAccess, STATUS_ACCESS_DENIED);
            if (FileHandle) *FileHandle = nullptr;
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Real_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
                           IoStatusBlock, ShareAccess, OpenOptions);
}

// ============================================================================
// NtDeleteFile Hook
// ============================================================================

static NTSTATUS WINAPI Hook_NtDeleteFile(PVOID ObjectAttributes) {
    if (!Real_NtDeleteFile) return STATUS_ACCESS_DENIED;

    wchar_t path[1024] = {0};
    if (ExtractPathFromOA(ObjectAttributes, path, 1024) && path[0]) {
        std::wstring pathStr(path);
        FilePermission perm = CheckFilePermissionWithHardLinks(pathStr);
        if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
            AuditLog(AuditEventType::FileDeny, pathStr, L"deny_delete", DELETE, STATUS_ACCESS_DENIED);
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
    } else {
        AuditLog(AuditEventType::FileDeny, L"<unresolved>", L"delete_unresolved_path",
                 DELETE, 0);
    }

    return Real_NtDeleteFile(ObjectAttributes);
}

// ============================================================================
// NtSetInformationFile Hook（重命名/硬链接/删除标记）
// ============================================================================

static NTSTATUS WINAPI Hook_NtSetInformationFile(
    HANDLE FileHandle, PVOID IoStatusBlock,
    PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass)
{
    if (!Real_NtSetInformationFile) return STATUS_ACCESS_DENIED;

    auto resolveTargetPath = [&](wchar_t* outPath, size_t outSize) -> bool {
        if (outSize == 0) return false;
        outPath[0] = L'\0';
        if (Length < 20) return false;

        BYTE* info = (BYTE*)FileInformation;
#ifdef _M_IX86
        HANDLE rootDir = *(HANDLE*)(info + 4);
        DWORD nameLenBytes = *(DWORD*)(info + 8);
        WCHAR* fileName = (WCHAR*)(info + 12);
#else
        HANDLE rootDir = *(HANDLE*)(info + 8);
        DWORD nameLenBytes = *(DWORD*)(info + 16);
        WCHAR* fileName = (WCHAR*)(info + 20);
#endif
        if (nameLenBytes == 0 || nameLenBytes >= 4096) return false;
        size_t nameChars = nameLenBytes / sizeof(WCHAR);
        if (nameChars >= outSize) nameChars = outSize - 1;

        if (rootDir && rootDir != INVALID_HANDLE_VALUE) {
            if (EnterResolveRelative()) {
                wchar_t dirPath[1024] = {0};
                if (GetFinalPathNameByHandleW(rootDir, dirPath, 1024, 0) > 0) {
                    int pos = (wcsncmp(dirPath, L"\\\\?\\", 4) == 0) ? 4 : 0;
                    wchar_t* dirStart = dirPath + pos;
                    size_t dirLen = wcslen(dirStart);
                    if (dirLen > 0 && dirStart[dirLen - 1] != L'\\') {
                        if (dirLen < 1023) { dirStart[dirLen] = L'\\'; dirStart[dirLen + 1] = L'\0'; }
                    }
                    wcsncpy_s(outPath, outSize, dirStart, _TRUNCATE);
                }
                LeaveResolveRelative();
            }
            if (!outPath[0]) return false;
            size_t baseLen = wcslen(outPath);
            size_t copyChars = nameChars;
            if (baseLen + copyChars >= outSize) copyChars = outSize - baseLen - 1;
            wcsncpy_s(outPath + baseLen, outSize - baseLen, fileName, copyChars);
            outPath[baseLen + copyChars] = L'\0';
        } else {
            wcsncpy_s(outPath, outSize, fileName, nameChars);
            outPath[nameChars] = L'\0';
            if (wcsncmp(outPath, L"\\??\\", 4) == 0) {
                wcscpy_s(outPath, outSize, outPath + 4);
            }
        }

        if (outPath[0]) {
            std::transform(outPath, outPath + wcslen(outPath), outPath, ::towupper);
            return true;
        }
        return false;
    };

    // 重命名拦截 (FileRenameInformation=10, FileRenameInformationEx=66)
    if (FileInformationClass == 10 || FileInformationClass == 66) {
        wchar_t targetPath[1024] = {0};
        if (resolveTargetPath(targetPath, 1024)) {
            FilePermission perm = CheckFilePermission(targetPath);
            if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
                AuditLog(AuditEventType::FileDeny, targetPath, L"deny_rename",
                         0, STATUS_ACCESS_DENIED);
                SetLastError(ERROR_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            }
        }
    }

    // 硬链接拦截 (FileLinkInformation=11)
    if (FileInformationClass == 11) {
        wchar_t targetPath[1024] = {0};
        if (resolveTargetPath(targetPath, 1024)) {
            wchar_t srcPath[1024] = {0};
            if (GetPathFromHandle(FileHandle, srcPath, 1024) && srcPath[0]) {
                FilePermission targetPerm = CheckFilePermission(targetPath);
                if (targetPerm == FilePermission::Deny || targetPerm == FilePermission::ReadOnly) {
                    AuditLog(AuditEventType::FileDeny, targetPath, L"deny_link_target",
                             0, STATUS_ACCESS_DENIED);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }

                FilePermission srcPerm = CheckFilePermissionWithHardLinks(srcPath);
                if (srcPerm == FilePermission::Deny || srcPerm == FilePermission::ReadOnly) {
                    AuditLog(AuditEventType::FileDeny, targetPath, L"deny_link_src_hardlink",
                             0, STATUS_ACCESS_DENIED);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            }
        }
    }

    // 标记删除 (FileDispositionInformation=13)
    if (FileInformationClass == 13 && Length >= 1) {
        if (*(BYTE*)FileInformation) {
            wchar_t path[1024] = {0};
            if (GetPathFromHandle(FileHandle, path, 1024) && path[0]) {
                FilePermission perm = CheckFilePermissionWithHardLinks(path);
                if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
                    AuditLog(AuditEventType::FileDeny, path, L"deny_delete_via_setinfo",
                             0, STATUS_ACCESS_DENIED);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            } else {
                AuditLog(AuditEventType::FileDeny, L"<class13_nopath>",
                         L"delete_class13_no_path", FileInformationClass, GetLastError());
            }
        }
    }

    // 标记删除 EX (FileDispositionInformationEx=37, Win10 1903+)
    if (FileInformationClass == 37 && Length >= 4) {
        if ((*(DWORD*)FileInformation) & FILE_DISPOSITION_DELETE) {
            wchar_t path[1024] = {0};
            if (GetPathFromHandle(FileHandle, path, 1024) && path[0]) {
                FilePermission perm = CheckFilePermissionWithHardLinks(path);
                if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
                    AuditLog(AuditEventType::FileDeny, path, L"deny_delete_via_setinfo_ex",
                             0, STATUS_ACCESS_DENIED);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }
            } else {
                AuditLog(AuditEventType::FileDeny, L"<class37_nopath>",
                         L"delete_class37_no_path", FileInformationClass, GetLastError());
            }
        }
    }

    return Real_NtSetInformationFile(FileHandle, IoStatusBlock,
        FileInformation, Length, FileInformationClass);
}

// ============================================================================
// NtWriteFile Hook（★ 使用 NtQueryObject 快速路径 + GetFinalPathNameByHandleW 回退）
// ============================================================================

static NTSTATUS WINAPI Hook_NtWriteFile(
    HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext,
    PVOID IoStatusBlock, PVOID Buffer,
    ULONG Length, PLARGE_INTEGER ByteOffset,
    PULONG Key)
{
    if (!Real_NtWriteFile) return STATUS_ACCESS_DENIED;

    // Tier 1: NtQueryObject 快速路径（无递归风险，<1μs）
    wchar_t path[1024] = {0};
    bool pathResolved = GetPathFromHandleNt(FileHandle, path, 1024);

    // Tier 2: 回退到 GetFinalPathNameByHandleW（带 TLS 守卫）
    if (!pathResolved || !path[0]) {
        path[0] = L'\0';
        pathResolved = GetPathFromHandle(FileHandle, path, 1024);
    }

    if (pathResolved && path[0]) {
        FilePermission perm = CheckFilePermission(path);
        if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
            AuditLog(AuditEventType::FileDeny, path, L"deny_writefile",
                     0, STATUS_ACCESS_DENIED);
            SetLastError(ERROR_ACCESS_DENIED);
            return STATUS_ACCESS_DENIED;
        }
    }

    return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

// ============================================================================
// 安装函数
// ============================================================================

void InstallNtCreateFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtCreateFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtCreateFile, "NtCreateFile");
        if (tramp) Real_NtCreateFile = (decltype(Real_NtCreateFile))tramp;
    }
}

void InstallNtOpenFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtOpenFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtOpenFile, "NtOpenFile");
        if (tramp) Real_NtOpenFile = (decltype(Real_NtOpenFile))tramp;
    }
}

void InstallNtDeleteFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtDeleteFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtDeleteFile, "NtDeleteFile");
        if (tramp) Real_NtDeleteFile = (decltype(Real_NtDeleteFile))tramp;
    }
}

void InstallNtSetInformationFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtSetInformationFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtSetInformationFile, "NtSetInformationFile");
        if (tramp) Real_NtSetInformationFile = (decltype(Real_NtSetInformationFile))tramp;
    }
}

void InstallNtWriteFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtWriteFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtWriteFile, "NtWriteFile");
        if (tramp) Real_NtWriteFile = (decltype(Real_NtWriteFile))tramp;
    }
}
