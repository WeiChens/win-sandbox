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
#define STATUS_NO_SUCH_FILE  ((NTSTATUS)0xC000000FL)
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

// IO_STATUS_BLOCK
typedef struct _MY_IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG    Information;
} MY_IO_STATUS_BLOCK, *PMY_IO_STATUS_BLOCK;

// FILE_BOTH_DIR_INFORMATION — NtQueryDirectoryFile 常用格式
#pragma pack(push, 1)
typedef struct _MY_FILE_BOTH_DIR_INFORMATION {
    ULONG  NextEntryOffset;
    ULONG  FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG  FileAttributes;
    ULONG  FileNameLength;     // 字节数
    ULONG  EaSize;             // 扩展属性大小
    CCHAR  ShortNameLength;
    WCHAR  ShortName[12];
    WCHAR  FileName[1];        // 变长数组，实际长度由 FileNameLength 决定
} MY_FILE_BOTH_DIR_INFORMATION;

typedef struct _MY_FILE_FULL_DIR_INFORMATION {
    ULONG  NextEntryOffset;
    ULONG  FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG  FileAttributes;
    ULONG  FileNameLength;
    ULONG  EaSize;
    WCHAR  FileName[1];
} MY_FILE_FULL_DIR_INFORMATION;

// ★ FILE_NAMES_INFORMATION 官方定义只有 NextEntryOffset + FileIndex + FileNameLength + FileName
//   之前的定义多了 7 个 LARGE_INTEGER 字段（56 字节），导致 FilterDeniedEntries 中偏移计算全错
typedef struct _MY_FILE_NAMES_INFORMATION {
    ULONG  NextEntryOffset;
    ULONG  FileIndex;
    ULONG  FileNameLength;     // 字节数
    WCHAR  FileName[1];        // 变长数组
} MY_FILE_NAMES_INFORMATION;
#pragma pack(pop)

// NtQueryDirectoryFile 的 FileInformationClass 常量
#define FileDirectoryInformation      1
#define FileFullDirectoryInformation  2
#define FileBothDirectoryInformation  3
#define FileNamesInformation          12

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

static NTSTATUS (WINAPI *Real_NtQueryDirectoryFile)(
    HANDLE, HANDLE, PVOID, PVOID, PMY_IO_STATUS_BLOCK,
    PVOID, ULONG, ULONG, BOOLEAN, PVOID, BOOLEAN) = nullptr;

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

// 符号链接解析函数实现在 file_acl.cpp 中定义
// (CheckFilePermissionWithSymlink, ResolveSymbolicLink, IsReparsePoint)

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
        // ★ 始终使用 CheckFilePermissionWithSymlink（含 WOW64 重定向 + 符号链接解析）
        //    FILE_CREATE 时文件虽不存在，但 WOW64 重定向仍然需要
        perm = CheckFilePermissionWithSymlink(pathStr);
    } else {
        perm = FilePermission::Inherit;
    }

    if (perm == FilePermission::Deny) {
        AuditLog(AuditEventType::FileDeny, pathStr, L"deny_create", DesiredAccess, STATUS_ACCESS_DENIED);
        if (FileHandle) *FileHandle = nullptr;
        SetLastError(ERROR_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    // ★ ReadOnly + FILE_DELETE_ON_CLOSE → 拒绝（防 DeleteFileW 绕过）
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

    FilePermission perm = CheckFilePermissionWithSymlink(pathStr);
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
        FilePermission perm = CheckFilePermissionWithSymlink(pathStr);
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
            FilePermission perm = CheckFilePermissionWithSymlink(targetPath);
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
                FilePermission targetPerm = CheckFilePermissionWithSymlink(targetPath);
                if (targetPerm == FilePermission::Deny || targetPerm == FilePermission::ReadOnly) {
                    AuditLog(AuditEventType::FileDeny, targetPath, L"deny_link_target",
                             0, STATUS_ACCESS_DENIED);
                    SetLastError(ERROR_ACCESS_DENIED);
                    return STATUS_ACCESS_DENIED;
                }

                FilePermission srcPerm = CheckFilePermissionWithSymlink(srcPath);
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
                FilePermission perm = CheckFilePermissionWithSymlink(path);
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
                FilePermission perm = CheckFilePermissionWithSymlink(path);
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
        // 解析符号链接后检查权限
        std::wstring pathStr(path);
        FilePermission perm = CheckFilePermissionWithSymlink(pathStr);
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
// NtQueryDirectoryFile Hook — 目录枚举过滤（防止拒绝路径文件泄漏）
//
// 当 NtQueryDirectoryFile 返回目录列表时，遍历所有条目，
// 检查每个文件的完整路径是否匹配 Deny/ReadOnly 权限。
// 如果匹配，从返回缓冲区中移除该条目。
// ============================================================================

/// 从目录句柄获取目录路径（带缓存）
static bool GetDirectoryPath(HANDLE hDir, wchar_t* out, size_t outSize) {
    if (!hDir || hDir == INVALID_HANDLE_VALUE || !out || outSize == 0)
        return false;

    // Tier 1: NtQueryObject 快速路径
    if (GetPathFromHandleNt(hDir, out, outSize) && out[0])
        return true;

    // Tier 2: GetFinalPathNameByHandleW 回退
    return GetPathFromHandle(hDir, out, outSize);
}

/// 检查目录条目文件名是否应被隐藏（匹配 Deny/ReadOnly 规则，含符号链接检测）
static bool ShouldHideEntry(const std::wstring& dirPath, const WCHAR* fileName, ULONG fileNameLen) {
    if (!fileName || fileNameLen == 0) return false;

    // 跳过 . 和 ..
    if (fileNameLen == 1 && fileName[0] == L'.') return false;
    if (fileNameLen == 2 && fileName[0] == L'.' && fileName[1] == L'.') return false;

    // 构造完整路径
    std::wstring fullPath = dirPath;
    if (!fullPath.empty() && fullPath.back() != L'\\')
        fullPath += L'\\';
    fullPath.append(fileName, fileNameLen / sizeof(WCHAR));

    // 大写归一化
    std::transform(fullPath.begin(), fullPath.end(), fullPath.begin(), ::towupper);

    // 检查权限（含符号链接解析 + 硬链接防护）
    FilePermission perm = CheckFilePermissionWithSymlink(fullPath);
    return (perm == FilePermission::Deny || perm == FilePermission::ReadOnly);
}

/// 从缓冲区中移除被拒绝的目录条目
/// 通过调整 NextEntryOffset 跳过匹配的条目
static ULONG FilterDeniedEntries(BYTE* buffer, ULONG bufferLen,
                                  const std::wstring& dirPath,
                                  ULONG infoClass) {
    if (!buffer || bufferLen == 0) return bufferLen;

    BYTE* current = buffer;
    BYTE* writePos = buffer;
    BYTE* bufferEnd = buffer + bufferLen;

    while (current < bufferEnd) {
        ULONG nextOffset = 0;

        // 根据信息类提取 NextEntryOffset 和 FileName
        WCHAR* fileName = nullptr;
        ULONG fileNameLen = 0;

        switch (infoClass) {
            case FileBothDirectoryInformation: {
                auto* entry = reinterpret_cast<MY_FILE_BOTH_DIR_INFORMATION*>(current);
                nextOffset = entry->NextEntryOffset;
                fileName = entry->FileName;
                fileNameLen = entry->FileNameLength;
                break;
            }
            case FileFullDirectoryInformation: {
                auto* entry = reinterpret_cast<MY_FILE_FULL_DIR_INFORMATION*>(current);
                nextOffset = entry->NextEntryOffset;
                fileName = entry->FileName;
                fileNameLen = entry->FileNameLength;
                break;
            }
            case FileDirectoryInformation: {
                // FileDirectoryInformation 和 FileFullDirectoryInformation 结构相同
                auto* entry = reinterpret_cast<MY_FILE_FULL_DIR_INFORMATION*>(current);
                nextOffset = entry->NextEntryOffset;
                fileName = entry->FileName;
                fileNameLen = entry->FileNameLength;
                break;
            }
            case FileNamesInformation: {
                auto* entry = reinterpret_cast<MY_FILE_FULL_DIR_INFORMATION*>(current);
                nextOffset = entry->NextEntryOffset;
                fileName = entry->FileName;
                fileNameLen = entry->FileNameLength;
                break;
            }
            default:
                // 不支持的信息类，保持原样
                return bufferLen;
        }

        // 计算当前条目大小（包括到下一个条目的偏移）
        ULONG entrySize = (nextOffset > 0) ? nextOffset : (ULONG)(bufferEnd - current);

        // 检查是否应该隐藏此条目
        bool shouldHide = ShouldHideEntry(dirPath, fileName, fileNameLen);

        if (!shouldHide) {
            // 保留此条目：如果 writePos != current，移动数据
            if (writePos != current) {
                memmove(writePos, current, entrySize);
            }
            writePos += entrySize;
        } else {
            // 跳过此条目（不拷贝），记录审计
            std::wstring hiddenName(fileName, fileNameLen / sizeof(WCHAR));
            AuditLog(AuditEventType::FileDeny, dirPath + L"\\" + hiddenName,
                     L"hidden_from_directory_enum", 0, STATUS_ACCESS_DENIED);
        }

        if (nextOffset == 0) break;  // 最后一项
        current += nextOffset;
    }

    // 最后一项的 NextEntryOffset 必须置 0
    if (writePos > buffer && writePos <= bufferEnd) {
        // 根据信息类设置 NextEntryOffset = 0
        switch (infoClass) {
            case FileBothDirectoryInformation:
                reinterpret_cast<MY_FILE_BOTH_DIR_INFORMATION*>(writePos - sizeof(MY_FILE_BOTH_DIR_INFORMATION))->NextEntryOffset = 0;
                break;
            case FileFullDirectoryInformation:
            case FileDirectoryInformation:
                reinterpret_cast<MY_FILE_FULL_DIR_INFORMATION*>(writePos - sizeof(MY_FILE_FULL_DIR_INFORMATION))->NextEntryOffset = 0;
                break;
            case FileNamesInformation:
                reinterpret_cast<MY_FILE_NAMES_INFORMATION*>(writePos - sizeof(MY_FILE_NAMES_INFORMATION))->NextEntryOffset = 0;
                break;
        }
    }

    return (ULONG)(writePos - buffer);
}

static NTSTATUS WINAPI Hook_NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext,
    PMY_IO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length,
    ULONG FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PVOID FileName,
    BOOLEAN RestartScan)
{
    if (!Real_NtQueryDirectoryFile) {
        return STATUS_ACCESS_DENIED;
    }

    // 只处理我们支持的信息类
    if (FileInformationClass != FileBothDirectoryInformation &&
        FileInformationClass != FileFullDirectoryInformation &&
        FileInformationClass != FileDirectoryInformation &&
        FileInformationClass != FileNamesInformation) {
        return Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, FileInformation, Length, FileInformationClass,
            ReturnSingleEntry, FileName, RestartScan);
    }

    // 调用原始函数
    NTSTATUS status = Real_NtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, FileInformation, Length, FileInformationClass,
        ReturnSingleEntry, FileName, RestartScan);

    // 只处理成功的返回
    if (status < 0) return status;
    if (!IoStatusBlock || IoStatusBlock->Information == 0) return status;

    // 获取目录路径
    wchar_t dirPath[1024] = {0};
    if (!GetDirectoryPath(FileHandle, dirPath, 1024) || !dirPath[0]) {
        return status;  // 无法获取路径，放行
    }

    std::wstring dirPathStr(dirPath);

    // 过滤被拒绝的条目
    ULONG newInfoLength = FilterDeniedEntries(
        reinterpret_cast<BYTE*>(FileInformation),
        Length,
        dirPathStr,
        FileInformationClass);

    // 更新返回长度
    IoStatusBlock->Information = newInfoLength;

    // 如果所有条目都被过滤了，返回 STATUS_NO_SUCH_FILE
    if (newInfoLength == 0 && !ReturnSingleEntry) {
        return STATUS_NO_SUCH_FILE;
    }

    return status;
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

void InstallNtQueryDirectoryFileHook() {
    BYTE* target = FindFunction("ntdll.dll", "NtQueryDirectoryFile");
    if (target) {
        auto* tramp = (BYTE*)DetourInstall(target, (BYTE*)Hook_NtQueryDirectoryFile, "NtQueryDirectoryFile");
        if (tramp) Real_NtQueryDirectoryFile = (decltype(Real_NtQueryDirectoryFile))tramp;
    }
}
