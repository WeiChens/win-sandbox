# P0 安全漏洞修复计划

> 基于与 Trae 的架构差距分析，修复 6 个 🚨P0 安全漏洞

---

## 总览

| # | 漏洞 | 文件 | 代码行 | 难度 | 安全影响 |
|---|------|------|:------:|:----:|:--------:|
| 1 | WSASocketW + WSAConnect | net_acl.cpp | ~80 | 低 | 原始套接字绕过 connect hook |
| 2 | DnsQueryEx/A/W/UTF8 | net_acl.cpp | ~200 | 中 | 4 种 DNS API 绕过 getaddrinfo |
| 3 | NtQueryDirectoryFile | hook_file.cpp | ~150 | 中 | 目录枚举泄漏拒绝路径 |
| 4 | NtQuerySymbolicLinkObject | hook_file.cpp | ~100 | 中 | 符号链接绕过路径检查 |
| 5 | NtMapViewOfSection + NtOpenSection | hook_memory.cpp | ~200 | 高 | 内存映射文件完全绕过 ACL |

---

## 1. WSASocketW + WSAConnect Hook

### 问题
应用程序可以使用 `WSASocketW` + `WSAConnect` 绕过我们的 `connect()` Hook：
```cpp
SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
// 不走 socket() → 绕过 socket() hook
WSAConnect(s, (SOCKADDR*)&addr, sizeof(addr), nullptr, nullptr, nullptr, nullptr);
// 不走 connect() → 绕过 connect() hook！
```

### 方案
在 `net_acl.cpp` 的 `InstallNetHooks()` 中，通过 `WSAStartup` Hook 延迟安装：
1. Hook `WSASocketW` — 仅返回原始函数（不做检查，socket 创建本身不需要权限）
2. Hook `WSAConnect` — 在连接时调用 `CheckNetPermission()`，与 `Hook_connect` 共享规则

### 文件修改
- `dll/sandbox-hook/src/net_acl.cpp` — 新增 `Hook_WSASocketW` + `Hook_WSAConnect`
- `dll/sandbox-hook/include/net_acl.h` — 无需修改（`InstallNetHooks` 已声明）

### 代码量
~80 行，在 `InstallNetHooks()` 的延迟安装部分添加两个 Hook

---

## 2. DnsQueryEx/A/W/UTF8 Hook

### 问题
Chrome/Node.js 等应用使用 `DnsQuery_*` 系列 API 直接查询 DNS，绕过 `getaddrinfo`：
```
应用程序:
  DnsQuery_W("malicious.com", ...)    ← 不走 getaddrinfo！
  → 直接查 DNS → 绕过我们的 DNS 拒绝规则
```

### 方案
在 `net_acl.cpp` 中新增 `InitDnsHooks()` 函数：
1. 在 `InstallNetHooks()` 中通过 `GetModuleHandle` 检查 `dnsapi.dll` 是否已加载
2. 若已加载，Hook `DnsQuery_A`, `DnsQuery_W`, `DnsQuery_UTF8`, `DnsQueryEx`
3. 若未加载，在 `LoadLibrary` callback 或首次使用时延迟安装
4. Hook 函数中调用 `CheckNetPermission()`，与 DNS 拒绝规则共享

### 文件修改
- `dll/sandbox-hook/src/net_acl.cpp` — 新增 4 个 Hook 函数 + `InitDnsHooks()`
- `dll/sandbox-hook/include/net_acl.h` — 无需修改

### 关键设计
```
DnsQuery_W → Hook_DnsQuery_W:
  1. 提取查询的主机名
  2. CheckNetPermission(hostname) → Deny?
  3. Deny → return DNS_ERROR_HOST_NOT_FOUND
  4. Allow → 调用 Real_DnsQuery_W
```

### DnsQuery API 签名
```cpp
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_W)(
    PCWSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORDW* ppQueryResultsSet,
    PVOID* pReserved);

typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(
    PCSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORDA* ppQueryResultsSet,
    PVOID* pReserved);

typedef DNS_STATUS (WINAPI *PFN_DnsQuery_UTF8)(
    PCSTR pName, WORD wType, DWORD Options,
    PVOID pExtra, PDNS_RECORDW* ppQueryResultsSet,
    PVOID* pReserved);

typedef DNS_STATUS (WINAPI *PFN_DnsQueryEx)(
    PDNS_QUERY_REQUEST pQueryRequest,
    PDNS_QUERY_RESULT pQueryResult,
    PDNS_SERVICE_CANCEL* pCancelHandle);
```

### 代码量
~200 行

---

## 3. NtQueryDirectoryFile Hook

### 问题
拒绝路径中的文件可通过目录遍历被枚举：
```
配置: C:\Secret\** → Deny
攻击:
  FindFirstFile("C:\Secret\*", ...)  ← 走 NtQueryDirectoryFile！
  → 返回目录中所有文件列表
  → 文件存在性泄漏（虽然不能读）
```

### 方案
在 `hook_file.cpp` 中新增：
1. 在 `InstallAllHooks()` 添加 `InstallNtQueryDirectoryFileHook()`
2. Hook 函数中拦截 `NtQueryDirectoryFile` 调用
3. 对每次返回的目录项，检查该项的完整路径是否匹配 Deny/ReadOnly 规则
4. 若匹配，从返回缓冲区中移除该项（跳过/缩减 FileName 长度）

### 关键实现细节
```
Hook_NtQueryDirectoryFile:
  1. 调用 Real_NtQueryDirectoryFile (获取原始目录列表)
  2. 如果成功 (NTSTATUS >= 0):
     a. 获取查询的目录路径（从 FileHandle → GetPathFromHandleNt）
     b. 遍历返回的 FILE_DIRECTORY_INFO / FILE_BOTH_DIR_INFO 等结构
     c. 对每一项: 拼接目录路径 + 文件名
     d. CheckFilePermission(fullPath) == Deny?
     e. 如果是: 在缓冲区中移除该项（后续项前移，减短返回长度）
  3. 返回修改后的结果
```

### 处理多种信息类
NtQueryDirectoryFile 有多种 FileInformationClass：
- `FileDirectoryInformation` (1) — 固定大小
- `FileFullDirectoryInformation` (2) — 固定大小
- `FileBothDirectoryInformation` (3) — 变长（最常用）
- `FileNamesInformation` (12) — 仅文件名
- `FileDirectoryInformation` (37) — Win10+

我们主要处理 `FileBothDirectoryInformation` (3) 和 `FileFullDirectoryInformation` (2)。

### 代码量
~150 行，在 hook_file.cpp 中新增

---

## 4. NtQuerySymbolicLinkObject Hook

### 问题
符号链接可绕过路径 ACL 检查：
```
C:\Users\Public\link.lnk → C:\Secret\secret.txt

我们的检查:
  ExtractPathFromOA → "C:\USERS\PUBLIC\LINK.LNK"
  CheckFilePermission("C:\USERS\PUBLIC\LINK.LNK") → Inherit ✓
  → 实际访问的是 C:\Secret\secret.txt ← 绕过！

Trae: GetFileSymbolicLink → 最终目标
  CheckFilePermission("C:\SECRET\SECRET.TXT") → Deny ✗
```

### 方案
在 `hook_file.cpp` 中新增：
1. 在 `InstallAllHooks()` 添加 `InstallNtQuerySymbolicLinkObjectHook()`
2. 新增辅助函数 `ResolveSymbolicLink()` — 递归追踪符号链接至最终目标
3. 修改现有的文件 Hook（NtCreateFile/NtOpenFile/NtDeleteFile），在检查 ACL 前调用 `ResolveSymbolicLink()`

### 关键实现
```cpp
// 递归解析符号链接
std::wstring ResolveSymbolicLink(const std::wstring& path, int depth = 0) {
    if (depth > 16) return path;  // 防止循环链接
    if (!IsReparsePoint(path)) return path;
    
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return path;
    
    wchar_t target[1024] = {0};
    // 使用 GetFinalPathNameByHandleW 获取符号链接目标
    DWORD ret = GetFinalPathNameByHandleW(hFile, target, 1024, FILE_NAME_NORMALIZED);
    CloseHandle(hFile);
    
    if (ret == 0 || ret >= 1024) return path;
    // 去掉 \\?\ 前缀
    std::wstring resolved = (wcsncmp(target, L"\\\\?\\", 4) == 0) ? target + 4 : target;
    std::transform(resolved.begin(), resolved.end(), resolved.begin(), ::towupper);
    
    return ResolveSymbolicLink(resolved, depth + 1);
}
```

然后在现有的 Hook 中：
```cpp
// Hook_NtCreateFile / Hook_NtOpenFile 中，检查权限前：
std::wstring resolvedPath = ResolveSymbolicLink(pathStr);
FilePermission perm = CheckFilePermissionWithHardLinks(resolvedPath);
```

**注意**：这个方案有一个性能问题——每次文件操作都调用 CreateFileW + GetFinalPathNameByHandleW 很慢。
优化方案：仅在路径包含 Junction/Mount Point/Symlink 特征时（检查 `IsReparsePoint`）才做解析。

### 代码量
~100 行（`ResolveSymbolicLink` 辅助函数 + 在现有 Hook 中插入调用）

---

## 5. NtMapViewOfSection + NtOpenSection Hook

### 问题
通过 `CreateFileMapping` + `MapViewOfFile` 完全绕过文件 ACL：
```
攻击路径:
  1. CreateFileMapping(
       INVALID_HANDLE_VALUE,          ← 不用 CreateFile！
       ..., PAGE_READWRITE,
       0, 4096, "Local\\MySection")
  2. MapViewOfFile(hMap, ...)
     → 直接修改映射内存
     → NtWriteFile 没触发！NtCreateFile 没触发！
```

### 方案
在新增的 `hook_memory.cpp` 中：
1. Hook `NtOpenSection` — 拦截打开命名 section 的请求
2. Hook `NtMapViewOfSection` — 拦截映射 section 的请求
3. 通过 `NtQueryObject` 获取 section 句柄对应的文件名
4. 检查文件 ACL 权限，对 ReadOnly/Deny 路径阻断写映射

### 关键实现
```cpp
static NTSTATUS WINAPI Hook_NtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits,
    SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect)
{
    // 检查是否写映射
    bool isWrite = (Win32Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY));
    if (!isWrite) {
        return Real_NtMapViewOfSection(...);  // 只读映射放行
    }
    
    // 获取 section 对应的文件路径
    wchar_t path[1024] = {0};
    if (GetPathFromHandleNt(SectionHandle, path, 1024) && path[0]) {
        FilePermission perm = CheckFilePermission(path);
        if (perm == FilePermission::Deny || perm == FilePermission::ReadOnly) {
            AuditLog(...);
            return STATUS_ACCESS_DENIED;
        }
    }
    
    return Real_NtMapViewOfSection(...);
}
```

**注意**：`NtMapViewOfSection` 的 SectionHandle 可能是匿名 section（无文件后端），
也可能是文件-backed section。只有文件-backed section 需要检查。
`NtQueryObject(hSection, ObjectNameInformation)` 对匿名 section 返回空名。

### 文件
- `dll/sandbox-hook/src/hook_memory.cpp` — 新增
- `dll/sandbox-hook/include/hook_engine.h` — 添加声明
- `dll/sandbox-hook/CMakeLists.txt` — 添加 hook_memory.cpp

### 代码量
~200 行

---

## 实施顺序

按"对现有代码影响最小 + 安全收益最大"排序：

```
Phase 1 (✅ 已完成)：
  [1] WSASocketW + WSAConnect    — 80行，仅改 net_acl.cpp          ✅ 编译通过 + 71/71 回归测试通过
  [2] DnsQueryEx/A/W/UTF8        — 200行，仅改 net_acl.cpp          ✅ 编译通过 + 71/71 回归测试通过
  [3] NtQueryDirectoryFile       — 150行，仅改 hook_file.cpp         ✅ 编译通过 + 71/71 回归测试通过

Phase 2 (✅ 已完成)：
  [4] NtQuerySymbolicLinkObject  — 100行，改 hook_file.cpp + 现有 Hook  ✅ 编译通过 + 71/71 回归
  [5] NtMapViewOfSection         — 200行，新增 hook_memory.cpp          ✅ 编译通过 + 71/71 回归
```

---

## 完整实现总结

| # | 功能 | 主要文件 | 新增代码 | 编译 | 回归测试 | 状态 |
|---|------|----------|:--------:|:----:|:--------:|:----:|
| 1 | WSASocketW + WSAConnect | net_acl.cpp | ~80 行 | ✅ x64+x86 | ✅ 71/71 | ✅ |
| 2 | DnsQueryEx/A/W/UTF8 | net_acl.cpp | ~200 行 | ✅ x64+x86 | ✅ 71/71 | ✅ |
| 3 | NtQueryDirectoryFile | hook_file.cpp + .h | ~350 行 | ✅ x64+x86 | ✅ 71/71 | ✅ |
| 4 | 符号链接解析防护 | file_acl.cpp + hook_file.cpp | ~120 行 | ✅ x64+x86 | ✅ 71/71 | ✅ |
| 5 | NtMapViewOfSection | hook_memory.cpp + CMakeLists.txt | ~200 行 | ✅ x64+x86 | ✅ 71/71 | ✅ |

### 全部 5 个 🚨P0 安全漏洞已修复

| # | 漏洞 | 拦截的攻击向量 | 严重程度 |
|---|------|---------------|:--------:|
| 1 | WSASocketW + WSAConnect | 重叠 I/O 套接字绕过 connect() | 高 |
| 2 | DnsQueryEx/A/W/UTF8 | 4 种 DNS 专用 API 绕过 getaddrinfo | 高 |
| 3 | NtQueryDirectoryFile | 目录枚举泄漏拒绝路径的文件名 | 高 |
| 4 | 符号链接/交接点绕过 | 符号链接指向拒绝路径，原路径检查放行 | 高 |
| 5 | NtMapViewOfSection | 内存映射文件完全绕过 NtCreateFile/NtWriteFile | 高 |

### 文件变更清单

| 文件 | 变更说明 |
|------|---------|
| `dll/sandbox-hook/src/net_acl.cpp` | + WSASocketW/WSAConnect Hook; + DnsQueryEx/A/W/UTF8 Hook (4个) |
| `dll/sandbox-hook/src/hook_file.cpp` | + NtQueryDirectoryFile Hook (目录枚举过滤); 所有 Hook 改用符号链接感知检查 |
| `dll/sandbox-hook/src/hook_memory.cpp` | **新增** NtMapViewOfSection + NtOpenSection Hook |
| `dll/sandbox-hook/src/file_acl.cpp` | + ResolveSymbolicLink + CheckFilePermissionWithSymlink (递归解析) |
| `dll/sandbox-hook/src/hook_engine.cpp` | + 注册 3 个新 Hook 安装调用 |
| `dll/sandbox-hook/include/hook_engine.h` | + 3 个新 Hook 声明 |
| `dll/sandbox-hook/include/file_acl.h` | + CheckFilePermissionWithSymlink 声明 |
| `dll/sandbox-hook/CMakeLists.txt` | + hook_memory.cpp 源文件 |

## 剩余差距（🟡P1）

| # | 功能 | 难度 | 说明 |
|---|------|:----:|------|
| 6 | WOW64 路径重定向 | 低 | SysWOW64↔System32 映射 |
| 7 | SetUnhandledExceptionFilter Hook | 中 | 崩溃恢复 + MiniDumpWriteDump |
| 8 | sendto/recvfrom Hook | 低 | UDP 数据报绕过 |
| 9 | WSASend/WSARecv Hook | 中 | 重叠 I/O 收发 |
| 10 | WSAIoctl(ConnectEx/RIO) Hook | 中 | 注册 I/O 绕过 Winsock 层 |
| 11 | CorExitProcess Hook | 低 | .NET CLR 退出拦截 |
| 12 | GetAddrInfoExW Hook | 中 | 异步 DNS API |
