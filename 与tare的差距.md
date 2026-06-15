# 与 Trae 的架构差距分析

> 分析日期: 2025
> 分析对象: `参考\tare-impl\sandbox\x64\trae_sbox.dll` (678 KB), `sbox_ipc.dll` (562 KB), `sbox_sdk.dll` (1.8 MB)
> 分析方法: PE 导出表/导入表分析、字符串提取、反编译推断

---

## 一、基础架构对比

| 维度 | Trae | 我们 |
|------|------|------|
| **DLL 大小** | 678 KB (trae_sbox.dll) | 104 KB (sandbox_hook_x64.dll) |
| **二进制数量** | 4 个（trae_sbox + sbox_ipc + sbox_sdk + exe） | 3 个（sandbox_hook + sandbox_helper + host） |
| **Hook 引擎** | Microsoft Detours（商业级, 40+ 年验证） | 自研 detour.cpp（~550 行手写） |
| **代码组织** | 面向对象 C++（CFileMgr/CProcMgr/CNetMgr/CDebugMgr） | 过程式 C++（hook_engine.cpp 全局函数） |
| **IPC 层** | 独立 sbox_ipc.dll（ALPC 风格消息队列） | 共享内存 + 无锁 Ring Buffer |
| **SDK 层** | 独立 sbox_sdk.dll（CreateSandbox/Init/UnInit API） | 无 SDK，仅 CLI 调用 |
| **崩溃处理** | SetUnhandledExceptionFilter Hook + MiniDumpWriteDump | VEH（仅捕获 trampoline 访问违规） |
| **架构** | 分层: SDK → Hook DLL → IPC DLL | 扁平: Rust Host ↔ C++ DLL |

---

## 二、Trae 的模块结构（从字符串还原）

```
trae_sbox.dll (单体 DLL, 678 KB)
├── 📁 File System
│   ├── CFileMgr                   — 文件操作管理器
│   │   ├── OnNtdllNtCreateFile    — NtCreateFile Hook
│   │   ├── OnNtdllNtOpenFile      — NtOpenFile Hook  
│   │   ├── OnNtdllNtDeleteFile    — NtDeleteFile Hook
│   │   ├── OnNtdllNtWriteFile     — NtWriteFile Hook
│   │   ├── AfterNtSetInformationFile — NtSetInformationFile 后处理
│   │   ├── SetInformationFileRenameInformation — 重命名处理
│   │   └── DeleteFileOnClose      — FILE_DELETE_ON_CLOSE 处理
│   ├── FileACLModel               — 文件 ACL 模型
│   │   ├── CheckConfigPermission  — 配置权限检查（fallback 机制）
│   │   ├── CheckFileACL           — 文件 ACL 匹配
│   │   ├── CheckFileACLAdapterHardLinks — 硬链接适配检查
│   │   ├── RecordAudit            — 审计记录
│   │   └── PrintACLFilesLog       — ACL 日志输出
│   ├── FileLinkHelper             — 硬链接/符号链接辅助
│   │   ├── FindHardLinks          — 查找硬链接
│   │   ├── GetFileHardLinks       — 获取硬链接列表
│   │   ├── GetFileRetrievesFinalPath — 最终路径解析
│   │   └── GetFileSymbolicLink    — 符号链接解析 ← 我们没有！
│   └── FileHelper                 — 文件辅助
│       ├── GetFilePath            — 路径提取
│       ├── InitTempPath           — 临时路径初始化
│       └── WowPathRedirectIfNeed  — WOW64 路径重定向 ← 我们没有！
│
├── 📁 Process
│   ├── CProcMgr                   — 进程管理器
│   │   ├── OnNtdllNtCreateUserProcess — 子进程创建 Hook
│   │   ├── OnNtdllNtResumeThread     — 线程恢复 Hook（自注入触发）
│   │   └── CreateSubProcessEvent     — 子进程事件创建
│   └── InjectBizDllToProcess      — 注入核心函数
│       └── 失败回退 → helper process（和我们一样）
│
├── 📁 Network
│   ├── CNetMgr                    — 网络管理器
│   │   ├── OnWs2_32WSAStartup           — WSAStartup Hook
│   │   ├── OnWs2_32GetAddrInfoExW       — GetAddrInfoExW Hook ← 我们没有！
│   │   ├── OnWs2_32WSAIoctl             — WSAIoctl Hook ← 我们没有！
│   │   └── OnWs2_32connect              — connect Hook
│   ├── SocketACLModel             — 网络 ACL 模型
│   │   ├── GetACL                 — ACL 匹配
│   │   ├── GetData                — 规则加载
│   │   ├── RecordAudit            — 审计记录
│   │   └── PrintACLsLog           — ACL 日志
│   └── DnsCache                   — DNS 缓存 ← 我们没有！
│       ├── InitCachedDns          — 缓存初始化
│       └── PrintCachedDns         — 缓存输出
│
├── 📁 Debug/Crash
│   ├── CDebugMgr                  — 调试管理器
│   │   └── OnKernelBaseSetUnhandledExceptionFilter ← 我们放弃了！
│   └── ExceptionHandlerDump       — 异常转储
│       ├── CrashCallback          — 崩溃回调
│       └── MiniDumpWriteDump      — 生成 minidump ← 我们没有！
│
├── 📁 IPC
│   ├── sbox_ipc.dll 桥接层
│   │   ├── CreateIPCInterface2    — 创建 IPC 连接
│   │   └── DestroyIPCInterface    — 销毁 IPC 连接
│   ├── IPCSendThreadProc          — 发送线程
│   ├── IPCRecvThreadProc          — 接收线程
│   └── DispatchMsgToBiz           — 消息分发
│
├── 🧩 Detour Engine
│   ├── Microsoft Detours v4.0.1
│   ├── DetourFinishHelperProcess  — 唯一导出函数
│   ├── .detour / .detourc / .detourd — Detour 节区
│   └── 完整指令解码 + 跳板重定位
│
└── 📋 配置
    └── CheckConfigPermission      — 配置权限检查
```

---

## 三、Hook 覆盖差距 — Trae 领先 15 个 API

### 3.1 NT API Hook 覆盖

```
NT API                       Trae     我们    差距    安全影响
─────────────────────────────────────────────────────────────
NtCreateFile                 ✅       ✅     =
NtOpenFile                   ✅       ✅     =
NtDeleteFile                 ✅       ✅     =
NtSetInformationFile         ✅       ✅     =
NtWriteFile                  ✅       ✅ 已修复  =   (NtQueryObject 解决性能+递归)
NtResumeThread               ✅       ✅
NtCreateUserProcess          ✅       ✅     =

NtQueryDirectoryFile         ✅       ❌    🚨 P0  目录枚举泄漏拒绝路径
NtMapViewOfSection           ✅       ❌    🚨 P0  内存映射文件绕过 ACL
NtOpenSection                ✅       ❌    🚨 P0  配合 MapViewOfSection
NtQuerySymbolicLinkObject    ✅       ❌    🚨 P0  符号链接绕过路径检查
NtOpenSymbolicLinkObject     ✅       ❌    🚨 P0  符号链接创建控制
NtQueryFullAttributesFile    ✅       ❌    🟡 P1  属性查询泄漏文件存在性
NtQueryInformationProcess    ✅       ❌    🟡 P1  进程信息泄漏
NtQueryInformationToken      ✅       ❌    🟡 P1  Token 信息泄漏
NtOpenProcessToken           ✅       ❌    🟡 P1  权限令牌访问
NtCreateEvent                ✅       ❌    🟢 P2  事件对象创建控制
NtOpenEvent                  ✅       ❌    🟢 P2  事件对象打开控制
NtQueryObject                ✅       ❌    🟢 P2  对象信息查询
NtClose                      ✅       ❌    🟢 P2  句柄关闭追踪
```

### 3.2 网络 API Hook 覆盖

```
Winsock API                  Trae     我们    差距    说明
─────────────────────────────────────────────────────────────
connect                      ✅       ✅     =
getaddrinfo                  ✅       ✅     =
GetAddrInfoW                 ✅       ✅     =
WSAStartup                   ✅       ✅     =

GetAddrInfoExW               ✅       ❌    🚨 P0  现代 DNS API 绕过
WSAIoctl                     ✅       ❌    🟡 P1  获取 ConnectEx/RIO 绕过
WSASocketW                   ✅       ❌    🟡 P1  原始 socket 创建绕过
```

### 3.3 DNS API Hook 覆盖（Trae 独有）

```
DNS API                      Trae     我们    差距    说明
─────────────────────────────────────────────────────────────
getaddrinfo / GetAddrInfoW   ✅       ✅     =
GetAddrInfoExW               ✅       ❌    🚨 P0  Windows 8+ 现代 API
DnsQueryEx                   ✅       ❌    🚨 P0  DNS 专用 API
DnsQuery_A                   ✅       ❌    🚨 P0  ANSI DNS 查询
DnsQuery_W                   ✅       ❌    🚨 P0  Wide DNS 查询
DnsQuery_UTF8                ✅       ❌    🚨 P0  UTF-8 DNS 查询
DnsFree                      ✅       ❌    🟡 P1  DNS 结果释放
DnsCache::InitCachedDns      ✅       ❌    🟢 P2  DNS 缓存
```

**DnsQuery 系列绕过示例:**
```
应用程序 (如 Chrome/Node.js):
  DnsQuery_W("malicious.com", ...)    ← 不走 getaddrinfo！
  → 直接查 DNS → 绕过我们的 DNS 拒绝规则

我们只 Hook 了:
  getaddrinfo("malicious.com", ...)   ← 只拦截了这个路径
```

### 3.4 崩溃处理对比

```
能力                          Trae     我们        差距
────────────────────────────────────────────────────────
SetUnhandledExceptionFilter   ✅      ⚠️ 放弃了   🚨 P1
MiniDumpWriteDump             ✅      ❌          🟡 P1
VEH (Vectored Exception)      ❌      ✅          = (互补)
CrashCallback                 ✅      ❌          🟡 P1
异常发生时刷出审计            ✅      ✅          =
加载时崩溃保护                ✅      ❌          🟢 P2
```

---

## 四、安全漏洞分析（我们需要优先修复的）

### 🚨 P0: `NtQueryDirectoryFile` — 目录枚举泄漏

```
威胁: 拒绝路径中的文件可通过目录遍历被枚举

场景:
  配置: C:\Secret\** → Deny
  
攻击路径 1:
  dir C:\Secret\                    ← NtCreateFile/FILE_DIRECTORY_FILE 被阻断 ✓
  
攻击路径 2:
  FindFirstFile("C:\Secret\*", ...) ← 走 NtQueryDirectoryFile → 我们没 Hook！
  → 返回目录中的所有文件列表
  → 虽然不能读取，但文件存在性已泄漏

修复难度: 中
需要在 NtQueryDirectoryFile Hook 中：
  1. 提取查询路径
  2. 逐项检查文件权限
  3. 过滤掉 Deny/ReadOnly 路径的文件
```

### 🚨 P0: `NtMapViewOfSection` — 内存映射文件绕过

```
威胁: 通过 CreateFileMapping + MapViewOfFile 完全绕过文件 ACL

流程:
  1. CreateFile(C:\Secret\secret.txt)  ← NtCreateFile → 被拒绝 ✗
  
  绕过路径:
  1. CreateFileMapping(
       INVALID_HANDLE_VALUE,          ← 不用 CreateFile！
       ..., PAGE_READWRITE,
       0, 4096,
       "Local\\MySection"
     )
  2. ReadFile(hMap, buf, ...)         ← 读文件 → 只要读取权限
     → 如果是 ReadOnly 路径，读操作放行
     → 然后 MapViewOfFile → 直接修改映射内存
     → NtWriteFile 没触发！NtCreateFile 没触发！
     
修复难度: 高
需要在 NtMapViewOfSection Hook 中：
  1. 获取 section 句柄对应的文件名
  2. 检查文件 ACL 权限
  3. 对 ReadOnly/Deny 路径阻断写映射
```

### 🚨 P0: `NtQuerySymbolicLinkObject` — 符号链接绕过

```
威胁: 符号链接可绕过路径 ACL 检查

场景:
  C:\Users\Public\link.lnk → C:\Secret\secret.txt
  
如果应用程序:
  CreateFile(C:\Users\Public\link.lnk, ...)
  
我们的路径检查:
  ExtractPathFromOA → "C:\USERS\PUBLIC\LINK.LNK"
  CheckFilePermission("C:\USERS\PUBLIC\LINK.LNK") → Inherit ✓
  → 实际访问的是 C:\Secret\secret.txt ← 绕过！

Trae:
  GetFileSymbolicLink → 追踪到 C:\SECRET\SECRET.TXT
  CheckFilePermission("C:\SECRET\SECRET.TXT") → Deny ✗

修复难度: 中
需要在路径检查前：
  1. 用 GetFinalPathNameByHandleW 或 NtQuerySymbolicLinkObject
  2. 解析所有符号链接/挂载点/交接点
  3. 对最终目标路径做 ACL 检查
```

### 🚨 P0: DnsQuery 系列 — DNS 绕过

```
威胁: 4 种 DNS API 未 Hook，getaddrinfo 可被绕过

Chrome/Edge/Node.js 使用 DnsQuery_* 系列 API:
  → 不走 ws2_32!getaddrinfo
  → 直接查询 DNS
  → 即使配置了 *.evil.com → deny，恶意域名仍可解析

修复难度: 中
需要 Hook:
  1. DnsQueryEx (Windows 8+)
  2. DnsQuery_W
  3. DnsQuery_A (已废弃但可能被调用)
  4. DnsQuery_UTF8
```

---

## 五、健壮性差距

### 🟡 P1: `SetUnhandledExceptionFilter` Hook — 崩溃恢复

```
现状: 我们注释掉了 InstallCrashHandlerHook()
原因: 自研 detour.cpp 的 x64 CALL rel32 重定位与 /GS cookie 冲突
       → 跳板中的 call __security_cookie 地址错误
       → STATUS_STACK_BUFFER_OVERRUN

Trae 的方案:
  Microsoft Detours 的指令解码器更完善
  → 能正确处理 x64 CALL (0xE8) 指令的重定位
  → 成功 Hook SetUnhandledExceptionFilter
  → 崩溃时生成 MiniDump + 刷出审计

我们需要:
  修复自研 detour.cpp 的 x64 CALL rel32 重定位
  → 我们已经添加了 RelocateInstruction 的 E8/E9 处理
  → 但需要验证是否完全正确
  → 如果仍然有问题，考虑换用 Microsoft Detours
```

### 🟡 P1: WOW64 路径重定向

```
x86 进程访问 C:\Windows\System32\...
→ WOW64 自动重定向到 C:\Windows\SysWOW64\...

我们的路径检查基于 GetFinalPathNameByHandleW:
  → 返回的是重定向后的 SysWOW64 路径
  
ACL 规则:
  "C:\\Windows\\System32\\**" → deny
  
实际路径:
  "C:\\WINDOWS\\SYSWOW64\\..."  ← 和规则不匹配！
  → ACL 失效！

Trae: FileHelper::WowPathRedirectIfNeed 处理此映射
我们需要: 在路径检查前，对 x86 进程做 WOW64 路径逆向映射
```

### 🟡 P1: 崩溃转储

```
Trae 在崩溃时:
  1. Hook_SetUnhandledExceptionFilter 捕获所有未处理异常
  2. CrashCallback → 刷出审计缓冲
  3. MiniDumpWriteDump → 生成 .dmp 文件
  4. 安全退出

我们:
  VEH 只捕获了 trampoline 访问违规和 /GS 异常
  其他未处理异常直接转给 WER (Windows Error Reporting)
  无法在崩溃时刷出审计

需要: 增加崩溃转储和审计刷出机制
```

---

## 六、IPC 架构对比

```
Trae (sbox_ipc.dll)               我们 (共享内存)
────────────────────────────────  ────────────────────────
DLL 内部有发送/接收线程           无独立 IPC 线程
消息队列 (ALPC 风格)              无锁环形缓冲区
DispatchMsg 消息分发              直接读取共享内存
支持双向通信 (Send+Recv)          单向: DLL → Host (审计)
                                  配置下发: Host → DLL (一次写入)

Trae IPC 更强大:
  - 可实时下发配置更新
  - 支持宿主动态查询状态
  - 消息有优先级/超时机制

我们 IPC 更轻量:
  - 无线程开销
  - 零拷贝 (内存映射)
  - 无死锁风险
```

---

## 七、差距优先级汇总

```
优先级  功能                        难度   安全影响  当前状态
──────────────────────────────────────────────────────────────
🚨 P0  NtQueryDirectoryFile Hook    中     🔴高     ❌ 缺失
🚨 P0  NtMapViewOfSection Hook      高     🔴高     ❌ 缺失
🚨 P0  NtQuerySymbolicLinkObject    中     🔴高     ❌ 缺失
🚨 P0  DnsQueryEx/A/W/UTF8 Hook     中     🔴高     ❌ 缺失

🟡 P1  SetUnhandledExceptionFilter  高     🟡中     ⚠️ 放弃
🟡 P1  WOW64 路径重定向             低     🟡中     ❌ 缺失
🟡 P1  MiniDumpWriteDump            低     🟢低     ❌ 缺失
🟡 P1  GetAddrInfoExW Hook          中     🟡中     ❌ 缺失
🟡 P1  WSAIoctl/WSASocketW Hook     中     🟡中     ❌ 缺失

🟢 P2  NtQueryFullAttributesFile    低     🟢低     ❌ 缺失
🟢 P2  NtQueryInformationProcess    低     🟢低     ❌ 缺失
🟢 P2  NtQueryInformationToken      低     🟢低     ❌ 缺失
🟢 P2  NtClose Hook                 低     🟢低     ❌ 缺失
🟢 P2  DNS 缓存                     中     🟢低     ❌ 缺失
🟢 P2  C++ 类重构                   高     🟢无     ❌ 过程式
🟢 P2  SDK 封装                     高     🟢无     ❌ 仅 CLI
```

---

## 八、我们领先 Trae 的地方

```
能力                            我们      Trae
────────────────────────────────────────────────
VEH 向量化异常处理               ✅       ❌
无锁 Ring Buffer 审计            ✅       ❌ (有锁消息队列)
Rust 类型安全                     ✅       ❌ (纯 C++)
轻量级 DLL (104 KB vs 678 KB)    ✅       ❌
自研 detour 引擎 (无版权风险)     ✅       ❌ (GPL 风险?)
CALL/JMP rel32 跳板重定位修复     ✅       ❌ (Detours 不支持?)
硬链接遍历防护                    ✅       ✅ (持平)
FILE_DELETE_ON_CLOSE 检测         ✅       ✅ (持平)
跨架构 x86 注入辅助               ✅       ✅ (持平)
```

---

## 九、行动建议

### 第一阶段（P0 — 安全漏洞修复）

```
1. NtQueryDirectoryFile Hook
   └─ 在目录枚举时过滤 Deny/ReadOnly 路径的文件

2. NtMapViewOfSection Hook
   └─ 在内存映射时检查文件 ACL
   └─ 阻断 ReadOnly/Deny 路径的写映射

3. NtQuerySymbolicLinkObject Hook
   └─ 在路径检查前追踪所有符号链接
   └─ 对最终目标做 ACL 检查

4. DnsQueryEx / DnsQuery_W Hook
   └─ 4 种 DNS API 全覆盖
   └─ 共享 getaddrinfo 的 DNS 拒绝规则
```

### 第二阶段（P1 — 健壮性提升）

```
5. 修复自研 detour 的 CALL rel32 重定位
   └─ 验证 x64 E8 指令在跳板中的偏移计算
   └─ 重新启用 SetUnhandledExceptionFilter Hook

6. WOW64 路径重定向处理
   └─ 在路径检查前做 SysWOW64 → System32 逆向映射
   └─ 确保 ACL 规则对 x86 进程也生效

7. 崩溃转储 + 审计刷出
   └─ 崩溃时生成 MiniDump
   └─ 在 ExitProcess 前刷出审计 Ring Buffer
```

### 第三阶段（P2 — 完善）

```
8. GetAddrInfoExW / WSAIoctl / WSASocketW Hook
9. NtQueryFullAttributesFile / NtQueryInformationProcess Hook
10. DNS 缓存
11. C++ 类重构
12. SDK API 封装
```
