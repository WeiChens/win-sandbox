# Windows Sandbox — 本地沙盒终端

> 一款轻量级 Windows 沙箱，通过 NT API 内联 Hook 实现文件系统/网络 ACL 控制。
> 支持递归注入（子进程自动继承沙箱）。

---

## 项目结构

```
win-sandbox/
├── CMakeLists.txt              # 顶层 CMake — 一键构建所有组件
├── config/
│   └── default-sandbox.json    # 默认沙箱 ACL 配置
├── crates/
│   ├── sandbox-core/           # Rust 共享库（配置模型、IPC 协议、ACL 类型）
│   │   ├── src/
│   │   │   ├── acl.rs          # 文件/网络 ACL 类型定义
│   │   │   ├── config.rs       # SandboxConfig 配置模型
│   │   │   ├── ipc.rs          # 共享内存/审计 Ring Buffer 协议
│   │   │   ├── ffi.rs          # Windows FFI 常量
│   │   │   └── lib.rs          # Crate 入口
│   │   └── Cargo.toml
│   └── sandbox-host/           # Rust 宿主进程（本地 CLI）
│       ├── src/
│       │   ├── main.rs         # 入口：Exec/Config/Audit 子命令
│       │   ├── cli.rs          # 命令行参数解析
│       │   ├── inject.rs       # 进程创建 + DLL 注入（含 WOW64 辅助）
│       │   ├── ipc.rs          # 共享内存管理 + Ring Buffer 消费
│       │   ├── config.rs       # 配置加载
│       │   └── audit.rs        # 审计日志显示
│       └── Cargo.toml
├── dll/
│   ├── sandbox-hook/           # C++ 注入 DLL（核心沙箱引擎）
│   │   ├── CMakeLists.txt
│   │   ├── include/
│   │   │   ├── detour.h        # 内联 Hook 引擎接口
│   │   │   ├── hook_engine.h   # Hook 管理器 + 自注入引擎
│   │   │   ├── file_acl.h      # 文件 ACL 检查
│   │   │   ├── net_acl.h       # 网络 ACL 检查
│   │   │   ├── ipc_client.h    # 共享内存客户端
│   │   │   ├── shared_config.h # 配置加载
│   │   │   └── utils.h         # 工具函数
│   │   └── src/
│   │       ├── dllmain.cpp     # DLL 入口点
│   │       ├── detour.cpp      # x64/x86 内联 Hook 引擎
│   │       ├── hook_engine.cpp # NT API Hook + 自注入引擎（核心 ~1250 行）
│   │       ├── file_acl.cpp    # 文件 ACL + 硬链接防护
│   │       ├── net_acl.cpp     # 网络 ACL（connect/DNS Hook）
│   │       ├── ipc_client.cpp  # 审计日志 Ring Buffer 生产者
│   │       ├── shared_config.cpp# 从共享内存加载配置
│   │       └── utils.cpp       # 工具函数
│   └── inject-helper/          # 32-bit WOW64 注入辅助程序
│       ├── CMakeLists.txt
│       └── src/main.cpp        # C++ 注入逻辑（32-bit GetProcAddress）
├── output/                     # 构建输出目录
│   ├── sandbox-host.exe        # Rust 宿主
│   ├── sandbox_hook_x64.dll    # x64 沙箱 Hook DLL
│   ├── sandbox_hook_x86.dll    # x86 沙箱 Hook DLL
│   └── sandbox_helper_x86.exe  # 32-bit 注入辅助
└── sandbox-logs/               # 审计日志输出
```

---

## 架构概览

### 核心流程

```
用户 (CLI)
    │
    ▼
sandbox-host.exe (Rust, x64)
    │  CreateProcess(SUSPENDED)
    │  VirtualAllocEx + WriteProcessMemory(DLL path)
    │  CreateRemoteThread(LoadLibraryW)  ← 初始注入
    │  ResumeThread
    ▼
目标进程 (cmd/python/...)
    │  DllMain → InitHookEngine() → CacheDllPaths()
    │  → LoadConfigFromSharedMemory() → InitFileAcl()/InitNetAcl()
    │  → InstallAllHooks() → SignalInitComplete()
    │
    │  ┌─────────────────────────────────────────────────────┐
    │  │ Hook 列表 (NT API 级别)                             │
    │  │  ├─ NtCreateFile      → 文件创建/打开权限检查       │
    │  │  ├─ NtOpenFile        → 文件打开权限检查            │
    │  │  ├─ NtDeleteFile      → 文件删除权限检查             │
    │  │  ├─ NtSetInformationFile → 重命名/硬链接/删除标记   │
    │  │  ├─ NtWriteFile       → 写入权限检查（NtQueryObject 快速路径）│
    │  │  ├─ NtCreateUserProcess → 子进程挂起 + 追踪         │
    │  │  ├─ NtResumeThread    → 自注入 + 恢复               │
    │  │  ├─ WSAStartup        → 延迟安装 connect/DNS Hook   │
    │  │  ├─ connect           → 目标 IP:PORT 权限检查       │
    │  │  ├─ getaddrinfo       → DNS 查询权限检查            │
    │  │  └─ GetAddrInfoW      → DNS 查询权限检查 (Wide)     │
    │  └─────────────────────────────────────────────────────┘
    │
    ▼
子进程 (递归注入)
    │  NtCreateUserProcess Hook → 挂起子进程
    │  NtResumeThread Hook → SelfInject() [同进程直投, <100μs]
    │  → DLL 加载 → Hook 安装 → 恢复线程
    ▼
孙进程 (递归继续)
    ...
```

### 关键设计决策

| 特性 | 方案 | 对比 Failure-01 |
|------|------|----------------|
| **注入时机** | `Hook_NtResumeThread` 中**同进程直投** | IPC 到 Rust Host → 5 秒延迟 |
| **CLR 兼容** | VEH 捕获 `STATUS_STACK_BUFFER_OVERRUN` | 未处理 → PowerShell 崩溃 |
| **x86 注入** | 32-bit 辅助进程 (`sandbox_helper_x86.exe`) | 64-bit 地址 → 远程线程崩溃 |
| **审计** | 共享内存 Ring Buffer (无锁 SPSC) | 文件 I/O (慢，易丢失) |
| **检测绕过** | 硬链接遍历 + `FILE_DELETE_ON_CLOSE` 检查 | 未处理 |

---

## 沙箱 ACL 规则

### 文件权限

三条规则按顺序匹配，**第一个匹配生效**：

| 权限值 | 含义 | 拦截的操作 |
|--------|------|-----------|
| `deny` | 完全拒绝 | 创建、打开(任何访问)、写入、删除、重命名、硬链接 |
| `read_only` | 只读 | 写入、追加、删除、重命名、创建子文件/目录 |
| `inherit` | 放行 | 无限制 |

**硬链接绕过防护**: `CheckFilePermissionWithHardLinks()` 会遍历文件所有 NTFS 硬链接路径，只要任一硬链接路径被拒绝/只读，就拒绝操作。

**支持的 NT API 路径**: `NtCreateFile` / `NtOpenFile` / `NtDeleteFile` / `NtSetInformationFile`(重命名/硬链接/删除标记) / `NtWriteFile`

### 网络权限

| 字段 | 说明 | 示例 |
|------|------|------|
| `host` | 支持 `*` 通配符 | `*.github.com`, `*` |
| `port` | 端口号，0=所有端口 | `443`, `80` |
| `protocol` | `tcp` / `udp` / `any` | `tcp` |
| `action` | `allow` / `deny` | `deny` |

### 默认配置

```json
{
  "file_permissions": [
    {"pattern": "C:\\Users\\*\\Projects\\**", "permission": "inherit"},
    {"pattern": "C:\\Users\\*\\.cargo\\**", "permission": "inherit"},
    {"pattern": "C:\\Users\\*\\*", "permission": "read_only"},
    {"pattern": "C:\\Windows\\**", "permission": "read_only"},
    {"pattern": "C:\\Program Files\\**", "permission": "deny"}
  ],
  "network_permissions": [
    {"host": "*.npmjs.org", "port": 443, "protocol": "tcp", "action": "allow"},
    {"host": "*.github.com", "port": 443, "protocol": "tcp", "action": "allow"},
    {"host": "*", "port": 0, "protocol": "tcp", "action": "allow"}
  ]
}
```

---

## 构建指南

### 前置条件

- **Visual Studio 2022**（含 MSVC x64/x86 工具链）
- **Rust** 1.75+ (rustup + MSVC target)
- **CMake** 3.20+
- **Git**（用于下载依赖）

### 一键构建

```powershell
# 1. 生成 VS 解决方案
cd win-sandbox
cmake -B build-root -DCMAKE_BUILD_TYPE=Release

# 2. 构建全部
cmake --build build-root --config Release
```

构建产出在 `output/` 目录：

```
output/
├── sandbox-host.exe              # Rust 宿主 (x64)
├── sandbox_hook_x64.dll          # 沙箱 Hook DLL (x64)
├── sandbox_hook_x86.dll          # 沙箱 Hook DLL (x86)
└── sandbox_helper_x86.exe        # WOW64 注入辅助 (x86)
```

### 单独构建

```powershell
# 仅 DLL
cmake --build build-root --config Release --target all-dlls

# 仅 Rust
cmake --build build-root --config Release --target all-rust
```

---

## 使用指南

### CLI 模式

```powershell
# 基本执行
sandbox-host.exe cmd.exe /c whoami

# 指定配置文件 + 超时
sandbox-host.exe --config strict.json --timeout 30 python script.py

# 显式 exec 子命令（支持 -- 分隔选项和参数）
sandbox-host.exe exec --config my.json -- cmd.exe /c dir C:\

# 配置管理
sandbox-host.exe config init                    # 生成默认配置
sandbox-host.exe config show                    # 显示当前配置
sandbox-host.exe config validate sandbox.json   # 验证配置

# 审计日志
sandbox-host.exe audit                          # 文本格式
sandbox-host.exe audit --json                   # JSON 格式

# 帮助
sandbox-host.exe help
```

---



## 注入架构详解

### 初始注入（Rust Host → 目标进程）

```
sandbox-host.exe (x64)
  │  CreateProcess(SUSPENDED)          ← 目标进程挂起
  │  VirtualAllocEx + WriteMemory     ← 写入 DLL 路径
  │  CreateRemoteThread(LoadLibraryW) ← 注入 sandbox_hook.dll
  │  ResumeThread                     ← 恢复执行
  ▼
目标进程启动 → DLL 初始化 → Hook 安装
```

### 递归注入（C++ DLL → 子进程）

```
父进程 (已 Hook)
  │  子进程创建 → NtCreateUserProcess Hook 挂起
  │  NtResumeThread Hook 触发
  │  → SelfInject() 同进程直投
  │    ├─ 判定架构 (IsWow64Process)
  │    ├─ x64 → 直接 CreateRemoteThread(GetProcAddress("LoadLibraryW"))
  │    ├─ x86 → sandbox_helper_x86.exe 辅助注入
  │    └─ 等待 LoadLibraryW 完成 (WaitForSingleObject, 5s)
  │  → ResumeThread (原始调用)
  ▼
子进程 → DLL 初始化 → SignalInitComplete() → Hook 安装
```

### x86/WOW64 注入挑战

**问题**: 64-bit 进程调用 `GetProcAddress(kernel32, "LoadLibraryW")` 返回 64-bit 地址，该地址在 32-bit (WOW64) 进程中无效 → `CreateRemoteThread` 崩溃。

**解决方案** (`sandbox_helper_x86.exe`):

```
sandbox-host.exe (x64)
  └→ CreateProcess: sandbox_helper_x86.exe <target_pid> <dll_path>
       │  sandbox_helper_x86.exe (32-bit)
       │  → GetModuleHandle("kernel32") → 返回 32-bit 基址 ✅
       │  → GetProcAddress("LoadLibraryW") → 返回 32-bit 地址 ✅
       │  → OpenProcess(target) → VirtualAllocEx → WriteProcessMemory
       │  → CreateRemoteThread(32-bit_LoadLibraryW) → 注入成功 ✅
       │  → WaitForSingleObject → 检查退出码 → 返回 0/1
       └→ Host 检查退出码
```

### CLR/.NET PowerShell 兼容性

PowerShell 是 CLR 宿主，与内联 Hook 有几个冲突点：

1. **/GS 栈检测冲突**: x64 Detour 跳板中 `CALL rel32` 指令（如 `call __security_cookie`）未被重定位，导致 cookie 值读取错误 → `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409)
   - **修复**: `RelocateInstruction()` 新增 x64 CALL (0xE8) / JMP (0xE9) 指令的跳板重定位处理
   - **兜底**: VEH 捕获此异常 → `ExitProcess(1)` 优雅退出

2. **DLL 卸载崩溃**: 进程退出时内核可能在线程清理中调用已释放的 trampoline → `ACCESS_VIOLATION`
   - **修复**: VEH 检测故障地址是否在跳板区域内，跳过故障指令继续执行

---

## Hook 引擎技术细节

### detour.cpp — 内联 Hook 引擎

自研引擎（非 Microsoft Detours），支持 x64/x86：

| 特性 | 实现 |
|------|------|
| **指令解码** | 手写 x64/x86 指令长度分析器（~120 行） |
| **x64 JMP** | `mov rax, imm64; jmp rax`（12字节） |
| **x86 JMP** | `jmp rel32`（5字节） |
| **RIP-relative 重定位** | x64 模式下 `[rip+disp32]` → 跳板中重算偏移 |
| **CALL/JMP rel32 重定位** | x86 模式下 `E8/E9` 相对地址 → 跳板中重算 |
| **安全 patch 大小** | `CalcSafePatchSize()` 停在完整指令边界 |
| **间接跳转追踪** | `FollowJumps()` 追踪 `FF 25`/`EB`/`E9` 跳转链 |

### hook_engine.cpp — NT API 拦截

| Hook | 拦截目的 | 检查维度 |
|------|---------|---------|
| `NtCreateFile` | 文件创建/打开 | 路径 ACL + 硬链接 + FILE_DELETE_ON_CLOSE |
| `NtOpenFile` | 文件打开（不含创建） | 路径 ACL + 硬链接 |
| `NtDeleteFile` | 文件删除 | 路径 ACL + 硬链接 |
| `NtSetInformationFile` | 重命名/硬链接/标记删除 | 目标路径 ACL + 硬链接 |
| `NtWriteFile` | 绕过 CreateFile 的直接写入 | 路径 ACL |
| `NtCreateUserProcess` | 子进程追踪 | 强制挂起 + 注入 |
| `NtResumeThread` | 自注入触发 | 递归注入控制 |
| `WSAStartup` | 延迟安装网络 Hook | ws2_32 可用性 |
| `connect` | TCP 连接 | IP + PORT ACL |
| `getaddrinfo`/`GetAddrInfoW` | DNS 查询 | 域名 ACL |

---

## 测试

```powershell
# 运行全部测试（68 项）
cd win-sandbox
python tests/test_all.py

# 特定模块
python tests/test_all.py --security          # 安全边界 (7.x)
python tests/test_all.py --path              # 路径健壮性 (8.x)
python tests/test_all.py --config-edge       # 配置极端 (9.x)
python tests/test_all.py --quick             # 仅基础功能
python tests/test_all.py --x64               # 仅 x64 相关
python tests/test_all.py --x86               # 仅 x86 相关

# 指定 pytest 运行特定模块
python -m pytest tests/test_file_acl.py -v
python -m pytest tests/test_network.py -v
python -m pytest tests/test_edge.py -v
```

### 测试覆盖

| 类别 | 数量 | 覆盖范围 |
|------|------|---------|
| **1. 基础功能** | 8 | cmd echo/whoami/dir, 退出码, stderr, 环境变量, PowerShell |
| **2. 文件 ACL** | 19 | Inherit/ReadOnly/Deny 下的写入/删除/读取/mkdir/rmdir/重命名/硬链接, 空格路径/深度嵌套/设备路径 |
| **3. 网络 ACL** | 8 | ping/nslookup/curl, TCP 拒绝, DNS 拒绝/允许, 端口级屏蔽 |
| **4. 递归注入** | 5 | 2层/3层/5层嵌套, 跨架构 x64→x86, 递归禁用 |
| **5. x86/WOW64** | 5 | 基础命令, 文件写入, ReadOnly 写入拦截 |
| **6. 安全边界 🔴** | 4 | NtOpenFile+ReadOnly 回归, FILE_DELETE_ON_CLOSE+Deny 回归, 多硬链接防护, 符号链接防护 |
| **7. 路径健壮性** | 4 | 中文/日文 Unicode 路径, 超长路径 >200 字符, 备用数据流 (ADS) |
| **8. 配置极端** | 9 | 超时终止, 不存在/空命令, 禁用递归, 5 层深度递归, IPv6, 100 次快速创建删除, 空规则列表, Deny 深层目录 |
| **总计** | **64** | **全场景覆盖** |

---

## 代码质量与维护

### 编码规范

- **C++**: C++17，MSVC 编译，完整 CRT 链接
- **Rust**: 2021 edition，纯 FFI（无 windows-sys crate）
- **无第三方依赖**: 自研 detour 引擎、自研简易 JSON 解析器

### 已知限制

1. **x86 Hook 引擎**: detour.cpp 的 x86 版本不支持 `FF 25`（`jmp [addr]`）间接跳转追踪（仅在 hook_engine.cpp 的 C++ DLL 中运行，而 DLL 编译时目标架构固定）
2. **Ring Buffer 审计**: Rust Host 端完全实现了 Ring Buffer 消费，但 C++ DLL 端也同时写审计日志文件，双通道存在冗余
3. **路径重解析**: `GetFinalPathNameByHandleW` 可能触发递归（已通过 TLS 重入守卫防护）
4. **硬链接检测性能**: 对每个文件操作都调用 `FindFirstFileNameW`，在高 I/O 场景下可能有性能影响
