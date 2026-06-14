# Windows Sandbox — 开发计划

> 状态：Phase 0 完成（项目框架 + 编译链路验证通过）

---

## 已完成 (Phase 0: 框架搭建)

- [x] 项目目录结构
- [x] Rust workspace (`sandbox-core` + `sandbox-host`)
- [x] C++ DLL 项目 (`sandbox-hook`)，完整 CRT + C++17
- [x] 内联 Hook 引擎 (`detour.cpp`，从 Failure-01 移植，C++ 化)
- [x] 自注入引擎骨架 (`hook_engine.cpp:SelfInject()`)
- [x] 文件系统 ACL (`file_acl.cpp`，glob 匹配)
- [x] 网络 ACL (`net_acl.cpp`，Winsock Hook)
- [x] Rust Host：CLI、进程创建+初始注入、IPC 共享内存、审计、AI HTTP 服务
- [x] 根 CMakeLists.txt（一键编译三个子项目）
- [x] x64 + x86 DLL 编译通过
- [x] Rust Host 编译通过
- [x] 默认沙箱配置 (`config/default-sandbox.json`)

---

## Phase 1: 核心功能完善（自注入 + x86 支持）

### 1.1 WOW64 自注入 — DLL 架构自动选择

**问题：** 当前 `SelfInject()` 对 WOW64（32位进程在64位系统）目标使用相同的 DLL
路径。64 位 DLL 无法注入 32 位进程。

**方案：**
- 在 `SelfInject()` 中调用 `IsWow64Process()` 检测目标架构
- 若为 WOW64，从注册表/文件系统获取 x86 DLL 路径
- DLL 路径可通过环境变量 `SBOX_DLL_X64` / `SBOX_DLL_X86` 传入，或从注册表读取当前 DLL 的安装目录
- 实现 `GetWow64LoadLibraryW()` — 通过 ToolHelp 快照 + `ReadProcessMemory` 获取 32 位 `kernel32!LoadLibraryW` 地址（参考 Failure-01 `process.rs:get_wow64_loadlibraryw`）

**文件：** `dll/sandbox-hook/src/hook_engine.cpp`

**估时：** 3-4h  ✅ **已完成** (2024-06-14)

---

### 1.2 x86 NtResumeThread Hook 修复

**问题：** 当前 x86 构建中 `InstallNtResumeThreadHook()` 直接返回（跳过安装）。
Failure-01 的根因是 DLL 卸载时内核态调用 `NtResumeThread`，trampoline 已被释放 → `STATUS_ACCESS_VIOLATION`。

**方案：**
1. 在 `Hook_NtResumeThread` 开头检查 `g_dll_detaching` 标志（已实现）
2. 在 `UninstallAllHooks()` 中：先设置 `g_dll_detaching = true`，再卸载 hook（已实现）
3. **关键修复：** 在 `DLL_PROCESS_DETACH` 中，调用 `UninstallAllHooks()` **之前**，
   用 `VirtualProtect` 检查 trampoline 页面是否仍可访问。若页面已被释放（DLL 先于 hook 目标卸载），
   跳过 trampoline 释放，只清理上下文
4. 添加 VEH (Vectored Exception Handler) 作为最后防线，捕获 trampoline 访问违规并安全降级

**文件：** `dll/sandbox-hook/src/hook_engine.cpp`, `dll/sandbox-hook/src/detour.cpp`

**估时：** 4-6h  ✅ **已完成** (2024-06-14)

---

### 1.3 DLL 路径自动发现

**问题：** `SelfInject()` 需要知道自身 DLL 的 x64/x86 路径。

**方案：**
- Rust Host 在创建进程前通过环境变量传入：
  - `SBOX_DLL_PATH_SELF` = 当前 DLL 的完整路径
  - `SBOX_DLL_PATH_X64` = x64 sandbox_hook.dll 路径
  - `SBOX_DLL_PATH_X86` = x86 sandbox_hook.dll 路径
- C++ DLL 在 `dllmain.cpp` 初始化时缓存 `GetModuleFileNameW(NULL)` 作为自身路径
- 对于 x86→x86 和 x64→x64：使用自身路径（`SBOX_DLL_PATH_SELF`）
- 对于 x64→x86（WOW64）：使用 `SBOX_DLL_PATH_X86`
- 对于 x86→x64（理论上少见）：使用 `SBOX_DLL_PATH_X64`

**文件：** `dll/sandbox-hook/src/hook_engine.cpp`, `crates/sandbox-host/src/inject.rs`

**估时：** 2h

---

## Phase 2: IPC 与审计

### 2.1 审计 Ring Buffer（共享内存）

**问题：** 当前审计日志只写入本地文件（`ipc_client.cpp` 中的 `AuditLogFileAction`），
Rust Host 无法实时获取审计事件。

**方案：**
- 创建第二个共享内存区域：`Global\SBoxAudit_<HostPID>`
- 布局：无锁 ring buffer（单生产者 / 单消费者）
  ```
  [header: write_cursor(4B)][slots: N × AuditEventC(800B)]
  ```
- C++ DLL 端：`AuditLog()` 使用 `InterlockedIncrement` 获取写入位置，
  写入事件后更新 cursor（fire-and-forget，不阻塞 Hook）
- Rust Host 端：定期轮询 cursor，读取新事件（100ms 间隔）
- 溢出策略：覆盖最旧事件（ring buffer 足够大，如 1024 条）

**文件：** 
- `dll/sandbox-hook/src/ipc_client.cpp`（重写）
- `crates/sandbox-host/src/ipc.rs`（新增审计消费线程）
- `crates/sandbox-core/src/ipc.rs`（定义 ring buffer 布局）

**估时：** 5-6h  ✅ **已完成** (2024-06-14)

---

### 2.2 审计事件序列化标准化

**问题：** 当前 `AuditEvent` 只在 Rust 端定义（serde JSON），C++ 端用字符串拼接。

**方案：**
- 定义 `repr(C)` 的 `AuditEventC` 结构体（固定大小 800B），C++/Rust 共享布局
- C++ 端直接写二进制结构到 ring buffer
- Rust 端从 ring buffer 读取二进制结构，转换为 `AuditEvent`（带时间戳格式化）
- 不再使用 JSON 作为传输格式（减少序列化开销）

**文件：** `crates/sandbox-core/src/ipc.rs`, `dll/sandbox-hook/include/ipc_client.h`

**估时：** 3h  ✅ **已完成** (2024-06-14)

---

## Phase 3: CLR 兼容性与健壮性

### 3.1 CorExitProcess Hook

**问题：** .NET CLR 进程退出时调用 `CorExitProcess`（内部函数），可能是绕过沙箱的路径。
TRAE 有专门的 `CorExitProcess` Hook。

**方案：**
- Hook `mscoree!CorExitProcess`（如果 `mscoree.dll` 已加载）
- 在 Hook 中执行沙箱清理（刷出审计日志、释放资源）
- 然后透传到原始函数

**文件：** `dll/sandbox-hook/src/hook_engine.cpp`

**估时：** 2h  ✅ 已完成

---

### 3.2 崩溃恢复（UnhandledExceptionFilter）

**问题：** 沙箱进程崩溃时，我们可能丢失审计数据。TRAE 通过 Hook `SetUnhandledExceptionFilter` +
`MiniDumpWriteDump` 实现崩溃恢复。

**方案：**
- Hook `kernel32!SetUnhandledExceptionFilter`
- 安装一个 VEH (Vectored Exception Handler)，在异常时：
  1. 尝试刷出审计缓冲
  2. 调用原始异常处理器
- 可选：生成 minidump（需要 `dbghelp.dll`，但 DLL 体积会增加）

**文件：** `dll/sandbox-hook/src/hook_engine.cpp`，新增 `dll/sandbox-hook/src/crash_handler.cpp`

**估时：** 3-4h

---

### 3.3 CLR 集成测试

**方案：**
- 测试用例：
  1. `pwsh.exe -NoProfile -Command "Write-Host 'hello'"` — 验证 CLR 不崩溃
  2. `dotnet new console && dotnet run` — 验证 .NET SDK 递归进程
  3. `python -c "import os; os.system('dir')"` — 验证 Python 子进程
  4. 嵌套沙箱：`cmd.exe /c cmd.exe /c cmd.exe /c whoami` — 验证三层递归注入

**文件：** `tests/test_clr.py`

**估时：** 2h

---

## Phase 4: AI 集成

### 4.1 AI exec 端点接入沙箱

**问题：** 当前 `ai_server.rs` 的 `/exec` 端点直接执行命令，未经过沙箱。

**方案：**
- 重构 `main.rs:run_sandbox()` 为可复用的函数
- `/exec` 端点调用沙箱化执行：
  1. 接收 JSON：`{"command": "cmd.exe", "args": ["/c", "dir"], "config": {...}}`
  2. 创建沙箱进程 + 注入 DLL
  3. 捕获 stdout/stderr（通过管道）
  4. 返回 JSON：`{"exit_code": 0, "stdout": "...", "stderr": "...", "audit": [...]}`
- 添加超时控制（`WaitForSingleObject` + `TerminateProcess`）

**文件：** `crates/sandbox-host/src/ai_server.rs`, `crates/sandbox-host/src/main.rs`

**估时：** 4h

---

### 4.2 AI 流式审计推送

**方案：**
- 新增 WebSocket 端点 `/ws/audit` — 实时推送审计事件
- Rust Host 的审计消费线程检测到新事件 → 推送到 WebSocket 客户端
- AI 可以实时监控沙箱内的文件/网络活动

**文件：** `crates/sandbox-host/src/ai_server.rs`

**估时：** 5h（需引入 `tokio-tungstenite` 依赖）

---

## Phase 5: 测试与文档

### 5.1 集成测试套件

| 测试 | 描述 | 优先级 |
|------|------|--------|
| `test_basic` | cmd.exe /c dir, whoami | P0 |
| `test_file_acl` | 读写拒绝/只读目录 | P0 |
| `test_network` | DNS 解析, TCP 连接 | P0 |
| `test_clr` | pwsh.exe, dotnet | P0 |
| `test_recursive` | 三层嵌套 cmd.exe | P1 |
| `test_x86` | 32位进程注入 | P1 |
| `test_wow64` | 64→32 位递归注入 | P1 |

**文件：** `tests/test_*.py`

**估时：** 6h

---

### 5.2 文档

- [ ] `README.md` — 项目概述、快速开始、架构图
- [ ] `ARCHITECTURE.md` — 详细架构文档（数据流图、IPC 协议、Hook 列表）
- [ ] `BUILDING.md` — 构建指南（MSVC 安装、CMake 命令、常见问题）

**估时：** 4h

---

## 技术债 & 未来改进

- [ ] **ALPC 替代共享内存**：TRAE 使用 ALPC（内核级 IPC），性能优于共享内存+事件
- [ ] **ETW 集成**：利用 Event Tracing for Windows 获取更细粒度的事件
- [ ] **DLL 签名**：对 sandbox_hook.dll 进行 Authenticode 签名，避免杀软误报
- [ ] **沙箱配置热更新**：运行时通过 IPC 更新 ACL 规则，无需重启进程
- [ ] **GUI 沙箱支持**：目前只支持控制台进程，需要额外处理消息泵和 GDI Hook
- [ ] **Linux/macOS 支持**：当前仅 Windows（使用 seccomp/pledge 等机制）

---

## 估时总览

| Phase | 内容 | 估时 |
|-------|------|------|
| Phase 0 | ✅ 框架搭建 | 已完成 |
| Phase 1 | 自注入 + x86 + DLL 路径 | 9-12h |
| Phase 2 | Ring Buffer + 审计标准化 | 8-9h |
| Phase 3 | CLR 兼容 + 崩溃恢复 | 7-8h |
| Phase 4 | AI 集成 | 9h |
| Phase 5 | 测试 + 文档 | 10h |
| **总计** | | **43-48h** |
