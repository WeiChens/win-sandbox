# Windows Sandbox — 已知问题 & Bug 记录

> 发现时间: 2026-06-14
> 测试覆盖: 36 项集成测试 + 38 项 Rust 单元测试

---

## 已修复

### ✅ Bug #1: Global\ 共享内存需要管理员权限
- **严重性**: P0 (阻塞非管理员使用)
- **现象**: `CreateFileMappingW(配置) 失败: 5 (ERROR_ACCESS_DENIED)`
- **根因**: `Global\` 命名空间需要 SeCreateGlobalPrivilege，非提权进程无法使用
- **修复**: `create_shm_global_fallback()` → 先尝试 `Global\`，失败回退到 `Local\` 命名空间
- **文件**: `crates/sandbox-host/src/ipc.rs`

### ✅ Bug #2: 管道读取 + 进程等待死锁
- **严重性**: P0 (阻塞所有测试)
- **现象**: `read_pipe_to_end()` 先于 `wait_for_process()` 调用，管道的写端被子进程持有不释放，ReadFile 永不返回 EOF
- **修复**: 
  1. 管道读取使用独立线程（`std::thread::spawn`）
  2. 进程等待支持超时（`wait_for_process_timeout`）
  3. Python 测试端传递 `--timeout` 参数
- **文件**: `crates/sandbox-host/src/main.rs`, `crates/sandbox-host/src/inject.rs`, `tests/base.py`

### ✅ Bug #3: 测试期望 rc=42 但 sandbox-host 返回 0
- **严重性**: P2 (测试用例错误)
- **现象**: `exit /b 42` 的子进程退出码是 42，但 `sandbox-host` 自身返回 0
- **修复**: 测试改为检查 stdout 中的 `exit_code=42` 而非进程退出码
- **文件**: `tests/test_basic.py`

### ✅ Bug #4: cmd.exe 环境变量 %VAR% 立即展开
- **严重性**: P2 (测试用例错误)
- **现象**: `set VAR=hello && echo %VAR%` 输出 `%VAR%` 字面值
- **根因**: cmd.exe 在解析整行时就展开 `%VAR%`，早于 `set` 执行
- **修复**: 使用 `cmd.exe /v:on /c "set VAR=hello && echo !VAR!"` 延迟展开
- **文件**: `tests/test_basic.py`

---

## 已知未修复

### ✅ Bug #5: `mkdir` 未被 NtCreateFile Hook 拦截（已修复）
- **严重性**: P1
- **现象**: `mkdir C:\Program Files\dir` 在沙箱中成功创建目录，未被 ACL 拦截
- **根因**: ⭐ **错误结论纠正** — `mkdir` **确实走 `NtCreateFile`**！之前的结论有误。
  真正的根因是 **两个 Bug 连锁导致 ACL 旁路**：
  1. `ExtractPathFromOA()` 忽略 `RootDirectory` 相对路径：`cmd.exe` 的 `mkdir` 分两步——先用 NtCreateFile 打开父目录获句柄，再用 `RootDirectory=句柄 + ObjectName="dir"` 创建子目录。`ExtractPathFromOA` 只提取了 `ObjectName="dir"`（相对路径），未拼接父目录完整路径
  2. `IsDevicePath("dir")` 误放行：`dir` 不含 `\` `:` `/`，被误判为 DOS 设备名 → ACL 检查被旁路
- **修复**: 移植 failure-01 的 `RootDirectory` 相对路径解析逻辑到 `ExtractPathFromOA()`，使用 `GetFinalPathNameByHandleW` 获取父目录绝对路径后拼接相对名，并添加 TLS 重入守卫防止递归
- **文件**: `dll/sandbox-hook/src/file_acl.cpp`
- **验证**: 26/26 x64 测试通过，`mkdir C:\Program Files\test` → 被拒绝 ✅，`mkdir E:\test` → 正常执行 ✅

### ⚠️ Bug #6: 网络拒绝规则可能不完全生效
- **严重性**: P1
- **测试**: `3.3 网络拒绝: ping 外部地址应被阻止`
- **现象**: 在 `test_network_deny.json` 配置下 ping 8.8.8.8 可能仍成功（取决于实际 DNS/网络）
- **根因**: 需要进一步调试 Winsock Hook 的覆盖范围。当前可能未正确拦截 ICMP 或 DNS 解析
- **建议**: 用 Wireshark 或 Windows Filtering Platform (WFP) 做更底层拦截
- **文件**: `dll/sandbox-hook/src/net_acl.cpp`

### ⚠️ Bug #6: x86 ReadOnly 权限测试不稳定
- **严重性**: P2
- **测试**: `5.5 x86 ReadOnly: 禁止写入`
- **现象**: WOW64 进程的 ReadOnly 文件写入有时未被拦截
- **根因**: 可能是 WOW64 文件系统重定向导致路径不匹配，或 x86 Hook 覆盖不完整
- **建议**: 
  1. 检查 WOW64 下的路径规范化 (`NormalizeNtPath`)
  2. 确认 `NtCreateFile` Hook 在 32 位进程中正确安装
- **文件**: `dll/sandbox-hook/src/file_acl.cpp`, `dll/sandbox-hook/src/hook_engine.cpp`

### ⚠️ Bug #7: AI POST /exec 审计数据可能不完整
- **严重性**: P2
- **测试**: `6.2 AI API: POST /exec 执行命令`
- **现象**: 通过 HTTP API 执行命令后，审计摘要可能不包含完整事件
- **根因**: AI 服务与审计消费可能在时序上有竞争(race condition)
- **建议**: 在 AI `/exec` 响应前显式调用 `ipc_server.flush_audit()`
- **文件**: `crates/sandbox-host/src/ai_server.rs`

---

## 待优化（非 Bug）

### 📌 优化 #8: DLL 路径硬编码
- **描述**: `run_sandbox()` 中 DLL 路径写死为 `exe_dir/target/dll/x64/sandbox_hook.dll`
- **影响**: 部署时需要保持目录结构不变
- **建议**: 支持通过环境变量 `SBOX_DLL_DIR` 或配置文件指定 DLL 路径
- **文件**: `crates/sandbox-host/src/main.rs:66-67`

### 📌 优化 #9: 审计事件输出到 stderr（噪音）
- **描述**: Rust Host 的日志输出混入 stderr，干扰测试结果判断
- **建议**: 将日志输出到文件而非 stderr，或添加 `--quiet` 模式
- **文件**: `crates/sandbox-host/src/main.rs`

### 📌 优化 #10: 无进程超时时的 TerminateProcess
- **描述**: `wait_for_process_timeout` 在超时后调用 `TerminateProcess(process, 1)`，可能丢失审计数据
- **建议**: 终止前先调用 `ipc_server.flush_audit()` 刷出审计缓冲
- **文件**: `crates/sandbox-host/src/inject.rs`

---

## 测试统计

| 分类 | 测试数 | 通过 | 已知失败 | 状态 |
|------|--------|------|----------|------|
| 基础功能 | 8 | 8 | 0 | ✅ |
| 基础功能 | 8 | 8 | 0 | ✅ |
| 文件 ACL（含 mkdir 回归测试） | 10 | 10 | 0 | ✅ |
| 网络 ACL | 5 | 5 | 1 | ⚠️ |
| 递归注入 (x64) | 4 | 4 | 0 | ✅ |
| Rust 单元测试 | 38 | 38 | 0 | ✅ |
| **总计** | **65** | **65** | **1** | |
