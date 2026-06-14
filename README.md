# Windows Sandbox

> AI 可调用的 Windows 沙盒终端 — C++ 注入 DLL + Rust 宿主

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-blue)]()

## 简介

Windows Sandbox 是一个轻量级 Windows 进程沙箱，通过 NT API Hook 实现文件系统和网络的隔离控制。AI 可以通过 HTTP API 在沙箱中执行任意命令，并获得审计报告。

### 核心特性

- **文件系统隔离** — 基于 glob 模式的读/写/拒绝 ACL
- **网络隔离** — Winsock Hook，按域名/IP/端口控制连接
- **递归注入** — 子进程自动继承沙箱保护（含 WOW64 32位进程）
- **自注入引擎** — 同进程直投（<100μs），CLR 兼容
- **AI API** — HTTP JSON-RPC，沙箱执行 + 审计报告
- **审计 Ring Buffer** — 无锁共享内存，实时事件采集

## 快速开始

### 构建

```powershell
# 方式 1: 一键构建
cmake -B build-root && cmake --build build-root --config Release

# 方式 2: 分别构建
cargo build --release                          # Rust Host
cd dll\sandbox-hook
cmake -B build-x64 -A x64 && cmake --build build-x64 --config Release
cmake -B build-x86 -A Win32 && cmake --build build-x86 --config Release
```

### 运行

```powershell
# CLI 模式
.\target\release\sandbox-host.exe exec cmd.exe /c "dir C:\"
.\target\release\sandbox-host.exe exec --config sandbox.json pwsh.exe -NoProfile

# AI 服务模式
.\target\release\sandbox-host.exe serve 9800

# 调用 AI API
curl -X POST http://127.0.0.1:9800/exec \
  -H "Content-Type: application/json" \
  -d '{"command":"cmd.exe","args":["/c","whoami"]}'
```

## 架构

```
┌──────────────────────────────────────────────────────────┐
│  AI / CLI                                                │
│    │                                                     │
│    ▼                                                     │
│  Rust Host (sandbox-host.exe)                            │
│  ┌──────────┐ ┌──────────┐ ┌────────────────────────┐   │
│  │ CLI/Parser│ │ Config   │ │ IPC Server             │   │
│  └──────────┘ └──────────┘ │ - 配置共享内存          │   │
│  ┌──────────────────────┐  │ - 审计 Ring Buffer      │   │
│  │ Process Manager      │  │ - 审计消费 & 报告       │   │
│  │ - CreateProcess(SUS) │  └────────────────────────┘   │
│  │ - 注入 DLL           │                               │
│  │ - 管道 stdout/stderr │                               │
│  └──────────────────────┘                               │
└──────────────────────────────────────────────────────────┘
         │ inject DLL              │ shared memory
         ▼                         ▼
┌──────────────────────────────────────────────────────────┐
│  C++ DLL (sandbox_hook.dll) — 运行在目标进程内            │
│  ┌─────────────────────────────────────────────────┐    │
│  │ ★ Self-Injection Engine                        │    │
│  │   Hook NtResumeThread → 同进程直投(<100μs)     │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌────────────────────────┐  │
│  │ File ACL │ │ Net ACL  │ │ Audit Ring Buffer      │  │
│  │ NtCrtFile│ │ connect  │ │ 1024 slots × 800B      │  │
│  │ NtOpenF  │ │ getaddri │ │ InterlockedIncrement   │  │
│  │ NtDelF   │ │ DnsQuery │ └────────────────────────┘  │
│  └──────────┘ └──────────┘                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │ Safety: VEH + UEH + CorExitProcess Hook          │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

## 配置

```json
{
  "name": "my-sandbox",
  "file_permissions": [
    {"pattern": "C:\\Users\\*\\Projects\\**", "permission": "inherit"},
    {"pattern": "C:\\Windows\\**",             "permission": "read_only"},
    {"pattern": "C:\\Program Files\\**",        "permission": "deny"}
  ],
  "network_permissions": [
    {"host": "*.github.com", "port": 443, "protocol": "tcp", "action": "allow"},
    {"host": "127.0.0.1",    "port": 0,   "protocol": "any", "action": "allow"}
  ],
  "enable_network_isolation": true,
  "enable_recursive_injection": true,
  "audit_log_dir": ".\\sandbox-logs"
}
```

## 项目结构

```
win-sandbox/
├── CMakeLists.txt              # 根构建（一键编译三个子项目）
├── Cargo.toml                  # Rust workspace
├── plan.md                     # 开发计划
├── build.ps1                   # PowerShell 构建脚本
├── crates/
│   ├── sandbox-core/           # 共享类型（ACL、IPC协议、配置）
│   └── sandbox-host/           # Rust 宿主（CLI、注入、IPC、AI服务）
├── dll/sandbox-hook/           # C++ 注入 DLL（完整 CRT + C++17）
│   ├── CMakeLists.txt
│   ├── include/                # 7个头文件
│   └── src/                    # 8个实现文件
├── config/default-sandbox.json # 默认沙箱策略
├── tests/test_clr.py           # CLR 兼容性测试
└── target/
    ├── dll/x64/sandbox_hook.dll
    ├── dll/x86/sandbox_hook.dll
    └── release/sandbox-host.exe
```

## 支持

- **Windows**: x64 / x86 (WOW64)
- **编译器**: MSVC 2022+ / Rust 1.80+
- **CMake**: 3.20+
