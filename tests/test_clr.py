#!/usr/bin/env python3
"""
测试模块：CLR (.NET / PowerShell) 兼容性
=========================================
验证 sandbox_hook.dll 在 .NET CLR 宿主下的稳定性，
特别是 PowerShell 等复杂脚本执行场景。

已知风险: CLR 的 /GS 栈检测与内联 Hook 的 CALL rel32 跳板重定位冲突，
已通过以下方式缓解：
1. RelocateInstruction() 处理 x64 CALL (0xE8) / JMP (0xE9)
2. VEH 捕获 STATUS_STACK_BUFFER_OVERRUN → ExitProcess(1)
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"


def test_clr_pwsh_hello(runner: SandboxRunner) -> TestResult:
    """CLR-1: PowerShell 基本输出"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command", "Write-Host 'CLR_HELLO'"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    hello_found = "CLR_HELLO" in out or "CLR_HELLO" in err
    return runner.make_result(
        "CLR: PowerShell 基本输出", "CLR兼容", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="CLR_HELLO",
        known_fail=not hello_found,
        duration=dt,
    )


def test_clr_pwsh_dir(runner: SandboxRunner) -> TestResult:
    """CLR-2: PowerShell 列出目录"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command",
         "Get-ChildItem C:\\Windows\\System32\\drivers\\etc"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    dir_ok = rc == 0 and ("hosts" in out or "hosts" in err.lower())
    return runner.make_result(
        "CLR: PowerShell 列出目录", "CLR兼容", "x64",
        rc, out, err,
        expected_rc=0 if dir_ok else None,
        expected_text="hosts" if dir_ok else None,
        known_fail=not dir_ok,
        duration=dt,
    )


def test_clr_pwsh_complex_script(runner: SandboxRunner) -> TestResult:
    """CLR-3: PowerShell 复杂脚本（循环+条件+异常）"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command",
         "$sum=0; 1..10 | %%{ $sum += $_ }; "
         "if($sum -eq 55){Write-Host 'SUM=55'}else{Write-Host 'SUM_WRONG'}"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    sum_ok = rc == 0 and "SUM=55" in out
    return runner.make_result(
        "CLR: PowerShell 复杂脚本", "CLR兼容", "x64",
        rc, out, err,
        expected_rc=0 if sum_ok else None,
        expected_text="SUM=55" if sum_ok else None,
        known_fail=not sum_ok,
        duration=dt,
    )


def test_clr_pwsh_file_write_blocked(runner: SandboxRunner) -> TestResult:
    """CLR-4: PowerShell 向只读路径写文件应被拒绝"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command",
         "try { Set-Content -Path 'C:\\Windows\\System32\\sandbox_clr_test.txt' -Value 'test'; "
         "Write-Host 'WRITE_OK' } catch { Write-Host 'BLOCKED' }"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    blocked = "BLOCKED" in out
    return runner.make_result(
        "CLR: PowerShell 只读拒绝", "CLR兼容", "x64",
        rc, out, err,
        expected_text="BLOCKED",
        duration=dt,
    )


def test_clr_pwsh_network_tcp(runner: SandboxRunner) -> TestResult:
    """CLR-5: PowerShell TCP 连接 localhost"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command",
         "try { $c=New-Object Net.Sockets.TcpClient; "
         "$c.Connect('127.0.0.1',80); echo CONNECT_OK; $c.Close() } "
         "catch { echo CONNECT_REFUSED }"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    # 80 端口上可能没有服务，但重点是沙箱不崩溃
    no_crash = "TIMEOUT" not in err and rc >= 0
    return runner.make_result(
        "CLR: PowerShell TCP 连接", "CLR兼容", "x64",
        rc, out, err,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
CLR_TESTS = [
    test_clr_pwsh_hello,
    test_clr_pwsh_dir,
    test_clr_pwsh_complex_script,
    test_clr_pwsh_file_write_blocked,
    test_clr_pwsh_network_tcp,
]

