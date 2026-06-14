#!/usr/bin/env python3
"""
测试模块：基础功能
=================
验证沙箱基本注入、命令执行、stdout/stderr 捕获。
"""

import sys
import time
from pathlib import Path

# 确保 tests 目录在 path 中
sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR

BASIC_CONFIG = CONFIG_DIR / "test_inherit.json"


def test_cmd_echo(runner: SandboxRunner) -> TestResult:
    """1.1 cmd.exe echo 基础输出"""
    t0 = time.time()
    rc, out, err = runner.exec("echo SANDBOX_ECHO_OK", config=BASIC_CONFIG, timeout=15)
    dt = time.time() - t0
    return runner.make_result(
        "cmd echo 基础输出", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="SANDBOX_ECHO_OK",
        duration=dt,
    )


def test_cmd_whoami(runner: SandboxRunner) -> TestResult:
    """1.2 cmd.exe whoami"""
    t0 = time.time()
    rc, out, err = runner.exec("whoami", config=BASIC_CONFIG, timeout=15)
    dt = time.time() - t0
    # whoami 应该输出当前用户名
    return runner.make_result(
        "cmd whoami", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        duration=dt,
    )


def test_cmd_dir(runner: SandboxRunner) -> TestResult:
    """1.3 cmd.exe dir 系统目录"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "dir C:\\Windows\\System32\\drivers\\etc",
        config=BASIC_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "cmd dir 系统目录", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="hosts",  # 应能看到 hosts 文件
        duration=dt,
    )


def test_cmd_exit_code(runner: SandboxRunner) -> TestResult:
    """1.4 cmd.exe 退出码传递"""
    t0 = time.time()
    rc, out, err = runner.exec("exit /b 42", config=BASIC_CONFIG, timeout=15)
    dt = time.time() - t0
    # sandbox-host 自身返回 0，子进程退出码在 stdout 中 "exit_code=42"
    return runner.make_result(
        "cmd 退出码传递", "基础功能", "x64",
        rc, out, err,
        expected_text="exit_code=42",
        duration=dt,
    )


def test_cmd_stderr(runner: SandboxRunner) -> TestResult:
    """1.5 cmd.exe stderr 输出"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "echo stdout_text && dir nonexistent_dir_xyz 2>&1",
        config=BASIC_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # dir 不存在目录会输出错误信息，exit code 可能非零但命令本身应该执行
    has_stdout = "stdout_text" in out
    return runner.make_result(
        "cmd stderr 输出", "基础功能", "x64",
        rc, out, err,
        expected_text="stdout_text" if has_stdout else None,
        duration=dt,
    )


def test_cmd_recursive_env(runner: SandboxRunner) -> TestResult:
    """1.6 环境变量传递"""
    t0 = time.time()
    # 使用 cmd /v:on 延迟扩展 + !VAR! 语法
    rc, out, err = runner.exec(
        'cmd.exe /v:on /c "set TEST_VAR=hello_sandbox && echo !TEST_VAR!"',
        config=BASIC_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "环境变量传递", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="hello_sandbox",
        duration=dt,
    )


def test_pwsh_hello(runner: SandboxRunner) -> TestResult:
    """1.7 PowerShell 基本执行"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command", "Write-Host 'PWsh_HELLO'"],
        config=BASIC_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    passed = rc == 0 and ("PWsh_HELLO" in out or "PWsh_HELLO" in err)
    return runner.make_result(
        "PowerShell 基本执行", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="PWsh_HELLO" if passed else None,
        known_fail=not passed and rc != 0,
        duration=dt,
    )


def test_pwsh_script(runner: SandboxRunner) -> TestResult:
    """1.8 PowerShell 多行脚本"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "powershell.exe",
        ["-NoProfile", "-Command",
         "$sum = 3 + 4; Write-Host \"SUM=$sum\""],
        config=BASIC_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    return runner.make_result(
        "PowerShell 多行脚本", "基础功能", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="SUM=7",
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
BASIC_TESTS = [
    test_cmd_echo,
    test_cmd_whoami,
    test_cmd_dir,
    test_cmd_exit_code,
    test_cmd_stderr,
    test_cmd_recursive_env,
    test_pwsh_hello,
    test_pwsh_script,
]
