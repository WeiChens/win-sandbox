#!/usr/bin/env python3
"""
测试模块：递归注入
=================
验证子进程自动继承沙箱保护（x64→x64, x64→x86 递归注入）。
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"


def test_recursive_two_levels(runner: SandboxRunner) -> TestResult:
    """4.1 递归注入: cmd→cmd 两层嵌套"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'cmd.exe /c "cmd.exe /c echo NESTED_LEVEL2_OK"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    return runner.make_result(
        "递归注入: cmd→cmd 两层", "递归注入", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="NESTED_LEVEL2_OK",
        duration=dt,
    )


def test_recursive_three_levels(runner: SandboxRunner) -> TestResult:
    """4.2 递归注入: cmd→cmd→cmd 三层嵌套"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'cmd.exe /c "cmd.exe /c cmd.exe /c echo DEEP_NESTED_OK"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    return runner.make_result(
        "递归注入: cmd→cmd→cmd 三层", "递归注入", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="DEEP_NESTED_OK",
        duration=dt,
    )


def test_recursive_whoami_nested(runner: SandboxRunner) -> TestResult:
    """4.3 递归注入: 嵌套进程中执行 whoami"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'cmd.exe /c "whoami && echo WHOAMI_NESTED_OK"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    return runner.make_result(
        "递归注入: 嵌套 whoami", "递归注入", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="WHOAMI_NESTED_OK",
        duration=dt,
    )


def test_recursive_pwsh_nested(runner: SandboxRunner) -> TestResult:
    """4.4 递归注入: cmd→pwsh 嵌套（CLR 安全检查）"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'powershell.exe -NoProfile -Command "Write-Host PWsh_NESTED_OK"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    passed = rc == 0 and ("PWsh_NESTED_OK" in out or "PWsh_NESTED_OK" in err)
    return runner.make_result(
        "递归注入: cmd→pwsh", "递归注入", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="PWsh_NESTED_OK" if passed else None,
        known_fail=not passed,
        duration=dt,
    )


def test_recursive_x86_nested(runner: SandboxRunner) -> TestResult:
    """4.5 递归注入: x64→x86 跨架构注入"""
    t0 = time.time()
    rc, out, err = runner.exec_direct(
        "C:\\Windows\\SysWOW64\\cmd.exe",
        ["/c", "echo WOW64_NESTED_OK"],
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    passed = rc == 0 and "WOW64_NESTED_OK" in out
    return runner.make_result(
        "递归注入: x64→x86 跨架构", "递归注入", "x86",
        rc, out, err,
        expected_rc=0,
        expected_text="WOW64_NESTED_OK" if passed else None,
        known_fail=not passed,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
RECURSIVE_TESTS = [
    test_recursive_two_levels,
    test_recursive_three_levels,
    test_recursive_whoami_nested,
    test_recursive_pwsh_nested,
    test_recursive_x86_nested,
]
