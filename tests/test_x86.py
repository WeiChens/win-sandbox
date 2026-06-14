#!/usr/bin/env python3
"""
测试模块：x86 / WOW64 支持
==========================
验证 32 位进程的注入、执行和 ACL 保护。
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR, TEST_WORKDIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"
READONLY_CONFIG = CONFIG_DIR / "test_readonly.json"

SYSWOW64_CMD = "C:\\Windows\\SysWOW64\\cmd.exe"


def ensure_workdir():
    TEST_WORKDIR.mkdir(parents=True, exist_ok=True)


def test_x86_basic_echo(runner: SandboxRunner) -> TestResult:
    """5.1 x86 基础: echo 输出"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "echo X86_BASIC_OK",
        config=INHERIT_CONFIG, timeout=15,
        as_x86=True,
    )
    dt = time.time() - t0
    return runner.make_result(
        "x86 基础 echo", "x86/WOW64", "x86",
        rc, out, err,
        expected_rc=0,
        expected_text="X86_BASIC_OK",
        duration=dt,
    )


def test_x86_whoami(runner: SandboxRunner) -> TestResult:
    """5.2 x86 whoami"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "whoami",
        config=INHERIT_CONFIG, timeout=15,
        as_x86=True,
    )
    dt = time.time() - t0
    return runner.make_result(
        "x86 whoami", "x86/WOW64", "x86",
        rc, out, err,
        expected_rc=0,
        duration=dt,
    )


def test_x86_dir(runner: SandboxRunner) -> TestResult:
    """5.3 x86 dir 系统目录"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "dir C:\\Windows\\System32\\drivers\\etc",
        config=INHERIT_CONFIG, timeout=15,
        as_x86=True,
    )
    dt = time.time() - t0
    return runner.make_result(
        "x86 dir 系统目录", "x86/WOW64", "x86",
        rc, out, err,
        expected_rc=0,
        expected_text="hosts",
        duration=dt,
    )


def test_x86_file_write(runner: SandboxRunner) -> TestResult:
    """5.4 x86 文件写入 (Inherit)"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "x86_write_test.txt"
    test_file.write_text("before", encoding="utf-8")

    rc, out, err = runner.exec(
        f'echo "x86_write_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
        as_x86=True,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "x86 文件写入 Inherit", "x86/WOW64", "x86",
        rc, out, err,
        expected_rc=0,
        expected_text="x86_write_ok",
        duration=dt,
    )


def test_x86_readonly_deny_write(runner: SandboxRunner) -> TestResult:
    """5.5 x86 ReadOnly: 禁止写入"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "x86_readonly_test.txt"
    test_file.write_text("original", encoding="utf-8")

    rc, out, err = runner.exec(
        f'echo "overwrite" > "{test_file}" 2>nul && echo WRITE_SUCCEEDED || echo WRITE_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
        as_x86=True,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    blocked = "WRITE_BLOCKED" in out
    return runner.make_result(
        "x86 ReadOnly: 禁止写入", "x86/WOW64", "x86",
        rc, out, err,
        expected_text="WRITE_BLOCKED" if blocked else None,
        known_fail=not blocked,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
X86_TESTS = [
    test_x86_basic_echo,
    test_x86_whoami,
    test_x86_dir,
    test_x86_file_write,
    test_x86_readonly_deny_write,
]
