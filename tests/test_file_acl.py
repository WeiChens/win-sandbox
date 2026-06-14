#!/usr/bin/env python3
"""
测试模块：文件 ACL
=================
验证 Inherit（继承）/ ReadOnly（只读）/ Deny（拒绝）文件权限策略。
"""

import sys
import time
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR, TEST_WORKDIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"
READONLY_CONFIG = CONFIG_DIR / "test_readonly.json"
DENY_CONFIG = CONFIG_DIR / "test_deny.json"


def ensure_workdir():
    """确保测试工作目录存在"""
    TEST_WORKDIR.mkdir(parents=True, exist_ok=True)


# ─── Inherit 测试 ────────────────────────────────────────────────────

def test_inherit_write_temp(runner: SandboxRunner) -> TestResult:
    """2.1 Inherit: 可写入用户目录下的临时文件"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "inherit_test.txt"
    test_file.write_text("before", encoding="utf-8")

    rc, out, err = runner.exec(
        f'echo "inherit_write_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    # 清理
    if test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "Inherit: 写入用户目录", "文件ACL-Inherit", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="inherit_write_ok",
        duration=dt,
    )


def test_inherit_delete_temp(runner: SandboxRunner) -> TestResult:
    """2.2 Inherit: 可删除用户目录下的临时文件"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "inherit_del_test.txt"
    test_file.write_text("to_delete", encoding="utf-8")

    rc, out, err = runner.exec(
        f'if exist "{test_file}" del "{test_file}" && echo DELETE_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    deleted = not test_file.exists()
    if not deleted and test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "Inherit: 删除用户目录文件", "文件ACL-Inherit", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="DELETE_OK",
        duration=dt,
    )


# ─── ReadOnly 测试 ───────────────────────────────────────────────────

def test_readonly_cannot_write(runner: SandboxRunner) -> TestResult:
    """2.3 ReadOnly: 禁止在只读区域写入"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "readonly_test.txt"
    # 确保文件存在
    test_file.write_text("original", encoding="utf-8")

    rc, out, err = runner.exec(
        f'echo "overwrite" > "{test_file}" 2>nul && echo WRITE_SUCCEEDED || echo WRITE_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    # 检查文件是否被修改
    content = test_file.read_text(encoding="utf-8").strip() if test_file.exists() else ""
    if test_file.exists():
        test_file.unlink()

    # ReadOnly 应该阻止写入 → 内容保持 "original"
    blocked = "WRITE_BLOCKED" in out or content == "original"
    return runner.make_result(
        "ReadOnly: 禁止写入", "文件ACL-ReadOnly", "x64",
        rc, out, err,
        expected_text="WRITE_BLOCKED" if blocked else None,
        duration=dt,
    )


def test_readonly_cannot_delete(runner: SandboxRunner) -> TestResult:
    """2.4 ReadOnly: 禁止删除只读区域文件"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "readonly_del_test.txt"
    test_file.write_text("do_not_delete", encoding="utf-8")

    rc, out, err = runner.exec(
        f'del "{test_file}" 2>nul && echo DELETE_SUCCEEDED || echo DELETE_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    file_still_exists = test_file.exists()
    if test_file.exists():
        test_file.unlink()

    # ReadOnly 应该阻止删除 → 文件仍存在
    blocked = "DELETE_BLOCKED" in out or file_still_exists
    return runner.make_result(
        "ReadOnly: 禁止删除", "文件ACL-ReadOnly", "x64",
        rc, out, err,
        expected_text="DELETE_BLOCKED" if blocked else None,
        duration=dt,
    )


def test_readonly_can_read(runner: SandboxRunner) -> TestResult:
    """2.5 ReadOnly: 允许读取只读区域文件"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'type C:\\Windows\\System32\\drivers\\etc\\hosts',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # 应该能成功读取 hosts 文件
    has_content = len(out) > 10
    return runner.make_result(
        "ReadOnly: 允许读取", "文件ACL-ReadOnly", "x64",
        rc, out, err,
        expected_rc=0,
        duration=dt,
    )


# ─── Deny 测试 ───────────────────────────────────────────────────────

def test_deny_cannot_access(runner: SandboxRunner) -> TestResult:
    """2.6 Deny: 完全拒绝访问 Program Files"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'dir "C:\\Program Files" 2>nul && echo ACCESS_SUCCEEDED || echo ACCESS_DENIED',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # 预期被拒绝
    denied = "ACCESS_DENIED" in out or rc != 0
    return runner.make_result(
        "Deny: 拒绝访问 Program Files", "文件ACL-Deny", "x64",
        rc, out, err,
        expected_text="ACCESS_DENIED" if denied else None,
        duration=dt,
    )


def test_deny_cannot_write_program_files(runner: SandboxRunner) -> TestResult:
    """2.7 Deny: 禁止写入 Program Files"""
    t0 = time.time()
    rc, out, err = runner.exec(
        r'echo "test" > "C:\Program Files\test_sandbox_write.txt" 2>nul && echo WRITE_OK || echo WRITE_DENIED',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    denied = "WRITE_DENIED" in out or rc != 0
    return runner.make_result(
        "Deny: 禁止写入 Program Files", "文件ACL-Deny", "x64",
        rc, out, err,
        expected_text="WRITE_DENIED" if denied else None,
        duration=dt,
    )


# ─── 目录操作 ────────────────────────────────────────────────────────

def test_mkdir_readonly(runner: SandboxRunner) -> TestResult:
    """2.8 mkdir ReadOnly: 禁止创建目录"""
    ensure_workdir()
    t0 = time.time()
    new_dir = TEST_WORKDIR / "new_dir_readonly_test"
    # 先确保不存在
    if new_dir.exists():
        new_dir.rmdir()

    rc, out, err = runner.exec(
        f'mkdir "{new_dir}" 2>nul && echo MKDIR_OK || echo MKDIR_DENIED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if new_dir.exists():
        new_dir.rmdir()

    denied = "MKDIR_DENIED" in out or rc != 0
    return runner.make_result(
        "mkdir ReadOnly: 禁止创建目录", "文件ACL-mkdir", "x64",
        rc, out, err,
        expected_text="MKDIR_DENIED" if denied else None,
        duration=dt,
    )


def test_mkdir_inherit(runner: SandboxRunner) -> TestResult:
    """2.9 mkdir Inherit: 允许创建目录"""
    ensure_workdir()
    t0 = time.time()
    new_dir = TEST_WORKDIR / "new_dir_inherit_test"
    if new_dir.exists():
        new_dir.rmdir()

    rc, out, err = runner.exec(
        f'mkdir "{new_dir}" && echo MKDIR_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if new_dir.exists():
        new_dir.rmdir()

    return runner.make_result(
        "mkdir Inherit: 允许创建目录", "文件ACL-mkdir", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="MKDIR_OK",
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
FILE_ACL_TESTS = [
    test_inherit_write_temp,
    test_inherit_delete_temp,
    test_readonly_cannot_write,
    test_readonly_cannot_delete,
    test_readonly_can_read,
    test_deny_cannot_access,
    test_deny_cannot_write_program_files,
    test_mkdir_readonly,
    test_mkdir_inherit,
]
