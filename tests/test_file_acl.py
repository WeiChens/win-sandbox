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
    result = runner.make_result(
        "ReadOnly: 禁止写入", "文件ACL-ReadOnly", "x64",
        rc, out, err,
        expected_text="WRITE_BLOCKED",
        duration=dt,
    )
    # 双重验证：文件内容也应未被修改
    if result.passed and not blocked:
        result.passed = False
        result.error = "输出中未找到 WRITE_BLOCKED 且文件内容已被修改"
    return result


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

    # ★ cmd.exe 的 del 即使删除失败也返回 0，所以不能依赖 || 分支
    #   必须以文件是否仍然存在作为判断依据
    file_still_exists = test_file.exists()
    if test_file.exists():
        test_file.unlink()

    # ReadOnly 应该阻止删除 → 文件仍存在
    result = runner.make_result(
        "ReadOnly: 禁止删除", "文件ACL-ReadOnly", "x64",
        rc, out, err,
        duration=dt,
    )
    if not file_still_exists:
        result.passed = False
        result.error = "文件已被删除（沙箱未阻止删除）"
    return result


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
    # 预期被拒绝 — 必须收到 ACCESS_DENIED
    return runner.make_result(
        "Deny: 拒绝访问 Program Files", "文件ACL-Deny", "x64",
        rc, out, err,
        expected_text="ACCESS_DENIED",
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
    return runner.make_result(
        "Deny: 禁止写入 Program Files", "文件ACL-Deny", "x64",
        rc, out, err,
        expected_text="WRITE_DENIED",
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
    result = runner.make_result(
        "mkdir ReadOnly: 禁止创建目录", "文件ACL-mkdir", "x64",
        rc, out, err,
        expected_text="MKDIR_DENIED",
        duration=dt,
    )
    if result.passed and not denied:
        result.passed = False
        result.error = "输出中未找到 MKDIR_DENIED 且目录可能已被创建"
    return result


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


# ★ 回归测试：Bug #5 — mkdir 在 Deny 路径上应被拦截
def test_mkdir_deny(runner: SandboxRunner) -> TestResult:
    """2.10 mkdir Deny: 禁止在拒绝路径创建目录（回归测试 Bug #5）"""
    t0 = time.time()

    # 测试 Deny 路径上的 mkdir（使用 RootDirectory 相对路径方式）
    rc, out, err = runner.exec(
        r'mkdir "C:\Program Files\sandbox_mkdir_deny_test" 2>nul && echo MKDIR_OK || echo MKDIR_DENIED',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    denied = "MKDIR_DENIED" in out
    return runner.make_result(
        "mkdir Deny: 禁止在拒绝路径创建目录", "文件ACL-mkdir", "x64",
        rc, out, err,
        expected_text="MKDIR_DENIED",
        duration=dt,
    )


# ─── 重命名测试（NtSetInformationFile Hook）─────────────────────────────

def test_rename_inherit(runner: SandboxRunner) -> TestResult:
    """2.11 Rename Inherit: 允许在继承区域重命名文件"""
    ensure_workdir()
    t0 = time.time()
    old_file = TEST_WORKDIR / "rename_old.txt"
    new_file = TEST_WORKDIR / "rename_new.txt"

    # 清理残留
    if new_file.exists():
        new_file.unlink()
    if old_file.exists():
        old_file.unlink()

    old_file.write_text("rename_test", encoding="utf-8")

    # ren 命令通过 MoveFileW → NtSetInformationFile(FileRenameInformation)
    rc, out, err = runner.exec(
        # 使用完整路径 ren（但 ren 的语法是: ren old new，需要同一目录）
        # 改用 move 命令，它更通用
        f'move /Y "{old_file}" "{new_file}" >nul && if exist "{new_file}" echo RENAME_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    renamed = new_file.exists()
    if old_file.exists():
        old_file.unlink()
    if new_file.exists():
        new_file.unlink()

    result = runner.make_result(
        "Rename Inherit: 允许重命名", "文件ACL-Rename", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="RENAME_OK",
        duration=dt,
    )
    if result.passed and not renamed:
        result.passed = False
        result.error = "输出含 RENAME_OK 但目标文件未创建"
    return result


def test_rename_to_readonly_blocked(runner: SandboxRunner) -> TestResult:
    """2.12 Rename ReadOnly: 禁止重命名文件到只读区域（目标路径检查）"""
    ensure_workdir()
    t0 = time.time()
    old_file = TEST_WORKDIR / "rename_to_ro.txt"
    old_file.write_text("rename_test", encoding="utf-8")

    # 尝试将文件从 Inherit 区域移动到 ReadOnly 区域（C:\Windows\...）
    # NtSetInformationFile 检查目标路径权限 → 应被阻止
    rc, out, err = runner.exec(
        f'move /Y "{old_file}" "C:\\Windows\\System32\\drivers\\etc\\sandbox_ro_rename_test.txt" 2>nul && echo RENAME_OK || echo RENAME_BLOCKED',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    # 清理
    if old_file.exists():
        old_file.unlink()
    ro_dest = Path("C:\\Windows\\System32\\drivers\\etc\\sandbox_ro_rename_test.txt")
    if ro_dest.exists():
        ro_dest.unlink()

    blocked = "RENAME_BLOCKED" in out or rc != 0
    result = runner.make_result(
        "Rename ReadOnly: 禁止到只读区域", "文件ACL-Rename", "x64",
        rc, out, err,
        expected_text="RENAME_BLOCKED",
        duration=dt,
    )
    if result.passed and not blocked:
        result.passed = False
        result.error = "输出中未找到 RENAME_BLOCKED 且退出码为0"
    return result


# ─── 目录删除测试（NtSetInformationFile + NtDeleteFile Hook）────────────

def test_rmdir_inherit(runner: SandboxRunner) -> TestResult:
    """2.13 rmdir Inherit: 允许在继承区域删除空目录"""
    ensure_workdir()
    t0 = time.time()
    test_dir = TEST_WORKDIR / "rmdir_inherit_test"
    test_dir.mkdir(parents=True, exist_ok=True)

    # rmdir 通过 NtSetInformationFile(FileDispositionInformation) 或 NtDeleteFile
    rc, out, err = runner.exec(
        f'rmdir "{test_dir}" >nul && echo RMDIR_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    dir_removed = not test_dir.exists()
    if test_dir.exists():
        test_dir.rmdir()

    result = runner.make_result(
        "rmdir Inherit: 允许删除目录", "文件ACL-rmdir", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="RMDIR_OK",
        duration=dt,
    )
    if result.passed and not dir_removed:
        result.passed = False
        result.error = "输出含 RMDIR_OK 但目录未被删除"
    return result


def test_rmdir_readonly_blocked(runner: SandboxRunner) -> TestResult:
    """2.14 rmdir ReadOnly: 禁止在只读区域删除目录"""
    ensure_workdir()
    t0 = time.time()
    test_dir = TEST_WORKDIR / "rmdir_ro_test"
    test_dir.mkdir(parents=True, exist_ok=True)

    # 在 ReadOnly 配置下删除目录 → 应被阻止
    rc, out, err = runner.exec(
        f'rmdir "{test_dir}" 2>nul && echo RMDIR_OK || echo RMDIR_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    dir_still_exists = test_dir.exists()
    if test_dir.exists():
        test_dir.rmdir()

    # ★ rmdir 也可能返回 0 即使失败，以目录是否仍然存在为准
    result = runner.make_result(
        "rmdir ReadOnly: 禁止删除目录", "文件ACL-rmdir", "x64",
        rc, out, err,
        duration=dt,
    )
    if not dir_still_exists:
        result.passed = False
        result.error = "目录已被删除（沙箱未阻止删除）"
    return result


# ─── 硬链接测试（NtSetInformationFile + CheckFilePermissionWithHardLinks）─

def test_hardlink_to_deny_blocked(runner: SandboxRunner) -> TestResult:
    """2.15 Hardlink Deny: 禁止创建硬链接到拒绝区域"""
    ensure_workdir()
    t0 = time.time()
    source_file = TEST_WORKDIR / "hardlink_source.txt"
    source_file.write_text("hardlink_test_data", encoding="utf-8")

    # 尝试在 C:\Program Files (Deny 区域) 创建指向源文件的硬链接
    # mklink /H 触发 NtSetInformationFile(FileLinkInformation) → 应被阻止
    link_target = "C:\\Program Files\\sandbox_hardlink_test.txt"
    rc, out, err = runner.exec(
        f'mklink /H "{link_target}" "{source_file}" 2>nul && echo LINK_OK || echo LINK_BLOCKED',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if source_file.exists():
        source_file.unlink()
    link_path = Path(link_target)
    if link_path.exists():
        link_path.unlink()

    blocked = "LINK_BLOCKED" in out or rc != 0
    result = runner.make_result(
        "Hardlink Deny: 禁止到拒绝区域", "文件ACL-Hardlink", "x64",
        rc, out, err,
        expected_text="LINK_BLOCKED",
        duration=dt,
    )
    if result.passed and not blocked:
        result.passed = False
        result.error = "输出中未找到 LINK_BLOCKED 且退出码为0"
    return result


def test_hardlink_inherit_allowed(runner: SandboxRunner) -> TestResult:
    """2.16 Hardlink Inherit: 允许在继承区域创建硬链接"""
    ensure_workdir()
    t0 = time.time()
    source_file = TEST_WORKDIR / "hardlink_src.txt"
    link_file = TEST_WORKDIR / "hardlink_link.txt"

    if link_file.exists():
        link_file.unlink()
    source_file.write_text("hardlink_data", encoding="utf-8")

    # 同一区域创建硬链接 → 应被允许
    rc, out, err = runner.exec(
        f'mklink /H "{link_file}" "{source_file}" >nul && echo LINK_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    link_created = link_file.exists()
    if source_file.exists():
        source_file.unlink()
    if link_file.exists():
        link_file.unlink()

    # ★ 硬链接必须创建成功 — 如果创建失败，应标记为失败而非通过
    result = runner.make_result(
        "Hardlink Inherit: 允许同区域", "文件ACL-Hardlink", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="LINK_OK",
        duration=dt,
    )
    # 如果退出码和文本都匹配但文件不存在，仍是失败
    if result.passed and not link_created:
        result.passed = False
        result.error = "mklink 命令成功但硬链接文件未创建"
    return result


# ─── 边界/边缘测试 ──────────────────────────────────────────────────

def test_file_with_spaces(runner: SandboxRunner) -> TestResult:
    """2.17 文件名含空格: 在继承区域可正常读写"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "file with spaces.txt"

    rc, out, err = runner.exec(
        f'echo "spaces_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "文件名含空格: 正常读写", "文件ACL-Edge", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="spaces_ok",
        duration=dt,
    )


def test_deep_nested_path(runner: SandboxRunner) -> TestResult:
    """2.18 深度嵌套路径: 在继承区域创建多层目录并写入"""
    ensure_workdir()
    t0 = time.time()
    deep_dir = TEST_WORKDIR / "a" / "b" / "c" / "d" / "e"
    test_file = deep_dir / "deep_test.txt"

    rc, out, err = runner.exec(
        f'mkdir "{deep_dir}" 2>nul && echo "deep_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    # 清理
    if test_file.exists():
        test_file.unlink()
    # 从里到外删除目录
    for p in [deep_dir, deep_dir.parent, deep_dir.parent.parent,
              deep_dir.parent.parent.parent, deep_dir.parent.parent.parent.parent]:
        if p != TEST_WORKDIR and p.exists():
            try:
                p.rmdir()
            except OSError:
                break

    return runner.make_result(
        "深度嵌套路径: 多层目录创建", "文件ACL-Edge", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="deep_ok",
        duration=dt,
    )


def test_device_path_passthrough(runner: SandboxRunner) -> TestResult:
    """2.19 设备路径放行: NUL 设备应正常工作（绕过 ACL 检查）"""
    t0 = time.time()
    # NUL 是 DOS 设备名，IsDevicePath() 返回 true → 直接放行
    # 即使用 Deny 配置也应该能写入 NUL
    rc, out, err = runner.exec(
        'echo "device_test" > NUL && echo DEVICE_OK',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "设备路径放行: NUL 写入", "文件ACL-Edge", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="DEVICE_OK",
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
    test_mkdir_deny,       # Bug #5 回归测试
    test_rename_inherit,
    test_rename_to_readonly_blocked,
    test_rmdir_inherit,
    test_rmdir_readonly_blocked,
    test_hardlink_to_deny_blocked,
    test_hardlink_inherit_allowed,
    test_file_with_spaces,
    test_deep_nested_path,
    test_device_path_passthrough,
]
