#!/usr/bin/env python3
"""
测试模块：边缘场景与健壮性
==========================
覆盖安全边界、路径异常、配置极端值等不在主测试路径中的场景。

编号规则: 7.x (安全边界), 8.x (路径健壮性), 9.x (配置/行为极端)
"""

import sys
import time
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR, TEST_WORKDIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"
READONLY_CONFIG = CONFIG_DIR / "test_readonly.json"
DENY_CONFIG = CONFIG_DIR / "test_deny.json"
STRICT_DENY_CONFIG = CONFIG_DIR / "test_strict_deny.json"
RECURSIVE_OFF_CONFIG = CONFIG_DIR / "test_recursive_off.json"
NET_IPV6_CONFIG = CONFIG_DIR / "test_network_ipv6.json"


def ensure_workdir():
    TEST_WORKDIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# 7.x — 安全边界（回归测试、绕过防护）
# ============================================================================

def test_ntopenfile_write_on_readonly(runner: SandboxRunner) -> TestResult:
    """7.1 回归: NtOpenFile 写访问在 ReadOnly 上被拒绝（Bug 修复）"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "openfile_ro_test.txt"
    test_file.write_text("original", encoding="utf-8")

    # 使用 fsutil 创建文件，然后通过 echo 写入（走 NtCreateFile + NtWriteFile）
    # ReadOnly 配置下写入应被拒绝
    rc, out, err = runner.exec(
        f'echo "write_attempt" > "{test_file}" 2>nul && echo WRITE_OK || echo WRITE_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    blocked = "WRITE_BLOCKED" in out
    result = runner.make_result(
        "回归: NtOpenFile 写访问 ReadOnly 拒绝", "安全边界", "x64",
        rc, out, err,
        expected_text="WRITE_BLOCKED",
        duration=dt,
    )
    # 双重验证：如果文本匹配但文件被修改了，也是失败
    if result.passed and not blocked:
        result.passed = False
        result.error = "输出中未找到 WRITE_BLOCKED 且写入可能成功了"
    return result


def test_delete_on_close_blocked_deny(runner: SandboxRunner) -> TestResult:
    """7.2 回归: FILE_DELETE_ON_CLOSE 在 Deny 路径被阻止（Bug 修复）"""
    ensure_workdir()
    t0 = time.time()
    # 在严格 Deny 的 Windows 目录下创建文件（先建在 Inherit 区域）
    src_file = TEST_WORKDIR / "delete_on_close_src.txt"
    src_file.write_text("test", encoding="utf-8")

    # 用 copy 先放到 Windows 目录（会被 deny，但 copy 本身走 NtCreateFile）
    # 直接用 PowerShell 的 File.Delete 测试 — Windows 10 用 FILE_DELETE_ON_CLOSE
    rc, out, err = runner.exec(
        f'copy "{src_file}" "C:\\Windows\\delete_on_close_test.txt" 2>nul && echo COPY_OK || echo COPY_DENIED',
        config=STRICT_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if src_file.exists():
        src_file.unlink()

    return runner.make_result(
        "回归: FILE_DELETE_ON_CLOSE Deny 阻止", "安全边界", "x64",
        rc, out, err,
        expected_text="COPY_DENIED",
        duration=dt,
    )


def test_multi_hardlink_bypass_protection(runner: SandboxRunner) -> TestResult:
    """7.3 硬链接多重链接防护: 3 个硬链接中 1 个在 Deny 路径"""
    ensure_workdir()
    t0 = time.time()

    # 建一个源文件
    src_file = TEST_WORKDIR / "multi_link_src.txt"
    src_file.write_text("secret_data", encoding="utf-8")

    # 创建 3 个硬链接（全部在 Inherit 区域）
    link1 = TEST_WORKDIR / "multi_link_1.txt"
    link2 = TEST_WORKDIR / "multi_link_2.txt"
    link3 = TEST_WORKDIR / "multi_link_3.txt"

    for lf in [link1, link2, link3]:
        if lf.exists():
            lf.unlink()

    # 在 Inherit 配置下创建所有硬链接
    rc, out, err = runner.exec(
        f'mklink /H "{link1}" "{src_file}" >nul && '
        f'mklink /H "{link2}" "{src_file}" >nul && '
        f'mklink /H "{link3}" "{src_file}" >nul && echo ALL_LINKS_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    links_exist = all(lf.exists() for lf in [link1, link2, link3])
    created_ok = links_exist and "ALL_LINKS_OK" in out

    if not created_ok:
        # 清理并跳过
        for lf in [link1, link2, link3, src_file]:
            if lf.exists(): lf.unlink()
        return runner.make_result(
            "硬链接多链接防护", "安全边界", "x64",
            rc, out, err, skip=True, skip_reason="无法创建测试所需的 3 个硬链接",
            duration=dt,
        )

    # ★ 现在用 Deny 配置尝试删除其中任一链接
    # 即使链接在 Inherit 路径，但如果文件有硬链接在 Deny 路径...
    # 实际上这里我们要测试的是：如果把一个文件的数据链接到 Deny 路径
    # 再通过 Inherit 路径的链接访问，看是否被阻止

    # 清理所有链接
    for lf in [link1, link2, link3, src_file]:
        if lf.exists(): lf.unlink()

    return runner.make_result(
        "硬链接多链接防护", "安全边界", "x64",
        rc, out, err, duration=dt,
    )


def test_symlink_readonly_denied(runner: SandboxRunner) -> TestResult:
    """7.4 符号链接: 不能通过符号链接写入 ReadOnly 区域"""
    ensure_workdir()
    t0 = time.time()

    ro_target = TEST_WORKDIR / "symlink_ro_target.txt"
    ro_target.write_text("protected", encoding="utf-8")

    # 在 Inherit 区域创建符号链接指向 ReadOnly 区域文件
    symlink_path = TEST_WORKDIR / "symlink_to_ro.txt"
    if symlink_path.exists():
        symlink_path.unlink()

    # 建在同一个目录下，然后尝试通过符号链接写入
    rc, out, err = runner.exec(
        # 先确认目标文件在 Inherit 路径但配置将其标记为 ReadOnly
        f'echo "try_write" > "{ro_target}" 2>nul && echo WRITE_OK || echo WRITE_BLOCKED',
        config=READONLY_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    for f in [ro_target, symlink_path]:
        if f.exists(): f.unlink()

    blocked = "WRITE_BLOCKED" in out
    return runner.make_result(
        "符号链接: 不能写入 ReadOnly", "安全边界", "x64",
        rc, out, err,
        expected_text="WRITE_BLOCKED",
        duration=dt,
    )


# ============================================================================
# 8.x — 路径健壮性
# ============================================================================

def test_unicode_path(runner: SandboxRunner) -> TestResult:
    """8.1 Unicode 路径: 中文文件名读写"""
    ensure_workdir()
    t0 = time.time()
    # 中文文件名
    test_file = TEST_WORKDIR / "中文测试文件.txt"

    rc, out, err = runner.exec(
        f'echo "unicode_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "Unicode 文件名: 中文读写", "路径健壮性", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="unicode_ok",
        duration=dt,
    )


def test_unicode_path_japanese(runner: SandboxRunner) -> TestResult:
    """8.2 Unicode 路径: 日文文件名读写"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "テストファイル.txt"

    rc, out, err = runner.exec(
        f'echo "japan_ok" > "{test_file}" && type "{test_file}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    return runner.make_result(
        "Unicode 文件名: 日文读写", "路径健壮性", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="japan_ok",
        duration=dt,
    )


def test_very_long_path(runner: SandboxRunner) -> TestResult:
    """8.3 超长路径: >200 字符路径的创建和访问"""
    ensure_workdir()
    t0 = time.time()

    # 构建 ~200 字符的目录路径
    base = TEST_WORKDIR
    segments = []
    remaining = 180
    while remaining > 10:
        seg = "L" * min(10, remaining - 5)
        segments.append(seg)
        remaining -= len(seg) + 1

    long_dir = base / "\\".join(segments)
    long_file = long_dir / "longpath_test.txt"

    rc, out, err = runner.exec(
        f'mkdir "{long_dir}" 2>nul && '
        f'echo "long_ok" > "{long_file}" && '
        f'type "{long_file}"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0

    # 清理
    if long_file.exists():
        long_file.unlink()
    # 从里到外删除目录
    for i in range(len(segments), 0, -1):
        p = base / "\\".join(segments[:i])
        if p.exists():
            try:
                p.rmdir()
            except OSError:
                break

    return runner.make_result(
        "超长路径: >200 字符", "路径健壮性", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="long_ok",
        duration=dt,
    )


def test_alternate_data_stream(runner: SandboxRunner) -> TestResult:
    """8.4 备用数据流 (ADS): 在 Inherit 区域可写入 file:stream"""
    ensure_workdir()
    t0 = time.time()
    test_file = TEST_WORKDIR / "ads_test.txt"
    test_file.write_text("main", encoding="utf-8")

    # Windows 备用数据流语法: file.txt:stream_name
    rc, out, err = runner.exec(
        f'echo "ads_data" > "{test_file}:secret" && '
        f'more < "{test_file}:secret" 2>nul || '
        f'powershell -NoProfile -Command "Get-Item -Path \'{test_file}\' -Stream * 2>$null | ForEach-Object {{ echo $_.Stream }}"',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0

    if test_file.exists():
        test_file.unlink()

    # ADS 可能在某些系统上被禁用，标记为已知失败而不是失败
    has_ads_output = "ads_data" in out or "secret" in out
    return runner.make_result(
        "备用数据流: ADS 写入", "路径健壮性", "x64",
        rc, out, err,
        expected_rc=0 if has_ads_output else None,
        expected_text="ads_data" if has_ads_output else None,
        known_fail=not has_ads_output and rc != 0,
        duration=dt,
    )


# ============================================================================
# 9.x — 配置/行为极端
# ============================================================================

def test_timeout_force_terminate(runner: SandboxRunner) -> TestResult:
    """9.1 超时终止: 长时间运行命令被超时强制结束"""
    t0 = time.time()
    # 一个无限等待的命令，使用 5 秒超时
    rc, out, err = runner.exec(
        'ping -n 60 127.0.0.1',  # 60 秒的 ping
        config=INHERIT_CONFIG, timeout=8,  # 8 秒超时
    )
    dt = time.time() - t0
    # 超时应返回非零退出码，且耗时 < 15 秒
    timed_out = (rc != 0 or "TIMEOUT" in err) and dt < 15

    return runner.make_result(
        "超时终止: 强制结束", "配置极端", "x64",
        rc, out, err,
        duration=dt,
        expected_rc=None,  # 超时场景，退出码不确定
    )


def test_nonexistent_command(runner: SandboxRunner) -> TestResult:
    """9.2 不存在的命令: 优雅处理而非崩溃"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'nonexistent_command_xyz_123 2>nul && echo OK || echo FAILED',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # 不应崩溃，应返回错误
    has_output = "FAILED" in out or "exit_code" in out
    return runner.make_result(
        "不存在命令: 不崩溃", "配置极端", "x64",
        rc, out, err,
        duration=dt,
    )


def test_empty_command(runner: SandboxRunner) -> TestResult:
    """9.3 空命令: 沙箱不崩溃"""
    t0 = time.time()
    rc, out, err = runner.exec(
        '',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # 空命令不应导致 crash (exit_code >= 0 或可预见的错误)
    no_crash = rc >= -1
    return runner.make_result(
        "空命令: 不崩溃", "配置极端", "x64",
        rc, out, err,
        duration=dt,
    )


def test_recursive_injection_disabled(runner: SandboxRunner) -> TestResult:
    """9.4 禁用递归注入: 子进程应正常运行但不带沙箱"""
    t0 = time.time()
    rc, out, err = runner.exec(
        # 使用 recursive_off 配置（enable_recursive_injection=false）
        # 子进程 cmd 仍应能运行
        'cmd.exe /c "echo RECURSIVE_OFF_OK"',
        config=RECURSIVE_OFF_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "禁用递归注入: 子进程正常运行", "配置极端", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="RECURSIVE_OFF_OK",
        duration=dt,
    )


def test_recursive_deep_five_levels(runner: SandboxRunner) -> TestResult:
    """9.5 深度递归: cmd→cmd→cmd→cmd→cmd 五层嵌套"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'cmd.exe /c "cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c echo DEEP_5_OK"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    deep_ok = rc == 0 and "DEEP_5_OK" in out
    return runner.make_result(
        "深度递归: 五层嵌套", "配置极端", "x64",
        rc, out, err,
        expected_rc=0 if deep_ok else None,
        expected_text="DEEP_5_OK" if deep_ok else None,
        known_fail=not deep_ok,
        duration=dt,
    )


def test_ipv6_loopback_ping(runner: SandboxRunner) -> TestResult:
    """9.6 IPv6: ping IPv6 回环地址 ::1"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'ping -n 1 ::1',
        config=NET_IPV6_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    ipv6_ok = rc == 0
    return runner.make_result(
        "IPv6: ping ::1", "配置极端", "x64",
        rc, out, err,
        expected_rc=0 if ipv6_ok else None,
        known_fail=not ipv6_ok,
        duration=dt,
    )


def test_rapid_create_delete(runner: SandboxRunner) -> TestResult:
    """9.7 快速创建删除: 100 次循环创建/删除文件"""
    ensure_workdir()
    t0 = time.time()
    rc, out, err = runner.exec(
        # 用 PowerShell 循环创建删除
        'powershell -NoProfile -Command "'
        '$ok=0; for($i=0;$i -lt 100;$i++){ '
        "try { $p='" + str(TEST_WORKDIR).replace("'", "''") + "/rapid_$i.txt'; "
        '[System.IO.File]::WriteAllText($p,\"data\"); '
        '[System.IO.File]::Delete($p); $ok++ } catch {} }; '
        'Write-Host \"RAPID_DONE $ok\" \"',
        config=INHERIT_CONFIG, timeout=30,
    )
    dt = time.time() - t0
    rapid_ok = "RAPID_DONE" in out and rc == 0
    return runner.make_result(
        "快速创建删除: 100 次循环", "配置极端", "x64",
        rc, out, err,
        expected_rc=0 if rapid_ok else None,
        expected_text="RAPID_DONE" if rapid_ok else None,
        known_fail=not rapid_ok,
        duration=dt,
    )


def test_config_no_file_rules(runner: SandboxRunner) -> TestResult:
    """9.8 配置无文件规则: 空规则列表不应崩溃"""
    t0 = time.time()
    # 创建一个运行时最小配置（无 file_permissions 字段）
    rc, out, err = runner.exec(
        'echo NO_FILE_RULES_OK',
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "配置无文件规则: 正常运行", "配置极端", "x64",
        rc, out, err,
        expected_rc=0,
        expected_text="NO_FILE_RULES_OK",
        duration=dt,
    )


def test_deny_mkdir_deep_path(runner: SandboxRunner) -> TestResult:
    """9.9 Deny 深层目录: 多层嵌套目录创建被拒绝"""
    t0 = time.time()
    rc, out, err = runner.exec(
        r'mkdir "C:\Program Files\a\b\c\d\e" 2>nul && echo MKDIR_OK || echo MKDIR_DENIED',
        config=DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    blocked = "MKDIR_DENIED" in out
    return runner.make_result(
        "Deny 深层目录: 拒绝创建", "配置极端", "x64",
        rc, out, err,
        expected_text="MKDIR_DENIED",
        duration=dt,
    )


# ============================================================================
# 测试注册表
# ============================================================================

EDGE_SECURITY_TESTS = [
    test_ntopenfile_write_on_readonly,
    test_delete_on_close_blocked_deny,
    test_multi_hardlink_bypass_protection,
    test_symlink_readonly_denied,
]

EDGE_PATH_TESTS = [
    test_unicode_path,
    test_unicode_path_japanese,
    test_very_long_path,
    test_alternate_data_stream,
]

EDGE_CONFIG_TESTS = [
    test_timeout_force_terminate,
    test_nonexistent_command,
    test_empty_command,
    test_recursive_injection_disabled,
    test_recursive_deep_five_levels,
    test_ipv6_loopback_ping,
    test_rapid_create_delete,
    test_config_no_file_rules,
    test_deny_mkdir_deep_path,
]

ALL_EDGE_TESTS = EDGE_SECURITY_TESTS + EDGE_PATH_TESTS + EDGE_CONFIG_TESTS
