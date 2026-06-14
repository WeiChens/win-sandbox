#!/usr/bin/env python3
"""
Windows Sandbox 测试基础设施
============================
共享的配置、数据结构和沙箱运行器，供所有测试模块使用。
"""

import os
import sys
import subprocess
import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any

# ─── 路径配置 ────────────────────────────────────────────────────────
TESTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_DIR.parent
HOST_EXE_RELEASE = PROJECT_ROOT / "target" / "release" / "sandbox-host.exe"
HOST_EXE_DEBUG = PROJECT_ROOT / "target" / "debug" / "sandbox-host.exe"
CONFIG_DIR = TESTS_DIR / "configs"
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "default-sandbox.json"
TEST_WORKDIR = TESTS_DIR / "workdir"


def find_host_exe() -> Path:
    """查找 sandbox-host.exe"""
    if HOST_EXE_RELEASE.exists():
        return HOST_EXE_RELEASE
    if HOST_EXE_DEBUG.exists():
        return HOST_EXE_DEBUG
    return HOST_EXE_RELEASE  # 返回默认路径（后续报错）


HOST_EXE = find_host_exe()


# ─── 测试结果数据结构 ────────────────────────────────────────────────

@dataclass
class TestResult:
    """单个测试结果"""
    name: str
    category: str
    arch: str             # "x64" | "x86" | "both"
    passed: bool
    rc: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    expected_rc: Optional[int] = 0
    expected_text: Optional[str] = None
    expected_stderr_text: Optional[str] = None  # 期望在 stderr 中找到的文本
    known_fail: bool = False
    duration: float = 0.0
    skip: bool = False
    skip_reason: str = ""

    @property
    def status_icon(self) -> str:
        if self.skip:
            return "⏭️"
        if self.passed:
            return "✅"
        if self.known_fail:
            return "⚠️"
        return "❌"

    def short_str(self) -> str:
        extra = ""
        if self.skip:
            extra = f" (跳过: {self.skip_reason})"
        elif self.known_fail:
            extra = " (已知失败)"
        return f"{self.status_icon} [{self.arch}] {self.name}{extra}"

    def detail_str(self) -> str:
        lines = [f"{'='*60}", f"{self.short_str()}"]
        if self.skip:
            return "\n".join(lines) + "\n"
        if self.rc is not None:
            lines.append(f"  rc={self.rc} (expected={self.expected_rc})")
        if self.stdout:
            text = self.stdout.replace("\r\n", "\n").strip()
            if text:
                lines.append(f"  stdout: {text[:300]}")
        if self.stderr:
            text = self.stderr.replace("\r\n", "\n").strip()
            if text:
                lines.append(f"  stderr: {text[:300]}")
        if self.error:
            lines.append(f"  error: {self.error}")
        lines.append(f"  duration: {self.duration:.2f}s")
        if self.known_fail:
            lines.append(f"  ⚠️  已知失败（预先存在的问题）")
        lines.append("")
        return "\n".join(lines)


@dataclass
class TestSuite:
    """测试套件运行器"""
    verbose: bool = False
    results: List[TestResult] = field(default_factory=list)
    start_time: float = 0.0
    runner: "SandboxRunner" = None

    def __post_init__(self):
        self.runner = SandboxRunner(verbose=self.verbose)

    def run_tests(self, test_funcs: list, section_title: str = ""):
        """运行一组测试函数"""
        if section_title and self.verbose:
            print(f"\n═══ {section_title} ═══")
        for func in test_funcs:
            if self.verbose:
                print(f"  ▶ {func.__doc__ or func.__name__}")
            try:
                result = func(self.runner)
            except Exception as e:
                result = TestResult(
                    name=func.__doc__ or func.__name__,
                    category="异常", arch="both",
                    passed=False, error=str(e),
                    duration=0.0,
                )
            self.results.append(result)
            print(result.short_str())

    def begin(self):
        self.start_time = time.time()
        print(f"\n{'='*60}")
        print(f"🧪 Windows Sandbox 集成测试")
        print(f"{'='*60}")
        print(f"📂 sandbox-host: {HOST_EXE}")
        print(f"📂 配置目录:     {CONFIG_DIR}")
        print()

    def print_summary(self):
        elapsed = time.time() - self.start_time
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed and not r.known_fail and not r.skip)
        known = sum(1 for r in self.results if r.known_fail)
        skipped = sum(1 for r in self.results if r.skip)

        print(f"\n{'='*60}")
        print(f"📊 测试总结")
        print(f"{'='*60}")
        print(f"  总计:   {total}")
        print(f"  ✅ 通过: {passed}")
        print(f"  ⚠️  已知失败: {known}")
        print(f"  ⏭️  跳过: {skipped}")
        print(f"  ❌ 失败: {failed}")
        print(f"  耗时:   {elapsed:.1f}s")
        print()

        if failed > 0:
            print("❌ 失败的测试:")
            for r in self.results:
                if not r.passed and not r.known_fail and not r.skip:
                    print(f"  {r.status_icon} [{r.arch}] {r.name}")
                    if r.error:
                        print(f"     错误: {r.error}")
                    if r.stdout:
                        print(f"     stdout: {r.stdout[:200]}")
                    if r.stderr:
                        print(f"     stderr: {r.stderr[:200]}")
            print()

        print(f"{'='*60}")
        if failed == 0:
            print(f"🎉 所有 {passed}/{total} 项测试通过！")
        else:
            print(f"📌 {failed} 项测试失败，{passed} 项通过，{known} 项已知失败")


# ─── 沙箱运行器 ──────────────────────────────────────────────────────

class SandboxRunner:
    """封装 sandbox-host.exe 的调用"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def exec(self, command: str,
             config: Optional[Path] = None,
             timeout: int = 30,
             as_x86: bool = False) -> Tuple[int, str, str]:
        """
        在沙箱中执行命令，返回 (exit_code, stdout, stderr)

        参数:
            command: 要执行的命令（会自动用 cmd.exe /c 包装）
            config: 配置文件路径（默认使用 DEFAULT_CONFIG）
            timeout: 超时秒数
            as_x86: 使用 x86 cmd.exe (SysWOW64)
        """
        if config is None:
            config = DEFAULT_CONFIG

        # 选择 shell
        if as_x86:
            shell = "C:\\Windows\\SysWOW64\\cmd.exe"
        else:
            shell = "C:\\Windows\\System32\\cmd.exe"

        # 通过 exec 方式传递命令
        cmd = [
            str(HOST_EXE),
            "exec",
            "--config", str(config),
            "--",
            shell, "/c", command,
        ]

        if self.verbose:
            print(f"  🔧 {command[:80]}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(PROJECT_ROOT),
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except FileNotFoundError:
            return -2, "", f"sandbox-host.exe not found at {HOST_EXE}"
        except Exception as e:
            return -3, "", str(e)

    def exec_direct(self, exe: str, args: List[str] = None,
                    config: Optional[Path] = None,
                    timeout: int = 30) -> Tuple[int, str, str]:
        """
        直接执行可执行文件（不通过 cmd.exe）

        参数:
            exe: 可执行文件路径
            args: 参数列表
            config: 配置文件
            timeout: 超时秒数
        """
        if config is None:
            config = DEFAULT_CONFIG

        cmd = [
            str(HOST_EXE),
            "exec",
            "--config", str(config),
            "--",
            exe,
        ]
        if args:
            cmd.extend(args)

        if self.verbose:
            print(f"  🔧 {exe} {' '.join(args or [])}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(PROJECT_ROOT),
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except FileNotFoundError:
            return -2, "", f"sandbox-host.exe not found at {HOST_EXE}"
        except Exception as e:
            return -3, "", str(e)

    def make_result(self, name: str, category: str, arch: str,
                    rc: int, stdout: str, stderr: str,
                    expected_rc: Optional[int] = 0,
                    expected_text: Optional[str] = None,
                    expected_stderr_text: Optional[str] = None,
                    known_fail: bool = False,
                    duration: float = 0.0,
                    skip: bool = False,
                    skip_reason: str = "") -> TestResult:
        """构造 TestResult，自动判断通过/失败"""
        if skip:
            return TestResult(
                name=name, category=category, arch=arch,
                passed=False, skip=True, skip_reason=skip_reason,
                duration=duration,
            )

        passed = True
        error = ""

        if expected_rc is not None and rc != expected_rc:
            passed = False
            error = f"rc={rc} != expected={expected_rc}"

        if expected_text and passed:
            if expected_text not in stdout and expected_text not in stderr:
                passed = False
                error = f"预期文本 '{expected_text}' 未在输出中找到"

        if expected_stderr_text and passed:
            if expected_stderr_text not in stderr:
                passed = False
                error = f"预期文本 '{expected_stderr_text}' 未在 stderr 中找到"

        return TestResult(
            name=name, category=category, arch=arch,
            passed=passed, rc=rc, stdout=stdout, stderr=stderr,
            error=error, expected_rc=expected_rc,
            expected_text=expected_text,
            expected_stderr_text=expected_stderr_text,
            known_fail=known_fail,
            duration=duration,
        )


# ─── 便捷函数 ────────────────────────────────────────────────────────

def check_host() -> bool:
    """检查 sandbox-host.exe 是否存在"""
    if HOST_EXE.exists():
        return True
    print(f"❌ sandbox-host.exe 未找到: {HOST_EXE}")
    print("请先运行: cargo build --release")
    return False
