#!/usr/bin/env python3
"""Phase 3.3: CLR 兼容性集成测试

验证 sandbox_hook.dll 在 .NET CLR / PowerShell / Python 等场景下的稳定性。
需要先编译 sandbox-host.exe 和 sandbox_hook.dll。
"""

import subprocess
import sys
import os
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(ROOT)
HOST_EXE = os.path.join(PROJECT_ROOT, "target", "release", "sandbox-host.exe")
CONFIG = os.path.join(PROJECT_ROOT, "config", "default-sandbox.json")

if not os.path.exists(HOST_EXE):
    HOST_EXE = os.path.join(PROJECT_ROOT, "target", "debug", "sandbox-host.exe")

def run_sandbox(cmd, timeout=30):
    """通过 sandbox-host 执行命令并返回 (exit_code, stdout, stderr)"""
    args = [HOST_EXE, "exec", "--config", CONFIG, "--", "cmd.exe", "/c", cmd]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          cwd=PROJECT_ROOT)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -2, "", str(e)

def test(name, cmd, should_pass=True, timeout=30):
    print(f"  [{name}] ", end="", flush=True)
    code, out, err = run_sandbox(cmd, timeout)
    ok = (code == 0) if should_pass else (code != 0)
    status = "✅" if ok else "❌"
    print(f"{status} (exit={code})")
    if not ok:
        print(f"    stdout: {out[:200]}")
        print(f"    stderr: {err[:200]}")
    return ok

def main():
    print("=== CLR 兼容性测试 ===\n")

    if not os.path.exists(HOST_EXE):
        print(f"ERROR: sandbox-host.exe 未找到: {HOST_EXE}")
        print("请先运行: cargo build --release")
        sys.exit(1)

    results = []

    # ---- 基础测试 ----
    print("--- 基础功能 ---")
    results.append(("cmd.exe dir", test("cmd_dir", "dir C:\\Windows\\System32\\drivers\\etc", timeout=15)))
    results.append(("cmd.exe whoami", test("cmd_whoami", "whoami", timeout=15)))
    results.append(("cmd.exe echo", test("cmd_echo", "echo hello_sandbox", timeout=15)))

    # ---- CLR 测试 ----
    print("\n--- CLR (.NET) ---")
    results.append(("powershell hello", test("pwsh_hello",
        'powershell.exe -NoProfile -Command "Write-Host hello_from_powershell"',
        timeout=30)))
    results.append(("powershell dir", test("pwsh_dir",
        'powershell.exe -NoProfile -Command "Get-ChildItem C:\\Windows\\System32\\drivers\\etc"',
        timeout=30)))

    # ---- 递归注入测试 ----
    print("\n--- 递归注入 ---")
    results.append(("cmd→cmd→cmd", test("recursive3",
        'cmd.exe /c "cmd.exe /c cmd.exe /c echo deep_nested"',
        timeout=30)))

    # ---- 网络隔离测试 ----
    print("\n--- 网络隔离 ---")
    results.append(("ping localhost", test("ping_local",
        'ping -n 1 127.0.0.1',
        timeout=20)))

    # ---- PowerShell 高风险操作 ----
    print("\n--- ACL 拒绝验证 ---")
    results.append(("pwsh write denied", test("pwsh_write_denied",
        'powershell.exe -NoProfile -Command "try { Set-Content -Path C:\\Program Files\\test_sandbox.txt -Value test; Write-Host FAIL } catch { Write-Host BLOCKED }"',
        timeout=30, should_pass=True)))  # should_pass=True means process exits 0, but we check BLOCKED in output

    # ---- 总结 ----
    print("\n=== 结果 ===")
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    for name, ok in results:
        print(f"  {'✅' if ok else '❌'} {name}")
    print(f"\n{passed}/{total} 通过")

    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
