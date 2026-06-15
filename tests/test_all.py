#!/usr/bin/env python3
"""
Windows Sandbox — 集成测试统一运行器
======================================

运行全部测试套件：基础功能、文件 ACL、网络 ACL、递归注入、x86/WOW64、AI API。

用法:
    python tests/test_all.py                     # 运行全部测试
    python tests/test_all.py --quick             # 仅运行快速测试（基础功能）
    python tests/test_all.py --x64               # 仅运行 x64 相关测试
    python tests/test_all.py --x86               # 仅运行 x86 相关测试
    python tests/test_all.py --no-ai             # 跳过 AI API 测试
    python tests/test_all.py --verbose           # 详细输出
    python tests/test_all.py --list              # 列出所有测试项

退出码:
    0  - 所有测试通过（或仅已知失败/跳过）
    1  - 有测试失败
"""

import sys
import time
from pathlib import Path

# 将 tests 目录加入路径
sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import TestSuite, check_host
from test_basic import BASIC_TESTS
from test_file_acl import FILE_ACL_TESTS
from test_network import NETWORK_TESTS
from test_recursive import RECURSIVE_TESTS
from test_x86 import X86_TESTS
from test_ai_api import AI_API_TESTS


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Windows Sandbox 集成测试")
    parser.add_argument("--quick", action="store_true", help="仅运行快速测试（基础功能）")
    parser.add_argument("--x64", action="store_true", help="仅运行 x64 测试")
    parser.add_argument("--x86", action="store_true", help="仅运行 x86 测试")
    parser.add_argument("--no-ai", action="store_true", help="跳过 AI API 测试")
    parser.add_argument("--list", action="store_true", help="列出所有测试项")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    args = parser.parse_args()

    if args.list:
        print_test_list()
        return 0

    if not check_host():
        return 1

    suite = TestSuite(verbose=args.verbose)
    suite.begin()

    # ── 1. 基础功能（总是运行）──────────────────────────────────
    suite.run_tests(BASIC_TESTS, "1. 基础功能")

    if args.quick:
        suite.print_summary()
        return 0 if _all_passed(suite) else 1

    if args.x64:
        suite.run_tests(FILE_ACL_TESTS, "2. 文件 ACL")
        suite.run_tests(NETWORK_TESTS, "3. 网络 ACL")
        suite.run_tests(RECURSIVE_TESTS[:4], "4. 递归注入 (x64)")
    elif args.x86:
        suite.run_tests(X86_TESTS, "5. x86/WOW64")
    else:
        # ── 2. 文件 ACL ────────────────────────────────────────
        suite.run_tests(FILE_ACL_TESTS, "2. 文件 ACL")

        # ── 3. 网络 ACL ────────────────────────────────────────
        suite.run_tests(NETWORK_TESTS, "3. 网络 ACL")

        # ── 4. 递归注入 ────────────────────────────────────────
        suite.run_tests(RECURSIVE_TESTS, "4. 递归注入")

        # ── 5. x86/WOW64 ───────────────────────────────────────
        suite.run_tests(X86_TESTS, "5. x86/WOW64")

        # ── 6. AI API ──────────────────────────────────────────
        if not args.no_ai:
            suite.run_tests(AI_API_TESTS, "6. AI API")
        else:
            print("\n⏭️  跳过 AI API 测试")

    suite.print_summary()
    return 0 if _all_passed(suite) else 1


def _all_passed(suite: TestSuite) -> bool:
    """检查是否所有测试通过（跳过和已知失败不计入失败）"""
    for r in suite.results:
        if not r.passed and not r.known_fail and not r.skip:
            return False
    return True


def print_test_list():
    """打印所有测试清单"""
    all_tests = [
        ("基础功能", "x64", "1.1 cmd echo 基础输出"),
        ("基础功能", "x64", "1.2 cmd whoami"),
        ("基础功能", "x64", "1.3 cmd dir 系统目录"),
        ("基础功能", "x64", "1.4 cmd 退出码传递"),
        ("基础功能", "x64", "1.5 cmd stderr 输出"),
        ("基础功能", "x64", "1.6 环境变量传递"),
        ("基础功能", "x64", "1.7 PowerShell 基本执行"),
        ("基础功能", "x64", "1.8 PowerShell 多行脚本"),
        ("文件ACL-Inherit", "x64", "2.1 Inherit: 写入用户目录"),
        ("文件ACL-Inherit", "x64", "2.2 Inherit: 删除用户目录文件"),
        ("文件ACL-ReadOnly", "x64", "2.3 ReadOnly: 禁止写入"),
        ("文件ACL-ReadOnly", "x64", "2.4 ReadOnly: 禁止删除"),
        ("文件ACL-ReadOnly", "x64", "2.5 ReadOnly: 允许读取"),
        ("文件ACL-Deny", "x64", "2.6 Deny: 拒绝访问 Program Files"),
        ("文件ACL-Deny", "x64", "2.7 Deny: 禁止写入 Program Files"),
        ("文件ACL-mkdir", "x64", "2.8 mkdir ReadOnly: 禁止创建目录"),
        ("文件ACL-mkdir", "x64", "2.9 mkdir Inherit: 允许创建目录"),
        ("文件ACL-mkdir", "x64", "2.10 mkdir Deny: 禁止在拒绝路径创建目录"),
        ("文件ACL-Rename", "x64", "2.11 Rename Inherit: 允许重命名"),
        ("文件ACL-Rename", "x64", "2.12 Rename ReadOnly: 禁止到只读区域"),
        ("文件ACL-rmdir", "x64", "2.13 rmdir Inherit: 允许删除目录"),
        ("文件ACL-rmdir", "x64", "2.14 rmdir ReadOnly: 禁止删除目录"),
        ("文件ACL-Hardlink", "x64", "2.15 Hardlink Deny: 禁止到拒绝区域"),
        ("文件ACL-Hardlink", "x64", "2.16 Hardlink Inherit: 允许同区域"),
        ("文件ACL-Edge", "x64", "2.17 文件名含空格: 正常读写"),
        ("文件ACL-Edge", "x64", "2.18 深度嵌套路径: 多层目录创建"),
        ("文件ACL-Edge", "x64", "2.19 设备路径放行: NUL 写入"),
        ("网络ACL-Allow", "x64", "3.1 网络允许: ping localhost"),
        ("网络ACL-Allow", "x64", "3.2 网络允许: nslookup localhost"),
        ("网络ACL-Deny", "x64", "3.3 网络拒绝: 外部 TCP 连接"),
        ("网络ACL-Allow", "x64", "3.4 curl 可用性检查"),
        ("网络ACL-Allow", "x64", "3.5 DNS 解析: localhost"),
        ("网络ACL-Deny", "x64", "3.6 DNS 拒绝: 外部域名解析"),
        ("网络ACL-Deny", "x64", "3.7 端口拒绝: 阻止端口 9999"),
        ("网络ACL-Allow", "x64", "3.8 端口允许: 非拒绝端口放行"),
        ("递归注入", "x64", "4.1 cmd→cmd 两层嵌套"),
        ("递归注入", "x64", "4.2 cmd→cmd→cmd 三层嵌套"),
        ("递归注入", "x64", "4.3 嵌套 whoami"),
        ("递归注入", "x64", "4.4 cmd→pwsh (CLR 安全检查)"),
        ("递归注入", "x86", "4.5 x64→x86 跨架构"),
        ("x86/WOW64", "x86", "5.1 x86 基础 echo"),
        ("x86/WOW64", "x86", "5.2 x86 whoami"),
        ("x86/WOW64", "x86", "5.3 x86 dir 系统目录"),
        ("x86/WOW64", "x86", "5.4 x86 文件写入 Inherit"),
        ("x86/WOW64", "x86", "5.5 x86 ReadOnly: 禁止写入"),
        ("AI API", "x64", "6.1 /health 健康检查"),
        ("AI API", "x64", "6.2 POST /exec 执行命令"),
        ("AI API", "x64", "6.3 POST /exec 退出码"),
        ("AI API", "x64", "6.4 GET /audit 审计"),
    ]

    print("# Windows Sandbox 测试清单\n")
    for cat, arch, name in all_tests:
        print(f"  - [{arch}] {name} ({cat})")
    print(f"\n共计 {len(all_tests)} 项测试")


if __name__ == "__main__":
    sys.exit(main())
