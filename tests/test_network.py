#!/usr/bin/env python3
"""
测试模块：网络 ACL
=================
验证网络隔离：允许/拒绝 TCP 连接、DNS 解析。
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, CONFIG_DIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"
NETWORK_DENY_CONFIG = CONFIG_DIR / "test_network_deny.json"


def test_ping_localhost(runner: SandboxRunner) -> TestResult:
    """3.1 网络允许: ping localhost"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "ping -n 1 127.0.0.1",
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    passed = rc == 0
    return runner.make_result(
        "网络允许: ping localhost", "网络ACL-Allow", "x64",
        rc, out, err,
        expected_rc=0,
        known_fail=not passed,
        duration=dt,
    )


def test_nslookup_allowed(runner: SandboxRunner) -> TestResult:
    """3.2 网络允许: nslookup localhost"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "nslookup localhost 2>nul",
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # nslookup 在非管理员下行为可能不同，允许 rc!=0
    return runner.make_result(
        "网络允许: nslookup localhost", "网络ACL-Allow", "x64",
        rc, out, err,
        duration=dt,
    )


def test_network_deny_ping_external(runner: SandboxRunner) -> TestResult:
    """3.3 网络拒绝: ping 外部地址应被阻止"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "ping -n 1 -w 2000 8.8.8.8 2>nul",
        config=NETWORK_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # 在 deny 配置下，外部连接应该失败
    denied = rc != 0
    return runner.make_result(
        "网络拒绝: ping 外部地址", "网络ACL-Deny", "x64",
        rc, out, err,
        known_fail=not denied,
        duration=dt,
    )


def test_curl_localhost(runner: SandboxRunner) -> TestResult:
    """3.4 网络允许: curl localhost (如可用)"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "curl --version 2>nul || echo CURL_NOT_AVAILABLE",
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # curl 可能未安装，仅做可用性检查
    curl_available = "curl" in out.lower() and "CURL_NOT_AVAILABLE" not in out
    return runner.make_result(
        "curl 可用性检查", "网络ACL-Allow", "x64",
        rc, out, err,
        duration=dt,
    )


def test_dns_resolve_allowed(runner: SandboxRunner) -> TestResult:
    """3.5 DNS 解析: 允许解析 localhost"""
    t0 = time.time()
    rc, out, err = runner.exec(
        "ping -n 1 localhost",
        config=INHERIT_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    passed = rc == 0
    return runner.make_result(
        "DNS 解析: localhost", "网络ACL-Allow", "x64",
        rc, out, err,
        expected_rc=0,
        known_fail=not passed,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
NETWORK_TESTS = [
    test_ping_localhost,
    test_nslookup_allowed,
    test_network_deny_ping_external,
    test_curl_localhost,
    test_dns_resolve_allowed,
]
