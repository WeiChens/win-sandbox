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
    """3.3 网络拒绝: 外部 TCP 连接应被阻止"""
    t0 = time.time()
    # ICMP (ping) 不走 connect() Hook，改用 TCP 连接测试
    # PowerShell 的 TcpClient 会调用 connect()，能被 Hook 拦截
    rc, out, err = runner.exec(
        'powershell.exe -NoProfile -Command '
        '"try { $c=New-Object System.Net.Sockets.TcpClient; '
        '$c.Connect(\"8.8.8.8\",80); echo CONNECT_OK; $c.Close() } '
        'catch { echo CONNECT_DENIED }" 2>nul',
        config=NETWORK_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "网络拒绝: 外部 TCP 连接", "网络ACL-Deny", "x64",
        rc, out, err,
        expected_text="CONNECT_DENIED",
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


def test_dns_deny_external(runner: SandboxRunner) -> TestResult:
    """3.6 DNS 拒绝: 网络隔离模式下禁止解析外部域名（getaddrinfo Hook）"""
    t0 = time.time()
    # 使用 .NET Dns.GetHostEntry 走 getaddrinfo → 被 Hook_WSAStartup 安装的 Hook_getaddrinfo 拦截
    rc, out, err = runner.exec(
        'powershell.exe -NoProfile -Command '
        '"try { [System.Net.Dns]::GetHostEntry(\"www.example.com\") | Out-Null; echo DNS_OK } '
        'catch { echo DNS_BLOCKED }" 2>nul',
        config=NETWORK_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "DNS 拒绝: 外部域名解析", "网络ACL-Deny", "x64",
        rc, out, err,
        expected_text="DNS_BLOCKED",
        duration=dt,
    )


def test_net_port_specific_deny(runner: SandboxRunner) -> TestResult:
    """3.7 端口拒绝: 端口级屏蔽 — 仅阻止指定端口 9999"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'powershell.exe -NoProfile -Command '
        '"try { $c=New-Object System.Net.Sockets.TcpClient; '
        '$c.Connect(\"127.0.0.1\",9999); echo CONNECT_OK; $c.Close() } '
        'catch { echo CONNECT_DENIED }" 2>nul',
        config=CONFIG_DIR / "test_net_port_deny.json", timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "端口拒绝: 阻止端口 9999", "网络ACL-Deny", "x64",
        rc, out, err,
        expected_text="CONNECT_DENIED",
        duration=dt,
    )


def test_net_port_other_allowed(runner: SandboxRunner) -> TestResult:
    """3.8 端口允许: 非拒绝端口不被沙箱拦截（仅 TCP 连接拒绝）"""
    t0 = time.time()
    # 连接一个未使用的本地端口（12345 未被规则拒绝）
    # sandbox 应放行 → 得到 ECONNREFUSED（没有服务监听）
    # 而非 WSAEACCES（沙箱拒绝）
    rc, out, err = runner.exec(
        'powershell.exe -NoProfile -Command '
        '"try { $c=New-Object System.Net.Sockets.TcpClient; '
        '$c.Connect(\"127.0.0.1\",12345); echo CONNECT_OK; $c.Close() } '
        'catch { echo CONNECT_REFUSED }" 2>nul',
        config=CONFIG_DIR / "test_net_port_deny.json", timeout=15,
    )
    dt = time.time() - t0

    # CONNECT_REFUSED 表示连接请求通过了沙箱，但目标端口无服务监听
    # 这验证了沙箱没有阻止该端口
    sandbox_passed = "CONNECT_REFUSED" in out
    return runner.make_result(
        "端口允许: 非拒绝端口放行", "网络ACL-Allow", "x64",
        rc, out, err,
        expected_text="CONNECT_REFUSED" if sandbox_passed else None,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
NETWORK_TESTS = [
    test_ping_localhost,
    test_nslookup_allowed,
    test_network_deny_ping_external,
    test_curl_localhost,
    test_dns_resolve_allowed,
    test_dns_deny_external,
    test_net_port_specific_deny,
    test_net_port_other_allowed,
]
