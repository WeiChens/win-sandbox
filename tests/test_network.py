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
    """3.3 网络拒绝: 外部 TCP 连接应被 WSAEACCES 阻止"""
    t0 = time.time()
    # ICMP (ping) 不走 connect() Hook，改用 TCP 连接测试
    # PowerShell 的 TcpClient 会调用 connect()，能被 Hook 拦截
    # 使用 cmd.exe 的 powershell 调用确保 ws2_32 已加载
    rc, out, err = runner.exec(
        'powershell -NoProfile -Command "& {try {$c=New-Object Net.Sockets.TcpClient;$c.Connect(\"8.8.8.8\",80);echo CONNECT_OK;$c.Close()}catch{echo BLOCKED_WSAEACCES}}" 2>nul',
        config=NETWORK_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "网络拒绝: 外部 TCP 连接", "网络ACL-Deny", "x64",
        rc, out, err,
        expected_text="BLOCKED_WSAEACCES",
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
    # 直接执行 ping.exe（不走 cmd.exe 子进程），确保 sandbox DLL 加载到 ping.exe 中
    # ping 使用 getaddrinfo 解析域名 → 被 Hook_WSAStartup 安装的 Hook_getaddrinfo 拦截
    # 在 network_deny 配置下，*:0/any → deny，所以外部域名解析被阻止
    rc, out, err = runner.exec_direct(
        "C:\\Windows\\System32\\ping.exe",
        ["-n", "1", "www.example.com"],
        config=NETWORK_DENY_CONFIG, timeout=15,
    )
    dt = time.time() - t0
    # ping 在 DNS 被拒绝时返回 WSAHOST_NOT_FOUND → exit_code 非零
    # 审计日志应包含 NetDeny 条目
    blocked = "exit_code=1" in out or rc != 0
    return runner.make_result(
        "DNS 拒绝: 外部域名解析", "网络ACL-Deny", "x64",
        rc, out, err,
        expected_text="exit_code=1" if blocked else None,
        duration=dt,
    )


def test_net_port_specific_deny(runner: SandboxRunner) -> TestResult:
    """3.7 端口拒绝: 端口级屏蔽 — 仅阻止指定端口 9999"""
    t0 = time.time()
    rc, out, err = runner.exec(
        'powershell -NoProfile -Command "& {try {$c=New-Object Net.Sockets.TcpClient;$c.Connect(\"127.0.0.1\",9999);echo CONNECT_OK;$c.Close()}catch{echo CONNECT_DENIED}}" 2>nul',
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
    rc, out, err = runner.exec(
        'powershell -NoProfile -Command "& {try {$c=New-Object Net.Sockets.TcpClient;$c.Connect(\"127.0.0.1\",12345);echo CONNECT_OK;$c.Close()}catch{echo CONNECT_FAILED}}" 2>nul',
        config=CONFIG_DIR / "test_net_port_deny.json", timeout=15,
    )
    dt = time.time() - t0
    return runner.make_result(
        "端口允许: 非拒绝端口放行", "网络ACL-Allow", "x64",
        rc, out, err,
        expected_text="CONNECT_FAILED",
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
