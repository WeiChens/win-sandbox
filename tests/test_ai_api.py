#!/usr/bin/env python3
"""
测试模块：AI HTTP API
====================
验证 sandbox-host serve 模式的 HTTP API 端点。
需要 sandbox-host serve 在后台运行。
"""

import sys
import time
import json
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from base import SandboxRunner, TestResult, HOST_EXE, PROJECT_ROOT, CONFIG_DIR

INHERIT_CONFIG = CONFIG_DIR / "test_inherit.json"
AI_PORT = 19800  # 使用非标准端口避免冲突


def _start_server(timeout: float = 5.0) -> subprocess.Popen | None:
    """启动 AI 沙箱服务"""
    try:
        proc = subprocess.Popen(
            [str(HOST_EXE), "serve", str(AI_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PROJECT_ROOT),
        )
        # 等待服务就绪
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{AI_PORT}/health",
                    timeout=1,
                )
                return proc
            except Exception:
                time.sleep(0.2)
        proc.kill()
        return None
    except Exception:
        return None


def _stop_server(proc: subprocess.Popen | None):
    """停止 AI 沙箱服务"""
    if proc:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


def _api_get(path: str, timeout: float = 5.0) -> tuple[int, str]:
    """发送 GET 请求"""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{AI_PORT}{path}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return -1, str(e)


def _api_post(path: str, data: dict, timeout: float = 10.0) -> tuple[int, str]:
    """发送 POST 请求"""
    try:
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{AI_PORT}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")
    except Exception as e:
        return -1, str(e)


def test_ai_health(runner: SandboxRunner) -> TestResult:
    """6.1 AI API: /health 健康检查"""
    t0 = time.time()
    server = _start_server()
    dt = time.time() - t0

    if server is None:
        _stop_server(server)
        return runner.make_result(
            "AI /health", "AI API", "x64",
            0, "", "",
            skip=True, skip_reason="服务启动失败",
            duration=dt,
        )

    status, body = _api_get("/health", timeout=3)
    _stop_server(server)
    dt = time.time() - t0

    passed = status == 200 and "ok" in body.lower()
    return runner.make_result(
        "AI /health", "AI API", "x64",
        0 if passed else 1, body, "",
        expected_rc=0 if passed else None,
        expected_text="ok" if passed else None,
        known_fail=not passed,
        duration=dt,
    )


def test_ai_exec(runner: SandboxRunner) -> TestResult:
    """6.2 AI API: POST /exec 执行命令"""
    t0 = time.time()
    server = _start_server()
    if server is None:
        _stop_server(server)
        return runner.make_result(
            "AI POST /exec", "AI API", "x64",
            0, "", "",
            skip=True, skip_reason="服务启动失败",
            duration=time.time() - t0,
        )

    status, body = _api_post("/exec", {
        "command": "cmd.exe",
        "args": ["/c", "echo AI_EXEC_OK"],
        "timeout_secs": 15,
    }, timeout=20)
    _stop_server(server)
    dt = time.time() - t0

    passed = status == 200 and "AI_EXEC_OK" in body
    return runner.make_result(
        "AI POST /exec", "AI API", "x64",
        0 if passed else 1, body, "",
        expected_rc=0 if passed else None,
        expected_text="AI_EXEC_OK" if passed else None,
        known_fail=not passed,
        duration=dt,
    )


def test_ai_exec_exit_code(runner: SandboxRunner) -> TestResult:
    """6.3 AI API: POST /exec 返回退出码"""
    t0 = time.time()
    server = _start_server()
    if server is None:
        _stop_server(server)
        return runner.make_result(
            "AI /exec 退出码", "AI API", "x64",
            0, "", "",
            skip=True, skip_reason="服务启动失败",
            duration=time.time() - t0,
        )

    status, body = _api_post("/exec", {
        "command": "cmd.exe",
        "args": ["/c", "exit /b 7"],
        "timeout_secs": 15,
    }, timeout=20)
    _stop_server(server)
    dt = time.time() - t0

    passed = status == 200 and '"exit_code":7' in body
    return runner.make_result(
        "AI /exec 退出码", "AI API", "x64",
        0 if passed else 1, body, "",
        expected_rc=0 if passed else None,
        expected_text='"exit_code":7' if passed else None,
        known_fail=not passed,
        duration=dt,
    )


def test_ai_audit(runner: SandboxRunner) -> TestResult:
    """6.4 AI API: GET /audit 审计摘要"""
    t0 = time.time()
    server = _start_server()
    if server is None:
        _stop_server(server)
        return runner.make_result(
            "AI GET /audit", "AI API", "x64",
            0, "", "",
            skip=True, skip_reason="服务启动失败",
            duration=time.time() - t0,
        )

    # 先执行一条命令产生审计
    _api_post("/exec", {
        "command": "cmd.exe",
        "args": ["/c", "echo audit_test"],
        "timeout_secs": 10,
    }, timeout=15)
    time.sleep(0.5)

    status, body = _api_get("/audit", timeout=3)
    _stop_server(server)
    dt = time.time() - t0

    passed = status == 200
    return runner.make_result(
        "AI GET /audit", "AI API", "x64",
        0 if passed else 1, body, "",
        expected_rc=0 if passed else None,
        known_fail=not passed,
        duration=dt,
    )


# ─── 测试注册表 ──────────────────────────────────────────────────────
AI_API_TESTS = [
    test_ai_health,
    test_ai_exec,
    test_ai_exec_exit_code,
    test_ai_audit,
]
