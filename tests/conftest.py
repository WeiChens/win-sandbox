#!/usr/bin/env python3
"""
pytest 共享配置
===============
提供 SandboxRunner fixture，供所有测试模块使用。
"""

import sys
from pathlib import Path

# 确保 tests 目录在 path 中
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from base import SandboxRunner


@pytest.fixture(scope="session")
def runner() -> SandboxRunner:
    """创建一个 SandboxRunner 实例（会话级别，只创建一次）"""
    return SandboxRunner(verbose=True)
