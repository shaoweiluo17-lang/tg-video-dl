#!/usr/bin/env python3
"""校验版本号三处一致（manifest / __init__.py / pyproject.toml）。

背景：本项目版本号分散在三处，曾出现「包是新的、面板显示旧版本」的错位
（改了 manifest 漏改 __init__.py 的 __version__，而面板读的是后者）。
此脚本在构建前校验，把该错位挡在构建阶段。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_version(path: Path, pattern: str) -> str:
    m = re.search(pattern, path.read_text(encoding="utf-8"), re.M)
    return m.group(1).strip() if m else ""


def main() -> int:
    found = {
        "deploy/fpk/manifest": read_version(ROOT / "deploy/fpk/manifest", r"^version\s*=\s*(.+)$"),
        "server/__init__.py": read_version(
            ROOT / "deploy/fpk/app/server/__init__.py", r'__version__\s*=\s*"([^"]+)"'),
        "pyproject.toml": read_version(ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
    }
    for name, v in found.items():
        print(f"  {name:26} {v or '(未找到)'}")
    values = set(found.values())
    if "" in values:
        print("✗ 有位置未解析出版本号", file=sys.stderr)
        return 1
    if len(values) != 1:
        print(f"✗ 版本号不一致：{found}", file=sys.stderr)
        print("  请三处同改（manifest / __init__.py / pyproject.toml）", file=sys.stderr)
        return 1
    print(f"✓ 版本号一致：{values.pop()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
