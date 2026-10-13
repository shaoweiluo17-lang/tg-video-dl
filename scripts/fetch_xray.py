#!/usr/bin/env python3
"""获取 Xray-core 二进制并放到 <app>/bin（幂等）。

复用 fn-crypto-trader `scripts/fetch_xray.py`（已验证的 fpk 打包路径）。
飞影用 Docker 的 `COPY --from=teddysun/xray` 方式在 fpk 下不适用，故必须构建前拉取。

- 本机已存在 bin/xray(.exe) 则跳过（除非 --force）。
- 下载源：优先 GitHub 加速镜像（ghfast.top / ghproxy.net），直连 GitHub 兜底。
  本机通常需代理才能直连 GitHub，故默认走镜像。
- 供应链校验：比对官方发布清单 SHA-256（取不到清单时告警但不阻断）。
- 解压后只取可执行文件与 geoip/geosite 数据到 bin/。

用法: python scripts/fetch_xray.py [--force] [--bin-dir PATH]
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import sys
import tempfile
import urllib.request
import zipfile

_ASSETS = {
    "windows": "Xray-windows-64.zip",
    "linux": "Xray-linux-64.zip",
    "macos": "Xray-macos-arm64-v8a.zip",
}
_MIRRORS = ["https://ghfast.top/", "https://ghproxy.net/", ""]
_RELEASE = "https://github.com/XTLS/Xray-core/releases/latest/download/"


def _basedir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "deploy", "fpk", "app", "bin"))


def _bin_name() -> str:
    return "xray.exe" if os.name == "nt" else "xray"


def _oskey() -> str:
    sysname = platform.system().lower()
    if sysname.startswith("win"):
        return "windows"
    if sysname.startswith("darwin"):
        return "macos"
    return "linux"


def _download(url: str, dest: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "tgvdl-fetch-xray"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _sha256(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "tgvdl-fetch-xray"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _want_hash(prefix: str, asset: str) -> str | None:
    """尝试取官方 sha256 清单；返回 asset 对应期望 hash，取不到返回 None。"""
    for fname in (f"{asset}.sha256", "sha256sum.txt"):
        try:
            data = _fetch_bytes(f"{prefix}{_RELEASE}{fname}").decode("latin1", "replace")
        except Exception:
            continue
        for line in data.splitlines():
            if asset in line:
                parts = line.split()
                return parts[0] if parts else None
        parts = data.split()
        if parts:
            return parts[0]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="fetch xray-core binary")
    ap.add_argument("--force", action="store_true", help="已存在也重新下载")
    ap.add_argument("--bin-dir", default=None, help="目标目录（默认 <repo>/deploy/fpk/app/bin）")
    args = ap.parse_args()

    bin_dir = os.path.abspath(args.bin_dir) if args.bin_dir else _basedir()
    bin_name = _bin_name()
    target = os.path.join(bin_dir, bin_name)
    if not args.force and os.path.isfile(target):
        print(f"[xray] 已存在: {target}，跳过（--force 重下）")
        return 0

    oskey = _oskey()
    asset = _ASSETS[oskey]
    os.makedirs(bin_dir, exist_ok=True)

    last_err: Exception | None = None
    for prefix in _MIRRORS:
        url = f"{prefix}{_RELEASE}{asset}"
        try:
            with tempfile.TemporaryDirectory(prefix="tgvdl_xray_") as td:
                zpath = os.path.join(td, asset)
                print(f"[xray] 下载 {url}")
                _download(url, zpath)
                # 供应链校验：比对官方发布清单的 SHA-256
                got = _sha256(zpath)
                want = _want_hash(prefix, asset)
                if want:
                    if got.lower() != want.lower():
                        raise RuntimeError(
                            f"SHA-256 不匹配: got={got[:16]}… want={want[:16]}… 拒绝使用该二进制")
                    print(f"[xray] SHA-256 校验通过: {got[:16]}…")
                else:
                    print("[xray] 警告: 无法获取官方校验清单，未经过哈希校验（供应链风险仍存在）")
                with zipfile.ZipFile(zpath) as z:
                    names = z.namelist()
                    pick = "xray.exe" if oskey == "windows" else "xray"
                    if pick not in names:
                        raise RuntimeError(f"zip 内未找到 {pick}: {names[:8]}")
                    z.extract(pick, td)
                    # geo 数据缺则补
                    for geo in ("geoip.dat", "geosite.dat"):
                        if geo in names and not os.path.isfile(os.path.join(bin_dir, geo)):
                            z.extract(geo, bin_dir)
                shutil.move(os.path.join(td, pick), target)
            os.chmod(target, 0o755)
            print(f"[xray] 已就位: {target}")
            return 0
        except Exception as exc:  # 逐个镜像尝试
            last_err = exc
            print(f"[xray] 源失败 {prefix or '(直连)'}: {exc}")

    print(f"[xray] 全部下载源失败: {last_err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
