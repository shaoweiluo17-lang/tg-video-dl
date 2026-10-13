#!/usr/bin/env python3
"""tg-video-dl · 密钥 / 隐私扫描（纯标准库，本地与 CI 共用）。

三层，默认扫前两层：

  1. 待发布文件  git 跟踪的文件 + 未忽略的新文件（二进制自动跳过）
  2. 当前分支历史 git log -p HEAD 的每一行（含已被删掉的旧内容——历史才是漏点重灾区）
  3. .fpk 产物    --artifact <path>：只扫包内**文本成员**（跳过 xray / geoip / geosite / PNG 等二进制）

用法::

    python3 scripts/secret_scan.py                    # 文件 + 历史
    python3 scripts/secret_scan.py --no-history       # 只扫文件
    python3 scripts/secret_scan.py --artifact deploy/fpk/tg-video-dl-0.4.5.fpk

退出码：0 = 干净，1 = 有命中，2 = 用法 / git 环境错误。

⚠️ 命中内容一律**打码**后输出：公开仓库的 CI 日志是公开的，扫描器本身不能泄露它要找的东西。
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (名称, 正则, 允许的正则) —— 命中「允许的正则」的同一行视为已知假阳性，忽略。
# 脱敏口径与本项目 changes/CHANGES-项目上传GitHub与Gitea冲突.md 保持一致。
RULES: list[tuple[str, str, str | None]] = [
    # ---------- 通用凭据形态（任何项目都该拦） ----------
    ("GitHub token", r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", None),
    ("模型/服务 API key", r"sk-[A-Za-z0-9]{20,}", None),
    ("AWS access key", r"AKIA[0-9A-Z]{16}", None),
    ("Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}", None),
    ("私钥文件内容", r"BEGIN [A-Z ]*PRIVATE KEY", None),
    ("OAuth2 凭据", r"oauth2:[A-Za-z0-9._-]{20,}", None),
    ("Telegram api_hash 赋值", r"api_hash\"?\s*[:=]\s*\"?[0-9a-fA-F]{32}", None),
    ("Telegram StringSession", r"StringSession\(\"[A-Za-z0-9+/=]{40,}", None),
    # ---------- 本项目脱敏口径 ----------
    ("真实手机号", r"(?<![0-9])(?:\+?86)?1[3-9][0-9]{9}(?![0-9])", r"13800138000"),
    ("美服真实 IP", r"186\.241\.104\.25", None),
    ("内网/Gitea IP", r"192\.168\.\d{1,3}\.\d{1,3}", None),
    ("自有节点域名", r"bswy\.cc", None),
    ("真机盘名", r"4_HHD_4T", None),
    # 只盯**私有**路径：`/vol2/1000/影视` 这类是 fnOS 通用示例（使用说明里就有），不算隐私
    ("NAS 私有路径", r"/vol2/@appdata|/vol2/1000/备份|/vol2/@appcenter", None),
    ("2040 公开 api_hash 常量", r"b18441a1ff607e10a989891a5462e627", None),
    (
        "代理节点分享链接（非示例域名）",
        r"(?:vless|vmess|trojan)://[^\s\"']*@(?!ex\.com|example|host|t\.com|1\.2\.3\.4|node\.example|h:443)"
        r"[A-Za-z0-9.-]+",
        None,
    ),
]

# tracked 文件里出现这些文件名即异常（构建脚本另有入口校验，这里是兜底）
FILENAME_RULES = [
    (r"\.secrets\.ya?ml$", "机密配置 .secrets.yaml"),
    (r"(^|/)config\.yaml$", "运行期配置 config.yaml"),
    (r"\.session(-journal)?$", "Telegram session 文件"),
    (r"(^|/)\.env$", ".env"),
]

SKIP_DIFF_PREFIXES = (
    "diff --git", "index ", "--- ", "+++ ", "@@", "new file", "deleted file",
    "similarity index", "rename ", "Binary files", "old mode", "new mode",
)

# 扫描器自身含规则字面量（例如 "4_HHD_4T"、"b18441a1…"），它自己必然命中自己 —— 跳过本文件。
# 代价：放进这个文件的真实密钥扫不到；规则字面量只应该出现在这里，这是唯一豁免。
SELF = "scripts/secret_scan.py"

# 产物里这些成员是二进制/数据（xray、geoip/geosite、图标），不按文本扫，否则会随机误报
ARTIFACT_BINARY_PREFIXES = ("bin/",)
ARTIFACT_BINARY_SUFFIXES = (".dat", ".png", ".jpg", ".jpeg", ".zip", ".gz", ".exe", ".so", ".bin")


def _redact(line: str, pattern: str) -> str:
    """把命中的片段打码后再输出（公开日志里不能出现原文）。"""

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        if len(s) <= 4:
            return "*" * len(s)
        keep_head = 3 if len(s) > 8 else 1
        return s[:keep_head] + "*" * max(1, len(s) - keep_head - 2) + s[-2:]

    out = re.sub(pattern, repl, line)
    out = out.strip()
    return out[:180] + ("…" if len(out) > 180 else "")


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _matching_rules(line: str, rules: list[tuple[str, str, str | None]]) -> list[str]:
    hits = []
    for name, pattern, allow in rules:
        if not re.search(pattern, line):
            continue
        if allow and re.search(allow, line):
            continue
        hits.append(name)
    return hits


def _files_to_scan() -> list[str]:
    def _ls(*args: str) -> list[str]:
        # core.quotepath=false：否则中文路径会被 git 加引号转义，读文件时找不到
        out = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        return [p for p in out.split("\n") if p and p != SELF]

    return sorted(set(_ls("ls-files") + _ls("ls-files", "--others", "--exclude-standard")))


def scan_files(rules) -> list[str]:
    problems: list[str] = []
    by_name = {r[0]: r[1] for r in rules}
    files = _files_to_scan()
    scanned = 0
    for rel in files:
        path = ROOT / rel
        for pattern, label in FILENAME_RULES:
            if re.search(pattern, rel):
                problems.append(f"[文件] {rel} → 不该入库的文件名（{label}）")
        try:
            data = path.read_bytes()
        except OSError as exc:
            problems.append(f"[文件] {rel} 读取失败：{exc}")
            continue
        if _is_binary(data):
            continue
        scanned += 1
        text = data.decode("utf-8", "replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for name in _matching_rules(line, rules):
                problems.append(f"[文件] {rel}:{lineno} → {name}：{_redact(line, by_name[name])}")
    print(f"  待发布文件 {len(files)} 个（其中文本 {scanned} 个）")
    return problems


def scan_history(rules) -> list[str]:
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=false", "log", "-p", "--no-color",
         "--pretty=format:@@@%h %s", "HEAD"],
        cwd=ROOT, capture_output=True, text=True, errors="replace",
    )
    if proc.returncode != 0:
        print("  ⚠️ git log 失败，跳过历史扫描", file=sys.stderr)
        return []
    by_name = {r[0]: r[1] for r in rules}
    problems: list[str] = []
    commit = "?"
    cur_file = "?"
    seen: set[tuple[str, str, str]] = set()
    for line in proc.stdout.splitlines():
        if line.startswith("@@@"):
            commit = line[3:]
            continue
        if line.startswith("+++ b/"):
            cur_file = line[6:]
            continue
        if line.startswith("--- a/"):
            cur_file = line[6:]  # 删除的文件没有 +++ b/，靠这一行定位
            continue
        if not line or line.startswith(SKIP_DIFF_PREFIXES):
            continue
        if cur_file == SELF:
            continue
        body = line[1:] if line[0] in "+- " else line
        for name in _matching_rules(body, rules):
            key = (commit.split()[0], cur_file, name)
            if key in seen:  # 同一提交同一文件同一规则只报一次
                continue
            seen.add(key)
            problems.append(f"[历史] {commit} {cur_file} → {name}：{_redact(body, by_name[name])}")
    commits = proc.stdout.count("@@@") or 1
    print(f"  历史提交 {commits} 个（已含被删除的旧内容）")
    return problems


def _scan_member_text(name: str, data: bytes, rules, prefix: str) -> list[str]:
    if _is_binary(data):
        return []
    problems = []
    text = data.decode("utf-8", "replace")
    by_name = {r[0]: r[1] for r in rules}
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule in _matching_rules(line, rules):
            problems.append(f"[产物] {prefix}{name}:{lineno} → {rule}：{_redact(line, by_name[rule])}")
    return problems


def scan_artifact(paths: list[str], rules) -> list[str]:
    problems: list[str] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            problems.append(f"[产物] 找不到文件：{path}")
            continue
        if not tarfile.is_tarfile(path):
            problems.append(f"[产物] {path} 不是 tar 归档，跳过")
            continue
        with tarfile.open(path, "r:gz") as outer:
            for member in outer.getmembers():
                if not member.isfile():
                    continue
                if member.name.startswith(ARTIFACT_BINARY_PREFIXES) or member.name.endswith(
                    ARTIFACT_BINARY_SUFFIXES
                ):
                    continue
                handle = outer.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                if member.name == "app.tgz":
                    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as inner:
                        for im in inner.getmembers():
                            if not im.isfile():
                                continue
                            if im.name.startswith(ARTIFACT_BINARY_PREFIXES) or im.name.endswith(
                                ARTIFACT_BINARY_SUFFIXES
                            ):
                                continue
                            ih = inner.extractfile(im)
                            if ih is not None:
                                problems += _scan_member_text(
                                    im.name, ih.read(), rules, f"{path.name}!app.tgz!/"
                                )
                else:
                    problems += _scan_member_text(member.name, data, rules, f"{path.name}!/")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description="密钥/隐私扫描")
    ap.add_argument("--no-history", action="store_true", help="跳过 git 历史扫描")
    ap.add_argument("--artifact", nargs="*", default=[], help="额外扫描 .fpk 产物（只扫文本成员）")
    args = ap.parse_args()

    print(f"密钥扫描：{len(RULES)} 条规则 · 根目录 {ROOT}")
    problems: list[str] = []
    problems += scan_files(RULES)
    if not args.no_history:
        problems += scan_history(RULES)
    if args.artifact:
        problems += scan_artifact(args.artifact, RULES)

    if problems:
        print(f"\n✗ 命中 {len(problems)} 处（内容已打码）：")
        for p in problems:
            print(f"  - {p}")
        print("\n处理：确认后替换为占位符（见 changes/ 里的脱敏口径），或把确认无害的内容加入本脚本的 allow 正则。")
        return 1

    print("✓ 未发现密钥 / 隐私标识")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
