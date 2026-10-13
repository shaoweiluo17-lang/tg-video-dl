"""落盘路径：模板渲染 + 安全校验。

安全要点（FEASIBILITY §5.2）：

- 文件名清洗：剔除 `/` `\\` `..`、控制字符、Windows 保留名、结尾空格/点；
- **realpath 白名单校验**：渲染结果必须落在允许的根目录内（防 `../../etc/passwd`）；
- 重名不覆盖：按 `name (1).ext` 递增，除非显式要求覆盖；
- `.part` 中转 + 完成后原子改名：避免媒体库扫到半截文件。
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

# 控制字符（含 \x00-\x1f 与 \x7f）
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Windows 保留设备名（NAS 虽为 Linux，但下载目录可能被 SMB/媒体库在 Windows 侧读取）
_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_MAX_NAME_LEN = 180  # 留出扩展名与去重后缀空间，避开多数文件系统的 255 字节上限


class PathSafetyError(ValueError):
    """路径越界或非法。"""


def sanitize_filename(name: str, fallback: str = "unnamed") -> str:
    """把任意字符串清洗成安全的单层文件名（不含目录分隔符）。

    >>> sanitize_filename("../../etc/passwd")
    'etc_passwd'
    >>> sanitize_filename("a/b\\\\c.mp4")
    'a_b_c.mp4'
    """
    if not name:
        return fallback

    # Unicode 规范化：避免用不同码位伪装的同名/控制字符
    name = unicodedata.normalize("NFKC", str(name))
    name = _CTRL_RE.sub("", name)

    # 目录分隔符与穿越片段：一律替换为下划线（而不是删除，保留可读性）
    name = name.replace("/", "_").replace("\\", "_")
    name = name.replace("..", "_")

    # 前导点（隐藏文件）与首尾空白/点
    name = name.strip().strip(".")

    # 全部由标点/下划线构成的退化结果（如 "..." → "_"）视为无有效名称
    if not name.strip("_.- "):
        return fallback

    # 保留设备名
    stem = name.split(".")[0].upper()
    if stem in _RESERVED:
        name = f"_{name}"

    # 长度收敛（按字节粗算，UTF-8 中文占 3 字节）
    while len(name.encode("utf-8", "ignore")) > _MAX_NAME_LEN and len(name) > 1:
        name = name[: len(name) - 1]

    name = name.strip()
    return name or fallback


def split_name(filename: str) -> tuple[str, str]:
    """拆成 (stem, ext)，ext 含点（无扩展名时为空串）。"""
    p = Path(filename)
    return p.stem, p.suffix


def unique_path(path: Path, overwrite: bool = False) -> Path:
    """重名时追加 ` (n)`，不覆盖已有文件（媒体库场景下覆盖是危险的）。"""
    if overwrite or not path.exists():
        return path
    stem, ext = split_name(path.name)
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem} ({i}){ext}")
        if not candidate.exists():
            return candidate
    raise PathSafetyError(f"无法为 {path.name} 找到可用文件名（重名过多）")


TEMPLATE_FIELDS = ("date", "chat", "filename", "ext", "id")


def render_template(
    template: str,
    *,
    filename: str,
    date: str,
    chat: str = "",
    file_id: str | int = "",
) -> Path:
    """渲染落盘相对路径模板。

    支持字段：`{date}` `{chat}` `{filename}` `{ext}` `{id}`。
    模板里出现的任何目录层级都会被逐段清洗，杜绝穿越。
    """
    stem, ext = split_name(filename)
    mapping = {
        "date": date,
        "chat": chat or "saved",
        "filename": stem,
        "ext": ext.lstrip("."),
        "id": str(file_id or ""),
    }
    try:
        raw = template.format(**mapping)
    except KeyError as exc:
        raise PathSafetyError(
            f"路径模板含未知字段 {exc}；可用字段：{', '.join(TEMPLATE_FIELDS)}"
        ) from exc

    # 逐段清洗；`..` 段直接丢弃
    parts: list[str] = []
    for seg in raw.replace("\\", "/").split("/"):
        seg = seg.strip()
        if not seg or seg in (".", ".."):
            continue
        cleaned = sanitize_filename(seg, fallback="")
        if cleaned:
            parts.append(cleaned)
    if not parts:
        parts = [sanitize_filename(filename, "unnamed")]

    # 保留扩展名（段清洗会保留点，但若最后一段丢了扩展名则补回）
    if ext and not parts[-1].endswith(ext):
        parts[-1] = f"{parts[-1]}{ext}"
    return Path(Path(*parts))


@dataclass
class SafeRoot:
    """受信任的落盘根目录。所有写入路径必须经 `resolve_within` 校验。"""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve_within(self, relative: Path | str) -> Path:
        """把相对路径解析到 root 内，越界即抛 PathSafetyError。

        用 realpath（resolve）而非纯字符串前缀比较，才能挡住符号链接逃逸。
        """
        candidate = (self.root / Path(relative)).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise PathSafetyError(
                f"路径越界：{candidate} 不在允许的根目录 {self.root} 内"
            ) from exc
        return candidate


def disk_free_gb(path: Path) -> float:
    """可用磁盘空间（GB）。用于下载前的水位检查。"""
    import shutil

    target = Path(path)
    while not target.exists() and target.parent != target:
        target = target.parent
    try:
        return shutil.disk_usage(target).free / (1024 ** 3)
    except OSError:
        return float("inf")


__all__ = [
    "PathSafetyError",
    "SafeRoot",
    "disk_free_gb",
    "render_template",
    "sanitize_filename",
    "split_name",
    "unique_path",
    "TEMPLATE_FIELDS",
]
