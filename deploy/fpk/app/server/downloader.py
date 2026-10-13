"""下载引擎：媒体识别 + 流式落盘 + 原子改名。

M1 实装：识别 → 去重入队 → 流式下载 → 原子改名 → 状态落库。

设计（IMPLEMENTATION-PLAN §4.3）：
- `.part` 临时文件流式写盘 → 完成后**原子改名**，避免媒体库扫到半截文件；
- 文件名清洗 + realpath 白名单校验（见 paths.py）；
- 下载前磁盘水位检查。
"""
from __future__ import annotations

import asyncio
import logging
import os
import pickle
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .aio_guard import abandon_task, run_bounded
from .config import DEFAULT_DOC_EXTS, Config, accessible_paths, share_paths
from .paths import (
    PathSafetyError,
    SafeRoot,
    disk_free_gb,
    render_template,
    unique_path,
)

log = logging.getLogger("tgvdl.download")

# 常见视频容器后缀（document 型媒体靠它判定）
VIDEO_EXTS = {
    ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".m4v", ".ts", ".mpg", ".mpeg", ".rmvb", ".3gp", ".vob",
}
# 明确不下载的（字幕/封面/元数据等**附属文件**）。
#
# ⚠️ 与「文档白名单」的分工（真机需求，勿混）：
# - 本清单是**硬拒绝**：命中的后缀永远不下（即使有人把它写进 doc_exts）。
#   字幕/封面/缩略图跟着视频一起来，下了只会污染媒体库。
# - `.txt` **已从本清单移除**：TXT 电子书是「文档下载」的一等公民，
#   改由 `download.doc_exts` 白名单判定（见 identify_media）——
#   既把 TXT 放进来，又不必为了它把字幕/封面一起放进来。
IGNORED_EXTS = {".srt", ".ass", ".vtt", ".jpg", ".jpeg", ".png", ".webp", ".nfo"}

# 文档（电子书等）默认后缀白名单；真正的默认值由 config.default_config 提供，
# 这里是同一份常量的引用（config 是唯一来源，测试校验两者一致）。
DEFAULT_DOC_PATH_TEMPLATE = "{filename}"


def parse_doc_exts(raw: Any) -> set[str]:
    """解析文档后缀白名单 → 规范化集合（小写、带前导点）。

    - `None`（调用方未指定）→ 默认白名单 `DEFAULT_DOC_EXTS`；
    - 空串/纯分隔符 → 只下 `.txt`（需求约定：留空＝只下 .txt）；
    - 兼容逗号/分号/空白分隔，写 ``txt`` 或 ``.txt`` 都认。
    """
    if raw is None:
        items: list[str] = list(DEFAULT_DOC_EXTS)
    elif isinstance(raw, (list, tuple, set)):
        items = [str(x) for x in raw]
    else:
        items = re.split(r"[,;\s]+", str(raw))
    out: set[str] = set()
    for item in items:
        item = item.strip().lower()
        if not item:
            continue
        out.add(item if item.startswith(".") else f".{item}")
    return out or {".txt"}


@dataclass
class MediaInfo:
    """从一条 TG 消息里识别出的可下载媒体。

    `kind` 只有两个值，**决定落盘目录与模板**（见 plan_media_target）：
    - ``video``    —— message.video，以及「视频类」document（mime=video/* 或视频容器后缀）；
    - ``document`` —— 文档类（电子书：TXT/EPUB/PDF…），走 download.doc_dir。
    """

    kind: str  # video / document
    filename: str
    size: int
    mime: str = ""
    file_id: str = ""
    message_id: int = 0
    chat: str = "saved"

    @property
    def size_mb(self) -> float:
        return round(self.size / (1024 * 1024), 2)

    @property
    def ext(self) -> str:
        """小写扩展名（含点）；无扩展名时为空串。"""
        name = self.filename or ""
        return ("." + name.rsplit(".", 1)[1].lower()) if "." in name else ""

    @property
    def is_doc(self) -> bool:
        return self.kind == "document"

    @property
    def kind_cn(self) -> str:
        """给日志/面板用的中文类型名。"""
        return "文档" if self.is_doc else "视频"


# 不可下载的 media 类型（按类名判断，避免硬依赖 telethon 类型）
_SKIP_MEDIA_TYPES = {
    "MessageMediaWebPage",   # 链接预览 —— 最容易误判：它也会"借" message.video
    "MessageMediaPhoto",     # 图片
    "MessageMediaPoll",      # 投票
    "MessageMediaGeo",       # 位置
    "MessageMediaContact",   # 联系人
    "MessageMediaUnsupported",
    "MessageMediaEmpty",
    "MessageMediaGame",
    "MessageMediaInvoice",
}


def _is_downloadable(message: Any) -> bool:
    """判断 message.media 是否真的是可下载文件。

    ⚠️⚠️ 真机踩坑（务必保留）：
    Telegram 对**含链接的消息**，会同时把 `message.video` 也填上（用于渲染
    网页预览卡片）。若只检查 `message.video` 是否存在，就会把「一条带链接的
    文本消息」误判为视频 → 入队 → 下载时报
        TypeError: Cannot cast MessageMediaWebPage to any kind of InputFileLocation
    且会白白重试 3 次。
    故必须先看 media 的实际类型，只接受 Document（真文件）。
    """
    media = getattr(message, "media", None)
    if media is None:
        return False
    name = type(media).__name__
    if name in _SKIP_MEDIA_TYPES:
        return False
    # 只认 Document（video 消息的 media 也是 MessageMediaDocument）
    return name == "MessageMediaDocument"


def identify_media(message: Any, *, doc_exts: Any = None) -> MediaInfo | None:
    """识别消息里的可下载媒体；不可下载返回 None（并让上层记日志）。

    处理三类（IMPLEMENTATION-PLAN §4.2 + 「文档下载」一节）：
    1. ``message.video``                    → kind=video；
    2. 「视频类」document（mime/后缀判定）   → kind=video；
    3. 后缀命中**文档白名单**的 document     → kind=document（电子书等）。

    判定顺序（顺序本身就是安全边界）：附属文件硬拒绝 → 视频 → 文档白名单。
    `doc_exts` 传配置里的白名单原文（留空＝只下 .txt）；不传用默认白名单。

    前置条件：必须是真正可下载的文件（见 _is_downloadable）。
    """
    if message is None:
        return None

    # 先排除「不可下载」的 media（网页预览/图片/投票等）
    if not _is_downloadable(message):
        media = getattr(message, "media", None)
        if media is not None:
            log.debug("跳过非文件媒体（%s）：msg=%s",
                      type(media).__name__, getattr(message, "id", "?"))
        return None

    chat = "saved"
    try:
        if getattr(message, "chat", None) is not None and getattr(message.chat, "username", None):
            chat = str(message.chat.username)
    except Exception:
        pass

    msg_id = int(getattr(message, "id", 0) or 0)

    video = getattr(message, "video", None)
    if video is not None:
        name = getattr(video, "attributes", None)
        filename = _attr_filename(name) or f"video_{msg_id}.mp4"
        return MediaInfo(
            kind="video",
            filename=filename,
            size=int(getattr(video, "size", 0) or 0),
            mime=str(getattr(video, "mime_type", "") or "video/mp4"),
            file_id=str(getattr(video, "id", "") or ""),
            message_id=msg_id,
            chat=chat,
        )

    doc = getattr(message, "document", None)
    if doc is not None:
        mime = str(getattr(doc, "mime_type", "") or "")
        filename = _attr_filename(getattr(doc, "attributes", None)) or f"file_{msg_id}"
        ext = ("." + filename.rsplit(".", 1)[1].lower()) if "." in filename else ""

        # ① 附属文件（字幕/封面/元数据）硬拒绝：永远不下，不受白名单影响
        if ext in IGNORED_EXTS:
            log.info("忽略附属文件（%s）：%s", ext, filename)
            return None

        is_video = mime.startswith("video/") or ext in VIDEO_EXTS
        if not is_video:
            # ② 文档：只认后缀白名单。白名单外仍然忽略，但日志要说清"为什么"，
            #    否则用户会以为"转了却没反应"（真机排障的主要抱怨点）。
            allowed = parse_doc_exts(doc_exts)
            if ext and ext in allowed:
                log.info("识别到文档（%s, %.2f MB）：%s",
                         ext, int(getattr(doc, "size", 0) or 0) / (1024 * 1024), filename)
                return MediaInfo(
                    kind="document",
                    filename=filename,
                    size=int(getattr(doc, "size", 0) or 0),
                    mime=mime,
                    file_id=str(getattr(doc, "id", "") or ""),
                    message_id=msg_id,
                    chat=chat,
                )
            log.info(
                "忽略非白名单文档（mime=%s, ext=%s）：%s（文档白名单：%s）",
                mime or "?", ext or "无扩展名", filename,
                ",".join(sorted(allowed)),
            )
            return None

        return MediaInfo(
            kind="video",
            filename=filename,
            size=int(getattr(doc, "size", 0) or 0),
            mime=mime,
            file_id=str(getattr(doc, "id", "") or ""),
            message_id=msg_id,
            chat=chat,
        )

    return None


def _attr_filename(attributes: Any) -> str:
    """从 telethon 的 attributes 列表里取文件名。"""
    for attr in attributes or []:
        name = getattr(attr, "file_name", None)
        if name:
            return str(name)
    return ""


def plan_target(
    media: MediaInfo,
    *,
    download_dir: str,
    path_template: str,
    overwrite: bool = False,
    today: str | None = None,
) -> Any:
    """规划落盘绝对路径（含安全校验与去重）。抛 PathSafetyError 表示路径非法。"""
    root = SafeRoot(download_dir)
    relative = render_template(
        path_template,
        filename=media.filename,
        date=today or date.today().isoformat(),
        chat=media.chat,
        file_id=media.message_id or media.file_id,
    )
    target = root.resolve_within(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    return unique_path(target, overwrite=overwrite)


# ---------------- 文档/视频的路由与授权闸门 ----------------
#
# 需求（用户原话）：视频继续落 download.dir，TXT 等文档落到"我指定的目录"，
# 且文档目录必须在**系统已授权目录**内 —— 未授权要报明确错误，不能静默失败。


def doc_dir_explicit(cfg: dict[str, Any]) -> str:
    """配置里显式设置的文档目录（未设置时为空串）。"""
    dl = cfg.get("download") or {}
    return str(dl.get("doc_dir") or "").strip()


def resolve_doc_dir(cfg: dict[str, Any]) -> str:
    """文档落盘目录：`download.doc_dir` 留空时**回落到 `download.dir`**。"""
    dl = cfg.get("download") or {}
    return doc_dir_explicit(cfg) or str(dl.get("dir") or "")


def authorized_roots() -> list[str]:
    """系统授权给本应用的目录（env 声明），供落盘前的授权闸门使用。"""
    return accessible_paths() + share_paths()


def ensure_dir_authorized(path: str, *, roots: list[str] | None = None) -> None:
    """文档目录必须落在系统授权目录内，否则抛 PathSafetyError。

    为什么不让它"先试试能不能写"：fnOS 的授权可能只体现在 TrimApiUsers 组
    （env 为空也能写），但这属于**系统授权的事实来源**，不能靠"能写就放行"
    绕过用户授权。故这里做显式判断，未授权即拒绝，并在错误信息里给出
    可操作指引（到 fnOS 设置→应用 添加目录后重启应用）。

    用 resolve() + relative_to 比较，可挡住 `..` 与**符号链接逃逸**。
    """
    raw = (path or "").strip()
    if not raw:
        raise PathSafetyError("文档落盘目录为空")
    try:
        target = Path(raw).expanduser().resolve()
    except OSError as exc:
        raise PathSafetyError(f"文档落盘目录无法解析：{raw}（{exc}）") from exc

    allowed = authorized_roots() if roots is None else list(roots)
    for root in allowed:
        try:
            root_path = Path(root).expanduser().resolve()
        except OSError:
            continue
        if target == root_path:
            return
        try:
            target.relative_to(root_path)
            return
        except ValueError:
            continue

    hint = "、".join(allowed) if allowed else "（无 —— 系统尚未为本应用授权任何目录）"
    raise PathSafetyError(
        f"文档落盘目录未授权：{target} 不在系统授权目录内（当前已授权：{hint}）。"
        "请在 fnOS「设置 → 应用 → TG 视频下载」添加该目录并重启应用，"
        "或把「文档落盘目录」留空（落到视频目录）。"
    )


def target_dir_for(media: MediaInfo, cfg: dict[str, Any], *, roots: list[str] | None = None) -> str:
    """按媒体类型给出落盘根目录（文档 → doc_dir，其余 → download.dir）。"""
    if not media.is_doc:
        return str((cfg.get("download") or {}).get("dir") or "")
    explicit = doc_dir_explicit(cfg)
    # 只有「显式指向新目录」时才做授权闸门：留空（或与视频目录相同）＝沿用视频目录，
    # 与视频链路同样的信任级别，不再重复要求授权。
    if explicit and explicit != str((cfg.get("download") or {}).get("dir") or ""):
        ensure_dir_authorized(explicit, roots=roots)
    return resolve_doc_dir(cfg)


def plan_media_target(
    media: MediaInfo,
    cfg: dict[str, Any],
    *,
    today: str | None = None,
    roots: list[str] | None = None,
) -> Any:
    """按媒体类型规划落盘路径：视频用 `dir/path_template`，文档用 `doc_dir/doc_path_template`。

    两条链路互不影响（需求 2）；文档目录的授权校验失败时抛 PathSafetyError，
    由调用方落库为「已跳过 + 原因」，绝不静默丢消息。
    """
    dl = cfg.get("download") or {}
    beh = cfg.get("behavior") or {}
    overwrite = bool(beh.get("overwrite", False))

    if media.is_doc:
        doc_dir = target_dir_for(media, cfg, roots=roots)
        template = str(dl.get("doc_path_template") or "").strip() or DEFAULT_DOC_PATH_TEMPLATE
    else:
        doc_dir = str(dl.get("dir") or "")
        template = str(dl.get("path_template") or "").strip() or "{date}/{filename}"

    return plan_target(
        media, download_dir=doc_dir, path_template=template,
        overwrite=overwrite, today=today,
    )


def check_disk(download_dir: str, need_bytes: int, min_free_gb: float = 5) -> tuple[bool, str]:
    """下载前水位检查。返回 (是否放行, 说明)。"""
    free = disk_free_gb(__import__("pathlib").Path(download_dir))
    need_gb = need_bytes / (1024 ** 3)
    if free < min_free_gb:
        return False, f"磁盘可用空间不足：{free:.1f}GB < 阈值 {min_free_gb}GB"
    if need_bytes and free < need_gb * 1.1:
        return False, f"磁盘可用空间不足以容纳该文件：需 {need_gb:.2f}GB，可用 {free:.1f}GB"
    return True, f"可用 {free:.1f}GB"


# ---------------- 流式下载（M1 实装） ----------------

# 进度回报节流：每 N 秒写一次库/推一次事件，避免刷爆 SQLite 与前端
PROGRESS_INTERVAL = 1.0


async def stream_to_file(
    client: Any,
    message: Any,
    target: Path,
    *,
    on_progress: Callable[[int, int], None] | None = None,
    chunk_size: int = 1024 * 1024,
    resume: bool = False,
    total: int = 0,
) -> int:
    """流式下载到 `.part` 临时文件，完成后**原子改名**。

    为什么必须走 .part + 原子改名（IMPLEMENTATION-PLAN §4.3）：
    若直接写最终文件名，媒体库/同步工具会在下载中途扫到半截文件并入库。
    原子 rename 保证「最终路径出现时，文件一定是完整的」。

    **断点续传**（`resume=True`）：若存在同名 `.part`，从它已有大小继续
    （telethon 的 `iter_download` 支持 `offset`）。这样大文件中断后不必从头下。
    续传前会校验 `.part` 大小不超过总大小，否则视为损坏文件重下。

    返回**最终文件**的总字节数（续传时含之前已下载的部分）。
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".part")

    offset = 0
    if resume and part.is_file():
        try:
            offset = part.stat().st_size
        except OSError:
            offset = 0
        # 防御：.part 比总大小还大 / 总大小未知 → 不可信，重下
        if total and offset >= total:
            log.warning(".part 大小异常（%d >= %d），丢弃重下", offset, total)
            try:
                part.unlink(missing_ok=True)
            except OSError:
                pass
            offset = 0
        elif offset:
            log.info("断点续传：从 %.2f MB 继续（%s）", offset / (1024 * 1024), target.name)

    written = offset
    try:
        mode = "ab" if offset else "wb"
        with open(part, mode) as fh:
            kwargs: dict[str, Any] = {"chunk_size": chunk_size}
            if offset:
                kwargs["offset"] = offset

            # ⚠️ 无进展看门狗（真机踩坑）：
            # 下载中途网络静默中断时，telethon 的 iter_download 会**永久挂起**
            # 而不抛任何异常 —— 任务卡在 running 永不结束，面板进度停住不动，
            # 用户以为"什么都没发生"（真机实测就这样卡住了）。
            #
            # 实现要点：必须在 **asyncio 层**打断，而不是靠后台线程设置标志位 ——
            # 因为挂起的是 await，线程设标志它也不会醒。故用 wait_for 给每次
            # __anext__ 套一个超时，超时即判定停滞。
            # ⚠️⚠️ 关键实现说明（真机两次踩坑，务必读完再改）
            #
            # 目标：下载中途网络静默中断时，telethon 的 iter_download 会
            # **永久挂起且不抛任何异常**，必须能检测到并中断。
            #
            # ❌ 方案一（已废弃）：后台线程看门狗设置标志位。
            #    无效 —— 挂起的是 await，线程设标志它不会醒。
            #
            # ❌ 方案二（已废弃）：asyncio.wait_for(agen.__anext__(), timeout)。
            #    **不可靠** —— wait_for 超时后靠 **cancel** 来终止任务，
            #    但 telethon 内部在重试/重连路径上会捕获并吞掉 CancelledError
            #    （见 telethon/client/downloads.py `_request` 的 TimedOutError/
            #    FileMigrateError/FileReferenceExpired 分支用递归重试，
            #    以及 client/users.py 的抑制逻辑），于是取消不生效，
            #    wait_for 会一直等下去 → **看门狗永不触发**。
            #    真机实测：任务卡在 74.6% 长达两天，进程仍存活在 epoll_wait。
            #
            # ✅ 方案三（当前实现）：把「读一块」放进独立 Task，
            #    用 asyncio.wait(...) 观察是否在超时内完成。超时后**不依赖取消**，
            #    直接判定停滞并放弃该任务（后台 task 留着不管，进程退出时回收）。
            #    这样即使 telethon 吞取消，我们也能继续往下走。
            agen = client.iter_download(message.media, **kwargs).__aiter__()
            while True:
                reader = asyncio.ensure_future(agen.__anext__())
                done, _pending = await asyncio.wait({reader}, timeout=STALL_TIMEOUT)
                if not done:
                    # 超时：判定停滞。
                    # 注意：**不能 await 这个 reader** —— telethon 会吞掉取消，
                    # 等它就等于永远等下去（这正是旧方案卡死两天的地方）。
                    # 这里放弃它：调 cancel() 是尽力而为，被吞也无妨；
                    # 随后通过 _abandon_task() 让它脱离事件循环的清理等待，
                    # 避免阻塞 asyncio.run / 服务优雅退出。
                    reader.cancel()
                    abandon_task(reader)
                    raise RuntimeError(
                        f"下载停滞：{STALL_TIMEOUT:.0f}s 内无新数据（已下载 "
                        f"{written / (1024*1024):.2f} MB）。网络可能中断，可重试续传。"
                    )
                try:
                    chunk = reader.result()
                except StopAsyncIteration:
                    break
                if not chunk:
                    continue
                fh.write(chunk)
                written += len(chunk)
                if on_progress:
                    on_progress(written, total)
            fh.flush()
            os.fsync(fh.fileno())  # 落盘后再改名，避免断电留下空文件
        os.replace(part, target)   # 原子改名（同目录内 rename 是原子的）
        log.info("下载完成：%s（%.2f MB）", target.name, written / (1024 * 1024))
        return written
    except BaseException:
        # 失败/取消：保留 .part 以便下次续传；但若没开启续传则清掉
        if not resume:
            try:
                part.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def notify_policy(kind: str, behavior: dict[str, Any] | None = None) -> tuple[bool, bool]:
    """按媒体类型给出通知策略：返回 `(是否通知, 是否播报进度)`。

    - 视频：`behavior.notify_progress`（进度 + 完成）——默认行为不变；
    - 文档：默认**只报「完成」**（`notify_docs`），进度播报要显式打开
      `notify_doc_progress`；电子书多为小文件，逐块刷屏没有意义。
    """
    beh = behavior or {}
    if kind == "document":
        notify = bool(beh.get("notify_docs", True))
        return notify, bool(notify and beh.get("notify_doc_progress", False))
    notify = bool(beh.get("notify_progress", True))
    return notify, notify


class MediaDownloader:
    """把一条 TG 消息下载到落盘目录。供 DownloadQueue 调用。"""

    def __init__(self, tg_manager: Any, config: Config) -> None:
        self.tg = tg_manager
        self.config = config

    async def __call__(self, task: Any) -> None:
        """queue worker 入口：task 是 db.TaskRecord。"""
        from .db import TaskDB  # 避免环依赖
        from .notify import ProgressReporter

        cfg = self.config.load()
        dl = cfg["download"]
        beh = cfg["behavior"]

        client = await self.tg.ensure_connected()
        message = await self._refetch(client, task)
        media = identify_media(message, doc_exts=dl.get("doc_exts"))
        if media is None:
            raise RuntimeError(
                "消息中已无可下载媒体（可能已被删除，或后缀不在文档白名单内）"
            )

        # 落盘路由：视频 → download.dir/path_template；文档 → doc_dir/doc_path_template。
        # 文档目录未授权会在 target_dir_for 里抛 PathSafetyError（明确报错，不写坏地方）。
        fallback_dir = target_dir_for(media, cfg)
        target = Path(task.target_path) if task.target_path else plan_media_target(media, cfg)

        # 磁盘水位检查：不足就跳过而不是写坏文件（按**实际落盘**的分区判断，
        # 文档目录可能与视频目录不在同一个卷上）。
        check_dir = str(target.parent) if task.target_path else fallback_dir
        ok, why = check_disk(check_dir, task.size, float(beh.get("disk_min_free_gb", 5)))
        if not ok:
            raise RuntimeError(f"磁盘空间不足：{why}")

        log.info("开始下载%s：%s（%.2f MB, msg=%s）→ %s",
                 media.kind_cn, media.filename, media.size_mb, task.message_id, target)

        db: TaskDB | None = getattr(self, "db", None)

        # 通知策略（需求 4，文档与视频分开，见 notify_policy）
        want_notify, want_progress = notify_policy(media.kind, beh)

        # 进度播报器：在收藏夹里编辑同一条消息（不刷屏）。失败不影响下载。
        reporter: Any = None
        if want_notify:
            reporter = ProgressReporter(
                client, task_id=task.id, filename=media.filename,
                total=int(task.size or media.size or 0),
            )

        import time as _time

        last = [0.0]

        def progress(done: int, total: int) -> None:
            """由流式下载循环调用（同步回调）——只写库；
            异步的 TG 播报交给 _notify_progress 后续协程处理。"""
            now = _time.monotonic()
            if now - last[0] < PROGRESS_INTERVAL:
                return
            last[0] = now
            if db is not None:
                try:
                    db.mark_progress(task.id, done)
                except Exception:
                    log.debug("写进度失败", exc_info=True)
            if reporter is not None and want_progress:
                # 记录最新进度，由 _pump 定期推送（避免在同步回调里 await）
                pending[0] = (done, total or int(task.size or 0))

        pending: list[Any] = [None]

        async def pump() -> None:
            """把最新进度同步到 TG（协程内做，避免阻塞下载循环）。"""
            while True:
                await asyncio.sleep(1.0)
                item = pending[0]
                if item is None or reporter is None:
                    continue
                done, total = item
                pending[0] = None
                await reporter.on_progress(done, total)

        pump_task = asyncio.create_task(pump()) if (reporter is not None and want_progress) else None
        try:
            written = await stream_to_file(
                client, message, target,
                on_progress=progress,
                resume=bool(beh.get("resume", True)),
                total=int(task.size or media.size or 0),
            )
        except BaseException as exc:
            if pump_task:
                pump_task.cancel()
            if reporter is not None:
                try:
                    await reporter.fail(f"{exc.__class__.__name__}: {exc}")
                except Exception:
                    log.debug("发送失败通知出错（忽略）", exc_info=True)
            raise
        finally:
            if pump_task:
                pump_task.cancel()
                # ⚠️ 不能裸 `await pump_task`：若收尾播报卡在一次挂死的 TG 调用里，
                # 这里会把整个 worker 一起拖死（真机 2026-09-19 卡了 42 小时）。
                # 用 run_bounded 观察是否按时结束，超时即放弃该协程。
                ok, drained = await run_bounded(
                    pump_task, PUMP_DRAIN_TIMEOUT,
                    what=f"进度播报收尾（task={task.id}）",
                )
                if ok:
                    try:
                        drained.result()   # 消费异常，避免 "exception was never retrieved"
                    except (asyncio.CancelledError, Exception):
                        pass

        if db is not None:
            db.mark_done(task.id, target_path=str(target), downloaded=written)
        if reporter is not None:
            try:
                await reporter.finish(written, str(target))
            except Exception:
                log.debug("发送完成通知出错（忽略）", exc_info=True)

    async def _refetch(self, client: Any, task: Any) -> Any:
        """取得可下载的消息对象。

        优先用**内存缓存**（消息到达时就存了完整对象，无需重新拉取）；
        未命中才走网络。这样可规避 telethon 解析新对象失败导致的下载失败
        （真机实测：两个频道视频因 Constructor ID 不认识而失败 3 次）。
        """
        cached = get_cached_message(task.chat_id, task.message_id)
        if cached is not None:
            log.debug("命中消息缓存：msg=%s", task.message_id)
            return cached

        try:
            msg = await client.get_messages("me", ids=task.message_id)
        except Exception as exc:
            raise RuntimeError(
                f"重新获取消息失败：{exc}。"
                "（常见原因：Telegram 下发了当前 telethon 版本不认识的对象。"
                "可尝试重新转发该视频——新转发会被缓存，无需重新拉取。）"
            ) from exc
        if msg is None:
            raise RuntimeError(f"消息不存在（msg={task.message_id}），可能已被删除")
        return msg


def on_media_message_factory(tg_manager: Any, db: Any, queue: Any, config: Config):
    """构造收藏夹回调：识别 → 去重入队 → 唤醒队列。"""

    async def _on_media(message: Any) -> None:
        msg_id = int(getattr(message, "id", 0) or 0)
        cfg = config.load()
        media = identify_media(message, doc_exts=(cfg.get("download") or {}).get("doc_exts"))
        if media is None:
            log.info("收藏夹消息 %s 不含可下载媒体（视频/文档白名单），忽略", msg_id or "?")
            return

        # ★关键：此时手里已有完整 message 对象，先缓存起来，
        # 省掉 worker 重新拉取（也规避 telethon 解析新对象的兼容问题）。
        # 键用 media.chat，与 db.enqueue(chat_id=media.chat) 保持一致。
        cache_message(message, media.chat)

        # 去重：catch_up 会重投已处理过的消息，必须靠 (chat, message_id) 挡住
        if db.already_seen(media.chat, msg_id):
            log.info("消息 %s 已处理过，跳过（去重）", msg_id)
            return

        try:
            target = plan_media_target(media, cfg)
        except PathSafetyError as exc:
            # 路径规划失败（越界 / 文档目录未授权）：**记录成 skipped 并写明原因**，
            # 面板上看得见，绝不静默丢消息。
            log.warning("路径规划失败，跳过消息 %s（%s %s）：%s",
                        msg_id, media.kind_cn, media.filename, exc)
            rec, created = db.enqueue(
                chat_id=media.chat, message_id=msg_id, file_id=media.file_id,
                filename=media.filename, size=media.size, kind=media.kind,
            )
            if created and rec:
                db.mark_skipped(rec.id, str(exc))
            return

        rec, created = db.enqueue(
            chat_id=media.chat, message_id=msg_id, file_id=media.file_id,
            filename=media.filename, size=media.size, target_path=str(target),
            kind=media.kind,
        )
        if not created:
            log.info("消息 %s 已在队列中，跳过", msg_id)
            return
        log.info("已入队（%s）：%s（%.2f MB, msg=%s）→ %s",
                 media.kind_cn, media.filename, media.size_mb, msg_id, target)
        queue.notify()

    return _on_media


async def on_media_message(message: Any) -> None:  # pragma: no cover - 兼容旧调用
    """兼容入口（无队列时的降级：只识别记录，不下载）。"""
    media = identify_media(message)
    if media is None:
        log.info("收藏夹消息 %s 不含可下载媒体，忽略", getattr(message, "id", "?"))
        return
    log.info(
        "识别到%s但未接队列：%s（%.2fMB, msg=%s）",
        media.kind_cn, media.filename, media.size_mb, media.message_id,
    )


# ---------------- 消息对象缓存 ----------------

# 为什么要缓存（真机踩坑）：
# 原流程是「监听到消息 → 只存元数据入队 → worker 再用 message_id 重新拉取」。
# 但重新拉取依赖 telethon 解析 Telegram 返回的完整实体列表，
# 一旦 Telegram 下发 telethon 不认识的新对象，就会抛
#     TypeNotFoundError: Could not find a matching Constructor ID ... ID xxxxx
# 导致**下载失败**（真机实测：两个来自频道的视频连续失败 3 次）。
#
# 而消息刚到达时我们**手里就有完整的 message 对象**，根本不需要重新拉。
# 故加一个带上限的内存缓存：命中则直接用，未命中才回退到网络拉取。
#
#
# 代价（旧版）：进程重启后缓存为空 → 旧任务回退到网络拉取，可能再次遇到该问题。
# 现已改为**落盘**（见下），重启后仍可命中。
MESSAGE_CACHE_SIZE = int(os.environ.get("TGV_MESSAGE_CACHE_SIZE", "300"))

# ---- 缓存落盘 ----
# 为什么必须落盘（真机踩坑延伸）：应用重启（或崩溃后被 fnOS 拉起）时，内存缓存
# 归零，排队中的旧任务只能按 message_id 重新拉取 —— 而 Telegram 一旦下发
# telethon 不认识的新对象（Constructor ID 31774388），下载必然再失败 3 次。
# 把最近的消息对象 pickle 到 TGV_DATA_DIR/msg_cache.pkl 即可跨重启命中。
# （telethon 的 Message / MessageMediaDocument 等 TLObject 实测可 pickle，
#   回归测试 test_message_cache_persist_roundtrip 覆盖。）
MSG_CACHE_SAVE_INTERVAL = float(os.environ.get("TGV_MSG_CACHE_SAVE_INTERVAL", "10"))
MSG_CACHE_PERSIST_MAX = int(os.environ.get("TGV_MSG_CACHE_PERSIST_MAX", "100"))

# 最近处理过的消息对象（key: (chat_id, message_id)）
_msg_cache: OrderedDict[tuple[str, int], Any] = OrderedDict()

# 落盘状态机：loaded=已尝试读盘 / dirty=内存比磁盘新 / last_save=上次写盘时刻
# disabled=落盘不可用（pickle 失败等），本次进程内不再重试
_cache_state: dict[str, Any] = {
    "loaded": False, "dirty": False, "last_save": 0.0, "disabled": False,
}

# ⚠️ 真机踩坑（2026-09-21）：**live 消息对象不能直接 pickle**。
# telethon 会把客户端挂到消息上（`message._client`），而客户端对象里含
# `TelegramBaseClient.__init__` 中定义的**局部类**、asyncio 锁、logger 等：
#     Can't pickle local object 'TelegramBaseClient.__init__.<locals>._Loggers'
# 故用一个「丢弃运行期基础设施引用」的 Pickler —— 这些引用本来也不需要持久化，
# 反序列化后置 None 即可（下载只用 `message.media`，client 由调用方传入）。
_DROP_PREFIXES = (
    "telethon.client", "telethon.network", "telethon.sessions", "telethon.crypto",
    "asyncio", "_asyncio", "threading", "_thread", "concurrent", "logging", "socket",
)


class _CachePickler(pickle.Pickler):
    """pickle 时丢弃不可序列化的运行期对象（telethon client / 锁 / logger）。"""

    def persistent_id(self, obj: Any) -> Any:
        module = getattr(type(obj), "__module__", "") or ""
        if module.startswith(_DROP_PREFIXES):
            return ("tgvdl-drop", type(obj).__name__)
        return None


class _CacheUnpickler(pickle.Unpickler):
    """与 `_CachePickler` 配对：被丢弃的引用还原为 None。"""

    def persistent_load(self, pid: Any) -> Any:
        return None


def message_cache_path() -> Path | None:
    """缓存落盘路径：显式 `TGV_MSG_CACHE_FILE` 优先，其次 `TGV_DATA_DIR/msg_cache.pkl`。

    两者都没有时（如单元测试环境）**不落盘**，行为与旧版一致。
    """
    explicit = os.environ.get("TGV_MSG_CACHE_FILE")
    if explicit:
        return Path(explicit)
    data_dir = os.environ.get("TGV_DATA_DIR")
    if data_dir:
        return Path(data_dir) / "msg_cache.pkl"
    return None


def load_message_cache(path: str | Path | None = None) -> int:
    """把磁盘缓存读进内存（幂等；失败只降级不抛错）。返回恢复条数。"""
    if _cache_state["loaded"]:
        return 0
    target = Path(path) if path else message_cache_path()
    _cache_state["loaded"] = True
    if target is None or not target.is_file():
        return 0
    try:
        with target.open("rb") as fh:
            data = _CacheUnpickler(fh).load()   # 自家数据目录的自家格式，非外部输入
        if not isinstance(data, dict):
            raise ValueError(f"缓存格式异常：{type(data).__name__}")
        for (chat, msg_id), value in data.items():
            key = (str(chat), int(msg_id))
            _msg_cache[key] = value
            _msg_cache.move_to_end(key)
        log.info("消息缓存已从磁盘恢复 %d 条（%s）", len(data), target)
        return len(data)
    except Exception as exc:
        _cache_state["disabled"] = True
        log.warning("消息缓存读取失败，本次进程内禁用落盘（不影响下载）：%s", exc)
        return 0


def save_message_cache(*, force: bool = False, path: str | Path | None = None) -> bool:
    """把内存缓存落盘（默认按间隔节流 + 原子替换）。返回是否真的写了。"""
    if _cache_state["disabled"]:
        return False
    target = Path(path) if path else message_cache_path()
    if target is None:
        return False
    now = time.monotonic()
    if not force:
        if not _cache_state["dirty"]:
            return False
        if now - float(_cache_state["last_save"]) < MSG_CACHE_SAVE_INTERVAL:
            return False
    keep = max(1, MSG_CACHE_PERSIST_MAX)
    snapshot = dict(list(_msg_cache.items())[-keep:])
    tmp = target.with_name(target.name + ".tmp")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("wb") as fh:
            _CachePickler(fh, protocol=pickle.HIGHEST_PROTOCOL).dump(snapshot)
        os.replace(tmp, target)   # 原子替换：绝不留下半截缓存
        _cache_state["dirty"] = False
        _cache_state["last_save"] = now
        return True
    except Exception as exc:
        _cache_state["disabled"] = True
        log.warning("消息缓存落盘失败，本次进程内禁用（不影响下载）：%s", exc)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return False


def reset_message_cache(*, drop_disk: bool = False) -> None:
    """清空内存缓存并重置落盘状态（测试与诊断用）。"""
    _msg_cache.clear()
    _cache_state.update(loaded=False, dirty=False, last_save=0.0, disabled=False)
    if drop_disk:
        target = message_cache_path()
        if target is not None:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass


def cache_message(message: Any, chat_key: str | None = None) -> None:
    """把消息对象放进缓存（供 worker 直接使用，免去重新拉取）。

    ⚠️ 键必须与任务库一致：DB 里存的是 `media.chat`（收藏夹场景为 "saved"），
    而不是 `message.chat_id`。否则 worker 按 task.chat_id 查缓存会 miss，
    缓存形同虚设（真机测试验证过这个错配）。
    """
    load_message_cache()   # 首次调用先把磁盘上的旧缓存读进来，避免互相覆盖
    if chat_key is None:
        chat_key = "saved"
        try:
            ch = getattr(message, "chat", None)
            if ch is not None and getattr(ch, "username", None):
                chat_key = str(ch.username)
        except Exception:
            chat_key = "saved"
    key = (str(chat_key), int(getattr(message, "id", 0) or 0))
    _msg_cache[key] = message
    _msg_cache.move_to_end(key)
    while len(_msg_cache) > MESSAGE_CACHE_SIZE:
        _msg_cache.popitem(last=False)
    _cache_state["dirty"] = True
    save_message_cache()


def get_cached_message(chat_id: str, message_id: int) -> Any:
    """取出缓存的消息对象；没有则返回 None。"""
    load_message_cache()
    return _msg_cache.get((str(chat_id), int(message_id)))


# ---------------- 无进展超时 ----------------


def _abandon_task(task: asyncio.Future) -> None:
    """兼容旧名：等价于 `aio_guard.abandon_task`（不依赖取消的放弃）。

    实现已收敛到 aio_guard.py，供下载循环、通知播报、队列 worker 共用；
    保留此名字是为了不破坏既有导入与测试。
    """
    abandon_task(task)


# 多久没有新数据就判定为停滞（秒）。TG 大文件正常也不会这么久没有一块数据。
STALL_TIMEOUT = float(os.environ.get("TGV_STALL_TIMEOUT", "120"))

# 进度播报收尾的上限（秒）。
#
# ⚠️ 真机踩坑（2026-09-19，任务卡死 42 小时）：worker 结束时要 await 收尾播报
# 协程，若那次 TG 调用挂死，`await pump_task` 会把整个 worker 一起拖死 ——
# 下载其实早已结束，任务却永远停在 running，并发槽被占死、队列停摆。
# 故收尾同样走 run_bounded（不依赖取消的限时等待），超时即放弃。
PUMP_DRAIN_TIMEOUT = float(os.environ.get("TGV_PUMP_DRAIN_TIMEOUT", "15"))


__all__ = [
    "DEFAULT_DOC_PATH_TEMPLATE",
    "IGNORED_EXTS",
    "MESSAGE_CACHE_SIZE",
    "MSG_CACHE_PERSIST_MAX",
    "MSG_CACHE_SAVE_INTERVAL",
    "PROGRESS_INTERVAL",
    "PUMP_DRAIN_TIMEOUT",
    "STALL_TIMEOUT",
    "VIDEO_EXTS",
    "MediaDownloader",
    "MediaInfo",
    "authorized_roots",
    "cache_message",
    "check_disk",
    "doc_dir_explicit",
    "ensure_dir_authorized",
    "get_cached_message",
    "identify_media",
    "load_message_cache",
    "message_cache_path",
    "notify_policy",
    "on_media_message",
    "on_media_message_factory",
    "parse_doc_exts",
    "plan_media_target",
    "plan_target",
    "reset_message_cache",
    "resolve_doc_dir",
    "save_message_cache",
    "stream_to_file",
    "target_dir_for",
]
