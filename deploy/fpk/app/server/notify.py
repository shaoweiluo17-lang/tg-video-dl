"""TG 进度回报：在**同一条消息**上编辑进度，不刷屏。

设计依据（IMPLEMENTATION-PLAN §4.3「进度：每 N 秒更新同一条 TG 消息（编辑而非刷屏）」）：

- 每完成一条消息的第一条进度播报时，**发一条新消息**（拿到 message_id）；
- 后续进度全部 `edit_message` 同一条，避免把收藏夹刷爆；
- 完成/失败时做最后一次编辑，把结果留在收藏夹里当凭据；
- 节流：默认 3 秒一次，且进度变化小于 1% 不编辑，减少 API 调用（省 flood 额度）。

为什么进度回报要写进收藏夹而不是日志：
用户在手机上等着看"下好了没"，日志他看不到。这也顺带形成下载历史。
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from .aio_guard import run_bounded

log = logging.getLogger("tgvdl.notify")

# 编辑节流
EDIT_INTERVAL = 3.0      # 秒
MIN_DELTA = 0.01         # 进度变化小于 1% 不刷

# 进度条长度
BAR_WIDTH = 14

# 单次 TG 通知调用的超时（秒）。
#
# ⚠️ 真机踩坑（2026-09-19，任务卡死 42 小时）：进度播报 / 失败通知里的
# `client.send_message`、`client.edit_message` 一旦永久挂起，**整个 worker
# 就再也不返回** —— 任务停在 running、并发槽被占死、队列彻底停摆；而下载循环
# 自己的停滞看门狗**管不到这里**（它只包 iter_download 的取块动作）。
# 故所有通知调用统一走 run_bounded（不依赖取消的限时等待），超时即放弃。
NOTIFY_TIMEOUT = float(os.environ.get("TGV_NOTIFY_TIMEOUT", "30"))


def render_bar(ratio: float, width: int = BAR_WIDTH) -> str:
    """文本进度条，例如 ██████░░░░░░░░ 43%"""
    ratio = max(0.0, min(1.0, float(ratio or 0)))
    filled = int(round(ratio * width))
    return "█" * filled + "░" * (width - filled)


def human_size(n: float) -> str:
    """字节数转可读体积。"""
    step = 1024.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < step:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PB"


def human_speed(bps: float) -> str:
    return f"{human_size(bps)}/s" if bps > 0 else "-"


def human_eta(seconds: float) -> str:
    if seconds <= 0 or seconds > 86400 * 7:
        return "-"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def format_progress(
    filename: str, done: int, total: int, *, elapsed: float = 0.0, state: str = "下载中"
) -> str:
    """渲染进度文本（Markdown）。"""
    ratio = (done / total) if total else 0.0
    speed = (done / elapsed) if elapsed > 0.5 else 0.0
    eta = ((total - done) / speed) if speed > 0 and total > done else 0.0
    lines = [
        f"⬇️ **{state}**",
        f"`{render_bar(ratio)}` {ratio * 100:.0f}%",
        f"{human_size(done)} / {human_size(total)}"
        + (f"　·　{human_speed(speed)}" if speed else "")
        + (f"　·　剩余 {human_eta(eta)}" if eta else ""),
        f"📄 {filename}",
    ]
    return "\n".join(lines)


def format_done(filename: str, size: int, path: str, elapsed: float) -> str:
    avg = (size / elapsed) if elapsed > 0.5 else 0.0
    lines = [
        "✅ **下载完成**",
        f"📄 {filename}",
        f"💾 {human_size(size)}"
        + (f"　·　用时 {human_eta(elapsed)}" if elapsed else "")
        + (f"　·　均速 {human_speed(avg)}" if avg else ""),
    ]
    if path:
        lines.append(f"📁 `{path}`")
    return "\n".join(lines)


def format_failed(filename: str, error: str) -> str:
    return "\n".join([
        "❌ **下载失败**",
        f"📄 {filename}",
        f"⚠️ {error[:300]}",
        "",
        "可在面板「任务」页点重试。",
    ])


def format_flood(seconds: float) -> str:
    return (
        f"⏳ **Telegram 限流中**\n"
        f"需要等待 {human_eta(seconds)} 后继续。\n"
        f"_这是 TG 的保护机制，不是故障；队列会自动恢复。_"
    )


class ProgressReporter:
    """单任务进度播报器：首次发消息，后续编辑同一条。"""

    def __init__(self, client: Any, *, task_id: int, filename: str, total: int) -> None:
        self.client = client
        self.task_id = task_id
        self.filename = filename
        self.total = total
        self.started = time.monotonic()
        self._last_edit = 0.0
        self._last_ratio = -1.0
        self._message_id: int | None = None
        self._finalized = False

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    async def _notify_call(self, coro: Any, what: str) -> Any:
        """限时执行一次 TG 通知调用：**超时/异常都不抛出**，返回 None。

        这是本模块的防卡死核心：通知只是「附赠品」，绝不允许一次挂死的
        `send_message` / `edit_message` 把下载任务拖成永久 running。
        """
        ok, task = await run_bounded(coro, NOTIFY_TIMEOUT, what=what)
        if not ok:
            return None
        try:
            return task.result()
        except Exception as exc:
            log.debug("%s 失败（忽略，不影响下载）：%s", what, exc)
            return None

    async def _send(self, text: str) -> None:
        """在收藏夹发一条新消息（作为进度载体）。"""
        msg = await self._notify_call(
            self.client.send_message("me", text),
            f"发送进度消息（task={self.task_id}）",
        )
        if msg is not None:
            self._message_id = getattr(msg, "id", None)

    async def _edit(self, text: str) -> None:
        if self._message_id is None:
            return
        # 编辑失败不影响下载；可能消息被删了
        await self._notify_call(
            self.client.edit_message("me", self._message_id, text),
            f"编辑进度消息（task={self.task_id}）",
        )

    async def on_progress(self, done: int, total: int) -> None:
        """进度回调（由 downloader 调用）。节流后编辑。"""
        if self._finalized:
            return
        total = total or self.total
        ratio = (done / total) if total else 0.0
        now = time.monotonic()

        if self._message_id is None:
            # 第一条进度：发新消息（带文件名，方便在收藏夹识别）
            self._last_edit = now
            self._last_ratio = ratio
            await self._send(format_progress(self.filename, done, total, elapsed=self.elapsed))
            return

        if now - self._last_edit < EDIT_INTERVAL and ratio - self._last_ratio < MIN_DELTA:
            return
        self._last_edit = now
        self._last_ratio = ratio
        await self._edit(format_progress(self.filename, done, total, elapsed=self.elapsed))

    async def finish(self, done: int, path: str) -> None:
        """成功收尾。"""
        if self._finalized:
            return
        self._finalized = True
        text = format_done(self.filename, done or self.total, path, self.elapsed)
        if self._message_id is None:
            await self._send(text)
        else:
            await self._edit(text)

    async def fail(self, error: str) -> None:
        """失败收尾。"""
        if self._finalized:
            return
        self._finalized = True
        text = format_failed(self.filename, error)
        if self._message_id is None:
            await self._send(text)
        else:
            await self._edit(text)

    async def notify_flood(self, seconds: float) -> None:
        """限流提示（不终结本次播报）。"""
        if self._finalized:
            return
        text = format_flood(seconds)
        if self._message_id is None:
            await self._send(text)
        else:
            await self._edit(text)


__all__ = [
    "EDIT_INTERVAL",
    "MIN_DELTA",
    "NOTIFY_TIMEOUT",
    "ProgressReporter",
    "format_done",
    "format_failed",
    "format_flood",
    "format_progress",
    "human_eta",
    "human_size",
    "human_speed",
    "render_bar",
]
