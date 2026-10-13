"""下载队列：并发控制 + flood-wait 指数退避 + 失败重试。

并发上限刻意默认 1（IMPLEMENTATION-PLAN §4.3 / 风险表）：
参考项目飞影实测「调高反而更慢」——TG 对多路并发会触发限流，
退避等待的时间远超并发省下的时间。
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .aio_guard import abandon_task
from .db import RUNNING, TaskDB

log = logging.getLogger("tgvdl.queue")

# FloodWaitError 的秒数提取（telethon 异常消息形如 "A wait of 3600 seconds is required"）
_FLOOD_RE = re.compile(r"(\d+)\s*seconds?", re.I)

MAX_ATTEMPTS = 3
BASE_BACKOFF = 5.0      # 首次重试等待秒数
MAX_BACKOFF = 300.0     # 重试等待上限
FLOOD_CAP = 3600.0      # flood-wait 等待上限（避免被要求等几小时时把队列挂死）

# ---- worker 级看门狗（真机踩坑，2026-09-19 卡死 42 小时）----
#
# 下载循环自己的停滞看门狗只包住 `iter_download` 的取块动作，**管不到**同一个
# worker 里的其它 await：进度播报、失败通知、收尾 drain…… 这些 TG API 调用一旦
# 永久挂起，worker 就不再返回 —— 任务永远停在 running、并发槽被占死（并发=1 时
# 整个队列停摆），而且不报错、不重试、日志里也看不出所以然。
#
# 故在队列层再兜一道：观察 worker 的「心跳」（数据库 updated_at 由下载进度推进），
# 超过 WORKER_IDLE_TIMEOUT 无进展即判定 worker 卡死 → 放弃它、回收并发槽继续跑。
# 这是最后一道保险：即使将来又有某条 await 路径挂死，队列也不会停摆。
WORKER_IDLE_TIMEOUT = float(os.environ.get("TGV_WORKER_IDLE_TIMEOUT", "300"))
HEARTBEAT_INTERVAL = float(os.environ.get("TGV_WORKER_HEARTBEAT", "10"))


class WorkerStalled(RuntimeError):
    """worker 超过 WORKER_IDLE_TIMEOUT 无任何进展 → 判定卡死。"""


def flood_wait_seconds(exc: BaseException) -> float | None:
    """从异常里解析 flood-wait 秒数；不是限流异常则返回 None。"""
    name = exc.__class__.__name__.lower()
    text = str(exc)
    if "flood" not in name and "flood" not in text.lower():
        return None
    m = _FLOOD_RE.search(text)
    if not m:
        return 60.0  # 是限流但拿不到具体秒数：保守等 60s
    return float(m.group(1))


@dataclass
class QueueStats:
    total: int = 0
    done: int = 0
    failed: int = 0
    skipped: int = 0
    pending: int = 0
    running: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total": self.total, "done": self.done, "failed": self.failed,
            "skipped": self.skipped, "pending": self.pending, "running": self.running,
        }


class DownloadQueue:
    """串行/低并发的下载队列。

    工作模型：N 个 worker 协程轮询 `db.next_pending()`。
    简单但足够——任务是低频的用户手动转发，不是高吞吐场景。
    """

    def __init__(
        self,
        db: TaskDB,
        worker: Callable[[Any], Awaitable[None]],
        *,
        concurrency: int = 1,
        on_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.db = db
        self._worker = worker
        self.concurrency = max(1, min(5, int(concurrency)))
        self._on_event = on_event
        self._tasks: list[asyncio.Task] = []
        self._wake = asyncio.Event()
        self._stopping = False
        self._sleeping_until: float = 0.0  # flood-wait 全局闸门
        self._inflight: set[int] = set()

    # ---- 生命周期 ----
    async def start(self) -> None:
        if self._tasks:
            return
        self._stopping = False
        self._tasks = [
            asyncio.create_task(self._loop(i), name=f"dl-worker-{i}")
            for i in range(self.concurrency)
        ]
        log.info("下载队列已启动（并发 %d）", self.concurrency)

    async def stop(self) -> None:
        self._stopping = True
        self._wake.set()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        log.info("下载队列已停止")

    def set_concurrency(self, n: int) -> None:
        """运行期调整并发（下次 start 生效；这里只记录，避免打断进行中的下载）。"""
        self.concurrency = max(1, min(5, int(n)))

    def notify(self) -> None:
        """有新任务时唤醒 worker。"""
        self._wake.set()

    @property
    def stats(self) -> QueueStats:
        c = self.db.counts()
        total = sum(c.values())
        return QueueStats(
            total=total,
            done=c.get("done", 0),
            failed=c.get("failed", 0),
            skipped=c.get("skipped", 0),
            pending=c.get("pending", 0),
            running=c.get("running", 0),
        )

    @property
    def flood_wait_remaining(self) -> float:
        return max(0.0, self._sleeping_until - time.monotonic())

    # ---- worker 主循环 ----
    async def _loop(self, idx: int) -> None:
        while not self._stopping:
            try:
                # flood-wait 全局闸门：被限流时全体 worker 一起等
                remaining = self.flood_wait_remaining
                if remaining > 0:
                    await self._emit({
                        "type": "flood_wait", "seconds": round(remaining, 1),
                        "message": f"被 Telegram 限流，等待 {remaining:.0f}s 后继续",
                    })
                    await asyncio.sleep(min(remaining, 5.0))
                    continue

                task = self.db.next_pending()
                if task is None:
                    # 闲着的时候顺手做运行期僵尸回收（见 _reclaim_zombies）
                    self._reclaim_zombies()
                    # 没任务就等唤醒（或超时轮询，兜底外部直接写库的情况）
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=5.0)
                    except TimeoutError:
                        pass
                    continue

                if task.id in self._inflight:
                    await asyncio.sleep(0.5)
                    continue

                self._inflight.add(task.id)
                self.db.mark_running(task.id)
                await self._emit({"type": "task_start", "task": self.db.get(task.id).to_dict()
                                  if self.db.get(task.id) else None})
                try:
                    await self._run_worker(task)
                    rec = self.db.get(task.id)
                    if rec and rec.state == RUNNING:
                        # worker 没显式落状态：视为成功（worker 内部已落盘）
                        self.db.mark_done(task.id)
                    await self._emit({"type": "task_done", "task": {
                        "id": task.id, "filename": task.filename,
                    }})
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    await self._handle_failure(task, exc)
                finally:
                    self._inflight.discard(task.id)

            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("下载队列 worker %d 异常，1s 后继续", idx)
                await asyncio.sleep(1)

    # ---- worker 级看门狗 ----
    async def _run_worker(self, task: Any) -> None:
        """带看门狗地跑一次 worker：worker 卡死也能脱身，队列不至于停摆。

        观察方式：`asyncio.wait(worker_task, timeout=HEARTBEAT_INTERVAL)`；
        每一轮再看一次数据库心跳（`updated_at` 由下载进度 mark_progress 推进）。
        超过 WORKER_IDLE_TIMEOUT 无进展 → 放弃该 worker 协程（**不 await 它**，
        telethon 会吞 CancelledError）+ 丢弃残留 .part，然后抛 WorkerStalled
        交给 _handle_failure 走重试/失败流程。
        """
        wtask = asyncio.ensure_future(self._worker(task))
        try:
            while True:
                done, _pending = await asyncio.wait({wtask}, timeout=HEARTBEAT_INTERVAL)
                if wtask in done:
                    break
                idle = self._idle_seconds(task)
                if idle is not None and idle > WORKER_IDLE_TIMEOUT:
                    abandon_task(wtask)
                    self._discard_partial(task)
                    raise WorkerStalled(
                        f"worker 超过 {WORKER_IDLE_TIMEOUT:.0f}s 无任何进展"
                        f"（数据库心跳停在 {idle:.0f}s 前），已放弃并继续队列"
                    )
        except asyncio.CancelledError:
            # 停机：连 worker 一起放掉（它可能吞取消），绝不能卡住 stop()
            abandon_task(wtask)
            raise

        if wtask.cancelled():
            raise asyncio.CancelledError()
        exc = wtask.exception()
        if exc is not None:
            raise exc

    def _idle_seconds(self, task: Any) -> float | None:
        """worker 距上次「有进展」过去了多少秒（以库里的心跳时间为准）。"""
        rec = self.db.get(task.id)
        if rec is None:
            return None
        return max(0.0, time.time() - float(rec.updated_at))

    def _discard_partial(self, task: Any) -> None:
        """丢弃卡死任务的 `.part` 残留。

        为什么必须丢（而不是留给下次续传）：被放弃的 worker 协程可能只是
        「吞了取消、其实还活着」，它手里**仍握着那个文件句柄**；若下一次尝试
        继续往同一个 .part 追加，两个写者交叉写 → 生成一个「看起来完整、实际
        损坏」的视频。宁可重下一遍，也不要静默写坏文件。
        """
        target = str(getattr(task, "target_path", "") or "")
        if not target:
            return
        part = Path(target + ".part")
        try:
            if part.is_file():
                size = part.stat().st_size
                part.unlink()
                log.warning(
                    "已丢弃卡死残留分片 %s（%.2f MB），下次从头下载",
                    part.name, size / (1024 * 1024),
                )
        except OSError as exc:
            log.warning("丢弃残留分片失败（忽略）：%s", exc)

    def _reclaim_zombies(self) -> None:
        """运行期回收「库里有 running、但本进程没有任何 worker 在跑」的任务。

        启动时 main.py 已回收一次；运行期同样可能留下僵尸 running（worker 被
        放弃、状态写入与进程死亡交错等）。没有这道回收，这些记录会**永远停在
        running**：既不会被重试，面板也一直显示"下载中"（真机现象）。
        """
        if self._inflight:
            return   # 还有任务在跑，不能把别人正在跑的任务误判成僵尸
        try:
            n = self.db.recover_zombies()
        except Exception:
            log.debug("运行期僵尸回收失败", exc_info=True)
            return
        if n:
            log.warning("运行期回收 %d 个僵尸 running 任务，将重新排队", n)
            self.notify()

    async def _handle_failure(self, task: Any, exc: BaseException) -> None:
        flood = flood_wait_seconds(exc)
        rec = self.db.get(task.id)
        attempts = (rec.attempts if rec else 0)

        if getattr(exc, "permanent", False):
            # 「重试也没用」的失败（如文件引用过期且刷新后仍不可下载）：直接判失败，
            # 不再白等 3 次指数退避 —— 那只会让面板晚 70 秒才显示真实原因。
            self.db.mark_failed(task.id, f"{exc.__class__.__name__}: {exc}")
            log.error("任务 %s 不可重试的失败：%s", task.id, exc)
            await self._emit({
                "type": "task_failed", "task_id": task.id,
                "error": f"{exc.__class__.__name__}: {exc}"[:300],
            })
            return

        if flood is not None:
            # 限流：不计入失败次数，设全局闸门后把任务放回队列
            wait = min(flood, FLOOD_CAP)
            self._sleeping_until = time.monotonic() + wait
            self.db.reset_for_retry(task.id)
            log.warning("触发 flood-wait %.0fs，任务 %s 稍后重试", wait, task.id)
            await self._emit({
                "type": "flood_wait", "seconds": round(wait, 1), "task_id": task.id,
                "message": f"Telegram 限流，等待 {wait:.0f}s",
            })
            return

        if attempts < MAX_ATTEMPTS:
            backoff = min(BASE_BACKOFF * (2 ** max(0, attempts - 1)), MAX_BACKOFF)
            self.db.reset_for_retry(task.id)
            # 用全局闸门做退避，避免单任务重试与其它任务抢占
            self._sleeping_until = max(self._sleeping_until, time.monotonic() + backoff)
            log.warning("任务 %s 第 %d 次失败（%s），%.0fs 后重试", task.id, attempts, exc, backoff)
            await self._emit({
                "type": "task_retry", "task_id": task.id, "attempt": attempts,
                "backoff": backoff, "error": str(exc)[:300],
            })
            return

        self.db.mark_failed(task.id, f"{exc.__class__.__name__}: {exc}")
        log.error("任务 %s 失败（已重试 %d 次）：%s", task.id, attempts, exc)
        await self._emit({
            "type": "task_failed", "task_id": task.id,
            "error": f"{exc.__class__.__name__}: {exc}"[:300],
        })

    async def _emit(self, payload: dict[str, Any]) -> None:
        if not self._on_event:
            return
        try:
            await self._on_event(payload)
        except Exception:
            log.debug("事件回调失败", exc_info=True)


__all__ = [
    "BASE_BACKOFF",
    "DownloadQueue",
    "FLOOD_CAP",
    "HEARTBEAT_INTERVAL",
    "MAX_ATTEMPTS",
    "MAX_BACKOFF",
    "QueueStats",
    "WORKER_IDLE_TIMEOUT",
    "WorkerStalled",
    "flood_wait_seconds",
]
