"""异步看门狗工具：**不依赖取消**的限时等待。

为什么需要这个模块（真机两次踩坑，本项目最贵的教训）：

telethon 在重试/重连路径上会**吞掉 `CancelledError`**
（`client/downloads.py` 的 TimedOutError/FileMigrateError 分支递归重试、
`client/users.py` 的抑制逻辑等），于是：

    ❌ asyncio.wait_for(coro, timeout)

超时后靠 cancel 终止任务 —— 取消被吞 → wait_for 永不返回 →
**看门狗永不触发**，任务卡在 running 长达两天，进程仍存活在 epoll_wait。

    ✅ asyncio.wait({task}, timeout)

只是**观察**任务是否在超时内结束，超时即判定失败；然后
**绝不再 await 那个任务**（等它就等于挂死），只做尽力而为的 cancel、
消费掉它的异常，放手让事件循环回收。

本模块把这条纪律收敛成一处理，供下载循环、通知播报、队列 worker 复用。
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable
from typing import Any, TypeVar

log = logging.getLogger("tgvdl.guard")

T = TypeVar("T")


def abandon_task(task: asyncio.Future[Any]) -> None:
    """尽力放弃一个「可能吞掉取消」的 task：cancel + 消费异常，**绝不 await**。

    生产中可接受（进程常驻、卡死低频）；但**测试里不能用 asyncio.run 跑这类
    用例**（run 退出时会等残留 task），需用独立 loop 并直接 close。
    """
    try:
        task.cancel()
    except Exception:
        pass

    def _consume(t: asyncio.Future[Any]) -> None:
        try:
            t.exception()
        except (asyncio.CancelledError, Exception):
            pass

    try:
        task.add_done_callback(_consume)
    except Exception:
        pass


async def run_bounded(
    awaitable: Awaitable[T], timeout: float, *, what: str = "操作"
) -> tuple[bool, asyncio.Task[T]]:
    """限时等待一个协程，返回 `(是否按时结束, task)`。

    超时返回 `(False, task)` 并**放弃**该 task（不再等它）。
    调用方拿到 False 后自行决定后续（记日志、降级继续、判定卡死等）。
    """
    task: asyncio.Task[T] = asyncio.ensure_future(awaitable)
    done, _pending = await asyncio.wait({task}, timeout=timeout)
    if task in done:
        return True, task
    abandon_task(task)
    log.warning("%s 超过 %.0fs 未返回，已放弃（不再等待，避免拖死 worker）", what, timeout)
    return False, task


async def call_bounded(
    awaitable: Awaitable[T],
    timeout: float,
    *,
    what: str = "操作",
    default: T | None = None,
) -> T | None:
    """限时调用：**超时或异常都返回 default**，绝不把异常抛给调用方。

    专给「失败也不该影响主流程」的通知类调用（发/编辑 TG 进度消息）使用：
    一次挂死的通知调用不允许拖死整个下载任务。
    """
    ok, task = await run_bounded(awaitable, timeout, what=what)
    if not ok:
        return default
    try:
        return task.result()
    except Exception as exc:
        log.debug("%s 失败（忽略，不影响主流程）：%s", what, exc)
        return default


__all__ = [
    "abandon_task",
    "call_bounded",
    "run_bounded",
]
