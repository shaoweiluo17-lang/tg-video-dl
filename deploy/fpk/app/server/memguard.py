"""进程内存观测（2026-10-07 真机内存事故的直接产物）。

事故背景：应用跑到 1.74GB 而面板上**毫无迹象**——用户只能在 fnOS 资源管理器里
看到一个巨大的 python 进程，没有任何可按小时读的指标，事后才反推出 ~50MB/h 的
线性增长（根因见 `tg_client.background_tasks_alive` 的文档）。

故这里只做两件小事：

- `rss_mb()`：当前进程 RSS（MB），挂到 `/api/health` 上，长期观察一眼可见；
- `rss_watch()`：后台协程，每 interval 秒采一次，超过 warn_mb 记一条 WARNING。

**不自动杀进程、不自动重启客户端**：静默自愈比内存增长更危险（会打断正在下载的
任务、也会把根因藏起来）。阈值只用来提示人。下载大文件时 RSS 阶段性偏高属正常。
"""
from __future__ import annotations

import asyncio
import logging
import os

log = logging.getLogger("tgvdl.mem")

# 超过就 WARNING（不是硬上限，只是提示阈值）。可用 TGV_MEM_WARN_MB=0 关闭。
MEM_WARN_MB = float(os.environ.get("TGV_MEM_WARN_MB", "800"))
MEM_WATCH_INTERVAL = float(os.environ.get("TGV_MEM_WATCH_INTERVAL", "300"))
_STATUS_PATH = "/proc/self/status"


def rss_mb() -> float:
    """当前进程 RSS（MB）；取不到时返回 0.0（绝不让观测影响服务）。"""
    try:
        with open(_STATUS_PATH, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


async def rss_watch(*, interval: float | None = None, warn_mb: float | None = None) -> None:
    """后台内存守望：超阈值就 WARNING（只提示，不处置）。"""
    interval = MEM_WATCH_INTERVAL if interval is None else interval
    warn_mb = MEM_WARN_MB if warn_mb is None else warn_mb
    if interval <= 0:
        return
    while True:
        await asyncio.sleep(interval)
        mb = rss_mb()
        if warn_mb > 0 and mb >= warn_mb:
            log.warning(
                "进程 RSS 已达 %.0fMB（提示阈值 %.0fMB）。若长期只涨不落，"
                "多为 telethon 客户端异常（见 tg_client.background_tasks_alive）；"
                "可重启应用回收内存，并保留日志供排查",
                mb, warn_mb,
            )


__all__ = ["MEM_WARN_MB", "MEM_WATCH_INTERVAL", "rss_mb", "rss_watch"]
