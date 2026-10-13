"""SQLite 任务库：任务记录 + message_id 去重。

去重是硬要求（IMPLEMENTATION-PLAN §4.1）：Telegram 的 catch_up 会在断线重连后
重新投递消息，若不去重就会重复下载同一文件。
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("tgvdl.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id      TEXT NOT NULL DEFAULT 'me',
    message_id   INTEGER NOT NULL,
    file_id      TEXT NOT NULL DEFAULT '',
    filename     TEXT NOT NULL DEFAULT '',
    size         INTEGER NOT NULL DEFAULT 0,
    target_path  TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER NOT NULL DEFAULT 0,
    downloaded   INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    UNIQUE(chat_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_msg ON tasks(chat_id, message_id);

-- 去重记忆：**刻意与 tasks 分开**。面板「清空已完成」会删 tasks 行（见
-- delete_by_state）；若去重依据也放在 tasks 里，清空之后任何一次重启，
-- catch_up 都会把收藏夹最近 50 条里的媒体**重下一遍**
-- （2026-10-12 真机实测：清空后重启，7 条旧消息被重新入队，因目标文件已存在
--   而按既有规则自动加 " (1)" 后缀）。
CREATE TABLE IF NOT EXISTS seen_messages (
    chat_id      TEXT NOT NULL,
    message_id   INTEGER NOT NULL,
    seen_at      REAL NOT NULL,
    PRIMARY KEY (chat_id, message_id)
);
"""

# 老库补列（v0.4.0 起）：媒体类型 video/document，供面板与日志区分「视频 / 文档」。
# 建表语句加列只对新库生效，故必须显式迁移一次。
COLUMN_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("kind", "ALTER TABLE tasks ADD COLUMN kind TEXT NOT NULL DEFAULT ''"),
)

# 任务状态机
PENDING = "pending"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
SKIPPED = "skipped"

ACTIVE_STATES = (PENDING, RUNNING)


@dataclass
class TaskRecord:
    id: int
    chat_id: str
    message_id: int
    filename: str
    size: int
    target_path: str
    state: str
    attempts: int
    downloaded: int
    error: str
    created_at: float
    updated_at: float
    kind: str = ""   # video / document（老记录为空串）

    @property
    def progress(self) -> float:
        if not self.size:
            return 0.0
        return min(1.0, self.downloaded / self.size)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "message_id": self.message_id,
            "filename": self.filename,
            "kind": self.kind or "",
            "size": self.size,
            "size_mb": round(self.size / (1024 * 1024), 2),
            "downloaded": self.downloaded,
            "target_path": self.target_path,
            "state": self.state,
            "attempts": self.attempts,
            "progress": round(self.progress, 4),
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class TaskDB:
    """线程安全的任务库（下载在后台线程跑，故必须加锁）。"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate_columns()
            self._migrate_seen()
            self._conn.commit()

    def _migrate_seen(self) -> None:
        """把历史 tasks 行回填进 seen_messages（幂等，只补缺）。

        老库（≤0.4.4）只有 tasks 表承载去重；升级后若不回填，升级那一刻
        「早就下过」的消息会在下次 catch_up 里被当成新消息重下一遍。
        """
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO seen_messages (chat_id, message_id, seen_at) "
            "SELECT chat_id, message_id, created_at FROM tasks"
        )
        if cur.rowcount:
            log.info("去重表 seen_messages 回填 %d 条（来自历史任务）", cur.rowcount)

    def _migrate_columns(self) -> None:
        """给老库补列（幂等）。SQLite 的 ADD COLUMN 不能带 IF NOT EXISTS。"""
        have = {row["name"] for row in self._conn.execute("PRAGMA table_info(tasks)")}
        for column, ddl in COLUMN_MIGRATIONS:
            if column not in have:
                self._conn.execute(ddl)
                log.info("任务库补列：%s", column)

    # ---- 内部 ----
    def _now(self) -> float:
        return time.time()

    @staticmethod
    def _row(row: sqlite3.Row | None) -> TaskRecord | None:
        if row is None:
            return None
        keys = row.keys()
        return TaskRecord(
            id=row["id"], chat_id=row["chat_id"], message_id=row["message_id"],
            filename=row["filename"], size=row["size"], target_path=row["target_path"],
            state=row["state"], attempts=row["attempts"], downloaded=row["downloaded"],
            error=row["error"], created_at=row["created_at"], updated_at=row["updated_at"],
            # 老库（迁移前建的库）可能没有 kind 列
            kind=(row["kind"] if "kind" in keys else "") or "",
        )

    # ---- 去重与入队 ----
    def already_seen(self, chat_id: str, message_id: int) -> bool:
        """该消息是否已处理过 —— catch_up 重投时的去重依据。

        ⚠️⚠️ 必须查 `seen_messages`（独立表），**绝不能**查 `tasks`：
        面板「清空已完成」会删掉 tasks 行，去重记忆若挂在 tasks 上会随之丢失 ——
        真机实测（2026-10-12）：用户清空已完成记录后重启，catch_up 把 7 条早已
        下过的旧媒体消息重新入队，因目标文件已存在，全被写成 " (1)" 副本。
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM seen_messages WHERE chat_id=? AND message_id=? LIMIT 1",
                (str(chat_id), int(message_id)),
            )
            return cur.fetchone() is not None

    def mark_seen(self, chat_id: str, message_id: int) -> None:
        """标记「该消息已处理」——去重记忆独立于任务列表，清空任务不会丢。"""
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_messages (chat_id, message_id, seen_at) "
                "VALUES (?,?,?)",
                (str(chat_id), int(message_id), self._now()),
            )
            self._conn.commit()

    def enqueue(
        self, *, chat_id: str, message_id: int, file_id: str = "",
        filename: str = "", size: int = 0, target_path: str = "", kind: str = "",
    ) -> tuple[TaskRecord | None, bool]:
        """入队。返回 (记录, 是否新建)；已存在则返回原记录且 created=False。

        `kind`（video/document）只用于面板与日志区分类型，不参与去重与落盘决策。
        """
        now = self._now()
        with self._lock:
            if self.already_seen(chat_id, message_id):
                return self.get_by_message(chat_id, message_id), False
            cur = self._conn.execute(
                """INSERT INTO tasks
                   (chat_id, message_id, file_id, filename, size, target_path,
                    state, kind, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (str(chat_id), int(message_id), file_id, filename, int(size),
                 target_path, PENDING, str(kind or ""), now, now),
            )
            # 去重记忆与任务行同时写入，但**存活于两张表**（见 already_seen 注释）
            self._conn.execute(
                "INSERT OR IGNORE INTO seen_messages (chat_id, message_id, seen_at) "
                "VALUES (?,?,?)",
                (str(chat_id), int(message_id), now),
            )
            self._conn.commit()
            return self.get(cur.lastrowid), True

    # ---- 查询 ----
    def get(self, task_id: int) -> TaskRecord | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM tasks WHERE id=?", (int(task_id),))
            return self._row(cur.fetchone())

    def get_by_message(self, chat_id: str, message_id: int) -> TaskRecord | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM tasks WHERE chat_id=? AND message_id=?",
                (str(chat_id), int(message_id)),
            )
            return self._row(cur.fetchone())

    def list(self, *, state: str | None = None, limit: int = 100) -> list[TaskRecord]:
        with self._lock:
            if state:
                cur = self._conn.execute(
                    "SELECT * FROM tasks WHERE state=? ORDER BY id DESC LIMIT ?",
                    (state, int(limit)),
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM tasks ORDER BY id DESC LIMIT ?", (int(limit),)
                )
            return [r for r in (self._row(x) for x in cur.fetchall()) if r]

    def counts(self) -> dict[str, int]:
        with self._lock:
            cur = self._conn.execute("SELECT state, COUNT(*) c FROM tasks GROUP BY state")
            return {row["state"]: row["c"] for row in cur.fetchall()}

    def next_pending(self) -> TaskRecord | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM tasks WHERE state=? ORDER BY id ASC LIMIT 1", (PENDING,)
            )
            return self._row(cur.fetchone())

    # ---- 状态流转 ----
    def mark_running(self, task_id: int) -> None:
        self._update(task_id, state=RUNNING, attempts_delta=1, error="")

    def mark_progress(self, task_id: int, downloaded: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE tasks SET downloaded=?, updated_at=? WHERE id=?",
                (int(downloaded), self._now(), int(task_id)),
            )
            self._conn.commit()

    def mark_done(self, task_id: int, target_path: str = "", downloaded: int = 0) -> None:
        fields: dict[str, Any] = {"state": DONE, "error": ""}
        if target_path:
            fields["target_path"] = target_path
        if downloaded:
            fields["downloaded"] = int(downloaded)
        self._update(task_id, **fields)

    def mark_failed(self, task_id: int, error: str) -> None:
        self._update(task_id, state=FAILED, error=str(error)[:1000])

    def mark_skipped(self, task_id: int, reason: str = "") -> None:
        self._update(task_id, state=SKIPPED, error=str(reason)[:1000])

    def reset_for_retry(self, task_id: int) -> None:
        """把失败任务放回队列（手动重试）。"""
        self._update(task_id, state=PENDING, error="")

    def _update(self, task_id: int, *, attempts_delta: int = 0, **fields: Any) -> None:
        if not fields and not attempts_delta:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        vals = list(fields.values())
        sql = f"UPDATE tasks SET {cols}{', ' if cols else ''}updated_at=?"
        vals.append(self._now())
        if attempts_delta:
            sql = sql.replace("SET ", "SET attempts=attempts+?, ", 1)
            vals.insert(0, attempts_delta)
        sql += " WHERE id=?"
        vals.append(int(task_id))
        with self._lock:
            self._conn.execute(sql, vals)
            self._conn.commit()

    def recover_zombies(self) -> int:
        """回收「僵尸 running」任务：进程重启时被硬中断的任务。

        ⚠️ 真机踩坑：应用重启（stop/start 或崩溃）时，正在下载的任务
        在库里的 state 停在 'running' —— 数据库不知道"进程已经死了"。
        而队列的 next_pending() 只取 'pending'，于是这些僵尸记录
        **既不会被处理也不会被清理**，面板永远显示"下载中"、进度冻住。

        故启动时必须调用本方法把它们放回 pending（已下的 .part 会被续传复用）。
        返回回收条数。
        """
        with self._lock:
            cur = self._conn.execute(
                "UPDATE tasks SET state=?, error=?, updated_at=? WHERE state=?",
                (PENDING, "进程重启，已重新排队", self._now(), RUNNING),
            )
            self._conn.commit()
            return cur.rowcount or 0

    def delete_by_state(self, state: str) -> int:
        """按状态删除记录（清理已完成/失败）。返回删除条数。

        ⚠️ 只删 `tasks` 行，**不动** `seen_messages`：清空列表 ≠ 清空去重记忆，
        否则下一次 catch_up 会把旧消息重下一遍（见 `already_seen` 的踩坑注释）。
        """
        with self._lock:
            cur = self._conn.execute("DELETE FROM tasks WHERE state=?", (str(state),))
            self._conn.commit()
            return cur.rowcount or 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = [
    "ACTIVE_STATES",
    "COLUMN_MIGRATIONS",
    "DONE",
    "FAILED",
    "PENDING",
    "RUNNING",
    "SKIPPED",
    "TaskDB",
    "TaskRecord",
]
