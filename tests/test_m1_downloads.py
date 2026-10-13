"""M1：任务库、队列、流式下载的测试（用假 telethon 客户端，不依赖真实账号）。"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.db import DONE, FAILED, PENDING, RUNNING, TaskDB  # noqa: E402
from server.downloader import (  # noqa: E402
    MediaDownloader,
    on_media_message_factory,
    stream_to_file,
)
from server.queue import DownloadQueue, flood_wait_seconds  # noqa: E402

# ---------------- 假对象 ----------------


class FakeFlood(Exception):
    def __init__(self, seconds: int) -> None:
        super().__init__(f"A wait of {seconds} seconds is required")
        self.__class__.__name__ = "FloodWaitError"


class FakeMedia:
    def __init__(self, chunks, fail_after=None, fail_exc=None):
        self.chunks = chunks
        self.fail_after = fail_after
        self.fail_exc = fail_exc
        self.calls = 0


class FakeClient:
    """模拟 telethon client 的 iter_download / get_messages。"""

    def __init__(self, chunks=None, fail_after=None, fail_exc=None, message=None):
        self.media = FakeMedia(chunks or [b"x" * 1024] * 4, fail_after, fail_exc)
        self._message = message

    async def iter_download(self, media, chunk_size=1024 * 1024):
        for i, c in enumerate(self.media.chunks):
            if self.media.fail_after is not None and i >= self.media.fail_after:
                raise self.media.fail_exc or RuntimeError("boom")
            await asyncio.sleep(0)
            yield c

    async def get_messages(self, chat, ids=None):
        return self._message


class MessageMediaDocument:  # noqa: N801 - 模拟 telethon 类名（判定依据）
    pass


class MessageMediaWebPage:  # noqa: N801
    pass


def make_message(name="视频.mp4", size=None, mid=7):
    video = SimpleNamespace(
        size=size if size is not None else 4096,
        mime_type="video/mp4",
        id="fid",
        attributes=[SimpleNamespace(file_name=name)],
    )
    # media 必须是 MessageMediaDocument 才会被识别为可下载（见 downloader._is_downloadable）
    return SimpleNamespace(id=mid, video=video, document=None, chat=None,
                           media=MessageMediaDocument())


def make_webpage_message(mid=8):
    """含链接的消息：media 是 WebPage，不可下载。"""
    return SimpleNamespace(id=mid, video=None, document=None, chat=None,
                           media=MessageMediaWebPage())


# ---------------- TaskDB ----------------


class TestTaskDB:
    @pytest.fixture()
    def db(self, tmp_path: Path) -> TaskDB:
        return TaskDB(tmp_path / "t.sqlite")

    def test_enqueue_creates(self, db: TaskDB) -> None:
        rec, created = db.enqueue(chat_id="me", message_id=1, filename="a.mp4")
        assert created is True
        assert rec is not None and rec.state == PENDING

    def test_dedup_same_message(self, db: TaskDB) -> None:
        """核心：catch_up 重投同一消息不能重复入队。"""
        db.enqueue(chat_id="me", message_id=42, filename="a.mp4")
        rec2, created2 = db.enqueue(chat_id="me", message_id=42, filename="a.mp4")
        assert created2 is False
        assert rec2 is not None
        assert len(db.list()) == 1

    def test_dedup_is_per_chat(self, db: TaskDB) -> None:
        db.enqueue(chat_id="me", message_id=1)
        _, created = db.enqueue(chat_id="other", message_id=1)
        assert created is True
        assert len(db.list()) == 2

    def test_already_seen(self, db: TaskDB) -> None:
        assert db.already_seen("me", 5) is False
        db.enqueue(chat_id="me", message_id=5)
        assert db.already_seen("me", 5) is True

    def test_state_transitions(self, db: TaskDB) -> None:
        rec, _ = db.enqueue(chat_id="me", message_id=1)
        db.mark_running(rec.id)
        assert db.get(rec.id).state == RUNNING
        assert db.get(rec.id).attempts == 1
        db.mark_progress(rec.id, 500)
        assert db.get(rec.id).downloaded == 500
        db.mark_done(rec.id, target_path="/x/a.mp4", downloaded=1000)
        got = db.get(rec.id)
        assert got.state == DONE and got.target_path == "/x/a.mp4"

    def test_failed_then_retry(self, db: TaskDB) -> None:
        rec, _ = db.enqueue(chat_id="me", message_id=1)
        db.mark_failed(rec.id, "网络错误")
        assert db.get(rec.id).state == FAILED
        db.reset_for_retry(rec.id)
        assert db.get(rec.id).state == PENDING
        assert db.get(rec.id).error == ""

    def test_counts_and_next_pending(self, db: TaskDB) -> None:
        a, _ = db.enqueue(chat_id="me", message_id=1)
        db.enqueue(chat_id="me", message_id=2)
        db.mark_done(a.id)
        assert db.counts().get(DONE) == 1
        assert db.next_pending().message_id == 2

    def test_progress_ratio(self, db: TaskDB) -> None:
        rec, _ = db.enqueue(chat_id="me", message_id=1, size=1000)
        db.mark_progress(rec.id, 250)
        assert db.get(rec.id).progress == 0.25

    def test_delete_by_state(self, db: TaskDB) -> None:
        rec, _ = db.enqueue(chat_id="me", message_id=1)
        db.mark_done(rec.id)
        assert db.delete_by_state(DONE) == 1
        assert db.list() == []

    def test_clear_keeps_dedup(self, db: TaskDB) -> None:
        """真机踩坑（2026-10-12）：清空已完成记录**不能**丢去重记忆。

        旧实现 `already_seen()` 查的就是 `tasks` 表 → 用户点「清空已完成」后
        去重依据随行一起消失，下次重启 `catch_up` 便把收藏夹最近 50 条里的媒体
        重新下一遍（实测 7 条旧消息被重新入队，并写成 " (1)" 副本）。
        """
        rec, _ = db.enqueue(chat_id="me", message_id=77, filename="a.mp4")
        db.mark_done(rec.id)

        assert db.delete_by_state(DONE) == 1
        assert db.list() == []                       # 列表清空了
        assert db.already_seen("me", 77) is True     # 去重记忆还在
        _, created = db.enqueue(chat_id="me", message_id=77, filename="a.mp4")
        assert created is False

    def test_mark_seen_without_task_row(self, db: TaskDB) -> None:
        """只有去重记忆、没有任务行时（例如刚被清空）也必须挡住重投。"""
        db.mark_seen("me", 88)
        assert db.already_seen("me", 88) is True
        assert db.get_by_message("me", 88) is None

    def test_seen_backfilled_from_legacy_db(self, tmp_path: Path) -> None:
        """升级路径：老库（只有 tasks 表）打开时要回填 seen_messages。

        否则升级那一刻「早就下过」的消息会在下次 catch_up 里被重下一遍。
        """
        import sqlite3

        p = tmp_path / "legacy.sqlite"
        conn = sqlite3.connect(str(p))
        conn.executescript(
            """
            CREATE TABLE tasks (
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
            INSERT INTO tasks (chat_id, message_id, state, created_at, updated_at)
            VALUES ('me', 314, 'done', 1.0, 1.0);
            """
        )
        conn.commit()
        conn.close()

        db = TaskDB(p)  # 打开即迁移 + 回填
        assert db.already_seen("me", 314) is True
        assert len(db.list()) == 1  # 老任务行本身仍在
        db.close()

    def test_persists_across_reopen(self, tmp_path: Path) -> None:
        p = tmp_path / "t.sqlite"
        db1 = TaskDB(p)
        db1.enqueue(chat_id="me", message_id=9)
        db1.close()
        db2 = TaskDB(p)
        assert db2.already_seen("me", 9) is True
        db2.close()


# ---------------- flood-wait 解析 ----------------


class TestFloodWait:
    def test_parses_seconds(self) -> None:
        assert flood_wait_seconds(FakeFlood(3600)) == 3600.0

    def test_non_flood_returns_none(self) -> None:
        assert flood_wait_seconds(RuntimeError("普通错误")) is None

    def test_flood_without_number_defaults(self) -> None:
        class FloodWaitError(Exception):
            pass

        assert flood_wait_seconds(FloodWaitError("limit reached")) == 60.0


# ---------------- 流式下载 ----------------


class TestStreamToFile:
    def test_writes_and_renames_atomically(self, tmp_path: Path) -> None:
        target = tmp_path / "out" / "a.mp4"
        client = FakeClient(chunks=[b"a" * 100, b"b" * 200])
        written = asyncio.run(stream_to_file(client, make_message(), target))
        assert written == 300
        assert target.read_bytes() == b"a" * 100 + b"b" * 200

    def test_no_part_file_left_behind(self, tmp_path: Path) -> None:
        target = tmp_path / "a.mp4"
        asyncio.run(stream_to_file(FakeClient(), make_message(), target))
        assert not list(tmp_path.glob("*.part")), "完成后残留 .part 文件"

    def test_part_cleaned_on_failure(self, tmp_path: Path) -> None:
        """失败时必须清掉半成品，不能留下垃圾占空间。"""
        target = tmp_path / "a.mp4"
        client = FakeClient(chunks=[b"x" * 100] * 5, fail_after=2)
        with pytest.raises(RuntimeError):
            asyncio.run(stream_to_file(client, make_message(), target))
        assert not list(tmp_path.glob("*.part"))
        assert not target.exists(), "失败却留下了最终文件（原子性被破坏）"

    def test_progress_callback_invoked(self, tmp_path: Path) -> None:
        seen: list[int] = []
        asyncio.run(
            stream_to_file(
                FakeClient(chunks=[b"z" * 10] * 3), make_message(),
                tmp_path / "a.mp4", on_progress=lambda d, t: seen.append(d),
            )
        )
        assert seen and seen[-1] == 30

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "nested" / "a.mp4"
        asyncio.run(stream_to_file(FakeClient(), make_message(), target))
        assert target.exists()


# ---------------- 队列 ----------------


class TestQueue:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_processes_pending_task(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        processed = []

        async def worker(task):
            processed.append(task.id)

        async def scenario():
            q = DownloadQueue(db, worker, concurrency=1)
            db.enqueue(chat_id="me", message_id=1)
            await q.start()
            q.notify()
            await asyncio.sleep(1.0)
            await q.stop()
            return q

        q = self._run(scenario())
        assert processed == [1]
        assert db.get(1).state == DONE
        assert q.stats.done == 1

    def test_failed_task_retries_then_fails(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        calls = []

        async def worker(task):
            calls.append(task.id)
            raise RuntimeError("永久失败")

        async def scenario():
            q = DownloadQueue(db, worker, concurrency=1)
            db.enqueue(chat_id="me", message_id=1)
            await q.start()
            q.notify()
            # 等待重试耗尽（退避 5s/10s，靠缩短等待来加速）
            for _ in range(200):
                if db.get(1).state == FAILED:
                    break
                await asyncio.sleep(0.1)
                q._sleeping_until = 0  # 跳过退避等待
            await q.stop()

        self._run(scenario())
        assert db.get(1).state == FAILED
        assert len(calls) >= 2, "失败任务没有被重试"

    def test_flood_wait_sets_gate_without_failing_task(self, tmp_path: Path) -> None:
        """被限流不算失败：任务应回到 pending，并设置全局等待闸门。"""
        db = TaskDB(tmp_path / "t.sqlite")

        async def worker(task):
            raise FakeFlood(120)

        async def scenario():
            q = DownloadQueue(db, worker, concurrency=1)
            db.enqueue(chat_id="me", message_id=1)
            await q.start()
            q.notify()
            for _ in range(50):
                if q.flood_wait_remaining > 0:
                    break
                await asyncio.sleep(0.1)
            gate = q.flood_wait_remaining
            await q.stop()
            return gate

        gate = self._run(scenario())
        assert gate > 0, "未设置 flood-wait 闸门"
        assert db.get(1).state == PENDING, "限流不应把任务标为失败"

    def test_concurrency_clamped(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")

        async def worker(task):
            pass

        assert DownloadQueue(db, worker, concurrency=0).concurrency == 1
        assert DownloadQueue(db, worker, concurrency=99).concurrency == 5

    def test_stats_reflect_db(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")

        async def worker(task):
            pass

        q = DownloadQueue(db, worker)
        db.enqueue(chat_id="me", message_id=1)
        db.enqueue(chat_id="me", message_id=2)
        assert q.stats.total == 2 and q.stats.pending == 2


# ---------------- 收藏夹回调（识别 → 去重 → 入队） ----------------


class TestOnMediaMessageFactory:
    @pytest.fixture()
    def env(self, tmp_path: Path):
        from server.config import Config

        db = TaskDB(tmp_path / "t.sqlite")
        cfg = Config(config_dir=tmp_path / "config", secret_key="k")
        cfg.save({"download": {"dir": str(tmp_path / "dl"), "path_template": "{filename}"}})

        notified = []

        class FakeQueue:
            def notify(self):
                notified.append(1)

        class FakeTg:
            pass

        handler = on_media_message_factory(FakeTg(), db, FakeQueue(), cfg)
        return SimpleNamespace(db=db, cfg=cfg, handler=handler, notified=notified, tmp=tmp_path)

    def test_enqueues_video(self, env) -> None:
        asyncio.run(env.handler(make_message("影片.mp4", mid=1)))
        assert len(env.db.list()) == 1
        assert env.notified, "未唤醒队列"

    def test_dedup_on_repeat(self, env) -> None:
        """catch_up 重投：第二次不应再入队。"""
        asyncio.run(env.handler(make_message("影片.mp4", mid=1)))
        asyncio.run(env.handler(make_message("影片.mp4", mid=1)))
        assert len(env.db.list()) == 1

    def test_ignores_non_media(self, env) -> None:
        txt = SimpleNamespace(id=99, video=None, document=None, chat=None, media=None)
        asyncio.run(env.handler(txt))
        assert env.db.list() == []

    def test_ignores_webpage_link_message(self, env) -> None:
        """★真机回归：含链接的消息不该入队（否则下载时 TypeError 且白重试）。"""
        asyncio.run(env.handler(make_webpage_message(mid=100)))
        assert env.db.list() == [], "网页预览消息被误入队"

    def test_path_traversal_filename_contained(self, env) -> None:
        asyncio.run(env.handler(make_message("../../evil.mp4", mid=2)))
        rec = env.db.list()[0]
        root = str((env.tmp / "dl").resolve())
        assert rec.target_path.startswith(root), f"路径逃逸：{rec.target_path}"

    def test_target_path_planned(self, env) -> None:
        asyncio.run(env.handler(make_message("a.mp4", mid=3)))
        rec = env.db.list()[0]
        assert rec.target_path.endswith("a.mp4")


# ---------------- MediaDownloader 集成 ----------------


class TestMediaDownloader:
    def test_downloads_and_marks_done(self, tmp_path: Path) -> None:
        from server.config import Config

        db = TaskDB(tmp_path / "t.sqlite")
        cfg = Config(config_dir=tmp_path / "config", secret_key="k")
        cfg.save({"download": {"dir": str(tmp_path / "dl"), "path_template": "{filename}"}})

        msg = make_message("video.mp4")
        client = FakeClient(chunks=[b"v" * 512] * 3, message=msg)

        class FakeTg:
            async def ensure_connected(self):
                return client

        dl = MediaDownloader(FakeTg(), cfg)
        dl.db = db
        rec, _ = db.enqueue(chat_id="me", message_id=1, filename="video.mp4", size=1536)

        asyncio.run(dl(rec))

        got = db.get(rec.id)
        assert got.state == DONE
        assert Path(got.target_path).read_bytes() == b"v" * 1536

    def test_refuses_when_disk_low(self, tmp_path: Path) -> None:
        from server.config import Config

        db = TaskDB(tmp_path / "t.sqlite")
        cfg = Config(config_dir=tmp_path / "config", secret_key="k")
        cfg.save({
            "download": {"dir": str(tmp_path / "dl"), "path_template": "{filename}"},
            "behavior": {"disk_min_free_gb": 10 ** 9},
        })

        class FakeTg:
            async def ensure_connected(self):
                return FakeClient(message=make_message())

        dl = MediaDownloader(FakeTg(), cfg)
        rec, _ = db.enqueue(chat_id="me", message_id=1, filename="a.mp4")
        with pytest.raises(RuntimeError, match="磁盘"):
            asyncio.run(dl(rec))


class TestZombieRecovery:
    """缺陷 11（真机回归）：进程重启后 running 任务变僵尸。

    实测：max_concurrent=1 却有 2 个任务同时 running；
    其中一个 updated_at 是 1041s 前、.part 不再增长 ——
    重启时被硬中断，state 永远停在 running，队列不会再碰它。
    """

    def test_recover_zombies_resets_running_to_pending(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        rec, _ = db.enqueue(chat_id="me", message_id=1)
        db.mark_running(rec.id)
        assert db.get(rec.id).state == RUNNING

        n = db.recover_zombies()
        assert n == 1
        got = db.get(rec.id)
        assert got.state == PENDING, "僵尸任务未被回收"
        assert "重启" in got.error

    def test_recover_does_not_touch_other_states(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        a, _ = db.enqueue(chat_id="me", message_id=1)
        b, _ = db.enqueue(chat_id="me", message_id=2)
        c, _ = db.enqueue(chat_id="me", message_id=3)
        db.mark_done(a.id)
        db.mark_running(b.id)
        db.mark_failed(c.id, "x")

        db.recover_zombies()
        assert db.get(a.id).state == DONE
        assert db.get(b.id).state == PENDING
        assert db.get(c.id).state == FAILED

    def test_recover_is_idempotent(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        rec, _ = db.enqueue(chat_id="me", message_id=1)
        db.mark_running(rec.id)
        assert db.recover_zombies() == 1
        assert db.recover_zombies() == 0, "重复回收应返回 0"
