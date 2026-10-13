"""文档下载（TXT 电子书搬运）测试。

覆盖验收标准 A：
- 一条 .txt document 消息 → identify_media 返回可下载、类型=文档；
- 白名单外后缀（.srt/.jpg/.bin）仍返回 None 且日志可读；
- doc_dir 路由正确：留空 → 落 download.dir；设置了 → 落 doc_dir；
- doc_path_template 渲染正确（含 {date}/{filename} 等既有占位符）；
- 同名文件按 overwrite=false 生成不冲突的新路径；
- 未授权目录 → 抛既有 PathSafetyError，且不会真的写出去。

另外覆盖：通知策略（文档默认只报完成）、任务库 kind 列与老库迁移、
收藏夹回调按类型入队、API 层的授权闸门与保存拒绝。
"""
from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.config import Config, default_config  # noqa: E402
from server.db import SKIPPED, TaskDB  # noqa: E402
from server.downloader import (  # noqa: E402
    IGNORED_EXTS,
    MediaDownloader,
    ensure_dir_authorized,
    identify_media,
    notify_policy,
    on_media_message_factory,
    parse_doc_exts,
    plan_media_target,
    resolve_doc_dir,
)  # noqa: E402
from server.paths import PathSafetyError  # noqa: E402

# ---------------- 假对象（对齐 test_downloader / test_m1_downloads 的写法）----------------


class MessageMediaDocument:  # noqa: N801 - 模拟 telethon 的类名
    """模拟 telethon 的可下载文件媒体类型（判定依据是类名）。"""


class MessageMediaWebPage:  # noqa: N801
    pass


def doc_msg(name: str, size: int = 1_500_000, mime: str = "", mid: int = 43) -> SimpleNamespace:
    doc = SimpleNamespace(
        size=size, mime_type=mime, id="did",
        attributes=[SimpleNamespace(file_name=name)],
    )
    return SimpleNamespace(id=mid, video=None, document=doc, chat=None,
                           media=MessageMediaDocument())


def video_msg(name: str = "movie.mp4", size: int = 5_000_000, mid: int = 42) -> SimpleNamespace:
    video = SimpleNamespace(
        size=size, mime_type="video/mp4", id="fid",
        attributes=[SimpleNamespace(file_name=name)],
    )
    return SimpleNamespace(id=mid, video=video, document=None, chat=None,
                           media=MessageMediaDocument())


class FakeClient:
    """假 telethon 客户端：iter_download 流式吐块。"""

    def __init__(self, chunks=None, message=None):
        self.chunks = chunks or [b"x" * 1024] * 3
        self._message = message

    async def iter_download(self, media, chunk_size=1024 * 1024, offset=0):
        for c in self.chunks:
            await asyncio.sleep(0)
            yield c

    async def get_messages(self, chat, ids=None):
        return self._message


class FakeQueue:
    def __init__(self):
        self.woken = 0
        self.length = 0

    def notify(self):
        self.woken += 1
        self.length += 1


def make_config(tmp_path: Path, **download) -> Config:
    cfg = Config(config_dir=tmp_path / "config", secret_key="k")
    patch = {"download": {"dir": str(tmp_path / "videos"), "path_template": "{filename}"}}
    patch["download"].update(download)
    cfg.save(patch)
    return cfg


# ---------------- 1. 后缀白名单 ----------------

REQUIRED_ACCEPT = [".txt", ".epub", ".pdf", ".mobi", ".azw3"]
REQUIRED_IGNORE = [".srt", ".jpg", ".bin", ".nfo", ".ass", ".vtt", ".png"]


class TestDocWhitelist:
    def test_txt_document_recognized(self) -> None:
        m = identify_media(doc_msg("一本书.txt", size=1_234_567, mime="text/plain"))
        assert m is not None
        assert m.kind == "document"
        assert m.is_doc and m.kind_cn == "文档"
        assert m.filename == "一本书.txt"
        assert m.ext == ".txt"
        assert m.size == 1_234_567

    @pytest.mark.parametrize("ext", REQUIRED_ACCEPT)
    def test_default_whitelist_accepts_ebook_formats(self, ext: str) -> None:
        m = identify_media(doc_msg(f"book{ext}"))
        assert m is not None and m.kind == "document", f"{ext} 应被默认白名单接受"

    @pytest.mark.parametrize("ext", REQUIRED_IGNORE)
    def test_whitelist_out_exts_ignored_with_readable_log(self, ext, caplog) -> None:
        """白名单外（含字幕/封面/二进制）→ None，且日志能看出"为什么没下"。"""
        with caplog.at_level("INFO", logger="tgvdl.download"):
            assert identify_media(doc_msg(f"file{ext}")) is None
        text = caplog.text
        assert f"file{ext}" in text, f"日志里没有文件名，无法排障：{text!r}"
        assert ("忽略" in text) or ("附属" in text)

    def test_unknown_extension_has_no_ext_log(self, caplog) -> None:
        with caplog.at_level("INFO", logger="tgvdl.download"):
            assert identify_media(doc_msg("book")) is None
        assert "book" in caplog.text

    def test_txt_removed_from_ignored_exts(self) -> None:
        """★需求 1：.txt 从 IGNORED_EXTS 拿走；字幕/封面继续留在里面。"""
        assert ".txt" not in IGNORED_EXTS
        for ext in (".srt", ".ass", ".vtt", ".jpg", ".png", ".nfo"):
            assert ext in IGNORED_EXTS

    def test_custom_whitelist(self) -> None:
        assert identify_media(doc_msg("book.mobi"), doc_exts=".txt,.mobi") is not None
        assert identify_media(doc_msg("book.pdf"), doc_exts=".txt,.mobi") is None

    def test_empty_whitelist_means_txt_only(self) -> None:
        assert parse_doc_exts("") == {".txt"}
        assert parse_doc_exts("  ,;  ") == {".txt"}
        assert identify_media(doc_msg("book.txt"), doc_exts="") is not None
        assert identify_media(doc_msg("book.epub"), doc_exts="") is None

    def test_whitelist_accepts_lowercase_and_list(self) -> None:
        assert parse_doc_exts("TXT, Epub") == {".txt", ".epub"}
        assert parse_doc_exts(["txt", ".EPUB"]) == {".txt", ".epub"}

    def test_sidecar_wins_even_if_whitelisted(self) -> None:
        """附属文件是硬拒绝：即使被写进白名单也不下（防止误把字幕加入白名单）。"""
        assert identify_media(doc_msg("sub.srt"), doc_exts=".srt,.txt") is None

    def test_default_config_matches_downloader_default(self) -> None:
        """配置默认值与识别逻辑的默认值必须一致（防两处漂移）。"""
        from server.downloader import parse_doc_exts as parse

        assert parse(default_config()["download"]["doc_exts"]) == parse(None)

    def test_video_document_still_video(self) -> None:
        """回归：.mp4 的 document 仍按视频处理（不能因为加了文档白名单就落到文档目录）。"""
        m = identify_media(doc_msg("movie.mp4"))
        assert m is not None and m.kind == "video"

    def test_webpage_still_ignored(self) -> None:
        msg = SimpleNamespace(id=1, video=None, document=doc_msg("x.txt").document,
                              chat=None, media=MessageMediaWebPage())
        assert identify_media(msg) is None


# ---------------- 2. 路由（doc_dir / doc_path_template）----------------


@pytest.fixture()
def authorized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """把 tmp 下的 videos/docs 都标记为"系统已授权目录"。"""
    videos = tmp_path / "videos"
    docs = tmp_path / "docs"
    videos.mkdir(parents=True, exist_ok=True)
    docs.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{videos},{docs}")
    monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
    return SimpleNamespace(videos=videos, docs=docs, tmp=tmp_path)


class TestDocRouting:
    def test_doc_dir_empty_falls_back_to_video_dir(self, authorized) -> None:
        cfg = make_config(authorized.tmp)  # doc_dir 留空
        assert resolve_doc_dir(cfg.load()) == str(authorized.videos)
        target = plan_media_target(identify_media(doc_msg("book.txt")), cfg.load())
        assert target.parent == authorized.videos.resolve()
        assert target.name == "book.txt"

    def test_doc_dir_set_routes_to_doc_dir(self, authorized) -> None:
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs))
        cfg.save({"download": {"doc_dir": str(authorized.docs)}})
        assert resolve_doc_dir(cfg.load()) == str(authorized.docs)
        target = plan_media_target(identify_media(doc_msg("book.txt")), cfg.load())
        assert target.parent == authorized.docs.resolve()

    def test_default_doc_template_keeps_original_name(self, authorized) -> None:
        """默认 {filename}：只保留 TG 原文件名（下游按名导入）。"""
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs))
        cfg.save({"download": {"doc_dir": str(authorized.docs)}})
        target = plan_media_target(identify_media(doc_msg("三体 全集.txt")), cfg.load())
        assert target.name == "三体 全集.txt"
        assert target.parent == authorized.docs.resolve()

    def test_doc_template_with_date_and_filename(self, authorized) -> None:
        cfg = make_config(
            authorized.tmp, doc_dir=str(authorized.docs),
            doc_path_template="{date}/{filename}",
        )
        cfg.save({"download": {"doc_dir": str(authorized.docs),
                               "doc_path_template": "{date}/{filename}"}})
        target = plan_media_target(
            identify_media(doc_msg("book.epub")), cfg.load(), today="2026-10-08",
        )
        assert target.parent.name == "2026-10-08"
        assert target.name == "book.epub"
        assert target.parent.parent == authorized.docs.resolve()

    def test_doc_template_unknown_field_raises(self, authorized) -> None:
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs),
                          doc_path_template="{nope}/{filename}")
        cfg.save({"download": {"doc_dir": str(authorized.docs),
                               "doc_path_template": "{nope}/{filename}"}})
        with pytest.raises(PathSafetyError) as ei:
            plan_media_target(identify_media(doc_msg("b.txt")), cfg.load())
        assert "nope" in str(ei.value)

    def test_video_ignores_doc_settings(self, authorized) -> None:
        """★回归：文档目录/模板不得影响视频链路。"""
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs),
                          doc_path_template="{date}/{filename}")
        cfg.save({"download": {"doc_dir": str(authorized.docs),
                               "doc_path_template": "{date}/{filename}"}})
        target = plan_media_target(
            identify_media(video_msg("movie.mp4")), cfg.load(), today="2026-10-08",
        )
        # 视频仍用 download.dir + path_template（这里是 {filename}，见 make_config）
        assert target.parent == authorized.videos.resolve()
        assert target.name == "movie.mp4"

    def test_doc_template_traversal_contained(self, authorized) -> None:
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs),
                          doc_path_template="../../{filename}")
        cfg.save({"download": {"doc_dir": str(authorized.docs),
                               "doc_path_template": "../../{filename}"}})
        target = plan_media_target(identify_media(doc_msg("evil.txt")), cfg.load())
        assert str(target).startswith(str(authorized.docs.resolve()))


class TestDocUniquePath:
    def test_conflict_renamed_not_overwritten(self, authorized) -> None:
        """overwrite=false：同名生成不冲突的新路径，且原文件内容不被破坏。"""
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs))
        cfg.save({"download": {"doc_dir": str(authorized.docs)}})
        media = identify_media(doc_msg("book.txt"))

        first = plan_media_target(media, cfg.load())
        first.write_text("第一本", encoding="utf-8")

        second = plan_media_target(media, cfg.load())
        assert second != first
        assert second.name == "book (1).txt"
        assert first.read_text(encoding="utf-8") == "第一本"
        assert not second.exists()

    def test_overwrite_true_reuses_path(self, authorized) -> None:
        cfg = make_config(authorized.tmp, doc_dir=str(authorized.docs))
        cfg.save({"download": {"doc_dir": str(authorized.docs)},
                  "behavior": {"overwrite": True}})
        media = identify_media(doc_msg("book.txt"))
        first = plan_media_target(media, cfg.load())
        first.write_text("旧")
        assert plan_media_target(media, cfg.load()) == first


# ---------------- 3. 授权闸门（未授权必须报错，不能静默写出去）----------------


class TestDocAuthorization:
    def test_not_authorized_raises_and_writes_nothing(self, tmp_path, monkeypatch) -> None:
        no_auth = tmp_path / "books"
        no_auth.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(tmp_path / "videos"))
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")

        cfg = make_config(tmp_path, doc_dir=str(no_auth))
        cfg.save({"download": {"doc_dir": str(no_auth)}})

        with pytest.raises(PathSafetyError) as ei:
            plan_media_target(identify_media(doc_msg("book.txt")), cfg.load())
        msg = str(ei.value)
        assert "未授权" in msg and str(no_auth) in msg
        assert "设置" in msg, "错误信息要给出可操作指引"
        # 没有真的写出去
        assert list(no_auth.iterdir()) == []

    def test_dir_fallback_needs_no_auth(self, tmp_path, monkeypatch) -> None:
        """doc_dir 留空＝沿用视频目录，与视频同信任级别，不额外要求授权。"""
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        cfg = make_config(tmp_path)  # doc_dir 空
        target = plan_media_target(identify_media(doc_msg("book.txt")), cfg.load())
        assert target.parent == (tmp_path / "videos").resolve()

    def test_authorized_root_and_subpath_ok(self, tmp_path, monkeypatch) -> None:
        root = tmp_path / "share"
        sub = root / "books" / "2026"
        sub.mkdir(parents=True)
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(root))
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        ensure_dir_authorized(str(sub))          # 子目录：放行
        ensure_dir_authorized(str(root))         # 根本身：放行

    def test_traversal_into_authorized_root_rejected(self, tmp_path, monkeypatch) -> None:
        root = tmp_path / "share"
        root.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(root))
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        with pytest.raises(PathSafetyError):
            ensure_dir_authorized(str(root / ".." / "outside"))

    def test_symlink_escape_rejected(self, tmp_path, monkeypatch) -> None:
        """符号链接指向授权目录之外 → 必须拒绝（realpath 比较，不是字符串前缀）。"""
        root = tmp_path / "share"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        link = root / "link"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:  # pragma: no cover - 极少数文件系统不支持
            pytest.skip("本机文件系统不支持符号链接")
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(root))
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        with pytest.raises(PathSafetyError):
            ensure_dir_authorized(str(link))

    def test_empty_dir_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "/tmp")
        with pytest.raises(PathSafetyError):
            ensure_dir_authorized("")

    def test_two_dirs_colon_separated_both_authorized(self, tmp_path, monkeypatch) -> None:
        """★真机回归（2026-10-08 v0.4.1）：fnOS 多目录用 ":" 分隔。

        旧实现只按 "," 切 → 用户在设置里勾了第二个目录后，
        连第一个（本来可用的）目录都判成未授权，面板直接拒绝保存。
        """
        tg = tmp_path / "TG"
        books = tmp_path / "books"
        tg.mkdir()
        books.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{tg}:{books}")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")

        ensure_dir_authorized(str(tg))       # 原有目录仍放行
        ensure_dir_authorized(str(books))    # 新目录放行

        cfg = make_config(tmp_path, doc_dir=str(books))
        cfg.save({"download": {"doc_dir": str(books)}})
        target = plan_media_target(identify_media(doc_msg("book.txt")), cfg.load())
        assert target.parent == books.resolve()


# ---------------- 4. 通知策略（文档默认只报完成）----------------


class TestNotifyPolicy:
    def test_video_default_progress_and_done(self) -> None:
        assert notify_policy("video", {}) == (True, True)
        assert notify_policy("video", {"notify_progress": False}) == (False, False)

    def test_document_defaults_to_done_only(self) -> None:
        assert notify_policy("document", {}) == (True, False)

    def test_document_progress_opt_in(self) -> None:
        assert notify_policy("document", {"notify_doc_progress": True}) == (True, True)

    def test_document_notify_off(self) -> None:
        assert notify_policy("document", {"notify_docs": False}) == (False, False)
        # 关掉总开关时，进度开关不能把它打开
        assert notify_policy("document",
                             {"notify_docs": False, "notify_doc_progress": True}) == (False, False)


# ---------------- 5. 收藏夹回调按类型入队 ----------------


@pytest.fixture()
def enqueue_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    videos = tmp_path / "videos"
    docs = tmp_path / "docs"
    videos.mkdir()
    docs.mkdir()
    monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{videos},{docs}")
    monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")

    db = TaskDB(tmp_path / "t.sqlite")
    cfg = make_config(tmp_path, doc_dir=str(docs))
    cfg.save({"download": {"doc_dir": str(docs)}})
    queue = FakeQueue()
    handler = on_media_message_factory(SimpleNamespace(), db, queue, cfg)
    return SimpleNamespace(db=db, cfg=cfg, queue=queue, handler=handler,
                           videos=videos, docs=docs, tmp=tmp_path)


class TestDocEnqueue:
    def test_txt_enqueued_as_document_under_doc_dir(self, enqueue_env) -> None:
        asyncio.run(enqueue_env.handler(doc_msg("book.txt", mid=101)))
        rec = enqueue_env.db.list()[0]
        assert rec.kind == "document"
        assert rec.target_path.startswith(str(enqueue_env.docs.resolve()))
        assert rec.target_path.endswith("book.txt")
        assert enqueue_env.queue.woken == 1
        assert rec.to_dict()["kind"] == "document"

    def test_video_enqueued_as_video_under_video_dir(self, enqueue_env) -> None:
        asyncio.run(enqueue_env.handler(video_msg("movie.mp4", mid=102)))
        rec = enqueue_env.db.list()[0]
        assert rec.kind == "video"
        assert rec.target_path.startswith(str(enqueue_env.videos.resolve()))

    def test_unauthorized_doc_dir_marks_skipped_with_reason(self, tmp_path, monkeypatch) -> None:
        """未授权目录：任务进库但状态=已跳过 + 原因可见，绝不静默丢弃。"""
        videos = tmp_path / "videos"
        videos.mkdir()
        books = tmp_path / "books"          # 存在但未授权
        books.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(videos))
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")

        db = TaskDB(tmp_path / "t.sqlite")
        cfg = make_config(tmp_path, doc_dir=str(books))
        cfg.save({"download": {"doc_dir": str(books)}})
        handler = on_media_message_factory(SimpleNamespace(), db, FakeQueue(), cfg)

        asyncio.run(handler(doc_msg("book.txt", mid=103)))
        rec = db.list()[0]
        assert rec.state == SKIPPED
        assert "未授权" in rec.error
        assert rec.kind == "document"
        assert not rec.target_path                      # 没有规划出落盘路径
        assert list(books.iterdir()) == []              # 没有真的写出去

    def test_sidecar_never_enqueued(self, enqueue_env) -> None:
        asyncio.run(enqueue_env.handler(doc_msg("sub.srt", mid=104)))
        assert enqueue_env.db.list() == []


# ---------------- 6. 任务库 kind 列（含老库迁移）----------------


class TestTaskKindColumn:
    def test_kind_stored_and_exposed(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        rec, _ = db.enqueue(chat_id="saved", message_id=1, filename="b.txt", kind="document")
        assert rec is not None and rec.kind == "document"
        assert db.get(rec.id).kind == "document"
        assert db.get(rec.id).to_dict()["kind"] == "document"

    def test_default_kind_is_empty(self, tmp_path: Path) -> None:
        db = TaskDB(tmp_path / "t.sqlite")
        rec, _ = db.enqueue(chat_id="saved", message_id=2, filename="a.mp4")
        assert rec.kind == ""

    def test_old_db_migrated(self, tmp_path: Path) -> None:
        """老库（无 kind 列）打开后自动补列，旧记录可读且 kind 为空串。"""
        path = tmp_path / "old.sqlite"
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL DEFAULT 'me',
                message_id INTEGER NOT NULL,
                file_id TEXT NOT NULL DEFAULT '',
                filename TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0,
                target_path TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                UNIQUE(chat_id, message_id)
            );
            """
        )
        conn.execute(
            "INSERT INTO tasks (chat_id, message_id, filename, state, created_at, updated_at)"
            " VALUES ('saved', 7, 'old.mp4', 'done', 1.0, 1.0)"
        )
        conn.commit()
        conn.close()

        db = TaskDB(path)                      # 打开即迁移
        cols = {r[1] for r in db._conn.execute("PRAGMA table_info(tasks)")}
        assert "kind" in cols
        old = db.get_by_message("saved", 7)
        assert old is not None and old.kind == "" and old.filename == "old.mp4"
        # 迁移后照常入队
        rec, created = db.enqueue(chat_id="saved", message_id=8, kind="video")
        assert created and db.get(rec.id).kind == "video"


# ---------------- 7. 端到端：文档落盘 + 原子改名 ----------------


class TestDocDownloadEndToEnd:
    def _run(self, tmp_path, monkeypatch, name="book.txt", chunks=None, **behavior):
        videos = tmp_path / "videos"
        docs = tmp_path / "docs"
        videos.mkdir()
        docs.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{videos},{docs}")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")

        cfg = make_config(tmp_path, doc_dir=str(docs))
        patch = {"download": {"doc_dir": str(docs), "doc_path_template": "{filename}"}}
        if behavior:
            patch["behavior"] = behavior
        cfg.save(patch)

        db = TaskDB(tmp_path / "t.sqlite")
        msg = doc_msg(name, size=sum(len(c) for c in (chunks or [b"t" * 300] * 4)), mid=55)
        client = FakeClient(chunks or [b"t" * 300] * 4, message=msg)

        class FakeTg:
            async def ensure_connected(self):
                return client

        dl = MediaDownloader(FakeTg(), cfg)
        dl.db = db
        media = identify_media(msg)
        target = plan_media_target(media, cfg.load())
        rec, _ = db.enqueue(chat_id="saved", message_id=55, filename=name,
                            size=media.size, target_path=str(target), kind="document")
        asyncio.run(dl(rec))
        return SimpleNamespace(db=db, rec=rec, docs=docs, target=target, cfg=cfg)

    def test_document_lands_in_doc_dir_atomically(self, tmp_path, monkeypatch) -> None:
        env = self._run(tmp_path, monkeypatch)
        got = env.db.get(env.rec.id)
        assert got.state == "done"
        assert Path(got.target_path).parent == env.docs.resolve()
        assert Path(got.target_path).name == "book.txt"
        assert Path(got.target_path).read_bytes() == b"t" * 1200
        assert not list(env.docs.glob("*.part")), "完成后残留 .part"

    def test_document_notify_off_sends_no_notification(self, tmp_path, monkeypatch) -> None:
        """notify_docs=false 时不构造播报器（文档完全不打扰收藏夹）。"""
        import server.notify as notify_mod

        sent: list[str] = []

        class RecordingReporter:
            def __init__(self, client, **kw):
                sent.append("init")

            async def on_progress(self, done, total):
                sent.append("progress")

            async def finish(self, done, path):
                sent.append("finish")

            async def fail(self, error):
                sent.append("fail")

        monkeypatch.setattr(notify_mod, "ProgressReporter", RecordingReporter)
        env = self._run(tmp_path, monkeypatch, notify_docs=False)
        assert sent == []
        assert env.db.get(env.rec.id).state == "done"

    def test_document_notifies_done_but_not_progress_by_default(self, tmp_path, monkeypatch) -> None:
        import server.notify as notify_mod

        sent: list[str] = []

        class RecordingReporter:
            def __init__(self, client, **kw):
                sent.append("init")

            async def on_progress(self, done, total):
                sent.append("progress")

            async def finish(self, done, path):
                sent.append("finish")

            async def fail(self, error):
                sent.append("fail")

        monkeypatch.setattr(notify_mod, "ProgressReporter", RecordingReporter)
        env = self._run(tmp_path, monkeypatch)   # 默认：notify_docs=true / notify_doc_progress=false
        assert "init" in sent
        assert "finish" in sent
        assert "progress" not in sent
        assert env.db.get(env.rec.id).state == "done"


# ---------------- 8. API 层（授权闸门 + 保存拒绝）----------------


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from server import config as cfg_mod
    from server import main as srv

    cfg_dir = tmp_path / "config"
    dl_dir = tmp_path / "downloads"
    monkeypatch.setenv("TGV_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("TGV_SECRET_KEY", "unit-test-key")
    monkeypatch.setenv("TGV_DOWNLOAD_DIR", str(dl_dir))
    monkeypatch.setattr(cfg_mod, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(cfg_mod, "DOWNLOAD_DIR", dl_dir)
    srv.STATE = srv.AppState()
    srv.STATE.load_from_config()
    with TestClient(srv.app) as c:
        yield c
    srv.STATE.stop_proxy()


PREFIX = "/app/tg-video-dl"


class TestDocApi:
    def test_public_config_exposes_doc_fields(self, api_client) -> None:
        body = api_client.get(f"{PREFIX}/api/config").json()
        dl = body["config"]["download"]
        assert dl["doc_dir"] == ""
        assert dl["doc_path_template"] == "{filename}"
        assert dl["doc_exts"] == ".txt,.epub,.pdf,.mobi,.azw3"
        beh = body["config"]["behavior"]
        assert beh["notify_docs"] is True and beh["notify_doc_progress"] is False

    def test_check_dir_requires_auth_for_doc_dir(self, api_client, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(tmp_path / "videos"))
        books = tmp_path / "books"
        books.mkdir()
        r = api_client.post(f"{PREFIX}/api/download/check-dir",
                            json={"dir": str(books), "create": True, "require_auth": True})
        res = r.json()["result"]
        assert res["ok"] is False
        assert "未授权" in res["error"]
        assert res.get("need_auth") is True

    def test_check_dir_without_auth_flag_keeps_old_behavior(self, api_client, tmp_path,
                                                          monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        d = tmp_path / "videos"
        d.mkdir()
        r = api_client.post(f"{PREFIX}/api/download/check-dir",
                            json={"dir": str(d), "create": True})
        assert r.json()["result"]["ok"] is True

    def test_save_rejects_unauthorized_doc_dir(self, api_client, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(tmp_path / "videos"))
        books = tmp_path / "books"
        books.mkdir()
        r = api_client.post(f"{PREFIX}/api/config",
                            json={"config": {"download": {"doc_dir": str(books)}}})
        assert r.status_code == 422
        assert "未授权" in r.json()["error"]
        # 没被写进配置（仍是空）
        assert api_client.get(f"{PREFIX}/api/config").json()["config"]["download"]["doc_dir"] == ""

    def test_save_accepts_authorized_doc_dir_and_takes_effect(self, api_client, tmp_path,
                                                              monkeypatch) -> None:
        docs = tmp_path / "books"
        docs.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(docs))
        r = api_client.post(f"{PREFIX}/api/config", json={
            "config": {
                "download": {"doc_dir": str(docs), "doc_path_template": "{date}/{filename}",
                             "doc_exts": ".txt,.mobi"},
                "behavior": {"notify_doc_progress": True},
            }
        })
        assert r.status_code == 200 and r.json()["ok"] is True
        cfg = api_client.get(f"{PREFIX}/api/config").json()["config"]
        assert cfg["download"]["doc_dir"] == str(docs)
        assert cfg["download"]["doc_exts"] == ".txt,.mobi"
        assert cfg["behavior"]["notify_doc_progress"] is True

    def test_save_rejects_bad_doc_template(self, api_client) -> None:
        r = api_client.post(f"{PREFIX}/api/config", json={
            "config": {"download": {"doc_path_template": "{bogus}/{filename}"}}
        })
        assert r.status_code == 422
        assert "bogus" in r.json()["error"]

    def test_validate_reports_doc_checks(self, api_client, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        r = api_client.post(f"{PREFIX}/api/config/validate", json={
            "doc_path_template": "{filename}", "doc_exts": "", "doc_dir": str(tmp_path / "books"),
        })
        checks = {c["name"]: c for c in r.json()["checks"]}
        assert checks["文档路径模板"]["ok"] is True
        assert "txt" in checks["文档后缀白名单"]["detail"]
        assert checks["文档落盘目录"]["ok"] is False
