"""媒体识别测试：视频 + 文档白名单；附属文件（字幕/封面）必须忽略。"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.downloader import (  # noqa: E402
    IGNORED_EXTS,
    check_disk,
    identify_media,
    plan_target,
)


class MessageMediaDocument:  # noqa: N801 - 模拟 telethon 的类名
    """模拟 telethon 的可下载文件媒体类型（判定依据是类名）。"""


class MessageMediaWebPage:  # noqa: N801
    """模拟链接预览（不可下载；会"借" message.video 导致误判）。"""


def video_msg(name: str = "a.mp4", size: int = 50_000_000, mid: int = 42) -> SimpleNamespace:
    video = SimpleNamespace(
        size=size, mime_type="video/mp4", id="fid",
        attributes=[SimpleNamespace(file_name=name)],
    )
    return SimpleNamespace(id=mid, video=video, document=None, chat=None,
                           media=MessageMediaDocument())


def doc_msg(name: str, mime: str = "", mid: int = 43) -> SimpleNamespace:
    doc = SimpleNamespace(
        size=1000, mime_type=mime, id="did",
        attributes=[SimpleNamespace(file_name=name)],
    )
    return SimpleNamespace(id=mid, video=None, document=doc, chat=None,
                           media=MessageMediaDocument())


def webpage_msg(mid: int = 44, with_video_attr: bool = True) -> SimpleNamespace:
    """含链接的消息：Telegram 会同时填 message.video，但 media 是 WebPage。"""
    video = (SimpleNamespace(size=999, mime_type="video/mp4", id="x", attributes=[])
             if with_video_attr else None)
    return SimpleNamespace(id=mid, video=video, document=None, chat=None,
                           media=MessageMediaWebPage())


class TestIdentifyMedia:
    def test_video_message(self) -> None:
        m = identify_media(video_msg("电影.mkv", size=1_500_000_000))
        assert m is not None
        assert m.kind == "video"
        assert m.filename == "电影.mkv"
        assert m.size == 1_500_000_000
        assert m.size_mb == pytest.approx(1430.51, abs=0.1)

    def test_video_without_filename_gets_default(self) -> None:
        msg = video_msg()
        msg.video.attributes = []
        m = identify_media(msg)
        assert m is not None and m.filename == "video_42.mp4"

    @pytest.mark.parametrize("name", ["a.mp4", "b.mkv", "c.avi", "d.webm", "e.ts"])
    def test_video_document_by_extension(self, name: str) -> None:
        """document 型视频也是「视频」：kind=video（决定落到视频目录）。"""
        m = identify_media(doc_msg(name))
        assert m is not None and m.kind == "video"

    def test_video_document_by_mime(self) -> None:
        m = identify_media(doc_msg("noext", mime="video/x-matroska"))
        assert m is not None and m.kind == "video"

    def test_non_video_document_ignored(self) -> None:
        assert identify_media(doc_msg("report.pdf", mime="application/pdf")) is not None  # 白名单内
        assert identify_media(doc_msg("data.bin", mime="application/octet-stream")) is None

    @pytest.mark.parametrize("name", ["sub.srt", "cover.jpg", "info.nfo"])
    def test_sidecar_files_ignored(self, name: str) -> None:
        assert identify_media(doc_msg(name)) is None

    def test_txt_is_no_longer_a_sidecar(self) -> None:
        """★文档下载：.txt 已从附属文件清单里移除，改由文档白名单判定。"""
        assert ".txt" not in IGNORED_EXTS
        m = identify_media(doc_msg("book.txt", mime="text/plain"))
        assert m is not None and m.kind == "document"

    def test_empty_message(self) -> None:
        assert identify_media(None) is None
        assert identify_media(
            SimpleNamespace(id=1, video=None, document=None, media=None)
        ) is None

    def test_text_only_message_ignored(self) -> None:
        """纯文本（media=None）不处理。"""
        assert identify_media(
            SimpleNamespace(id=1, video=None, document=None, text="t.me/x/1", media=None)
        ) is None

    def test_webpage_preview_ignored_even_with_video_attr(self) -> None:
        """★真机回归：含链接的消息 media 是 WebPage，即使挂着 video 也不能下。

        错误表现：TypeError: Cannot cast MessageMediaWebPage to any kind of
        InputFileLocation（且会白白重试 3 次）。
        """
        assert identify_media(webpage_msg()) is None

    def test_webpage_without_video_attr_ignored(self) -> None:
        assert identify_media(webpage_msg(with_video_attr=False)) is None

    def test_media_none_ignored(self) -> None:
        assert identify_media(SimpleNamespace(id=1, video=None, document=None, media=None)) is None

    def test_message_id_recorded_for_dedup(self) -> None:
        m = identify_media(video_msg(mid=999))
        assert m is not None and m.message_id == 999


class TestPlanTarget:
    def test_default_template(self, tmp_path: Path) -> None:
        m = identify_media(video_msg("影片.mp4"))
        assert m is not None
        out = plan_target(
            m, download_dir=str(tmp_path), path_template="{date}/{filename}",
            today="2026-09-16",
        )
        assert out.parent.name == "2026-09-16"
        assert out.name == "影片.mp4"

    def test_malicious_remote_filename_contained(self, tmp_path: Path) -> None:
        """远端文件名带穿越 → 必须仍落在下载根目录内。"""
        m = identify_media(video_msg("../../../etc/evil.mp4"))
        assert m is not None
        out = plan_target(
            m, download_dir=str(tmp_path), path_template="{filename}", today="2026-09-16"
        )
        assert str(out).startswith(str(tmp_path.resolve()))

    def test_conflict_renamed_not_overwritten(self, tmp_path: Path) -> None:
        m = identify_media(video_msg("a.mp4"))
        assert m is not None
        first = plan_target(m, download_dir=str(tmp_path), path_template="{filename}", today="d")
        first.write_text("existing")
        second = plan_target(m, download_dir=str(tmp_path), path_template="{filename}", today="d")
        assert second != first
        assert first.read_text() == "existing"  # 原文件未被破坏


class TestDiskCheck:
    def test_plenty_of_space_allowed(self, tmp_path: Path) -> None:
        ok, msg = check_disk(str(tmp_path), 1024, min_free_gb=0)
        assert ok is True

    def test_below_threshold_rejected(self, tmp_path: Path) -> None:
        ok, msg = check_disk(str(tmp_path), 1024, min_free_gb=10**9)
        assert ok is False
        assert "不足" in msg

    def test_file_larger_than_free_rejected(self, tmp_path: Path) -> None:
        ok, msg = check_disk(str(tmp_path), 10**15, min_free_gb=0)
        assert ok is False
