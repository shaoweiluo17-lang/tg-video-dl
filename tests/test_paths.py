"""路径安全与模板渲染测试（防止目录穿越是安全底线）。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.paths import (  # noqa: E402
    PathSafetyError,
    SafeRoot,
    render_template,
    sanitize_filename,
    unique_path,
)


class TestSanitizeFilename:
    def test_strips_directory_traversal(self) -> None:
        out = sanitize_filename("../../etc/passwd")
        assert "/" not in out and ".." not in out
        assert out  # 不返回空

    def test_strips_separators(self) -> None:
        assert sanitize_filename("a/b\\c.mp4") == "a_b_c.mp4"

    def test_keeps_unicode(self) -> None:
        assert "测试" in sanitize_filename("视频 测试.mp4")

    def test_removes_control_chars(self) -> None:
        assert "\x00" not in sanitize_filename("a\x00b.mp4")
        assert "\n" not in sanitize_filename("a\nb.mp4")

    def test_strips_leading_dots(self) -> None:
        # 防止写出隐藏文件
        assert not sanitize_filename(".hidden").startswith(".")

    def test_escapes_windows_reserved(self) -> None:
        assert sanitize_filename("CON.txt").startswith("_")

    def test_fallback_on_empty(self) -> None:
        assert sanitize_filename("") == "unnamed"
        assert sanitize_filename("...") == "unnamed"

    def test_truncates_long_names(self) -> None:
        out = sanitize_filename("x" * 500 + ".mp4")
        assert len(out.encode("utf-8")) <= 180


class TestRenderTemplate:
    def test_basic_template(self) -> None:
        out = render_template(
            "{date}/{filename}", filename="a.mp4", date="2026-09-16", file_id=1
        )
        assert str(out) == "2026-09-16/a.mp4"

    def test_malicious_filename_neutralized(self) -> None:
        """模板本身合法，但文件名带穿越 → 必须被清洗。"""
        out = render_template(
            "{date}/{filename}", filename="../../evil.mp4", date="2026-09-16", file_id=1
        )
        assert ".." not in str(out)
        assert str(out).startswith("2026-09-16/")

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(PathSafetyError):
            render_template("{bogus}", filename="a.mp4", date="2026-09-16")

    def test_ext_field(self) -> None:
        out = render_template(
            "{filename}.{ext}", filename="a.mp4", date="d", file_id=1
        )
        assert str(out) == "a.mp4"


class TestSafeRoot:
    def test_resolves_inside(self, tmp_path: Path) -> None:
        root = SafeRoot(tmp_path / "dl")
        out = root.resolve_within("2026-09-16/a.mp4")
        assert str(out).startswith(str(root.root))

    def test_rejects_traversal(self, tmp_path: Path) -> None:
        root = SafeRoot(tmp_path / "dl")
        with pytest.raises(PathSafetyError):
            root.resolve_within("../../etc/passwd")

    def test_rejects_absolute_escape(self, tmp_path: Path) -> None:
        root = SafeRoot(tmp_path / "dl")
        with pytest.raises(PathSafetyError):
            root.resolve_within("/etc/passwd")

    def test_rejects_symlink_escape(self, tmp_path: Path) -> None:
        """符号链接逃逸：纯字符串前缀比较挡不住，必须用 realpath。"""
        root = SafeRoot(tmp_path / "dl")
        outside = tmp_path / "outside"
        outside.mkdir()
        link = root.root / "link"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("当前环境不支持创建符号链接")
        with pytest.raises(PathSafetyError):
            root.resolve_within("link/evil.mp4")


class TestUniquePath:
    def test_no_conflict_returns_same(self, tmp_path: Path) -> None:
        p = tmp_path / "a.mp4"
        assert unique_path(p) == p

    def test_renames_on_conflict(self, tmp_path: Path) -> None:
        p = tmp_path / "a.mp4"
        p.write_text("x")
        assert unique_path(p).name == "a (1).mp4"

    def test_overwrite_flag_keeps_name(self, tmp_path: Path) -> None:
        p = tmp_path / "a.mp4"
        p.write_text("x")
        assert unique_path(p, overwrite=True) == p
