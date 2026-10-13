"""P0/P1 新功能测试：进度通知、断点续传、日志接口。"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.downloader import stream_to_file  # noqa: E402
from server.notify import (  # noqa: E402
    ProgressReporter,
    format_done,
    format_failed,
    format_flood,
    format_progress,
    human_eta,
    human_size,
    human_speed,
    render_bar,
)

# ---------------- 文本渲染 ----------------


class TestFormatting:
    def test_bar_bounds(self) -> None:
        assert render_bar(0.0).count("█") == 0
        assert render_bar(1.0).count("█") == 14
        assert render_bar(0.5).count("█") == 7

    def test_bar_clamps_out_of_range(self) -> None:
        assert render_bar(-5).count("█") == 0
        assert render_bar(99).count("█") == 14

    @pytest.mark.parametrize(
        "n,expect",
        [(0, "0 B"), (512, "512 B"), (2048, "2.0 KB"), (5 * 1024**2, "5.0 MB")],
    )
    def test_human_size(self, n: int, expect: str) -> None:
        assert human_size(n) == expect

    def test_human_speed_zero(self) -> None:
        assert human_speed(0) == "-"

    @pytest.mark.parametrize(
        "s,expect",
        [(0, "-"), (30, "30s"), (90, "1m30s"), (3700, "1h01m"), (10**9, "-")],
    )
    def test_human_eta(self, s: float, expect: str) -> None:
        assert human_eta(s) == expect

    def test_progress_contains_key_info(self) -> None:
        t = format_progress("片子.mp4", 500, 1000, elapsed=2.0)
        assert "片子.mp4" in t
        assert "50%" in t
        assert "███" in t

    def test_progress_survives_unknown_total(self) -> None:
        """total=0 不能除零崩溃。"""
        t = format_progress("a.mp4", 100, 0)
        assert "a.mp4" in t

    def test_done_includes_path(self) -> None:
        t = format_done("a.mp4", 1024, "/dl/a.mp4", 3.0)
        assert "下载完成" in t and "/dl/a.mp4" in t

    def test_failed_truncates_long_error(self) -> None:
        t = format_failed("a.mp4", "x" * 5000)
        assert len(t) < 1000

    def test_flood_mentions_wait(self) -> None:
        assert "限流" in format_flood(120)


# ---------------- 进度播报器 ----------------


class FakeMsg:
    def __init__(self, mid):
        self.id = mid


class FakeTGClient:
    """记录 send/edit 调用，用于验证「编辑同一条而非刷屏」。"""

    def __init__(self, fail_send=False):
        self.sent: list[str] = []
        self.edited: list[tuple[int, str]] = []
        self.fail_send = fail_send
        self._next = 100

    async def send_message(self, chat, text):
        if self.fail_send:
            raise RuntimeError("发送失败")
        self.sent.append(text)
        self._next += 1
        return FakeMsg(self._next)

    async def edit_message(self, chat, mid, text):
        self.edited.append((mid, text))


class TestProgressReporter:
    def test_first_progress_sends_new_message(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=1000)
        asyncio.run(r.on_progress(10, 1000))
        assert len(c.sent) == 1
        assert c.edited == []

    def test_subsequent_progress_edits_same_message(self) -> None:
        """核心：不能刷屏——后续进度必须编辑同一条。"""
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=1000)
        asyncio.run(r.on_progress(10, 1000))
        first_id = c._next  # 首次发的 id
        r._last_edit = 0  # 绕过节流以便观察
        for done in (200, 400, 600):
            r._last_ratio = -1
            asyncio.run(r.on_progress(done, 1000))
        assert len(c.sent) == 1, f"发了多条消息（刷屏）：{len(c.sent)}"
        assert c.edited, "没有编辑任何消息"
        assert all(mid == first_id for mid, _ in c.edited)

    def test_throttle_skips_small_updates(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=100000)
        asyncio.run(r.on_progress(1000, 100000))
        n_after_first = len(c.edited)
        # 紧接着的微小进度变化应被节流
        asyncio.run(r.on_progress(1001, 100000))
        assert len(c.edited) == n_after_first, "微小变化未被节流"

    def test_finish_edits_same_message(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=1000)
        asyncio.run(r.on_progress(10, 1000))
        asyncio.run(r.finish(1000, "/dl/a.mp4"))
        assert len(c.sent) == 1
        assert "下载完成" in c.edited[-1][1]

    def test_fail_when_never_started_sends_new(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=0)
        asyncio.run(r.fail("boom"))
        assert len(c.sent) == 1 and "失败" in c.sent[0]

    def test_finalize_is_idempotent(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=10)
        asyncio.run(r.on_progress(1, 10))
        asyncio.run(r.finish(10, "/p"))
        n = len(c.edited)
        asyncio.run(r.finish(10, "/p"))
        asyncio.run(r.fail("late"))
        assert len(c.edited) == n, "收尾后仍在编辑"

    def test_send_failure_does_not_raise(self) -> None:
        """通知失败绝不能影响下载。"""
        c = FakeTGClient(fail_send=True)
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=100)
        asyncio.run(r.on_progress(10, 100))   # 不应抛异常
        asyncio.run(r.finish(100, "/p"))
        assert c.sent == []

    def test_progress_after_finalize_ignored(self) -> None:
        c = FakeTGClient()
        r = ProgressReporter(c, task_id=1, filename="a.mp4", total=100)
        asyncio.run(r.finish(100, "/p"))
        before = len(c.edited) + len(c.sent)
        asyncio.run(r.on_progress(50, 100))
        assert len(c.edited) + len(c.sent) == before


# ---------------- 断点续传 ----------------


class ResumeClient:
    """记录 iter_download 收到的 offset。"""

    def __init__(self, chunks, record):
        self.chunks = chunks
        self.record = record

    async def iter_download(self, media, chunk_size=1024 * 1024, offset=0, **kw):
        self.record.append(offset)
        for c in self.chunks:
            await asyncio.sleep(0)
            yield c


def make_msg():
    return SimpleNamespace(id=1, media=object())


class TestResume:
    def test_fresh_download_starts_at_zero(self, tmp_path: Path) -> None:
        rec: list[int] = []
        c = ResumeClient([b"a" * 100], rec)
        target = tmp_path / "a.mp4"
        n = asyncio.run(stream_to_file(c, make_msg(), target, resume=True, total=100))
        assert rec == [0]
        assert n == 100

    def test_resumes_from_part_size(self, tmp_path: Path) -> None:
        """存在 .part 时应从已下载位置继续（offset=已有大小）。"""
        target = tmp_path / "a.mp4"
        part = tmp_path / "a.mp4.part"
        part.write_bytes(b"x" * 400)  # 假设已下 400

        rec: list[int] = []
        c = ResumeClient([b"y" * 600], rec)
        n = asyncio.run(stream_to_file(c, make_msg(), target, resume=True, total=1000))

        assert rec == [400], f"未从断点续传（offset={rec}）"
        assert n == 1000, "返回值应为最终总大小"
        assert target.read_bytes() == b"x" * 400 + b"y" * 600

    def test_oversized_part_is_discarded(self, tmp_path: Path) -> None:
        """.part 比总大小还大说明文件损坏，必须重下而不是续传出错。"""
        target = tmp_path / "a.mp4"
        (tmp_path / "a.mp4.part").write_bytes(b"x" * 2000)

        rec: list[int] = []
        c = ResumeClient([b"z" * 100], rec)
        asyncio.run(stream_to_file(c, make_msg(), target, resume=True, total=100))

        assert rec == [0], "损坏的 .part 未被丢弃"
        assert target.read_bytes() == b"z" * 100

    def test_resume_disabled_starts_fresh(self, tmp_path: Path) -> None:
        target = tmp_path / "a.mp4"
        (tmp_path / "a.mp4.part").write_bytes(b"x" * 400)
        rec: list[int] = []
        c = ResumeClient([b"y" * 100], rec)
        asyncio.run(stream_to_file(c, make_msg(), target, resume=False, total=1000))
        assert rec == [0]
        assert target.read_bytes() == b"y" * 100

    def test_failure_keeps_part_when_resume_enabled(self, tmp_path: Path) -> None:
        """开启续传时失败必须保留 .part，否则下次无法续。"""
        target = tmp_path / "a.mp4"

        class Failing:
            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                yield b"a" * 100
                raise RuntimeError("网络断了")

        with pytest.raises(RuntimeError):
            asyncio.run(stream_to_file(Failing(), make_msg(), target, resume=True, total=1000))
        part = tmp_path / "a.mp4.part"
        assert part.is_file(), "开启续传却删掉了 .part"
        assert part.stat().st_size == 100

    def test_failure_removes_part_when_resume_disabled(self, tmp_path: Path) -> None:
        target = tmp_path / "a.mp4"

        class Failing:
            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                yield b"a" * 100
                raise RuntimeError("网络断了")

        with pytest.raises(RuntimeError):
            asyncio.run(stream_to_file(Failing(), make_msg(), target, resume=False, total=1000))
        assert not (tmp_path / "a.mp4.part").exists()
        assert not target.exists()

    def test_atomic_rename_still_holds_with_resume(self, tmp_path: Path) -> None:
        target = tmp_path / "a.mp4"
        (tmp_path / "a.mp4.part").write_bytes(b"x" * 500)
        c = ResumeClient([b"y" * 500], [])
        asyncio.run(stream_to_file(c, make_msg(), target, resume=True, total=1000))
        assert target.is_file()
        assert not (tmp_path / "a.mp4.part").exists()


# ---------------- 日志接口 ----------------


class TestLogsApi:
    @pytest.fixture()
    def client(self, tmp_path: Path, monkeypatch):
        from fastapi.testclient import TestClient
        from server import config as cfgmod
        from server import main as srv

        logdir = tmp_path / "logs"
        logdir.mkdir()
        (logdir / "tg-video-dl.log").write_text(
            "\n".join(f"line {i}" for i in range(500)), encoding="utf-8"
        )
        (logdir / "xray-stderr.log").write_text(
            "xray started\nconnected to vless://secret-node@host:443#x\n", encoding="utf-8"
        )

        monkeypatch.setenv("TGV_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setenv("TGV_LOG_DIR", str(logdir))
        monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path / "config")
        srv.STATE = srv.AppState()
        srv.STATE.load_from_config()
        with TestClient(srv.app) as c:
            yield c
        srv.STATE.stop_proxy()

    def test_reads_app_log_tail(self, client) -> None:
        r = client.get("/app/tg-video-dl/api/logs?source=app&lines=50")
        d = r.json()
        assert d["ok"] is True
        assert len(d["lines"]) == 50
        assert d["lines"][-1] == "line 499"

    def test_lines_clamped(self, client) -> None:
        d = client.get("/app/tg-video-dl/api/logs?source=app&lines=99999").json()
        assert len(d["lines"]) <= 2000

    def test_redacts_share_link(self, client) -> None:
        """日志里的分享链接必须被隐藏（防机密泄漏到前端）。"""
        d = client.get("/app/tg-video-dl/api/logs?source=xray&lines=50").json()
        blob = "\n".join(d["lines"])
        assert "vless://secret-node@host:443" not in blob
        assert "已隐藏" in blob

    def test_missing_file_reports_clearly(self, client, monkeypatch) -> None:
        monkeypatch.setenv("TGV_LOG_DIR", "/nonexistent-dir-xyz")
        d = client.get("/app/tg-video-dl/api/logs?source=app").json()
        assert d["ok"] is False
        assert "未找到" in d["error"]


class TestTasksApi:
    @pytest.fixture()
    def client(self, tmp_path: Path, monkeypatch):
        from fastapi.testclient import TestClient
        from server import config as cfgmod
        from server import main as srv

        monkeypatch.setenv("TGV_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path / "config")
        srv.STATE = srv.AppState()
        srv.STATE.load_from_config()
        srv.STATE.setup_downloads()
        with TestClient(srv.app) as c:
            yield c
        srv.STATE.stop_proxy()

    def test_empty_list(self, client) -> None:
        d = client.get("/app/tg-video-dl/api/tasks").json()
        assert d["ok"] is True and d["tasks"] == []
        assert "total" in d["stats"]

    def test_retry_unknown_task_404(self, client) -> None:
        r = client.post("/app/tg-video-dl/api/tasks/99999/retry")
        assert r.status_code == 404

    def test_clear_done(self, client) -> None:
        d = client.post("/app/tg-video-dl/api/tasks/clear", json={"state": "done"}).json()
        assert d["ok"] is True and d["deleted"] == 0


# ---------------- 目录预检 ----------------


class TestDirPreflight:
    """真机踩到的问题：用户把落盘目录指向媒体库，但应用以独立用户运行，
    目录属主是那个用户（700），应用**写不进去**。若等到下载时才失败，
    用户只能看到"任务失败"而不知原因。
    """

    def test_ok_for_writable_dir(self, tmp_path: Path) -> None:
        from server.main import _dir_report

        r = _dir_report(str(tmp_path))
        assert r["ok"] is True
        assert r.get("writable") is True
        assert "free_gb" in r

    def test_reports_missing_dir_without_create(self, tmp_path: Path) -> None:
        from server.main import _dir_report

        r = _dir_report(str(tmp_path / "nope"))
        assert r["ok"] is False
        assert "不存在" in r["error"]

    def test_creates_when_asked(self, tmp_path: Path) -> None:
        from server.main import _dir_report

        target = tmp_path / "a" / "b" / "c"
        r = _dir_report(str(target), create=True)
        assert r["ok"] is True
        assert r["created"] is True
        assert target.is_dir()

    def test_reports_unwritable_dir(self, tmp_path: Path) -> None:
        import os
        import stat as st

        from server.main import _dir_report

        d = tmp_path / "locked"
        d.mkdir()
        os.chmod(d, st.S_IRUSR | st.S_IXUSR)  # 500：不可写
        try:
            if os.geteuid() == 0:
                pytest.skip("root 无视权限位，无法验证不可写场景")
            r = _dir_report(str(d))
            assert r["ok"] is False
            assert "不可写" in r["error"]
        finally:
            os.chmod(d, 0o700)

    def test_rejects_file_path(self, tmp_path: Path) -> None:
        from server.main import _dir_report

        f = tmp_path / "a.txt"
        f.write_text("x")
        r = _dir_report(str(f))
        assert r["ok"] is False
        assert "不是目录" in r["error"]

    def test_empty_path_rejected(self) -> None:
        from server.main import _dir_report

        assert _dir_report("")["ok"] is False

    def test_probe_file_cleaned_up(self, tmp_path: Path) -> None:
        """预检写入的探针文件必须清理，不能留垃圾。"""
        from server.main import _dir_report

        _dir_report(str(tmp_path))
        assert not (tmp_path / ".tgvdl_write_probe").exists()

    def test_health_includes_download_dir(self, tmp_path: Path, monkeypatch) -> None:
        from fastapi.testclient import TestClient
        from server import config as cfgmod
        from server import main as srv

        monkeypatch.setenv("TGV_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path / "config")
        srv.STATE = srv.AppState()
        srv.STATE.load_from_config()
        d = tmp_path / "dl"
        d.mkdir()
        srv.STATE.config.save({"download": {"dir": str(d)}})
        srv.STATE.load_from_config()
        with TestClient(srv.app) as c:
            h = c.get("/app/tg-video-dl/api/health").json()
        srv.STATE.stop_proxy()
        assert h["download_dir"]["ok"] is True


# ---------------- （已移除）飞牛开放 API 诊断 ----------------
# 原实现走 open API 的 trim.file.userAccess"申请"目录授权，真机核实后确认
# **机制不对**：fnOS 的目录授权是用户在「设置 → 应用」勾选，系统启动应用时
# 通过 TRIM_DATA_ACCESSIBLE_PATHS 注入，应用只能读取遵守。
# 故 trimapp.py 已删除，相关测试一并移除；新机制测试见下一节。


# ---------------- fnOS 目录授权机制（真实机制） ----------------


class TestFnOSDirectoryAuthorization:
    """真机核实：fnOS 的目录授权**不是**应用调用 API 申请的。

    正确机制（以 qBittorrent 为参照，其 env 实测）：
      TRIM_DATA_ACCESSIBLE_PATHS=/vol1/1000/media/影视
    即：用户在 fnOS「设置 → 应用」里勾选目录，系统在**启动应用时**把
    已授权目录列表注入环境变量。应用只负责读取并遵守，不能自己"申请"。

    同时 `config/resource` 需声明 `data-share` 才能获得应用专属共享目录
    （qBittorrent / Emby 都声明了）。
    """

    def test_parses_accessible_paths(self, monkeypatch) -> None:
        from server.config import accessible_paths

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "/a/b,/c/d")
        assert accessible_paths() == ["/a/b", "/c/d"]

    def test_empty_when_unauthorized(self, monkeypatch) -> None:
        from server.config import accessible_paths

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        assert accessible_paths() == []

    def test_is_authorized_inside(self, tmp_path: Path, monkeypatch) -> None:
        from server.config import is_authorized

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(tmp_path))
        assert is_authorized(str(tmp_path / "sub" / "a.mp4")) is True

    def test_is_authorized_outside(self, tmp_path: Path, monkeypatch) -> None:
        from server.config import is_authorized

        granted = tmp_path / "granted"
        other = tmp_path / "other"
        granted.mkdir()
        other.mkdir()
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(granted))
        assert is_authorized(str(other / "a.mp4")) is False

    def test_is_authorized_handles_share_paths(self, tmp_path: Path, monkeypatch) -> None:
        """应用专属共享目录也算授权范围。"""
        from server.config import is_authorized

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", str(tmp_path))
        assert is_authorized(str(tmp_path / "x")) is True

    def test_is_authorized_false_on_garbage(self, monkeypatch) -> None:
        from server.config import is_authorized

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        assert is_authorized("/nonexistent/xxx") is False

    def test_preflight_reports_authorization(self, tmp_path: Path, monkeypatch) -> None:
        """预检结果必须带 authorized 与 authorized_paths，供 UI 给正确指引。"""
        from server.main import _dir_report

        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", str(tmp_path))
        r = _dir_report(str(tmp_path))
        assert r["ok"] is True
        assert r["authorized"] is True
        assert str(tmp_path) in r["authorized_paths"]

    def test_resource_declares_data_share(self) -> None:
        """config/resource 必须声明 data-share，否则拿不到应用专属共享目录。

        参照 qBittorrent / Emby 的 resource 写法。
        """
        import json

        res = json.loads(
            (Path(__file__).resolve().parent.parent
             / "deploy/fpk/config/resource").read_text(encoding="utf-8")
        )
        assert "data-share" in res, "缺少 data-share 声明"
        shares = res["data-share"]["shares"]
        assert shares and shares[0]["name"] == "tg-video-dl"
        assert "tg-video-dl" in shares[0]["permission"]["rw"]

    def test_resource_drops_unnecessary_scopes(self) -> None:
        """去掉不必要的 api-scope（授权不靠 API，靠 data-share + 系统设置）。"""
        import json

        res = json.loads(
            (Path(__file__).resolve().parent.parent
             / "deploy/fpk/config/resource").read_text(encoding="utf-8")
        )
        scopes = res.get("api-scope", [])
        assert "trim.file.userAccess" not in scopes, "该 scope 并非授权所需"
        assert "trim.system.getPlatformConfig" in scopes
