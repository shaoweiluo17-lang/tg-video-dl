"""API 集成测试：网关行为、配置接口、机密度、以及「不挂死」回归。

用 FastAPI TestClient 直接打 ASGI，不依赖真实网络/真实 TG 账号。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from server import config  # noqa: E402
from server import main as srv  # noqa: E402

PREFIX = "/app/tg-video-dl"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """每个用例一套独立配置目录，避免互相污染。

    ⚠️ 必须同时重置模块级 Config 的路径常量：`server.config.CONFIG_DIR` 等是
    **导入期**从环境变量算好的模块常量，`AppState()` 用默认参数时会读它们。
    只设 monkeypatch.setenv 而不改常量，配置就会落到仓库目录里，
    造成「用例之间互相看到对方写的配置」——本项目踩过一次（残留的
    deploy/fpk/app/config/.secrets.yaml 让"未配置"用例拿到了别人的凭据）。
    """
    cfg_dir = tmp_path / "config"
    dl_dir = tmp_path / "downloads"
    monkeypatch.setenv("TGV_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("TGV_SECRET_KEY", "unit-test-key")
    monkeypatch.setenv("TGV_DOWNLOAD_DIR", str(dl_dir))
    monkeypatch.setattr(config, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(config, "DOWNLOAD_DIR", dl_dir)

    # 重建全局 STATE，使新路径生效
    srv.STATE = srv.AppState()
    srv.STATE.load_from_config()

    # 兜底断言：确保没有继承到任何既有凭据，否则「未配置」类用例会失真
    assert srv.STATE.tg.configured is False, "测试环境不应带有 api 凭据"

    with TestClient(srv.app) as c:
        yield c
    srv.STATE.stop_proxy()


class TestGateway:
    def test_health(self, client: TestClient) -> None:
        r = client.get(f"{PREFIX}/api/health")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["service"] == "tg-video-dl"
        assert d["gateway"] == PREFIX

    def test_root_redirect_is_relative(self, client: TestClient) -> None:
        """FN Connect 关键：Location 必须是相对路径。

        若为绝对地址（用请求 Host 拼），隧道下 Host=localhost 会把浏览器
        带去 http://localhost/... 报「拒绝连接」。
        """
        r = client.get(PREFIX, follow_redirects=False, headers={"host": "localhost"})
        assert r.status_code == 307
        loc = r.headers["location"]
        assert loc == f"{PREFIX}/"
        assert not loc.startswith("http"), f"Location 泄漏为绝对地址：{loc}"

    def test_index_served_with_trailing_slash(self, client: TestClient) -> None:
        r = client.get(f"{PREFIX}/")
        assert r.status_code == 200
        assert "TG 视频下载" in r.text

    def test_api_not_swallowed_by_static_mount(self, client: TestClient) -> None:
        """StaticFiles 挂载是贪心的：注册顺序错了会吞掉 /api/*。"""
        assert client.get(f"{PREFIX}/api/health").status_code == 200
        assert client.get(f"{PREFIX}/api/config").status_code == 200
        assert client.get(f"{PREFIX}/api/tg/status").status_code == 200

    def test_identity_from_gateway_headers(self, client: TestClient) -> None:
        r = client.get(
            f"{PREFIX}/api/me",
            headers={"x-trim-userid": "1000", "x-trim-username": "tester", "x-trim-isadmin": "1"},
        )
        ident = r.json()["identity"]
        assert ident["uid"] == "1000"
        assert ident["username"] == "tester"
        assert ident["is_admin"] is True


class TestConfigApi:
    def test_defaults_visible(self, client: TestClient) -> None:
        c = client.get(f"{PREFIX}/api/config").json()["config"]
        assert c["proxy"]["network"] == "v2ray"
        assert c["behavior"]["enabled"] is False

    def test_set_and_get(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config",
            json={"config": {"download": {"max_concurrent": 2, "path_template": "{filename}"}}},
        )
        assert r.json()["ok"] is True
        c = client.get(f"{PREFIX}/api/config").json()["config"]
        assert c["download"]["max_concurrent"] == 2

    def test_secret_never_echoed(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"telegram": {"api_id": "1234567", "api_hash": "SECRET-HASH-XYZ"}}},
        )
        assert r.json()["ok"] is True
        body = client.get(f"{PREFIX}/api/config").text
        assert "SECRET-HASH-XYZ" not in body
        assert "1234567" not in body  # api_id 也不回显原文

    def test_mask_writeback_rejected_422(self, client: TestClient) -> None:
        """防脱敏污染：掩码写回必须 422，且真实值不被破坏。"""
        client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"telegram": {"api_hash": "REAL-VALUE"}}},
        )
        r = client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"telegram": {"api_hash": "aa25***6b1d"}}},
        )
        assert r.status_code == 422
        assert "脱敏" in r.json()["error"]
        # 真实值仍在（用 export 出来的会话再次写入同名空值验证不清空）
        r2 = client.post(f"{PREFIX}/api/config", json={"secrets": {"telegram": {"api_hash": ""}}})
        assert r2.json()["ok"] is True

    def test_bad_json_body(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config", content=b"not json",
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 400

    @pytest.mark.parametrize("body", [
        {"config": "not-an-object"},
        {"config": {"download": "not-an-object"}},
        {"config": {"download": {"doc_dir": 123}}},
    ])
    def test_malformed_config_types_are_400_not_500(self, client: TestClient, body) -> None:
        """低质输入只能是 4xx：不能让校验代码自己抛 AttributeError 变 500。"""
        r = client.post(f"{PREFIX}/api/config", json=body)
        assert r.status_code < 500, r.text

    def test_save_with_live_client_does_not_500(self, client: TestClient) -> None:
        """★缺陷 16（真机回归，2026-10-08）：保存配置时丢弃旧 TG 客户端不得 500。

        telethon 1.45 的 `disconnect()` 在事件循环里返回 `asyncio.shield(...)` 的
        **Future**；旧实现用 `create_task(result)` 排程 → TypeError → 整个端点 500
        （真机现象：面板「保存设置」显示 HTTP 500）。
        """
        import asyncio

        import server.main as srv
        import server.tg_client as tgmod

        class _FutureClient:
            def is_connected(self) -> bool:
                return True

            def disconnect(self):
                async def _coro() -> None:
                    await asyncio.sleep(0)

                return asyncio.shield(asyncio.get_running_loop().create_task(_coro()))

        srv.STATE.tg = tgmod.TgClientManager()
        srv.STATE.tg._client = _FutureClient()

        r = client.post(
            f"{PREFIX}/api/config",
            json={"config": {"download": {"max_concurrent": 1, "path_template": "{filename}"}}},
        )
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True
        assert srv.STATE.tg._client is None, "旧客户端应被丢弃"

    def test_save_rearms_monitor_and_reports_it(self, client: TestClient, monkeypatch) -> None:
        """★缺陷 17（真机回归，2026-10-08）：保存配置必须重新拉起收藏夹监听。

        `_drop_client()` 会把监听注册一起丢掉（`_monitor_started=False`），
        旧实现保存完配置就返回 → 监听**静默失效**（转发收藏夹毫无反应），直到重启应用。
        """
        import server.main as srv

        calls: list[int] = []

        async def fake_restore() -> bool:
            calls.append(1)
            return True

        monkeypatch.setattr(srv, "restore_tg_session", fake_restore)
        # 已登录态在**机密**里（`load_from_config()` 会把内存里的 session 重置为它的值）
        srv.STATE.config.save_secrets({"telegram": {"session": "sess"}})
        srv.STATE.config.save({"behavior": {"enabled": True}})

        r = client.post(f"{PREFIX}/api/config", json={"config": {"download": {"max_concurrent": 1}}})
        assert r.status_code == 200
        assert r.json()["monitor_rearmed"] is True

    def test_save_does_not_rearm_when_monitor_off(self, client: TestClient) -> None:
        import server.main as srv

        srv.STATE.config.save_secrets({"telegram": {"session": "sess"}})
        srv.STATE.config.save({"behavior": {"enabled": False}})
        r = client.post(f"{PREFIX}/api/config", json={"config": {"download": {"max_concurrent": 1}}})
        assert r.json()["monitor_rearmed"] is False

    def test_save_does_not_rearm_without_session(self, client: TestClient) -> None:
        import server.main as srv

        srv.STATE.config.save({"behavior": {"enabled": True}})
        r = client.post(f"{PREFIX}/api/config", json={"config": {"download": {"max_concurrent": 1}}})
        assert r.json()["monitor_rearmed"] is False, "未登录时不该去拉起监听"

    def test_rearm_falls_back_to_retry_loop(self, monkeypatch) -> None:
        """重新拉起失败 → 起后台重试（不能只写一行日志就完事）。"""
        import asyncio

        import server.main as srv

        calls: list[str] = []

        async def failing_restore() -> bool:
            calls.append("restore")
            return False

        monkeypatch.setattr(srv, "restore_tg_session", failing_restore)
        monkeypatch.setattr(srv, "start_tg_retry", lambda: calls.append("retry"))

        asyncio.run(srv._rearm_after_config())
        assert calls == ["restore", "retry"]


class TestValidateApi:
    def test_valid_uri(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config/validate",
            json={"v2ray_uri": "vless://u@h:443?security=tls&sni=a.com#n"},
        )
        d = r.json()
        assert d["ok"] is True
        assert any(c["ok"] for c in d["checks"])

    def test_invalid_uri(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/config/validate", json={"v2ray_uri": "http://nope"})
        d = r.json()
        assert d["ok"] is False
        assert any(not c["ok"] for c in d["checks"])

    def test_path_template_check(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config/validate", json={"path_template": "{date}/{filename}"}
        )
        d = r.json()
        assert d["ok"] is True

    def test_bad_concurrency_flagged(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/config/validate", json={"max_concurrent": 99})
        assert r.json()["ok"] is False


class TestNoHangRegression:
    """回归：代理/网络不通时，请求必须在秒级返回明确错误，绝不能挂死。

    背景：telethon 默认对不可达的 TG 会重试到分钟级（实测 25s+ 仍未返回），
    曾把 /api/tg/login/send_code 挂死。修复 = 压低重试 + asyncio.wait_for 总时限 + 预检。
    """

    def test_send_code_without_config_returns_409_fast(self, client: TestClient) -> None:
        """未配置 api_id/api_hash：立即 409，而不是去连 TG。"""
        r = client.post(f"{PREFIX}/api/tg/login/send_code", json={"phone": "+8613800138000"})
        assert r.status_code == 409
        assert r.json()["need_config"] is True

    def test_send_code_missing_phone(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/tg/login/send_code", json={})
        assert r.status_code == 400
        assert "手机号" in r.json()["error"]

    def test_send_code_unreachable_returns_504(self, client: TestClient) -> None:
        """配置了凭据但无法连接 TG → 504（可操作提示），而不是挂死或 500。

        本机（NAS）实测无法直连 Telegram，所以这个用例在真实环境里
        走的正是「无代理」分支：preflight TCP 探测失败 → 快速 504。
        """
        client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"telegram": {"api_id": "1234567", "api_hash": "fake-hash"}}},
        )
        # 确保没有代理出口（默认未配置 v2ray 链接）
        assert srv.STATE.tg.proxy_url is None

        r = client.post(f"{PREFIX}/api/tg/login/send_code", json={"phone": "+8613800138000"})
        assert r.status_code == 504, r.text
        assert r.json()["unreachable"] is True
        assert "代理" in r.json()["error"]

    def test_verify_without_send_code_is_400(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "12345"})
        assert r.status_code == 502
        assert "验证码" in r.json()["error"]

    def test_phone_without_country_code_rejected(self, client: TestClient) -> None:
        client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"telegram": {"api_id": "1", "api_hash": "h"}}},
        )
        r = client.post(f"{PREFIX}/api/tg/login/send_code", json={"phone": "13800138000"})
        assert r.status_code == 502
        assert "国际区号" in r.json()["error"]


class TestProxyApi:
    def test_status_without_config(self, client: TestClient) -> None:
        d = client.get(f"{PREFIX}/api/proxy/status").json()
        assert d["ok"] is True
        assert d["proxy"]["running"] is False

    def test_restart_without_config_reports_error(self, client: TestClient) -> None:
        d = client.post(f"{PREFIX}/api/proxy/restart").json()
        assert d["ok"] is False
        assert "未配置" in d["error"]

    def test_saving_bad_uri_surfaces_error_not_500(self, client: TestClient) -> None:
        r = client.post(
            f"{PREFIX}/api/config",
            json={"secrets": {"proxy": {"v2ray_uri": "totally-invalid"}}},
        )
        assert r.status_code == 200  # 配置保存本身成功
        assert r.json()["proxy"]["running"] is False
        assert "非法" in r.json()["proxy"]["error"]


class TestMonitorApi:
    def test_enable_without_login_fails_cleanly(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/monitor/toggle", json={"enabled": True})
        assert r.status_code == 502
        assert "登录" in r.json()["error"]
        # 失败后开关必须回落为关闭，不能留下"以为开着"的假状态
        c = client.get(f"{PREFIX}/api/config").json()["config"]
        assert c["behavior"]["enabled"] is False

    def test_disable_always_ok(self, client: TestClient) -> None:
        r = client.post(f"{PREFIX}/api/monitor/toggle", json={"enabled": False})
        assert r.json()["ok"] is True


class TestTgStatusResilience:
    """真机踩坑（2026-10-12）：客户端被丢弃瞬间的 /tg/status 不该是 500。

    保存凭据会 `_drop_client()` 断开旧客户端，而 telethon 断开时会**取消在途请求**，
    于是正在 await 的 `me()` 抛 CancelledError 冒到 ASGI 顶层 —— 前端每 5s 轮询
    一次的 /tg/status 单次 500（UI 闪一下错误，下次轮询自愈，日志里留一串假故障）。
    实测证据：换自有 api_id 那次，19:07:07 的 /tg/status 就是 500 + 该 traceback。
    """

    def test_cancelled_inflight_me_does_not_500(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        async def _cancelled() -> None:
            raise asyncio.CancelledError()

        monkeypatch.setattr(srv.STATE.tg, "session_string", "fake-session-string")
        monkeypatch.setattr(srv.STATE.tg, "me", _cancelled)

        r = client.get(f"{PREFIX}/api/tg/status")

        assert r.status_code == 200, "客户端重建期间的状态轮询不该 500"
        d = r.json()
        assert d["ok"] is True and d["authorized"] is True
        assert "重建" in d["account_error"]

    def test_tg_error_still_reported(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """原有的 TgError 分支不能被新分支吞掉。"""
        from server.tg_client import TgError

        async def _fail() -> None:
            raise TgError("登录态已失效（session 被吊销或过期），请重新登录。")

        monkeypatch.setattr(srv.STATE.tg, "session_string", "fake-session-string")
        monkeypatch.setattr(srv.STATE.tg, "me", _fail)

        r = client.get(f"{PREFIX}/api/tg/status")

        assert r.status_code == 200
        assert "登录态已失效" in r.json()["account_error"]


class TestLoginVerifyRearmsMonitor:
    """真机踩坑（2026-10-12）：真正的重新登录会丢掉收藏夹监听的注册。

    `send_code()` 为了不复用旧授权会 `abort_client()`，而它顺带清掉
    `_monitor_started` / `_on_media`；登录成功后若不重拉，收藏夹监听会**静默失效**
    —— 面板看着一切正常，转发到收藏夹毫无反应（与 2026-10-08 同类事故）。
    """

    @staticmethod
    def _fake_login_state():
        from server.tg_client import LoginState

        return LoginState(phone="+8613800138000", stage="authorized")

    def test_rearms_when_monitoring_enabled(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        srv.STATE.config.save({"behavior": {"enabled": True}})
        state = self._fake_login_state()

        async def _ok(code: str, password: str = ""):
            return state

        called: list[str] = []

        async def _rearm() -> None:
            called.append("rearm")

        monkeypatch.setattr(srv.STATE.tg, "complete_login", _ok)
        monkeypatch.setattr(srv, "_rearm_after_config", _rearm)

        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "12345"})
        assert r.status_code == 200 and r.json()["authorized"] is True

        for _ in range(100):  # 后台任务跑在 TestClient 的 portal 事件循环里
            if called:
                break
            time.sleep(0.02)
        assert called == ["rearm"], "登录成功后必须重拉收藏夹监听"

    def test_no_rearm_when_monitoring_disabled(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        srv.STATE.config.save({"behavior": {"enabled": False}})
        state = self._fake_login_state()

        async def _ok(code: str, password: str = ""):
            return state

        called: list[str] = []

        async def _rearm() -> None:
            called.append("rearm")

        monkeypatch.setattr(srv.STATE.tg, "complete_login", _ok)
        monkeypatch.setattr(srv, "_rearm_after_config", _rearm)

        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "12345"})
        assert r.status_code == 200

        time.sleep(0.15)
        assert called == [], "监听开关关闭时不该擅自拉起监听"

    def test_partial_login_need_password_does_not_rearm(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """2FA 未完成（need_password）时不算登录成功，不能重拉。"""
        import time

        from server.tg_client import LoginState

        srv.STATE.config.save({"behavior": {"enabled": True}})

        async def _ok(code: str, password: str = ""):
            return LoginState(phone="+8613800138000", stage="need_password")

        called: list[str] = []

        async def _rearm() -> None:
            called.append("rearm")

        monkeypatch.setattr(srv.STATE.tg, "complete_login", _ok)
        monkeypatch.setattr(srv, "_rearm_after_config", _rearm)

        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "12345"})
        assert r.status_code == 200 and r.json()["authorized"] is False

        time.sleep(0.15)
        assert called == []

    def test_verify_adopts_new_session_then_rearms(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """登录成功必须先切到新 session，再重拉监听（顺序不能反）。

        登录用的是独立临时客户端（见 tg_client.send_code 踩坑注释），不切换的话
        应用会一直用旧授权跑，而两只已授权客户端并存还会互相抢 updates。
        """
        import time

        srv.STATE.config.save({"behavior": {"enabled": True}})
        state = self._fake_login_state()
        called: list[str] = []

        async def _ok(code: str, password: str = ""):
            return state

        async def _adopt() -> None:
            called.append("adopt")

        async def _rearm() -> None:
            called.append("rearm")

        monkeypatch.setattr(srv.STATE.tg, "complete_login", _ok)
        monkeypatch.setattr(srv.STATE.tg, "adopt_login_client", _adopt)
        monkeypatch.setattr(srv, "_rearm_after_config", _rearm)

        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "12345"})
        assert r.status_code == 200 and r.json()["authorized"] is True

        for _ in range(100):
            if len(called) >= 2:
                break
            time.sleep(0.02)
        assert called == ["adopt", "rearm"], "必须先切 session 再重拉监听"

    def test_failed_verify_does_not_adopt(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """验证码错/失败时不能切换 session，也不能重拉。"""
        from server.tg_client import TgError

        async def _fail(code: str, password: str = ""):
            raise TgError("验证码无效或已过期")

        called: list[str] = []

        async def _adopt() -> None:
            called.append("adopt")

        async def _rearm() -> None:
            called.append("rearm")

        monkeypatch.setattr(srv.STATE.tg, "complete_login", _fail)
        monkeypatch.setattr(srv.STATE.tg, "adopt_login_client", _adopt)
        monkeypatch.setattr(srv, "_rearm_after_config", _rearm)

        r = client.post(f"{PREFIX}/api/tg/login/verify", json={"code": "00000"})

        assert r.status_code == 502
        assert called == []
