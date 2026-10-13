"""出站/依赖/密钥三大真机缺陷的回归测试。

每个用例对应一次真机踩坑，目的不是覆盖率而是「防止再次发生」。
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.config import (  # noqa: E402
    SECRET_KEY_FILE,
    Config,
    SecretBox,
    resolve_secret_key,
)
from server.proxy_uri import parse_v2ray_uri  # noqa: E402
from server.xray_outbound import (  # noqa: E402
    XrayError,
    XrayOutbound,
    _tail_text,
    _wait_socks_ready,
    build_xray_config,
)


class TestSocksDependency:
    """缺陷 1：httpx 走 socks5 需要 socksio，缺失时报 ImportError。

    真机现象：代理明明可用（curl 经 socks 能通），面板连通性测试却
    **0.04s 失败**并显示"无法访问 api.telegram.org"——看起来像网络故障，
    实际是缺依赖。旧实现把 ImportError 归入通用"连接失败"，极难反推。
    """

    def test_socksio_importable(self) -> None:
        """requirements 里必须带上 socksio（经 httpx[socks]）。"""
        import socksio  # noqa: F401

    def test_requirements_declares_socks_extra(self) -> None:
        req = (
            Path(__file__).resolve().parent.parent
            / "deploy" / "fpk" / "app" / "server" / "requirements.txt"
        ).read_text(encoding="utf-8")
        assert "httpx[socks]" in req, (
            "requirements.txt 必须写 httpx[socks]（而非裸 httpx），"
            "否则真机上 httpx 无法走 socks5 代理"
        )


class TestXrayLiveness:
    """缺陷 2：只探测端口不校验进程，会把「已崩溃」误判为「运行中」。"""

    def test_wait_detects_dead_process(self) -> None:
        """进程已死时，即使端口探测不成功也应立即返回 False（不等满超时）。"""
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()

        class FakeProc:
            def poll(self):
                return 1  # 已退出

        start = time.monotonic()
        ok = _wait_socks_ready(1, timeout=5.0, proc=FakeProc())  # type: ignore[arg-type]
        elapsed = time.monotonic() - start
        assert ok is False
        assert elapsed < 1.0, "进程已退出却等满了超时，说明未检查进程状态"

    def test_start_raises_when_binary_missing(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("TGV_XRAY_BIN", str(tmp_path / "nonexistent"))
        monkeypatch.setattr(
            "server.xray_outbound.find_xray_binary", lambda: None
        )
        ep = parse_v2ray_uri("trojan://pw@h:443#x")
        ob = XrayOutbound(ep)
        with pytest.raises(XrayError, match="xray"):
            ob.start()

    def test_crashed_xray_reports_exit_code_and_log(self, tmp_path: Path, monkeypatch) -> None:
        """xray 启动即崩溃时，错误信息必须带退出码与 stderr 尾部。

        旧实现把 stderr 接到 PIPE 却只在启动瞬间读一次，成功启动后再崩溃
        的日志全部丢失，导致「面板显示运行中但请求被 RST」无从排查。
        """
        # 造一个「立即退出并打印错误」的假 xray
        fake = tmp_path / "xray"
        fake.write_text("#!/bin/sh\necho 'failed to parse config: boom' >&2\nexit 23\n")
        fake.chmod(0o755)
        monkeypatch.setenv("TGV_XRAY_BIN", str(fake))
        monkeypatch.setenv("TGV_LOG_DIR", str(tmp_path / "logs"))

        ep = parse_v2ray_uri("trojan://pw@h:443#x")
        ob = XrayOutbound(ep)
        with pytest.raises(XrayError) as ei:
            ob.start()
        msg = str(ei.value)
        assert "exit=23" in msg, f"未带退出码：{msg}"
        assert "boom" in msg, f"未带 stderr 内容：{msg}"

    def test_stderr_persisted_to_log_file(self, tmp_path: Path, monkeypatch) -> None:
        """xray 的 stderr 必须落到日志文件，便于事后排查。"""
        fake = tmp_path / "xray"
        fake.write_text("#!/bin/sh\necho 'diagnostic-marker-xyz' >&2\nexit 7\n")
        fake.chmod(0o755)
        monkeypatch.setenv("TGV_XRAY_BIN", str(fake))
        logdir = tmp_path / "logs"
        monkeypatch.setenv("TGV_LOG_DIR", str(logdir))

        ob = XrayOutbound(parse_v2ray_uri("trojan://pw@h:443#x"))
        with pytest.raises(XrayError):
            ob.start()
        assert (logdir / "xray-stderr.log").is_file()
        assert "diagnostic-marker-xyz" in (logdir / "xray-stderr.log").read_text()

    def test_tail_text_handles_missing_file(self, tmp_path: Path) -> None:
        assert _tail_text(tmp_path / "nope.log") == ""

    def test_running_false_after_stop(self, tmp_path: Path) -> None:
        ob = XrayOutbound(parse_v2ray_uri("trojan://pw@h:443#x"))
        assert ob.running is False
        ob.stop()
        assert ob.running is False

    def test_socks_url_available_before_start(self) -> None:
        """缺陷连带项：socks_url 属性必须存在（曾因只有 socks_port 而 AttributeError）。"""
        ob = XrayOutbound(parse_v2ray_uri("trojan://pw@h:443#x"), socks_port=12345)
        assert ob.socks_url == "socks5://127.0.0.1:12345"


class TestSecretKeyAutoGeneration:
    """缺陷 3：加密默认关闭。真机面板显示「session 加密：未启用（明文 + 600 权限）」。

    session 是"拿到即控号"的凭据，不该依赖用户手动设置环境变量才加密。
    """

    def test_generates_key_when_absent(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        key = resolve_secret_key(tmp_path)
        assert key, "未自动生成密钥"
        assert (tmp_path / SECRET_KEY_FILE).is_file()

    def test_key_file_permissions_600(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        resolve_secret_key(tmp_path)
        mode = (tmp_path / SECRET_KEY_FILE).stat().st_mode & 0o777
        assert mode == 0o600, f"密钥文件权限应为 600，实际 {oct(mode)}"

    def test_key_is_stable_across_calls(self, tmp_path: Path, monkeypatch) -> None:
        """同一目录重复取必须拿到同一密钥，否则历史密文全部解不开。"""
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        assert resolve_secret_key(tmp_path) == resolve_secret_key(tmp_path)

    def test_env_var_takes_precedence(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("TGV_SECRET_KEY", "explicit-key")
        assert resolve_secret_key(tmp_path) == "explicit-key"
        assert not (tmp_path / SECRET_KEY_FILE).exists(), "有环境变量时不该再生成文件"

    def test_env_change_does_not_clobber_existing_file(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        first = resolve_secret_key(tmp_path)
        monkeypatch.setenv("TGV_SECRET_KEY", "other")
        resolve_secret_key(tmp_path)
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        assert resolve_secret_key(tmp_path) == first, "密钥文件被环境变量覆盖写坏"

    def test_config_encryption_on_by_default(self, tmp_path: Path, monkeypatch) -> None:
        """核心断言：不设任何环境变量，Config 也必须启用加密。"""
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        cfg = Config(config_dir=tmp_path)
        assert cfg.encryption_enabled is True, "默认未启用加密"
        cfg.save_secrets({"telegram": {"api_hash": "must-not-be-plaintext"}})
        raw = cfg.secrets_file.read_text(encoding="utf-8")
        assert "must-not-be-plaintext" not in raw
        assert cfg.load_secrets()["telegram"]["api_hash"] == "must-not-be-plaintext"

    def test_survives_across_config_instances(self, tmp_path: Path, monkeypatch) -> None:
        """重启服务（新建 Config）后必须还能解密已有密文。"""
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        Config(config_dir=tmp_path).save_secrets({"telegram": {"api_hash": "persisted"}})
        assert Config(config_dir=tmp_path).load_secrets()["telegram"]["api_hash"] == "persisted"

    def test_secretbox_explicit_key_still_works(self) -> None:
        box = SecretBox("k")
        assert box.enabled and box.decrypt(box.encrypt("v")) == "v"


class TestProxyTestLayering:
    """/api/proxy/test 必须分层报错，而不是笼统说「连不上」。

    真机踩坑：socksio 缺失被报成"无法访问 api.telegram.org"，
    用户以为节点坏了，实际是缺依赖。
    """

    @pytest.fixture()
    def client(self, tmp_path: Path, monkeypatch):
        from fastapi.testclient import TestClient
        from server import config as cfgmod
        from server import main as srv

        monkeypatch.setenv("TGV_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.delenv("TGV_SECRET_KEY", raising=False)
        monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path / "config")
        srv.STATE = srv.AppState()
        srv.STATE.load_from_config()
        with TestClient(srv.app) as c:
            yield c, srv
        srv.STATE.stop_proxy()

    def test_reports_not_ready_without_proxy(self, client) -> None:
        c, srv = client
        srv.STATE.stop_proxy()
        r = c.post("/app/tg-video-dl/api/proxy/test", json={})
        d = r.json()
        assert d["ok"] is False
        assert "代理未就绪" in d["detail"]
        # 分层检查列表必须存在，便于用户看到卡在哪一层
        assert any(ch["name"] == "xray 进程" for ch in d["checks"])

    def test_direct_mode_targets_network_not_proxy(self, client) -> None:
        """direct 模式不应报「代理未就绪」，而应真的去试网络。"""
        c, srv = client
        srv.STATE.proxy_status = {"mode": "direct", "running": False}
        srv.STATE.outbound = None
        r = c.post("/app/tg-video-dl/api/proxy/test", json={"timeout": 3})
        d = r.json()
        assert "代理未就绪" not in d["detail"]

    def test_instant_failure_is_labelled_as_such(self, client, monkeypatch) -> None:
        """瞬时失败必须被标注为「配置/依赖问题」而不是含糊的「无法访问」。"""
        c, srv = client
        # 造一个「运行中」但实际不可用的 socks 地址
        class FakeOut:
            running = True
            socks_port = 1  # 必然连不上
            socks_url = "socks5://127.0.0.1:1"
            def stop(self): pass

        srv.STATE.outbound = FakeOut()
        srv.STATE.proxy_status = {"mode": "v2ray", "running": True}
        r = c.post("/app/tg-video-dl/api/proxy/test", json={"timeout": 3})
        d = r.json()
        assert d["ok"] is False
        # 应当明确指出 socks 端口这一层不通
        names = {ch["name"]: ch["ok"] for ch in d["checks"]}
        assert "SOCKS 端口" in names
        assert names["SOCKS 端口"] is False


class TestBuildConfigNoRegressions:
    def test_generated_config_is_valid_json(self) -> None:
        import json

        ep = parse_v2ray_uri(
            "vless://uuid@node.example.com:46192?security=tls&type=ws&path=/&sni=node.example.com&fp=chrome#n"
        )
        cfg = build_xray_config(ep, 10809)
        json.dumps(cfg)
        assert cfg["inbounds"][0]["port"] == 10809


@pytest.mark.skipif(os.name == "nt", reason="POSIX 进程组语义")
class TestOrphanCleanupContract:
    """cmd/main 依赖 `tgvdl_xray_` 文件名前缀做 pkill 清扫，命名不能变。"""

    def test_config_filename_prefix_matches_cmdmain_pattern(self) -> None:
        import tempfile

        fd, path = tempfile.mkstemp(prefix="tgvdl_xray_", suffix=".json")
        os.close(fd)
        try:
            assert Path(path).name.startswith("tgvdl_xray_")
        finally:
            os.unlink(path)

    def test_cmdmain_uses_same_prefix(self) -> None:
        main = (
            Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "cmd" / "main"
        ).read_text(encoding="utf-8")
        assert "tgvdl_xray_" in main, "cmd/main 的 pkill 模式与 xray 配置名前缀不一致"


class TestXrayLogResilience:
    """缺陷 5（真机回归）：日志文件不可写导致 xray 起不来。

    现象：面板显示
        xray 启动失败：[Errno 13] Permission denied: '.../logs/xray-stderr.log'
    成因：日志文件被 root 创建（曾以 root 身份重启），而后应用以 package 用户
          运行 xray，打不开该文件。**日志只是诊断手段，不该阻断启动。**
    """

    def test_starts_even_when_log_dir_unwritable(self, tmp_path: Path, monkeypatch) -> None:
        """日志目录不可写时，xray 仍应正常启动（降级到 /tmp）。"""
        # 假 xray：能正常跑（sleep），证明启动了
        fake = tmp_path / "xray"
        fake.write_text("#!/bin/sh\nexec sleep 30\n")
        fake.chmod(0o755)
        monkeypatch.setenv("TGV_XRAY_BIN", str(fake))

        # 造一个不可写的日志目录
        logdir = tmp_path / "logs"
        logdir.mkdir()
        # 把 xray-stderr.log 造成一个目录 → open(..., "ab") 必然失败
        (logdir / "xray-stderr.log").mkdir()
        monkeypatch.setenv("TGV_LOG_DIR", str(logdir))

        ep = parse_v2ray_uri("trojan://pw@h:443#x")
        ob = XrayOutbound(ep, socks_port=_pick_free_port())
        # 假 xray 不会真的 listen，所以 start() 会因 socks 未就绪而失败；
        # 这里只断言**失败原因不是日志权限**，即降级逻辑生效了。
        with pytest.raises(XrayError) as ei:
            ob.start()
        msg = str(ei.value)
        assert "Permission denied" not in msg or "xray-stderr" not in msg, (
            f"日志不可写仍然阻断了 xray：{msg}"
        )
        ob.stop()

    def test_log_dir_creation_failure_falls_back(self, tmp_path: Path, monkeypatch) -> None:
        """TGV_LOG_DIR 指向一个不可创建的位置时，_stderr_log_path 应回落到 /tmp。"""
        from server.xray_outbound import _stderr_log_path

        # 用一个「父路径是文件」的路径，mkdir 必然失败
        blocker = tmp_path / "blocker"
        blocker.write_text("x")
        monkeypatch.setenv("TGV_LOG_DIR", str(blocker / "sub"))
        out = _stderr_log_path()
        assert "blocker" not in str(out), f"未回落到临时目录：{out}"


def _pick_free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestPortConflict:
    """缺陷 6（真机回归）：遗留 xray 占用 SOCKS 端口 → 新 xray exit=255 且无输出。

    现象：面板报
        xray 启动后立即崩溃（exit=255）：无输出
    exit=255 + 完全无 stderr 是 Go 程序 **bind 失败**的典型表现；
    成因是我用 root 重启留下了一个旧 xray 继续占着 10809，
    而后服务以 tgvdl 运行，新 xray 抢不到端口。
    """

    def test_port_in_use_detects_listener(self) -> None:
        import socket

        from server.xray_outbound import port_in_use

        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            assert port_in_use(port) is True
        assert port_in_use(port) is False

    def test_find_our_xray_pids_returns_list(self) -> None:
        from server.xray_outbound import find_our_xray_pids

        assert isinstance(find_our_xray_pids(), list)

    def test_reclaim_port_succeeds_when_free(self) -> None:
        """端口空闲时 reclaim 直接成功（无需杀任何进程）。"""
        from server.xray_outbound import free_port, reclaim_port

        assert reclaim_port(free_port()) is True

    def test_reclaim_returns_false_for_foreign_listener(self) -> None:
        """端口被**非本应用**的进程占用时不得乱杀，应返回 False。"""
        import socket

        from server.xray_outbound import reclaim_port

        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            # 占用者不是 xray，find_our_xray_pids 找不到 → 应如实返回 False
            assert reclaim_port(port) is False

    def test_exit_255_without_output_mentions_port(self, tmp_path: Path, monkeypatch) -> None:
        """exit=255 且无输出时，错误信息必须提示端口占用这一头号嫌疑。"""
        fake = tmp_path / "xray"
        fake.write_text("#!/bin/sh\nexit 255\n")   # 静默退出，模拟 bind 失败
        fake.chmod(0o755)
        monkeypatch.setenv("TGV_XRAY_BIN", str(fake))
        monkeypatch.setenv("TGV_LOG_DIR", str(tmp_path / "logs"))

        from server.xray_outbound import free_port

        port = free_port()
        ob = XrayOutbound(parse_v2ray_uri("trojan://pw@h:443#x"), socks_port=port)
        with pytest.raises(XrayError) as ei:
            ob.start()
        msg = str(ei.value)
        assert "exit=255" in msg
        assert "端口" in msg, f"未提示端口占用：{msg}"


class TestTelethonProxyFormat:
    """缺陷 7（真机回归）：telethon 不接受代理 URL 字符串。

    实测：传 `"socks5://127.0.0.1:10809"` 抛
        TypeError: Proxy of unknown format: <class 'str'>
    telethon 要的是元组 (protocol, addr, port, user, pass, rdns)。

    这与 httpx 相反（httpx 要 URL 字符串）——正是 FEASIBILITY §9.5
    警告的「telethon 与 httpx 各传各的参数，极易漏配」。
    若不复现此 bug，登录请求会以"看起来像网络问题"的方式失败。
    """

    def test_returns_tuple_not_string(self) -> None:
        from server.tg_client import proxy_for_telethon

        out = proxy_for_telethon("socks5://127.0.0.1:10809")
        assert isinstance(out, tuple), f"必须是元组，实际 {type(out)}（telethon 会拒绝字符串）"
        assert len(out) == 6

    def test_parses_host_port(self) -> None:
        from server.tg_client import proxy_for_telethon

        proto, host, port, user, pwd, rdns = proxy_for_telethon("socks5://127.0.0.1:10809")
        assert proto == "socks5" and host == "127.0.0.1" and port == 10809
        assert user is None and pwd is None
        assert rdns is True, "应让代理解析域名（socks5h 语义）"

    def test_parses_credentials(self) -> None:
        from server.tg_client import proxy_for_telethon

        proto, host, port, user, pwd, _ = proxy_for_telethon("socks5://u:p@1.2.3.4:1080")
        assert user == "u" and pwd == "p"

    def test_none_and_empty(self) -> None:
        from server.tg_client import proxy_for_telethon

        assert proxy_for_telethon(None) is None
        assert proxy_for_telethon("") is None

    def test_bare_hostport(self) -> None:
        """容错：未写协议时按 socks5 处理。"""
        from server.tg_client import proxy_for_telethon

        out = proxy_for_telethon("127.0.0.1:1080")
        assert out is not None and out[1] == "127.0.0.1" and out[2] == 1080


class TestDownloadStallDetection:
    """缺陷 8（真机回归）：下载中途静默中断 → 任务永久卡在 running。

    实测证据：任务 total=1 running=1，进度停在 56.7% 再不动，
    .part 文件 9.4MB/15.9MB 停止增长，**既不完成也不报错**。
    根因：telethon 的 iter_download 在网络静默断开时永不抛异常，只挂起。
    """

    def test_stalled_download_raises(self, tmp_path: Path, monkeypatch) -> None:
        """永不产出的迭代器必须在 STALL_TIMEOUT 后被判定为停滞。"""
        import asyncio

        from server.downloader import stream_to_file

        monkeypatch.setattr("server.downloader.STALL_TIMEOUT", 0.3)

        class HungClient:
            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                await asyncio.sleep(3600)   # 永久挂起（模拟网络静默中断）
                yield b""                   # pragma: no cover

        msg = SimpleNamespace(id=1, media=object())
        target = tmp_path / "a.mp4"

        with pytest.raises(RuntimeError, match="停滞"):
            asyncio.run(stream_to_file(HungClient(), msg, target, resume=True, total=1000))

    def test_part_kept_after_stall_for_resume(self, tmp_path: Path, monkeypatch) -> None:
        """停滞失败后应保留 .part（开启续传时），便于下次接着下。"""
        import asyncio

        from server.downloader import stream_to_file

        monkeypatch.setattr("server.downloader.STALL_TIMEOUT", 0.3)

        class StallingClient:
            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                yield b"x" * 1000          # 先给一块
                await asyncio.sleep(3600)  # 然后卡住
                yield b""                  # pragma: no cover

        msg = SimpleNamespace(id=1, media=object())
        target = tmp_path / "a.mp4"
        with pytest.raises(RuntimeError, match="停滞"):
            asyncio.run(stream_to_file(StallingClient(), msg, target, resume=True, total=5000))

        part = tmp_path / "a.mp4.part"
        assert part.is_file() and part.stat().st_size == 1000, "停滞时应保留已下部分以便续传"

    def test_healthy_download_unaffected(self, tmp_path: Path, monkeypatch) -> None:
        """看门狗不能误伤正常下载（每次都有数据）。"""
        import asyncio

        from server.downloader import stream_to_file

        monkeypatch.setattr("server.downloader.STALL_TIMEOUT", 5.0)

        class SlowButAlive:
            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                for _ in range(5):
                    await asyncio.sleep(0.05)   # 慢，但持续产出
                    yield b"y" * 100

        msg = SimpleNamespace(id=1, media=object())
        target = tmp_path / "a.mp4"
        n = asyncio.run(stream_to_file(SlowButAlive(), msg, target, total=500))
        assert n == 500


class TestLogNoiseSuppression:
    """缺陷 9（真机回归）：telethon 的 DEBUG 日志淹没应用日志。

    实测：日志 3.5MB / 4877 行，其中**只有 48 行是本应用的**，
    其余是 telethon 的 MTProto 原始字节 dump。排障时关键信息被埋掉。
    """

    def test_noisy_loggers_are_suppressed(self, tmp_path: Path, monkeypatch) -> None:
        import logging

        from fastapi.testclient import TestClient
        from server import config as cfgmod
        from server import main as srv

        monkeypatch.setenv("TGV_CONFIG_DIR", str(tmp_path / "config"))
        monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path / "config")
        srv.STATE = srv.AppState()
        srv.STATE.load_from_config()

        with TestClient(srv.app):   # 触发 lifespan → 配置日志
            pass

        for name in ("telethon", "telethon.network", "telethon.client", "httpx", "httpcore"):
            lvl = logging.getLogger(name).level
            assert lvl >= logging.WARNING, f"{name} 日志级别过低（{lvl}），会淹没应用日志"
        srv.STATE.stop_proxy()


class TestStallWatchdogSwallowsCancel:
    """缺陷 12（真机回归，严重）：wait_for 无法中断吞掉 CancelledError 的协程。

    真机现象：任务卡在 74.6% 长达**两天**，进程仍存活在 epoll_wait，
    看门狗（wait_for 版）从未触发。

    根因：asyncio.wait_for 超时后靠 **cancel** 终止任务，但 telethon 在
    重试/重连路径上会捕获并吞掉 CancelledError
    （client/downloads.py `_request` 的 TimedOutError/FileMigrateError/
    FileReferenceExpired 分支均递归重试；client/users.py 亦有抑制），
    取消不生效 → wait_for 永远等下去。

    修复：改用 asyncio.wait({task}, timeout) 观察完成情况；
    超时后**不依赖取消**，直接判定停滞。
    """

    def test_old_wait_for_approach_hangs_in_subprocess(self) -> None:
        """证明旧方案（wait_for）会被吞取消的协程卡死。

        ⚠️ 必须放**子进程**并加超时：该失效模式的本质就是"永不返回"，
        在本进程里跑会直接挂死整个测试套件。子进程超时即证明旧方案卡死。

        ⚠️ 也要用独立 loop 而非 asyncio.run()：run 退出时会等待那个
        永不结束的 reader task。（真机与本地均验证过）
        """
        import subprocess

        code = (
            "import asyncio\n"
            "async def swallow():\n"
            "    while True:\n"
            "        try:\n"
            "            await asyncio.sleep(3600)\n"
            "        except asyncio.CancelledError:\n"
            "            continue\n"
            "        yield b'x'\n"
            "async def main():\n"
            "    agen = swallow().__aiter__()\n"
            "    try:\n"
            "        await asyncio.wait_for(agen.__anext__(), timeout=0.2)\n"
            "        return 'no-timeout'\n"
            "    except TimeoutError:\n"
            "        return 'timeout-ok'\n"
            "loop = asyncio.new_event_loop()\n"
            "print(loop.run_until_complete(main()))\n"
        )
        with pytest.raises(subprocess.TimeoutExpired):
            subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True, text=True, timeout=8,
            )

    def test_new_wait_approach_detects_stall(self) -> None:
        """证明新方案（asyncio.wait，不依赖取消）能判定停滞。

        用独立 loop 并显式清理残留 task：reader 永不结束，
        若用 asyncio.run 会在退出时死等它。
        """
        import asyncio

        async def swallow():
            while True:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    continue
                yield b"x"                # pragma: no cover

        async def new_way() -> bool:
            agen = swallow().__aiter__()
            reader = asyncio.ensure_future(agen.__anext__())
            done, _ = await asyncio.wait({reader}, timeout=0.3)
            if not done:
                reader.cancel()           # 尽力而为，被吞也无妨
                return True               # 判定停滞
            return False

        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(new_way())
        finally:
            # ⚠️ 不要 gather 残留 task —— 它会吞取消、永不结束，
            # 等它就等于挂死（这正是本项目踩过的坑）。
            # 直接关 loop 并抑制告警即可。
            for t in asyncio.all_tasks(loop):
                if not t.done():
                    t.cancel()
            loop.close()

        assert ok is True, "新方案(asyncio.wait)未能在超时后判定停滞"

    def test_stream_to_file_detects_stall_with_swallowing_client(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """端到端：用「吞取消」的假客户端验证 stream_to_file 能判停滞。

        ⚠️ 必须用独立 loop + run_until_complete，**不能用 asyncio.run**：
        残留的 reader task 永不结束，asyncio.run 退出时会等它 → 测试挂死
        （真机已验证过这一现象）。
        """
        import asyncio

        from server.downloader import stream_to_file

        monkeypatch.setattr("server.downloader.STALL_TIMEOUT", 0.3)

        class SwallowingClient:
            """模拟 telethon：挂起且吞掉取消。"""

            async def iter_download(self, media, chunk_size=1024, offset=0, **kw):
                yield b"a" * 1000            # 先给一块
                while True:
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        continue             # 吞掉取消
                    yield b""                # pragma: no cover

        msg = SimpleNamespace(id=1, media=object())
        target = tmp_path / "a.mp4"

        loop = asyncio.new_event_loop()
        try:
            coro = stream_to_file(
                SwallowingClient(), msg, target, resume=True, total=9000
            )
            try:
                loop.run_until_complete(coro)
                result = "completed"
            except RuntimeError as e:
                result = "stall" if "停滞" in str(e) else f"other:{e}"
        finally:
            # 同上：不 gather 残留 task（会吞取消、永不结束）
            for t in asyncio.all_tasks(loop):
                if not t.done():
                    t.cancel()
            loop.close()

        assert result == "stall", f"未能识别停滞（结果={result}）"
        assert (tmp_path / "a.mp4.part").is_file(), "停滞时应保留 .part 供续传"


class TestMessageCache:
    """缺陷 13（真机回归）：重新拉取消息时 telethon 解析失败 → 下载失败。

    真机现象：两个来自**频道**的视频（#4/#5）连续失败 3 次：
        RuntimeError: 重新获取消息失败：Could not find a matching Constructor ID
        for the TLObject that was supposed to be read with ID 31774388.

    根因：原流程「监听到消息 → 只存元数据 → worker 重新拉取」，
    而重新拉取依赖 telethon 解析完整实体列表；Telegram 一旦下发
    telethon 不认识的新对象（1.45.0 已是最新版仍不认识），就抛
    TypeNotFoundError → 下载失败。

    而消息刚到达时**手里就有完整对象**，根本不需要重新拉取。
    """

    def test_cache_roundtrip(self) -> None:
        from server.downloader import cache_message, get_cached_message

        msg = SimpleNamespace(id=555, video=None)
        cache_message(msg, "saved")          # 键与 DB 一致（media.chat）
        assert get_cached_message("saved", 555) is msg

    def test_cache_miss_returns_none(self) -> None:
        from server.downloader import get_cached_message

        assert get_cached_message("me", 999999) is None

    def test_cache_evicts_oldest(self) -> None:
        """缓存有上限，不能无限增长（长跑应用的内存安全）。"""
        import server.downloader as dl

        dl._msg_cache.clear()
        limit = dl.MESSAGE_CACHE_SIZE
        for i in range(limit + 5):
            dl.cache_message(SimpleNamespace(id=i), "saved")
        assert len(dl._msg_cache) <= limit, f"超出上限：{len(dl._msg_cache)} > {limit}"
        newest = limit + 4
        assert dl.get_cached_message("saved", newest) is not None, "最新应保留"
        assert dl.get_cached_message("saved", 0) is None, "最旧应被淘汰"
        dl._msg_cache.clear()

    def test_on_media_caches_message(self, tmp_path: Path, monkeypatch) -> None:
        """回调收到消息时必须立刻缓存（否则 worker 又要重新拉取）。"""
        import asyncio

        import server.downloader as dl
        from server.config import Config
        from server.db import TaskDB

        dl._msg_cache.clear()
        db = TaskDB(tmp_path / "t.sqlite")
        cfg = Config(config_dir=tmp_path / "cfg", secret_key="k")
        cfg.save({"download": {"dir": str(tmp_path / "dl"), "path_template": "{filename}"}})

        class FakeQueue:
            def notify(self): pass

        handler = dl.on_media_message_factory(object(), db, FakeQueue(), cfg)

        # 类名必须是 MessageMediaDocument（identify_media 按类名判定）
        class MessageMediaDocument:  # noqa: N801
            pass

        msg = SimpleNamespace(
            id=777, chat_id="me", chat=None, media=MessageMediaDocument(),
            video=SimpleNamespace(size=1000, mime_type="video/mp4", id="f",
                                  attributes=[SimpleNamespace(file_name="a.mp4")]),
            document=None,
        )
        asyncio.run(handler(msg))
        # 键与 DB 一致：media.chat（收藏夹场景为 "saved"）
        assert dl.get_cached_message("saved", 777) is msg, "回调未按 media.chat 缓存"
        dl._msg_cache.clear()


def _run_isolated(coro, timeout: float = 15.0):
    """在独立 loop 里跑协程，退出前直接放弃残留 task。

    ⚠️ 不能用 asyncio.run：本文件后面的用例专门模拟「吞掉取消」的协程，
    run 退出时会 gather 这些永不结束的 task → 测试挂死（真机已验证过）。
    """
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout))
    finally:
        for t in asyncio.all_tasks(loop):
            if not t.done():
                t.cancel()
        loop.close()


class TestNotifyNeverWedgesWorker:
    """缺陷 14（真机回归，2026-09-19 卡死 42 小时）：通知类 TG 调用挂死。

    真机现象：任务 #4 卡在 60.7% 长达 42 小时 —— .part 不再增长、数据库
    updated_at 与文件 mtime 同时冻结（09-19 20:26:23），**日志里没有任何失败
    记录**，任务永远停在 running，并发槽被占死（并发=1 → 整个队列停摆）。

    根因：下载循环的停滞看门狗只包住 `iter_download` 的取块动作，
    **管不到**同一个 worker 里的其它 await —— 进度播报 `edit_message`、
    失败通知 `reporter.fail()`、收尾 drain。这些 TG 调用一旦永久挂起，
    worker 就再也不返回，既不报错也不重试。
    """

    def test_hung_edit_message_returns_within_timeout(self, monkeypatch) -> None:
        import asyncio

        from server.notify import ProgressReporter

        monkeypatch.setattr("server.notify.NOTIFY_TIMEOUT", 0.2)

        class SwallowingClient:
            """首条消息正常发送，之后 edit_message 永久挂起并吞掉取消。"""

            async def send_message(self, who, text):
                return SimpleNamespace(id=1)

            async def edit_message(self, who, mid, text):
                while True:
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        continue          # 模拟 telethon 吞取消
                    return None           # pragma: no cover

        rep = ProgressReporter(SwallowingClient(), task_id=1, filename="a.mp4", total=1000)

        started = time.monotonic()
        _run_isolated(rep.on_progress(10, 1000))     # 首条：_send 正常
        _run_isolated(rep.on_progress(900, 1000))    # 挂死的 _edit：必须限时返回
        _run_isolated(rep.fail("boom"))              # 失败通知同样不能卡住
        elapsed = time.monotonic() - started

        assert elapsed < 5.0, f"挂死的通知调用拖住了 worker（{elapsed:.1f}s）"

    def test_pump_drain_cannot_hang_forever(self, tmp_path: Path, monkeypatch) -> None:
        """收尾 `await pump_task` 必须有上限（真机卡死点之一）。"""
        import asyncio

        import server.downloader as dl

        monkeypatch.setattr(dl, "PUMP_DRAIN_TIMEOUT", 0.2)

        class SwallowingTask:
            """模拟一个永远不结束、且吞掉取消的收尾协程。"""

            async def run(self) -> None:
                while True:
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        continue                  # 吞取消
                    return                        # pragma: no cover

        async def scenario() -> float:
            from server.aio_guard import run_bounded

            task = asyncio.ensure_future(SwallowingTask().run())
            await asyncio.sleep(0.05)              # 让它真正跑起来、停在 await 上
            task.cancel()                          # 等价于 downloader 收尾时的 cancel
            started = asyncio.get_running_loop().time()
            ok, _t = await run_bounded(task, dl.PUMP_DRAIN_TIMEOUT, what="进度播报收尾")
            spent = asyncio.get_running_loop().time() - started
            assert ok is False, "吞掉取消的协程不可能按时结束，必须判定为超时"
            return spent

        spent = _run_isolated(scenario())
        assert spent < 3.0, f"收尾 drain 没有上限，卡了 {spent:.1f}s"


class TestWorkerLevelWatchdog:
    """缺陷 15（真机回归，2026-09-19）：worker 卡死必须能被队列层兜住。

    即使将来又有某条 await 路径挂死（通知、收尾、telethon 内部……），
    队列也不能停摆：靠「数据库心跳」判定无进展 → 放弃该 worker 协程
    （不 await 它）+ 丢弃残留 .part → 走正常重试/失败流程 → 继续下一个任务。
    """

    def test_wedged_worker_abandoned_and_part_discarded(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import asyncio

        from server.db import TaskDB
        from server.queue import DownloadQueue, WorkerStalled

        monkeypatch.setattr("server.queue.WORKER_IDLE_TIMEOUT", 0.2)
        monkeypatch.setattr("server.queue.HEARTBEAT_INTERVAL", 0.05)

        target = tmp_path / "a.mp4"
        part = tmp_path / "a.mp4.part"
        part.write_bytes(b"x" * 4096)

        async def hanging_worker(task) -> None:
            while True:
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    continue                  # 吞取消（模拟 telethon）
                return                        # pragma: no cover

        db = TaskDB(tmp_path / "t.sqlite")
        rec, _created = db.enqueue(
            chat_id="saved", message_id=1, filename="a.mp4", size=10,
            target_path=str(target),
        )
        assert rec is not None
        db.mark_running(rec.id)
        db.mark_progress(rec.id, 5)           # 最后一次心跳，之后就不再推进

        q = DownloadQueue(db, hanging_worker, concurrency=1)
        task = db.get(rec.id)
        started = time.monotonic()
        with pytest.raises(WorkerStalled):
            _run_isolated(q._run_worker(task))
        spent = time.monotonic() - started

        assert spent < 5.0, f"看门狗没有及时判定卡死（{spent:.1f}s）"
        assert not part.exists(), "卡死后必须丢弃残留分片，否则僵尸写者会写坏文件"

    def test_queue_survives_wedged_worker_and_continues(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """端到端：第 1 个任务永远卡死 → 重试到失败；第 2 个任务照常完成。"""
        import asyncio

        from server.db import DONE, FAILED, TaskDB
        from server.queue import DownloadQueue

        monkeypatch.setattr("server.queue.WORKER_IDLE_TIMEOUT", 0.2)
        monkeypatch.setattr("server.queue.HEARTBEAT_INTERVAL", 0.05)
        monkeypatch.setattr("server.queue.BASE_BACKOFF", 0.0)
        monkeypatch.setattr("server.queue.MAX_BACKOFF", 0.0)

        db = TaskDB(tmp_path / "t.sqlite")
        stuck, _ = db.enqueue(chat_id="saved", message_id=1, filename="stuck.mp4", size=10)
        ok2, _ = db.enqueue(chat_id="saved", message_id=2, filename="second.mp4", size=10)

        async def worker(task) -> None:
            if task.id == stuck.id:
                while True:
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        continue              # 吞取消
                    return                    # pragma: no cover
            db.mark_done(task.id)             # 第二个任务直接成功

        async def scenario() -> dict:
            q = DownloadQueue(db, worker, concurrency=1)
            await q.start()
            states: dict = {}
            for _ in range(300):              # 最多等 ~15s
                await asyncio.sleep(0.05)
                states = {r.id: r.state for r in db.list(limit=10)}
                if states.get(ok2.id) == DONE and states.get(stuck.id) == FAILED:
                    break
            await q.stop()
            return states

        states = _run_isolated(scenario(), timeout=30)
        assert states.get(ok2.id) == DONE, f"队列没有从卡死的 worker 里恢复：{states}"
        assert states.get(stuck.id) == FAILED, f"卡死任务应重试到失败：{states}"

    def test_runtime_zombie_reclaim(self, tmp_path: Path) -> None:
        """库里有 running、但本进程没有 worker 在跑 → 运行期就该回收。"""
        from server.db import PENDING, RUNNING, TaskDB
        from server.queue import DownloadQueue

        db = TaskDB(tmp_path / "t.sqlite")
        rec, _ = db.enqueue(chat_id="saved", message_id=7, filename="z.mp4", size=10)
        assert rec is not None
        db.mark_running(rec.id)

        q = DownloadQueue(db, lambda task: None, concurrency=1)
        q._reclaim_zombies()
        assert db.get(rec.id).state == PENDING, "运行期僵尸任务没有被放回队列"

        # 有任务正在跑时绝不能回收（否则会误伤正在下载的任务）
        db.mark_running(rec.id)
        q._inflight.add(rec.id)
        q._reclaim_zombies()
        assert db.get(rec.id).state == RUNNING, "有 inflight 时不应回收"
        q._inflight.clear()


class TestMessageCachePersistence:
    """缺陷 13 延伸（真机回归）：消息缓存必须跨重启存活。

    缓存只在进程内时，重启（或崩溃后被拉起）会让排队中的旧任务退回
    「按 message_id 重新拉取」——而 Telegram 下发的某些新对象 telethon
    解析不了（TypeNotFoundError: Constructor ID 31774388），下载必然再失败。
    """

    def test_message_cache_persist_roundtrip(self, tmp_path: Path, monkeypatch) -> None:
        import datetime
        import threading

        import server.downloader as dl
        from telethon.tl import types

        class _Loggers:
            """模拟 telegram client 里 `__init__` 中定义的**局部类**（不可 pickle）。"""

        def _init(self) -> None:
            self._log = _Loggers()
            self.lock = threading.RLock()

        # 类型名/模块与真机一致（telethon 的 TelegramBaseClient）：
        # 落盘时必须把整个 client 引用丢掉，否则就是真机上那条
        # 「Can't pickle local object 'TelegramBaseClient.__init__.<locals>._Loggers'」。
        FakeClient = type(
            "TelegramBaseClient",
            (),
            {"__init__": _init, "__module__": "telethon.client.telegrambaseclient"},
        )

        cache_file = tmp_path / "msg_cache.pkl"
        monkeypatch.setenv("TGV_MSG_CACHE_FILE", str(cache_file))
        dl.reset_message_cache()

        doc = types.Document(
            id=1, access_hash=2, file_reference=b"\x01",
            date=datetime.datetime.now(), mime_type="video/mp4", size=100, dc_id=4,
            attributes=[types.DocumentAttributeFilename(file_name="a.mp4")],
        )
        msg = types.Message(
            id=200, peer_id=types.PeerUser(user_id=1), date=datetime.datetime.now(),
            message="x", media=types.MessageMediaDocument(document=doc),
        )
        msg._client = FakeClient()          # 真机就是被这个拖垮的（Can't pickle local object）

        dl.cache_message(msg, "saved")
        assert cache_file.is_file(), "live 消息对象也必须能落盘（这是真机失败点）"

        dl.reset_message_cache()                       # 模拟进程重启：内存清空
        assert len(dl._msg_cache) == 0
        assert dl.load_message_cache() == 1, "未能从磁盘恢复消息缓存"
        restored = dl.get_cached_message("saved", 200)
        assert restored is not None and restored.id == 200
        assert restored.media.document.size == 100
        assert restored._client is None, "运行期 client 引用应被丢弃，不参与持久化"

        dl.reset_message_cache(drop_disk=True)

    def test_corrupt_cache_degrades_gracefully(self, tmp_path: Path, monkeypatch) -> None:
        """缓存文件损坏不能让服务起不来：读失败即降级为「无缓存」。"""
        import server.downloader as dl

        cache_file = tmp_path / "bad.pkl"
        cache_file.write_bytes(b"not-a-pickle")
        monkeypatch.setenv("TGV_MSG_CACHE_FILE", str(cache_file))
        dl.reset_message_cache()

        assert dl.load_message_cache() == 0            # 只降级，不抛错
        assert dl.get_cached_message("saved", 1) is None
        dl.reset_message_cache(drop_disk=True)

    def test_no_env_means_no_disk_side_effects(self, monkeypatch) -> None:
        """未配置数据目录（如单元测试）时不应产生任何落盘行为。"""
        import server.downloader as dl

        monkeypatch.delenv("TGV_MSG_CACHE_FILE", raising=False)
        monkeypatch.delenv("TGV_DATA_DIR", raising=False)
        assert dl.message_cache_path() is None
        dl.reset_message_cache()
        assert dl.save_message_cache(force=True) is False


class _FakeTask:
    """最小 asyncio.Task 替身：`background_tasks_alive` 只看 `done()`。"""

    def __init__(self, done: bool = False) -> None:
        self._done = done

    def done(self) -> bool:
        return self._done


class _ZombieClient:
    """能收不能发的僵尸 telethon 客户端（真机态）。

    sender 的收发循环活着（`is_connected()` 恒 True），
    但 `connect()` 被取消在末尾之前 → `_updates_handle`/`_keepalive_handle` 缺失，
    收到的新消息全进无人消费的 `_updates_queue`。
    """

    def __init__(self) -> None:
        self._updates_handle = None       # 关键：缺失
        self._keepalive_handle = None
        self.disconnected = 0

    def is_connected(self) -> bool:
        return True

    def disconnect(self):
        self.disconnected += 1

        async def _noop() -> None:
            return None

        return _noop()


class _FutureDisconnectClient:
    """按 telethon 1.45 的真实行为返回 **Future** 的客户端（缺陷 16 的复现件）。

    真实代码（`telethon/client/telegrambaseclient.py`）：
        if self.loop.is_running():
            return asyncio.shield(self.loop.create_task(self._disconnect_coro()))
    """

    def __init__(self) -> None:
        self.finished = 0

    def is_connected(self) -> bool:
        return True

    async def log_out(self) -> bool:
        return True

    def disconnect(self):
        async def _disconnect_coro() -> None:
            await asyncio.sleep(0)
            self.finished += 1

        # 必须真的在运行的事件循环里调用（与 telethon 一致）
        return asyncio.shield(asyncio.get_running_loop().create_task(_disconnect_coro()))


class _HealthyClient:
    def __init__(self) -> None:
        self._updates_handle = _FakeTask()
        self._keepalive_handle = _FakeTask()
        self.disconnected = 0
        self.connected = 0

    def is_connected(self) -> bool:
        return False

    async def connect(self) -> None:
        self.connected += 1

    async def is_user_authorized(self) -> bool:
        return True

    def disconnect(self):
        self.disconnected += 1

        async def _noop() -> None:
            return None

        return _noop()


class _HangingClient:
    """`connect()` 永不返回（模拟代理不通），但**正常响应取消**（不能吞取消）。"""

    def __init__(self) -> None:
        self.disconnected = 0

    def is_connected(self) -> bool:
        return False

    async def connect(self) -> None:
        import asyncio as _a

        await _a.sleep(3600)

    def disconnect(self):
        self.disconnected += 1

        async def _noop() -> None:
            return None

        return _noop()


class TestZombieTgClient:
    """缺陷 14（真机回归，2026-10-07）：connect() 被取消留下的半连接客户端必须丢弃。

    真机现象：应用 RSS 1.74GB、~50MB/h 线性增长，面板毫无迹象；进程 6.6 分钟
    **零写入**（无 ping/ack），只有收到 TG updates 时 rchar 脉冲、RSS 跟着台阶上涨。
    根因：启动连接 25s 超时触发 `asyncio.wait_for` 取消，取消点正好落在 telethon
    `TelegramClient.connect()` 的「sender 已连上、`_updates_handle`/`_keepalive_handle`
    尚未创建」之间 —— 客户端能收不能发；sender 自己重连且 `is_connected()` 恒为 True，
    应用再也不调用 connect()，这两个后台任务**永不重建**。
    """

    def test_background_tasks_alive_detects_zombie(self) -> None:
        from server.tg_client import background_tasks_alive

        alive = SimpleNamespace(_updates_handle=_FakeTask(), _keepalive_handle=_FakeTask())
        assert background_tasks_alive(alive) is True

        # 缺失（None）或已结束，都算僵尸
        assert background_tasks_alive(
            SimpleNamespace(_updates_handle=None, _keepalive_handle=_FakeTask())
        ) is False
        assert background_tasks_alive(
            SimpleNamespace(_updates_handle=_FakeTask(done=True), _keepalive_handle=_FakeTask())
        ) is False
        # 未知 telethon 版本（两个属性都不存在）：不做判断，避免误判导致反复重建
        assert background_tasks_alive(SimpleNamespace()) is True

    def test_ensure_connected_rebuilds_zombie_client(self) -> None:
        import asyncio

        import server.tg_client as tgmod

        zombie = _ZombieClient()
        healthy = _HealthyClient()
        mgr = tgmod.TgClientManager()
        mgr.session_string = "sess"
        mgr._client = zombie
        built: list[str] = []

        def _build(session: str = "") -> object:
            built.append(session)
            return healthy

        mgr._build_client = _build  # type: ignore[method-assign]

        client = asyncio.run(mgr.ensure_connected())

        assert client is healthy, "僵尸客户端必须被整只替换"
        assert zombie.disconnected == 1, "丢弃僵尸客户端时要真的断开（否则 sender 还在后台跑）"
        assert built == ["sess"], "重建时要把 session 传下去"

    def test_connect_timeout_discards_half_client(self, monkeypatch) -> None:
        """连接超时（代理不通）绝不能把半连接客户端留在 `_client` 里。"""
        import asyncio

        import server.tg_client as tgmod

        monkeypatch.setattr(tgmod, "CONNECT_TIMEOUT", 0.05)
        client = _HangingClient()
        mgr = tgmod.TgClientManager()
        mgr.session_string = "sess"
        mgr._client = client

        with pytest.raises(tgmod.TgUnreachable):
            asyncio.run(mgr.ensure_connected())

        assert mgr._client is None, "超时后不得留下半连接客户端（就是它把内存吃掉的）"
        assert client.disconnected == 1, "超时后必须断开，否则 sender 会继续在后台收消息"

    def test_drop_client_is_safe_without_running_loop(self) -> None:
        """同步上下文（如配置热更新）里丢客户端：不得抛错、不得留下未 await 的协程。"""
        import server.tg_client as tgmod

        mgr = tgmod.TgClientManager()
        mgr._client = _ZombieClient()
        mgr._monitor_started = True

        mgr._drop_client()  # 不应抛错

        assert mgr._client is None
        assert mgr._monitor_started is False

    def test_drop_client_with_future_disconnect_in_running_loop(self) -> None:
        """★缺陷 16（真机回归，2026-10-08）：telethon 1.45 的 `disconnect()` 在事件
        循环里返回的是 **Future**（`asyncio.shield(loop.create_task(...))`），
        旧实现 `loop.create_task(result)` 会抛
        `TypeError: a coroutine was expected, got <Future pending ...>`
        → 面板「保存设置」/「退出登录」全部 HTTP 500（真机实测）。
        """
        import asyncio

        import server.tg_client as tgmod

        client = _FutureDisconnectClient()
        mgr = tgmod.TgClientManager()
        mgr._client = client
        mgr._monitor_started = True

        async def scenario() -> None:
            mgr._drop_client()                  # 关键：不得抛错
            await asyncio.sleep(0.05)           # 让后台断开真的跑完
            assert client.finished == 1, "被丢弃的客户端必须真的断开（sender 不能留在后台）"

        asyncio.run(scenario())
        assert mgr._client is None
        assert mgr._monitor_started is False

    def test_sign_out_with_future_disconnect(self) -> None:
        """退出登录同样走 `_drop_client()`，必须不再 500。"""
        import asyncio

        import server.tg_client as tgmod

        client = _FutureDisconnectClient()
        mgr = tgmod.TgClientManager()
        mgr._client = client
        mgr.session_string = "sess"

        async def scenario() -> None:
            await mgr.sign_out()
            await asyncio.sleep(0.05)      # 让后台断开真的跑完（asyncio.run 退出会取消挂起任务）

        asyncio.run(scenario())

        assert mgr.session_string == "", "退出登录必须清掉本地 session"
        assert client.finished == 1


class TestStartupFailureIsolation:
    """缺陷 15（真机回归，2026-10-07）：启动连接失败不得连带废掉队列与监听。

    旧实现把「连接 + 启动队列 + 启动监听 + 补收」塞进同一个 try：10-05 那次启动
    TG 连接超时后，下载队列与收藏夹监听**整整两天没启动**，而半连接客户端还在
    后台吃内存——面板上看不出任何异常。
    """

    def test_restore_failure_keeps_queue_off_and_records_error(self, monkeypatch) -> None:
        import asyncio

        import server.main as m

        started: list[str] = []

        class _Tg:
            async def ensure_connected(self) -> None:
                raise RuntimeError("连接 Telegram超时（25s）")

        class _Queue:
            async def start(self) -> None:
                started.append("queue")

        monkeypatch.setattr(m.STATE, "tg", _Tg())
        monkeypatch.setattr(m.STATE, "queue", _Queue())
        monkeypatch.setattr(m.STATE, "last_error", "")

        assert asyncio.run(m.restore_tg_session()) is False
        assert started == [], "连接失败时不得启动下载队列（会把待下载任务判失败）"
        assert "超时" in m.STATE.last_error, "失败原因要写进 last_error（面板可见）"

    def test_restore_success_starts_queue_then_monitor(self, monkeypatch) -> None:
        import asyncio

        import server.main as m

        events: list[str] = []

        class _Tg:
            async def ensure_connected(self) -> None:
                events.append("connect")

            async def start_monitor(self, handler) -> None:
                events.append("monitor")

        class _Queue:
            async def start(self) -> None:
                events.append("queue")

        class _Cfg:
            def load(self) -> dict:
                return {"behavior": {"enabled": True, "catch_up": False}}

        monkeypatch.setattr(m.STATE, "tg", _Tg())
        monkeypatch.setattr(m.STATE, "queue", _Queue())
        monkeypatch.setattr(m.STATE, "config", _Cfg())
        monkeypatch.setattr(m.STATE, "last_error", "旧错误")

        assert asyncio.run(m.restore_tg_session()) is True
        assert events == ["connect", "queue", "monitor"]
        assert m.STATE.last_error == "", "连上后要清掉旧的错误提示"

    def test_restore_failure_starts_background_retry(self, monkeypatch) -> None:
        """失败后必须起后台重试任务（否则队列/监听永远起不来）。"""
        import asyncio

        import server.main as m

        class _Tg:
            async def ensure_connected(self) -> None:
                raise RuntimeError("boom")

        monkeypatch.setattr(m.STATE, "tg", _Tg())
        monkeypatch.setattr(m, "TG_RETRY_SECONDS", 0.02)

        async def _scenario() -> None:
            m.start_tg_retry()
            assert m._tg_retry_task is not None
            assert await m.restore_tg_session() is False
            m.start_tg_retry()  # 重复调用不得起第二个
            task = m._tg_retry_task
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            m._tg_retry_task = None

        asyncio.run(_scenario())


class TestMemGuard:
    """缺陷 14 的配套观测：RSS 要能在 /api/health 上看到，超阈值要有告警。"""

    def test_rss_mb_reads_proc_status(self) -> None:
        from server.memguard import rss_mb

        assert rss_mb() > 0, "本进程 RSS 必然大于 0（读 /proc/self/status）"

    def test_rss_watch_warns_over_threshold(self, caplog) -> None:
        import asyncio
        import contextlib
        import logging

        from server.memguard import rss_watch

        async def _scenario() -> None:
            task = asyncio.ensure_future(rss_watch(interval=0.01, warn_mb=0.001))
            await asyncio.sleep(0.05)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        with caplog.at_level(logging.WARNING, logger="tgvdl.mem"):
            asyncio.run(_scenario())

        assert "RSS" in caplog.text

    def test_health_reports_rss(self) -> None:
        import server.main as m

        assert "rss_mb" in m.health()


class _LoginClient:
    """登录流程用的 telethon 客户端替身：只暴露 `send_code()` 会碰的属性。

    `session.auth_key` 就是判据本身 —— 裸会话（`StringSession(None)`）为 None，
    从落盘 session 串建起来的客户端一定带值。
    """

    def __init__(self, auth_key: bytes | None = None) -> None:
        self.session = SimpleNamespace(auth_key=auth_key)
        self._updates_handle = _FakeTask()
        self._keepalive_handle = _FakeTask()
        self.connected = True
        self.disconnected = 0
        self.sent: list[str] = []

    def is_connected(self) -> bool:
        return self.connected

    async def send_code_request(self, phone: str):
        self.sent.append(phone)
        return SimpleNamespace(phone_code_hash=f"hash-{len(self.sent)}")

    def disconnect(self):
        self.disconnected += 1

        async def _noop() -> None:
            return None

        return _noop()


class TestReloginRotation:
    """缺陷 17/18（真机，2026-10-12）：重新登录要换 auth key，且**不能碰工作客户端**。

    两条真机事实都要钉住：

    事实 ①：旧实现复用「带落盘授权的客户端」发码，而 telethon 的 `sign_in()` 首行是
        `me = await self.get_me();  if me: return me`
    —— 已授权就直接返回，**用户填的验证码压根没提交给 Telegram**，不签发新 auth key；
    可 `_persist_session()` 照样把同一把旧 key 回写 `.secrets.yaml`：实测该文件 mtime
    与日志「TG 登录成功」同一秒，内容却与操作前备份**逐字节相同**（sha1 不变）。

    事实 ②：第一版修复是「先 `abort_client()` 再登录」，于是 19:50 三次发码全失败
    （504/500/504）时把收藏夹监听一起丢了（`abort_client()` 会清 `_monitor_started`
    / `_on_media`）—— 监听静默停在 19:49:18，直到手动保存一次配置才被重拉。

    最终形态：登录全程只用独立的 `_login_client`，与工作客户端、监听状态完全隔离。
    """

    @staticmethod
    def _manager():
        from server.tg_client import TgClientManager

        return TgClientManager(api_id="24991895", api_hash="hash", proxy_url=None)

    @staticmethod
    def _install_fakes(mgr, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
        calls = SimpleNamespace(built=0)

        async def _preflight() -> None:
            return None

        async def _connect_bounded(
            what: str = "连接 Telegram", *, client=None, abort=None
        ) -> None:
            return None

        def _build(session: str = "") -> _LoginClient:
            calls.built += 1
            return _LoginClient(auth_key=None)

        monkeypatch.setattr(mgr, "preflight", _preflight)
        monkeypatch.setattr(mgr, "_connect_bounded", _connect_bounded)
        monkeypatch.setattr(mgr, "_build_client", _build)
        return calls

    def test_login_never_touches_working_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """事实 ②：发码只用临时客户端，工作客户端与监听状态原样不动。"""
        mgr = self._manager()
        working = _LoginClient(auth_key=b"\x01" * 256)
        mgr._client = working
        mgr._monitor_started = True
        mgr._on_media = lambda _m: None
        calls = self._install_fakes(mgr, monkeypatch)

        state = asyncio.run(mgr.send_code("+8613800138000"))

        assert mgr.client is working, "登录绝不能替换工作客户端"
        assert working.disconnected == 0, "工作客户端不该被断开（断开＝监听随之失效）"
        assert mgr._monitor_started is True and mgr._on_media is not None
        assert mgr._login_client is not None and mgr._login_client is not working
        assert calls.built == 1
        assert mgr._login_client.sent == ["+8613800138000"]
        assert state.stage == "code_sent"

    def test_failed_send_code_keeps_working_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """事实 ②：发码失败也只丢临时客户端，工作链路毫发无损。"""
        from server.tg_client import TgError

        mgr = self._manager()
        working = _LoginClient(auth_key=b"\x01" * 256)
        mgr._client = working
        mgr._monitor_started = True
        mgr._on_media = lambda _m: None

        async def _preflight() -> None:
            return None

        def _build(session: str = "") -> _LoginClient:
            client = _LoginClient(auth_key=None)

            async def _boom(phone: str):
                raise RuntimeError("network down")

            client.send_code_request = _boom  # type: ignore[method-assign]
            return client

        monkeypatch.setattr(mgr, "preflight", _preflight)
        monkeypatch.setattr(mgr, "_build_client", _build)

        with pytest.raises(TgError):
            asyncio.run(mgr.send_code("+8613800138000"))

        assert mgr.client is working and working.disconnected == 0
        assert mgr._monitor_started is True and mgr._on_media is not None
        assert mgr._login_client is None, "失败的临时登录客户端必须丢弃"

    def test_login_client_reused_within_one_attempt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """同一次登录流程内复用临时客户端（send_code → verify 必须同一只）。"""
        mgr = self._manager()
        self._install_fakes(mgr, monkeypatch)

        asyncio.run(mgr.send_code("+8613800138000"))
        first = mgr._login_client
        asyncio.run(mgr.send_code("+8613800138000"))  # 面板「重新发送」

        assert mgr._login_client is first
        assert first is not None and first.sent == ["+8613800138000"] * 2

    def test_already_authorized_stage_rebuilds_login_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """上一轮已 authorized 再点登录 → 换一只干净临时客户端（事实 ①）。"""
        mgr = self._manager()
        self._install_fakes(mgr, monkeypatch)

        asyncio.run(mgr.send_code("+8613800138000"))
        first = mgr._login_client
        mgr._login.stage = "authorized"

        asyncio.run(mgr.send_code("+8613800138000"))

        assert mgr._login_client is not first
        assert first is not None and first.disconnected == 1

    def test_adopt_login_client_switches_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """登录成功后必须切到新 session：断开临时客户端 + 作废工作客户端。"""
        mgr = self._manager()
        working = _LoginClient(auth_key=b"\x01" * 256)
        mgr._client = working
        self._install_fakes(mgr, monkeypatch)

        asyncio.run(mgr.send_code("+8613800138000"))
        login = mgr._login_client

        asyncio.run(mgr.adopt_login_client())

        assert login is not None and login.disconnected == 1, "两只已授权客户端并存会抢 updates"
        assert mgr._login_client is None
        assert mgr.client is None, "工作客户端要作废，由上层按新 session 重建"
        assert mgr._monitor_started is False, "随后必须由 _rearm_after_config() 重拉监听"
        assert working.disconnected == 1

    def test_auth_key_is_the_discriminator(self) -> None:
        """判据本身的正确性（用真实 telethon StringSession 钉住）。

        若哪天 telethon 改成「裸会话也带 auth_key」，修复会开始误判 ——
        这条用例先红，避免静默退化。
        """
        pytest.importorskip("telethon")
        from server.tg_client import TgClientManager
        from telethon.crypto import AuthKey
        from telethon.sessions import StringSession

        mgr = TgClientManager(api_id="24991895", api_hash="hash", proxy_url=None)

        bare = mgr._build_client()
        assert mgr._has_stored_authorization(bare) is False

        stored = StringSession()
        stored.set_dc(2, "149.154.167.51", 443)
        stored.auth_key = AuthKey(b"\x02" * 256)
        loaded = mgr._build_client(stored.save())
        assert mgr._has_stored_authorization(loaded) is True

    def test_no_client_means_no_stored_authorization(self) -> None:
        from server.tg_client import TgClientManager

        mgr = TgClientManager(api_id="1", api_hash="h", proxy_url=None)
        assert mgr._has_stored_authorization() is False
