"""内置 xray-core 子进程管理：把 ProxyEndpoint 变成本机 socks5 出口。

为什么必须内置 xray（fn-crypto-trader ADR-002 的结论）：
带 `fp=` TLS 指纹要求的节点（含 reality），纯 Python 握手能到 TLS/WS 但
upgrade 后立即断开——stdlib 无法模拟 uTLS/浏览器指纹。故真实出站统一走 xray-core。

进程命名契约：xray 以 `-config <file>` 启动，config 文件名带 `tgvdl_xray_` 前缀，
`cmd/main` 的 stop/升级钩子用 `pkill -f tgvdl_xray_` 清扫孤儿进程。
⚠️ uvicorn 被杀后子进程会存活并占端口，这是必须显式清扫的原因。
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .proxy_uri import ProxyEndpoint

log = logging.getLogger("tgvdl.xray")

# 应用目录（deploy/fpk/app）与二进制搜索路径
_APP_DIR = Path(__file__).resolve().parent.parent
_BIN_DIR = _APP_DIR / "bin"


class XrayError(RuntimeError):
    """xray 启动/运行失败。"""


def find_xray_binary() -> Path | None:
    """按优先级定位 xray 可执行文件。

    1. 环境变量 TGV_XRAY_BIN（开发/测试注入）
    2. 应用内置 bin/xray（fpk 打包路径，构建前由 scripts/fetch_xray.py 拉取）
    3. PATH 中的 xray（系统已装时复用）
    """
    env = os.environ.get("TGV_XRAY_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file():
            return p
    for name in ("xray", "xray.exe"):
        p = _BIN_DIR / name
        if p.is_file():
            return p
    which = shutil.which("xray")
    return Path(which) if which else None


def free_port() -> int:
    """取一个空闲本机端口给 socks 入站用（避免固定端口冲突）。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def port_in_use(port: int) -> bool:
    """端口是否已被占用。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def find_our_xray_pids() -> list[int]:
    """列出本应用遗留的 xray 进程（按可执行文件路径识别，不误伤他人）。

    ⚠️ 只匹配**本应用的** bin/xray 路径。机器上可能有别的 xray
    （真机上就有一个 /usr/local/bin/xray 属于其他项目），绝不能一起杀掉。
    """
    me = str(_BIN_DIR / "xray")
    pids: list[int] = []
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/cmdline", "rb") as fh:
                    argv = fh.read().split(b"\0")
            except OSError:
                continue
            if argv and argv[0].decode("utf-8", "replace") == me:
                pids.append(int(entry))
    except OSError:
        pass
    return pids


def reclaim_port(port: int) -> bool:
    """回收被**本应用遗留 xray** 占用的端口。成功回收返回 True。

    为什么需要：应用重启时若旧 xray 没被清掉（例如服务被 kill -9、
    或有人手动用别的用户起过一次），新 xray 会因端口被占而 bind 失败，
    表现为 exit=255 且**无任何 stderr 输出**——极难反推。真机踩到过。
    """
    if not port_in_use(port):
        return True
    pids = find_our_xray_pids()
    if not pids:
        return False  # 端口被别人占着，不是我们能处理的
    log.warning("检测到本应用遗留 xray 占用端口 %d（pid=%s），回收中", port, pids)
    for pid in pids:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    # 等待端口真正释放（TIME_WAIT / 进程退出需要一点时间）
    for _ in range(20):
        if not port_in_use(port):
            return True
        time.sleep(0.1)
    return not port_in_use(port)


def build_xray_config(ep: ProxyEndpoint, socks_port: int) -> dict:
    """ProxyEndpoint → xray 配置（单 outbound + 本机 socks 入站）。

    注意（fn-crypto-trader §4 坑）：新版 Xray(≥26) 移除了 `allowInsecure`，
    改 `pinnedPeerCertSha256`，tlsSettings 里**不要**写它。
    """
    stream: dict = {"network": ep.network}

    if ep.security in ("tls", "reality", "xtls"):
        tls: dict = {}
        server_name = ep.sni or ep.ws_host or ep.address
        if server_name:
            tls["serverName"] = server_name
        if ep.alpn:
            tls["alpn"] = ep.alpn
        if ep.fingerprint:
            tls["fingerprint"] = ep.fingerprint
        if ep.security == "reality":
            tls["realitySettings"] = {
                "publicKey": ep.public_key,
                "shortId": ep.short_id,
                "fingerprint": ep.fingerprint or "chrome",
                "serverName": server_name or ep.address,
                **({"spiderX": ep.spider_x} if ep.spider_x else {}),
            }
        stream["security"] = "reality" if ep.security == "reality" else "tls"
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"

    if ep.network == "ws":
        stream["wsSettings"] = {
            "path": ep.ws_path or "/",
            **({"headers": {"Host": ep.ws_host}} if ep.ws_host else {}),
        }
    elif ep.network == "grpc":
        stream["grpcSettings"] = {"serviceName": ep.grpc_service}
    elif ep.network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": ep.ws_path or "/",
            **({"host": ep.ws_host} if ep.ws_host else {}),
        }
    elif ep.network == "xhttp":
        stream["xhttpSettings"] = {"path": ep.ws_path or "/"}
    elif ep.network == "tcp" and ep.security == "none" and ep.protocol == "vmess":
        # vmess over 裸 tcp 需显式 header 类型，否则部分服务端不认
        stream["tcpSettings"] = {"header": {"type": "none"}}

    if ep.protocol == "vless":
        user: dict = {"id": ep.uuid, "encryption": "none"}
        if ep.flow:
            user["flow"] = ep.flow
        outbound: dict = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": ep.address, "port": ep.port, "users": [user]}]},
        }
    elif ep.protocol == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": ep.address,
                    "port": ep.port,
                    "users": [{"id": ep.uuid, "alterId": 0, "security": "auto"}],
                }]
            },
        }
    elif ep.protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": ep.address, "port": ep.port, "password": ep.password}]
            },
        }
    elif ep.protocol == "ss":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": ep.address,
                    "port": ep.port,
                    "method": ep.method,
                    "password": ep.password,
                }]
            },
        }
    else:
        raise XrayError(f"不支持的出站协议：{ep.protocol}")

    outbound["streamSettings"] = stream
    outbound["tag"] = "proxy"

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


@dataclass
class XrayProcess:
    """一个运行中的 xray 子进程。"""

    process: subprocess.Popen
    socks_port: int
    config_path: Path
    endpoint: ProxyEndpoint

    @property
    def socks_url(self) -> str:
        return f"socks5://127.0.0.1:{self.socks_port}"

    def alive(self) -> bool:
        return self.process.poll() is None

    def stop(self) -> None:
        """停止进程并清理临时配置。幂等。"""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    pass
        try:
            self.config_path.unlink(missing_ok=True)
        except OSError:
            pass


def _stderr_log_path() -> Path:
    """xray stderr 的落盘位置（优先应用日志目录，便于排障时一处找齐）。

    只负责"选一个路径"，不保证可写——实际打开由调用方降级处理。
    """
    log_dir = os.environ.get("TGV_LOG_DIR", "").strip()
    base = Path(log_dir) if log_dir else Path(tempfile.gettempdir())
    try:
        base.mkdir(parents=True, exist_ok=True)
        return base / "xray-stderr.log"
    except OSError:
        return Path(tempfile.gettempdir()) / "xray-stderr.log"


def _tail_text(path: Path, limit: int = 500) -> str:
    """读文件尾部若干字节（错误日志通常很短，取尾部最有用）。"""
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", "replace").strip()


def _wait_socks_ready(port: int, timeout: float = 8.0, proc: Any = None) -> bool:
    """等待 socks 入站真正可连。

    ⚠️ 必须同时检查进程是否还活着：只探测端口的话，
    「xray bind 成功后立刻崩溃」的窗口期会让探测通过，误判为就绪
    （真机踩到过：面板显示"运行中"，实际请求 0.04s 被 RST）。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False  # 进程已退出，再等也没意义
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False


class XrayOutbound:
    """xray 出站生命周期管理（起停 + 复用 + 自愈）。"""

    def __init__(self, endpoint: ProxyEndpoint, socks_port: int | None = None) -> None:
        self.endpoint = endpoint
        self.socks_port = socks_port or free_port()
        self._proc: XrayProcess | None = None
        self._last_error: str = ""

    @property
    def socks_url(self) -> str:
        """本机 socks5 出口地址（未启动时也有值，端口已预留）。"""
        return f"socks5://127.0.0.1:{self.socks_port}"

    @property
    def last_error(self) -> str:
        return self._last_error

    def start(self) -> XrayProcess:
        """启动 xray；已在跑则直接复用。抛 XrayError 表示失败。"""
        if self._proc and self._proc.alive():
            return self._proc

        binary = find_xray_binary()
        if binary is None:
            raise XrayError(
                "未找到 xray 可执行文件。请先执行 `python scripts/fetch_xray.py` "
                "把二进制放到 deploy/fpk/app/bin/，或设置 TGV_XRAY_BIN 指定路径。"
            )

        # 端口预检：若被**本应用遗留的** xray 占着就先回收；被外人占着则明确报错。
        # 不做这一步的话，xray 会以 exit=255 + 无任何 stderr 的方式静默失败，
        # 现场只能看到"代理未就绪"，极难定位（真机踩到过）。
        if port_in_use(self.socks_port):
            if reclaim_port(self.socks_port):
                log.info("已回收端口 %d", self.socks_port)
            else:
                self._last_error = (
                    f"端口 {self.socks_port} 已被其它进程占用（且不是本应用的遗留 xray）。"
                    "请在「代理」区换一个本机 SOCKS 端口后重试。"
                )
                raise XrayError(self._last_error)

        # 配置文件名带 tgvdl_xray_ 前缀：cmd/main 的 pkill -f 依赖该标记清扫孤儿
        fd, path = tempfile.mkstemp(prefix="tgvdl_xray_", suffix=".json")
        os.close(fd)
        config_path = Path(path)
        config_path.write_text(
            json.dumps(build_xray_config(self.endpoint, self.socks_port), ensure_ascii=False),
            encoding="utf-8",
        )
        os.chmod(config_path, 0o600)  # 配置含节点凭据

        # xray 的 stderr 落到应用日志：否则运行期崩溃的报错全丢在管道里，无从排查。
        # （旧实现只在"启动即失败"那一刻读一次 stderr，成功启动后就再也不读。）
        #
        # ⚠️ 日志不可写**绝不能**阻断 xray 启动——它只是诊断手段，不是必需品。
        # 真机踩过：日志文件被 root 创建后，以 package 用户运行的 xray 因
        # Errno 13 起不来，面板只显示"代理未就绪"。故这里逐级降级。
        errlog = _stderr_log_path()
        errf = None
        try:
            errf = open(errlog, "ab")
        except OSError:
            errlog = Path(tempfile.gettempdir()) / f"tgvdl_xray_stderr_{os.getpid()}.log"
            try:
                errf = open(errlog, "ab")
            except OSError:
                errf = None  # 完全拿不到日志：退化为丢弃 stderr，但要能启动

        try:
            proc = subprocess.Popen(
                [str(binary), "run", "-config", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=errf if errf is not None else subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            config_path.unlink(missing_ok=True)
            self._last_error = f"xray 启动失败：{exc}"
            raise XrayError(self._last_error) from exc
        finally:
            # 父进程无需持有该 fd：子进程已继承，关闭避免 fd 泄漏
            if errf is not None:
                errf.close()

        self._proc = XrayProcess(proc, self.socks_port, config_path, self.endpoint)

        if not _wait_socks_ready(self.socks_port, proc=proc):
            if proc.poll() is not None:
                # 进程已死：带上退出码与日志尾部，直接给出可读原因
                tail = _tail_text(errlog, 500)
                self._proc.stop()
                self._proc = None
                hint = ""
                if proc.returncode == 255 and not tail:
                    # exit=255 + 无输出 = Go 程序连配置都没读到，头号嫌疑是端口被占
                    hint = (
                        f"（exit=255 且无输出，通常是 SOCKS 端口 {self.socks_port} "
                        "被占用导致 bind 失败；请换端口或清理遗留 xray 进程）"
                    )
                self._last_error = (
                    f"xray 启动即退出（exit={proc.returncode}）："
                    f"{tail or '无输出'}{hint}｜完整日志：{errlog}"
                )
                raise XrayError(self._last_error)
            self._last_error = f"xray socks 端口 {self.socks_port} 8s 内未就绪"
            self.stop()
            raise XrayError(self._last_error)

        # 启动后再确认一次：防止「bind 成功但随即崩溃」被误判为就绪
        time.sleep(0.3)
        if proc.poll() is not None:
            tail = _tail_text(errlog, 500)
            self._proc.stop()
            self._proc = None
            self._last_error = (
                f"xray 启动后立即崩溃（exit={proc.returncode}）："
                f"{tail or '无输出'}｜完整日志：{errlog}"
            )
            raise XrayError(self._last_error)

        log.info("xray 出站就绪：%s → %s", self.endpoint.tag, self._proc.socks_url)
        return self._proc

    def ensure(self) -> XrayProcess | None:
        """轻量自愈：进程死了就重启，失败则返回 None（不抛）。"""
        try:
            return self.start()
        except XrayError as exc:
            log.warning("xray 自愈失败：%s", exc)
            return None

    def stop(self) -> None:
        if self._proc:
            self._proc.stop()
            self._proc = None

    @property
    def running(self) -> bool:
        return bool(self._proc and self._proc.alive())


__all__ = [
    "XrayError",
    "XrayOutbound",
    "XrayProcess",
    "build_xray_config",
    "find_xray_binary",
    "free_port",
]
