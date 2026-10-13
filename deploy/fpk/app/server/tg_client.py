"""Telethon 用户号客户端：登录流程 + session 加密持久化 + 收藏夹监听。

为什么是用户号而不是 bot（FEASIBILITY §5.1）：
Bot API `getFile` 硬限 20MB，而 TG 视频基本都超；只有 MTProto 用户号能到 2GB。
且「收藏夹」是用户个人账号的私有对话，bot 根本看不见——所以用户号不是可选，是必需。

登录流程（M0 关键路径）分步暴露给前端，避免一次请求里卡住：
    send_code(phone)  →  code + 2FA password?  →  complete(code[, password])  →  保存 session

安全（FEASIBILITY §5.2）：
- session 是"拿到即控号"的凭证：AES-GCM 加密存 TRIM_PKGVAR，权限 600，
  **绝不入库、绝不写日志、绝不下发前端**；
- 提供 sign_out() 清 session（用户可随时吊销本应用对账号的访问）。
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .aio_guard import call_bounded, run_bounded

log = logging.getLogger("tgvdl.tg")


class TgError(RuntimeError):
    """TG 层错误（面向用户可读）。"""


class TgNotConfigured(TgError):
    """api_id/api_hash 未配置——M0 允许的合法状态，前端应引导去配置。"""


class TgUnreachable(TgError):
    """连不上 Telegram（网络/代理问题）。

    这是**高频**故障：本机实测无法直连 TG，代理没配好时 telethon 会一直重试
    （默认 3 次 × 30s 超时），足以把 HTTP 请求挂死。故必须显式限时并给出可操作提示。
    """


# 连接 TG 的总时限（秒）。超过即判定不可达——宁可快速失败，也不能挂死 Web 请求。
CONNECT_TIMEOUT = float(os.environ.get("TGV_CONNECT_TIMEOUT", "25"))
# 单次 TCP 连接超时：telethon 对连不上的地址会一直重试，必须由我们兜底限时
CONNECTION_TIMEOUT = 8
CONNECTION_RETRIES = 1

# 丢弃（断开）半连接客户端时的限时（秒）。
# 一律走 aio_guard 的「不依赖取消的限时等待」：telethon 会吞 CancelledError，
# 裸 `asyncio.wait_for(client.disconnect(), ...)` 可能永远不返回（见 aio_guard 模块头）。
CLIENT_DROP_TIMEOUT = float(os.environ.get("TGV_CLIENT_DROP_TIMEOUT", "10"))


@dataclass
class LoginState:
    """登录会话的中转状态（进程内，不落盘）。"""

    phone: str = ""
    phone_code_hash: str = ""
    stage: str = "idle"  # idle → code_sent → need_password → authorized
    error: str = ""

    @property
    def authorized(self) -> bool:
        return self.stage == "authorized"

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "phone": self.phone,
            "need_password": self.stage == "need_password",
            "error": self.error,
        }


# telethon 是可选的导入期依赖：缺失时应用仍应能起（走配置页而不是崩溃）
try:  # pragma: no cover - 环境相关
    from telethon import TelegramClient, events  # type: ignore
    from telethon.errors import (  # type: ignore
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )
    from telethon.sessions import StringSession  # type: ignore

    TELETHON_AVAILABLE = True
except Exception:  # pragma: no cover
    TelegramClient = None  # type: ignore
    events = None  # type: ignore
    StringSession = None  # type: ignore
    TELETHON_AVAILABLE = False

    class PhoneCodeInvalidError(Exception):  # type: ignore
        pass

    class PhoneCodeExpiredError(Exception):  # type: ignore
        pass

    class SessionPasswordNeededError(Exception):  # type: ignore
        pass


def proxy_for_telethon(socks_url: str | None) -> Any:
    """把 `socks5://host:port` 转成 **telethon 要求的代理元组**。

    ⚠️⚠️ 真机踩坑（务必保留此注释）：
    telethon **不接受代理 URL 字符串**。传入 `"socks5://127.0.0.1:10809"`
    会抛 `TypeError: Proxy of unknown format: <class 'str'>`。
    它要求元组 `(protocol, addr, port, username, password, rdns)`
    或同字段的 dict（见 telethon/network/connection/connection.py `_parse_proxy`）。

    而 httpx 恰恰相反——它要的是 URL 字符串。**两者格式不通用**，
    这正是 FEASIBILITY §9.5 警告的「各传各的参数，极易漏配」。
    故此处集中转换，调用方只传统一形态的 socks_url。
    """
    if not socks_url:
        return None

    try:
        import python_socks  # noqa: F401  # 缺失时 telethon 无法走 socks
    except Exception:
        log.warning("未安装 python-socks，Telegram 将无法经代理连接；"
                    "请安装 python-socks[asyncio]")
        return None

    from urllib.parse import urlparse

    raw = socks_url.strip()
    parsed = urlparse(raw if "://" in raw else f"socks5://{raw}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1080
    scheme = (parsed.scheme or "socks5").lower()
    if scheme not in ("socks5", "socks5h", "socks4", "http"):
        log.warning("不支持的代理协议 %s，回落 socks5", scheme)
        scheme = "socks5"

    # (protocol, addr, port, username, password, rdns)
    # rdns=True：让代理解析域名（socks5h 语义），避免本机 DNS 泄漏/解析失败
    return (
        scheme,
        host,
        int(port),
        parsed.username or None,
        parsed.password or None,
        True,
    )


_MISSING = object()


def background_tasks_alive(client: Any) -> bool:
    """telethon 客户端是否处于「健康连接」——而不是能收不能发的僵尸。

    ⚠️⚠️ 真机踩坑（2026-10-07，1.74GB / ~50MB·h⁻¹ 线性增长的根因，务必保留此注释）：

    `TelegramClient.connect()` 是**分两段**的：
      ① 先 `_sender.connect()` 起 sender 自己的收发循环；② 末尾才创建
      `_updates_handle`（消费 `_updates_queue` 的 update 循环）与
      `_keepalive_handle`（60s ping + 定期落盘）。
    若 connect() 在 ① 与 ② 之间被取消（典型：`asyncio.wait_for(client.connect(), 25)`
    超时），②**永远不会执行**，于是得到一个僵尸客户端：
      · 没有 ping/ack → Telegram 每 10-13 分钟判空闲并断链
        （日志里刷不完的 "Server closed the connection"）；
      · sender 自己重连（`MTProtoSender._reconnect`），`_user_connected` 恒为 True，
        故 `client.is_connected()` 也恒为 True —— 应用再也不会调用 connect()，
        这两个后台任务**永不重建**；
      · 收到的新消息全部进 `client._updates_queue`，**无人消费** → 内存只涨不落。
    实测该状态下进程 wchar 6.6 分钟零增长（无 ping/ack）、rchar 只在收到 updates
    时脉冲，RSS 跟着脉冲台阶式上涨 ≈50MB/h。

    所以每次拿到连接后都要校验这两个后台任务；缺失即视为损坏，整只重建。
    未知 telethon 版本（两者都不存在）时不做判断，避免误判导致反复重建。
    """
    names = ("_updates_handle", "_keepalive_handle")
    handles = [getattr(client, n, _MISSING) for n in names]
    if all(h is _MISSING for h in handles):
        return True
    for handle in handles:
        if handle is _MISSING or handle is None:
            return False
        if getattr(handle, "done", None) is not None and handle.done():
            return False
    return True


@dataclass
class TgClientManager:
    """持有唯一一个 telethon 客户端实例，并管理登录与监听生命周期。"""
    api_id: str = ""
    api_hash: str = ""
    session_string: str = ""
    proxy_url: str | None = None
    # session 变更回调（由上层写入加密配置）
    on_session_changed: Callable[[str], None] | None = None

    _client: Any = field(default=None, init=False, repr=False)
    # 登录流程专用的**临时客户端**：与应用工作链路（`_client` + 监听）完全隔离。
    # 为什么必须独立成一只客户端，见 `send_code()` 里的踩坑注释。
    _login_client: Any = field(default=None, init=False, repr=False)
    _login: LoginState = field(default_factory=LoginState, init=False, repr=False)
    _monitor_started: bool = field(default=False, init=False)
    _on_media: Callable[[Any], Awaitable[None]] | None = field(default=None, init=False, repr=False)

    # ---------------- 配置 ----------------

    @property
    def configured(self) -> bool:
        return bool(self.api_id and self.api_hash)

    @property
    def login_state(self) -> LoginState:
        return self._login

    def update(self, *, api_id: str = "", api_hash: str = "", proxy_url: str | None = None) -> None:
        """更新凭据（配置保存后调用）。凭据变化会丢弃旧客户端。"""
        if api_id and api_id != self.api_id:
            self.api_id = api_id
            self._drop_client()
        if api_hash and api_hash != self.api_hash:
            self.api_hash = api_hash
            self._drop_client()
        self.proxy_url = proxy_url

    # ---------------- 客户端生命周期 ----------------

    def _require_telethon(self) -> None:
        if not TELETHON_AVAILABLE:
            raise TgError(
                "服务端未安装 telethon。请在应用 venv 中执行 "
                "`pip install -r server/requirements.txt` 后重启服务。"
            )

    def _build_client(self, session: str = "") -> Any:
        self._require_telethon()
        if not self.configured:
            raise TgNotConfigured(
                "尚未配置 api_id / api_hash。请到 my.telegram.org → API development tools "
                "免费申请（几分钟出结果），填入配置页后即可登录。"
            )
        return TelegramClient(
            StringSession(session or None),
            int(self.api_id),
            self.api_hash,
            proxy=proxy_for_telethon(self.proxy_url),
            # ⚠️ 必须压低重试：telethon 默认 connection_retries=5 / retry_delay=1 / timeout=10，
            # 对不可达的 TG 会重试到分钟级，把 HTTP 请求挂死（实测踩到过）。
            # 这里配合 _with_timeout() 的总时限，确保任何登录请求都在秒级返回明确错误。
            connection_retries=CONNECTION_RETRIES,
            retry_delay=1,
            timeout=CONNECTION_TIMEOUT,
            # 只收自己收藏夹的消息，不订阅任何群/频道（风控最小化）
            device_model="tg-video-dl",
            system_version="fnOS",
            app_version="0.1.0",
        )

    async def _with_timeout(self, coro: Any, what: str) -> Any:
        """给 TG 网络操作套总时限，超时转成可操作的 TgUnreachable。

        没有这层保护时，代理不通会让请求挂到 60s+ 甚至永不返回（实测踩到过）。
        """
        try:
            return await asyncio.wait_for(coro, timeout=CONNECT_TIMEOUT)
        except TimeoutError as exc:
            proxy_hint = (
                f"当前代理出口：{self.proxy_url}" if self.proxy_url
                else "当前**未启用代理**（本机实测无法直连 Telegram）"
            )
            raise TgUnreachable(
                f"{what}超时（{CONNECT_TIMEOUT:.0f}s）。{proxy_hint}。"
                "请到配置页填写 v2ray 分享链接并确认「代理已就绪」，"
                "必要时点「测试 Telegram 连通性」定位。"
            ) from exc

    async def preflight(self) -> None:
        """发验证码前的快速预检：无代理时探测 TG DC 的 TCP 可达性。

        MTProto 只有 TCP（如 DC 149.154.167.51:443），一次 TCP 连接即可判定。
        无代理时这步 ~5s 内失败，比让 telethon 重试到 25s 超时体验好得多，
        也避免把半连接状态的客户端留在内存里。
        """
        if self.proxy_url:
            # 有代理时不能直连探测（直连必然不通），交由 telethon 经代理连接
            return
        loop = asyncio.get_running_loop()
        try:
            ok = await asyncio.wait_for(
                loop.run_in_executor(None, _tcp_probe, "149.154.167.51", 443, 5.0),
                timeout=8,
            )
        except Exception:
            return  # 探测本身出错不作为阻断理由，交由真实连接报错
        if not ok:
            raise TgUnreachable(
                "无法连接 Telegram（149.154.167.51:443 不通），且当前未启用代理。"
                "本机实测无法直连 Telegram，请先配置 v2ray 分享链接并确认代理已就绪。"
            )

    @property
    def client(self) -> Any:
        return self._client

    def _has_stored_authorization(self, client: Any = None) -> bool:
        """给定客户端（缺省＝工作客户端）是否带着「已落盘的授权」。

        `StringSession(None)`（登录用的裸会话）在拿到授权前 `auth_key` 为空；
        而从 session 串建起来的客户端一定带 `auth_key`（且是已授权那把）。
        用它区分「干净的登录客户端」与「复用旧授权的客户端」——判据本身的
        正确性由 tests/test_regressions.py::TestReloginRotation 用真实
        telethon StringSession 钉住（见 send_code 的踩坑注释）。
        """
        target = client if client is not None else self._client
        session = getattr(target, "session", None)
        return bool(getattr(session, "auth_key", None))

    def _drop_client(self) -> None:
        """丢引用（同步版），尽力在后台把旧连接断开。

        ⚠️ 仅丢引用是不够的：sender 的收发循环仍挂在事件循环上（"幽灵客户端"）。
        需要**确定**已断开的场景（连接失败 / 停机 / 重建）请用 `await abort_client()`。
        """
        client, self._client = self._client, None
        self._monitor_started = False
        self._on_media = None
        self._login = LoginState()
        _close_in_background(client)
        # 登录用的临时客户端一并作废（它带着旧 api_id 的半截会话）
        login_client, self._login_client = self._login_client, None
        _close_in_background(login_client)

    async def abort_client(self) -> None:
        """彻底断开并丢弃**工作客户端**（**绝不复用**半连接/僵尸客户端）。

        与 `_drop_client()` 的区别：那个只丢引用、不关连接——sender 的收发循环会
        继续在后台跑（真机上正是它把内存吃掉的）。这里先限时断开再丢引用。
        """
        client, self._client = self._client, None
        self._monitor_started = False
        self._on_media = None
        await self._disconnect(client, "TG 客户端")

    async def abort_login_client(self) -> None:
        """丢弃**登录用的临时客户端**。

        它不是应用工作链路的一部分，故**不动** `_monitor_started` / `_on_media` ——
        这正是「登录失败/中途放弃也不会掉收藏夹监听」的关键（见 send_code 踩坑注释）。
        """
        client, self._login_client = self._login_client, None
        await self._disconnect(client, "登录客户端")

    async def _disconnect(self, client: Any, what: str) -> None:
        if client is None:
            return
        try:
            result = client.disconnect()
        except Exception as exc:  # pragma: no cover - 依赖 telethon 内部状态
            log.debug("丢弃%s时 disconnect() 调用失败（忽略）：%s", what, exc)
            return
        if inspect.isawaitable(result):
            # 不依赖取消的限时等待：telethon 会吞 CancelledError（见 aio_guard）
            await call_bounded(result, CLIENT_DROP_TIMEOUT, what=f"断开{what}")

    async def _connect_bounded(
        self, what: str = "连接 Telegram", *, client: Any = None, abort: Any = None
    ) -> None:
        """限时连接；超时/异常一律**丢弃**客户端（绝不把半连接客户端留在内存里）。

        为什么不用 `asyncio.wait_for(client.connect(), ...)`：
        超时会 cancel connect()，若取消落在 sender 已连上、后台任务尚未创建之间，
        就留下 `background_tasks_alive()` 描述的僵尸客户端（内存只涨不落）。
        故改用 aio_guard 的观察式限时（只观察是否按时结束，不靠取消终止），
        一旦没按时成功，立刻整只断开丢弃 —— 半成品绝不复用。

        `client`/`abort` 缺省作用于工作客户端；登录流程传入自己的临时客户端
        （见 `send_code()`），这样登录失败只会丢弃临时客户端，不碰监听状态。
        """
        target = client if client is not None else self._client
        discard = abort if abort is not None else self.abort_client
        assert target is not None
        ok, task = await run_bounded(target.connect(), CONNECT_TIMEOUT, what=what)
        exc: BaseException | None = None
        if ok:
            try:
                exc = task.exception()
            except BaseException as e:  # 含 CancelledError
                exc = e

        if ok and exc is None:
            if background_tasks_alive(target):
                return
            await discard()
            raise TgUnreachable(
                f"{what}后客户端缺少后台任务（connect() 被中断的僵尸态），已丢弃，请重试"
            )

        await discard()
        if exc is not None and not isinstance(exc, asyncio.CancelledError):
            raise TgUnreachable(f"{what}失败：{_humanize(exc)}") from exc
        proxy_hint = (
            f"当前代理出口：{self.proxy_url}" if self.proxy_url
            else "当前**未启用代理**（本机实测无法直连 Telegram）"
        )
        raise TgUnreachable(
            f"{what}超时（{CONNECT_TIMEOUT:.0f}s）。{proxy_hint}。"
            "请到配置页填写 v2ray 分享链接并确认「代理已就绪」，"
            "必要时点「测试 Telegram 连通性」定位。"
        )

    async def ensure_connected(self) -> Any:
        """确保客户端已连接且已授权；返回 client。全程限时，绝不挂死调用方。"""
        if not self.session_string:
            raise TgError("尚未登录。请先完成手机号登录流程。")
        if self._client is None:
            self._client = self._build_client(self.session_string)
        if not self._client.is_connected():
            await self._connect_bounded("连接 Telegram")
        elif not background_tasks_alive(self._client):
            # 僵尸态（能收不能发）：sender 活着且 is_connected() 恒 True，
            # 但 update/keepalive 任务永久缺失 → 新消息只进不消费。
            # 这条分支专门兜住「历史遗留的坏客户端」，整只重建。
            log.warning("TG 客户端缺少后台任务（僵尸态），重建客户端")
            await self.abort_client()
            self._client = self._build_client(self.session_string)
            await self._connect_bounded("重连 Telegram")
        if not await self._with_timeout(self._client.is_user_authorized(), "校验登录态"):
            raise TgError("登录态已失效（session 被吊销或过期），请重新登录。")
        return self._client

    # ---------------- 登录流程（三步） ----------------

    async def send_code(self, phone: str) -> LoginState:
        """第一步：向手机号发送验证码。"""
        phone = (phone or "").strip()
        if not phone.startswith("+"):
            raise TgError("手机号需带国际区号，例如 +8613800138000")
        if not self.configured:
            # 必须先判配置：否则未配置时也会去连 TG，
            # 报出误导性的「网络不通」而非可操作的「请先填 api_id」。
            raise TgNotConfigured(
                "尚未配置 api_id / api_hash。请到 my.telegram.org → API development tools "
                "免费申请（几分钟出结果），填入配置页后即可登录。"
            )
        # ⚠️⚠️ 真机踩坑（2026-10-12，务必保留此注释）—— 两条教训缺一不可：
        #
        # ① 登录必须用**不带既有授权**的客户端。
        #    旧实现只在 `_client` 为空时才建新客户端，于是当内存里已经躺着
        #    「用落盘 session 建起来的客户端」（典型来源：保存新 api_id 后
        #    `_rearm_after_config()` 用【旧 session + 新 api_id】重连，即使那次连接
        #    25s 超时失败，客户端也被留在 `_client` 上）时，发码会直接复用它——
        #    而 telethon 的 `sign_in()` 首行正是
        #        `me = await self.get_me();  if me: return me`
        #    ：已授权就直接返回，**用户填的验证码根本没提交给 Telegram**，
        #    不签发新 auth key，`_persist_session()` 却照样把同一把旧 key 回写
        #    .secrets.yaml。结果：面板显示「登录成功」，实际 session 逐字节没变。
        #    真机证据：`.secrets.yaml` 的 mtime 与日志「TG 登录成功」同一秒，
        #    写进去的却是旧密钥。
        #
        # ② 登录**绝不能碰工作客户端**。第一版修复是「先 `abort_client()` 再登录」，
        #    结果 19:50 三次发码全失败（504/500/504）时，`abort_client()` 顺带清掉了
        #    `_monitor_started`/`_on_media` —— 收藏夹监听静默停在 19:49:18，直到手动
        #    保存一次配置才被重拉（又一次「面板看着正常、转发毫无反应」）。
        #    故登录全程只用独立的 `_login_client`，与 `_client`、监听状态完全隔离：
        #    登录成功、失败、中途放弃，都不影响正在跑的工作链路。
        login_client = self._login_client
        if (
            login_client is None
            or self._login.stage == "authorized"
            or self._has_stored_authorization(login_client)
        ):
            await self.abort_login_client()
            login_client = self._login_client = self._build_client()  # 裸会话，绝无既有授权
        try:
            await self.preflight()
            if not login_client.is_connected():
                await self._connect_bounded(
                    "连接 Telegram", client=login_client, abort=self.abort_login_client
                )
            sent = await self._with_timeout(
                login_client.send_code_request(phone), "发送验证码"
            )
        except TgError:
            # 连不上时**彻底**丢弃半连接客户端（只置 None 会让 sender 继续在后台跑）
            await self.abort_login_client()
            raise
        except Exception as exc:
            await self.abort_login_client()
            raise TgError(f"发送验证码失败：{_humanize(exc)}") from exc

        self._login = LoginState(
            phone=phone, phone_code_hash=sent.phone_code_hash, stage="code_sent"
        )
        log.info("已向 %s 发送登录验证码", _mask_phone(phone))
        return self._login

    async def complete_login(self, code: str, password: str = "") -> LoginState:
        """第二/三步：提交验证码；若账号开了 2FA 则再提交密码。"""
        if self._login.stage not in ("code_sent", "need_password"):
            raise TgError("请先发送验证码（send_code）")
        client = self._login_client
        if not client:
            raise TgError("登录会话已失效，请重新发送验证码")

        code = (code or "").strip().replace(" ", "").replace("-", "")
        if not code:
            raise TgError("验证码不能为空")

        try:
            await self._with_timeout(
                client.sign_in(
                    phone=self._login.phone,
                    code=code,
                    phone_code_hash=self._login.phone_code_hash,
                ),
                "提交验证码",
            )
        except SessionPasswordNeededError:
            if not password:
                self._login.stage = "need_password"
                return self._login
            try:
                await self._with_timeout(
                    client.sign_in(password=password), "提交两步验证密码"
                )
            except Exception as exc:
                self._login.error = _humanize(exc)
                raise TgError(f"两步验证密码错误：{_humanize(exc)}") from exc
        except (PhoneCodeInvalidError, PhoneCodeExpiredError) as exc:
            self._login.error = _humanize(exc)
            raise TgError(f"验证码无效或已过期：{_humanize(exc)}") from exc
        except Exception as exc:
            self._login.error = _humanize(exc)
            raise TgError(f"登录失败：{_humanize(exc)}") from exc

        self._login.stage = "authorized"
        self._login.error = ""
        self._persist_session()
        log.info("TG 登录成功：%s", _mask_phone(self._login.phone))
        return self._login

    async def adopt_login_client(self) -> None:
        """登录成功后的收尾：把工作链路切到新 session，并丢弃临时登录客户端。

        为什么必须显式切换：登录全程用的是独立临时客户端（见 `send_code()` 踩坑
        注释），此刻工作客户端还跑在**旧 session** 上（新 session 已由
        `_persist_session()` 加密落盘）。所以：
          ① 先断开临时客户端 —— 两只已授权客户端并存会互相抢 updates，害监听漏消息；
          ② 再作废工作客户端 —— 由上层（`_rearm_after_config()`）按**新 session**
             重建并重拉监听/队列/补收。
        """
        await self.abort_login_client()
        self._drop_client()

    def _persist_session(self) -> None:
        """把 StringSession 交给上层加密落盘。绝不写日志。"""
        client = self._login_client or self._client
        if not client:
            return
        session = client.session.save()
        self.session_string = session
        if self.on_session_changed:
            self.on_session_changed(session)

    async def sign_out(self) -> None:
        """退出登录：吊销服务端授权并清空本地 session。"""
        try:
            if self._client and self._client.is_connected():
                await self._with_timeout(self._client.log_out(), "退出登录")
        except Exception as exc:
            log.warning("log_out 失败（继续清理本地 session）：%s", exc)
        finally:
            self._drop_client()
            self.session_string = ""
            if self.on_session_changed:
                self.on_session_changed("")

    async def me(self) -> dict[str, Any]:
        """当前账号信息（不含任何机密）。"""
        client = await self.ensure_connected()
        user = await self._with_timeout(client.get_me(), "获取账号信息")
        if not user:
            raise TgError("无法获取账号信息")
        return {
            "id": user.id,
            "username": user.username or "",
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "phone_masked": _mask_phone(user.phone or ""),
        }

    # ---------------- 收藏夹监听（M1 的核心，M0 先打通连接） ----------------

    async def start_monitor(self, on_media: Callable[[Any], Awaitable[None]]) -> None:
        """监听收藏夹新消息。仅 `chats="me"`——不订阅任何群/频道。"""
        self._require_telethon()
        client = await self.ensure_connected()
        if self._monitor_started:
            return
        self._on_media = on_media

        @client.on(events.NewMessage(chats="me"))
        async def _handler(event: Any) -> None:  # pragma: no cover - 需真实 TG
            try:
                if self._on_media:
                    await self._on_media(event.message)
            except Exception:
                log.exception("处理收藏夹消息失败")

        self._monitor_started = True
        log.info("已开始监听收藏夹（chats=me）")

    async def catch_up(self, on_media: Callable[[Any], Awaitable[None]], limit: int = 50) -> int:
        """补收断线期间漏掉的消息（catch_up 语义）。返回处理条数。"""
        client = await self.ensure_connected()
        count = 0
        async for message in client.iter_messages("me", limit=limit):
            try:
                await on_media(message)
                count += 1
            except Exception:
                log.exception("补收消息失败：id=%s", getattr(message, "id", "?"))
        return count

    async def close(self) -> None:
        """停机：限时断开并丢弃客户端（绝不用裸 await —— telethon 会吞取消）。"""
        await self.abort_login_client()
        await self.abort_client()


# ---------------- 工具 ----------------


def _discard_awaitable(result: Any) -> None:
    """没有事件循环可调度时，尽力把它关掉，避免 "coroutine was never awaited" 警告。"""
    for name in ("close", "cancel"):
        fn = getattr(result, name, None)
        if callable(fn):
            try:
                fn()
            except Exception:
                pass
            return


def _close_in_background(client: Any) -> None:
    """尽力在后台断开一个被丢弃的客户端（fire-and-forget，绝不抛错）。

    ⚠️⚠️ 真机踩坑（2026-10-08，v0.4.2 修复，勿回退）：
    **不能假设 `disconnect()` 返回协程**。telethon 1.45 的实现是

        if self.loop.is_running():
            return asyncio.shield(self.loop.create_task(self._disconnect_coro()))

    即「事件循环在跑」时返回的是 **Future**（shield 又包了一层）。
    旧实现用 `loop.create_task(result)` 排程，于是运行期调用直接抛

        TypeError: a coroutine was expected, got <Future pending ...>

    后果（真机实测）：**面板「保存设置」必 500**（`/api/config` → `_drop_client()`），
    「退出登录」同样 500 —— 而同步上下文（无事件循环）的路径正常，
    所以上一版的单测（只测同步路径）全绿，缺陷被漏掉。
    统一改用 `asyncio.ensure_future`：协程（旧版 telethon）与 Future（1.45+）都能接。
    """
    if client is None:
        return
    try:
        result = client.disconnect()
    except Exception:
        return
    if not inspect.isawaitable(result):
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # 没有事件循环（同步上下文）：关掉它，避免 "never awaited" 警告
        _discard_awaitable(result)
        return
    try:
        task = asyncio.ensure_future(result)
    except Exception:
        _discard_awaitable(result)
        return

    def _consume(t: asyncio.Future[Any]) -> None:
        try:
            t.exception()
        except BaseException:
            pass

    task.add_done_callback(_consume)


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    """阻塞式 TCP 可达性探测（在 executor 里跑，不阻塞事件循环）。"""
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _mask_phone(phone: str) -> str:
    """日志用手机号掩码：只留区号与末 2 位。"""
    p = phone or ""
    if len(p) < 6:
        return "***"
    return f"{p[:4]}****{p[-2:]}"


def _humanize(exc: Exception) -> str:
    """把 telethon 异常翻译成用户能懂的话。"""
    text = str(exc) or exc.__class__.__name__
    low = text.lower()
    if "flood" in low or "too many" in low:
        return "请求过于频繁，被 Telegram 限流，请稍后再试"
    if "api_id" in low or "api_hash" in low:
        return "api_id / api_hash 无效，请核对 my.telegram.org 上的值"
    if "proxy" in low or "connection" in low or "timeout" in low:
        return "无法连接 Telegram（网络或代理问题）。本机无法直连 TG，请先确认代理已配置并启动"
    if "phone number" in low and "invalid" in low:
        return "手机号格式不正确（需带国际区号）"
    return text


__all__ = [
    "LoginState",
    "TgClientManager",
    "TgError",
    "TgNotConfigured",
    "TgUnreachable",
    "TELETHON_AVAILABLE",
    "background_tasks_alive",
    "proxy_for_telethon",
]
