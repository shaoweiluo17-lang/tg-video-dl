"""FastAPI 入口：统一网关 + API + 静态托管。

运行模型（IMPLEMENTATION-PLAN §3.1）：
    浏览器 → fnOS 网关 /app/tg-video-dl → Unix Socket → 本服务
    TG 服务器 ← MTProto（经内置 xray）← telethon 用户号

**无入站端口**：telethon 是出站长连接，不需要公网映射或 webhook。

FN Connect 防护三件套（复用 fn-crypto-trader 0.2.9 已验证方案）：
1. ui/config 入口 url **带尾斜杠**（从源头避开 StaticFiles 的 307）；
2. 无斜杠根路径由显式路由处理，Location 用**相对路径**；
3. 不加会泄漏 Host 的重定向——StaticFiles 默认用请求 Host 拼绝对地址，
   隧道下 Host=localhost，浏览器会被带去 http://localhost/... 报「拒绝连接」。
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from . import __version__
from .aio_guard import abandon_task
from .config import (
    DATA_DIR,
    DOWNLOAD_DIR,
    Config,
    accessible_paths,
    is_authorized,
    share_paths,
)
from .downloader import ensure_dir_authorized, load_message_cache, save_message_cache
from .memguard import rss_mb, rss_watch
from .paths import PathSafetyError, render_template
from .proxy_uri import ProxyUriError, parse_v2ray_uri
from .tg_client import (
    TELETHON_AVAILABLE,
    TgClientManager,
    TgError,
    TgNotConfigured,
    TgUnreachable,
)
from .xray_outbound import XrayError, XrayOutbound, find_xray_binary

log = logging.getLogger("tgvdl")

GATEWAY_PREFIX = "/app/tg-video-dl"
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # deploy/fpk/app
WWW_DIR = os.path.join(APP_DIR, "www")

# CORS：默认只放行本地开发静态预览；生产走网关**同源**，无需 CORS。
_DEFAULT_ORIGINS = ["http://127.0.0.1:8010", "http://localhost:8010"]
_ALLOW_ORIGINS = [
    o.strip() for o in os.environ.get("TGV_ALLOW_ORIGIN", "").split(",") if o.strip()
] or _DEFAULT_ORIGINS


# ---------------- 应用状态 ----------------
class AppState:
    """集中持有运行期对象，避免散落的模块级全局。"""

    def __init__(self) -> None:
        self.config = Config()
        self.tg = TgClientManager()
        self.outbound: XrayOutbound | None = None
        self.db: Any = None       # TaskDB（延迟建，路径依赖配置）
        self.queue: Any = None    # DownloadQueue
        self.proxy_status: dict[str, Any] = {
            "running": False,
            "endpoint": "",
            "socks": "",
            "error": "",
        }
        self.last_error: str = ""
        self.media_handler: Any = None  # 收藏夹消息回调

    # ---- 配置装载 ----
    def load_from_config(self) -> None:
        sec = self.config.load_secrets()
        cfg = self.config.load()
        self.tg.on_session_changed = self._persist_session
        self.tg.api_id = sec["telegram"]["api_id"]
        self.tg.api_hash = sec["telegram"]["api_hash"]
        self.tg.session_string = sec["telegram"]["session"]

        network = cfg["proxy"]["network"]
        uri = sec["proxy"]["v2ray_uri"]
        self.tg.proxy_url = self._proxy_url_for(network, uri, cfg["proxy"]["socks_port"])

    def _proxy_url_for(self, network: str, uri: str, socks_port: int) -> str | None:
        """给 telethon 用的代理 URL。

        注意：xray 尚未启动时端口未知，此处只在"外部 socks5"场景返回固定值；
        内置 xray 场景由 start_proxy() 启动后回填。
        """
        if network == "direct":
            return None
        if self.outbound and self.outbound.running:
            return self.outbound.socks_url
        return None

    def _persist_session(self, session: str) -> None:
        """session 变更 → 加密落盘。"""
        self.config.save_secrets({"telegram": {"session": session}})

    # ---- xray 出站 ----
    def start_proxy(self) -> dict[str, Any]:
        """（重）启动内置 xray 出站。配置变更后调用。"""
        self.stop_proxy()
        cfg = self.config.load()
        sec = self.config.load_secrets()
        network = cfg["proxy"]["network"]
        uri = sec["proxy"]["v2ray_uri"]

        if network == "direct":
            self.proxy_status = {
                "running": False, "endpoint": "", "socks": "", "error": "",
                "mode": "direct",
            }
            self.tg.proxy_url = None
            return self.proxy_status

        if not uri:
            self.proxy_status = {
                "running": False, "endpoint": "", "socks": "",
                "error": "未配置 v2ray 分享链接", "mode": "v2ray",
            }
            return self.proxy_status

        try:
            ep = parse_v2ray_uri(uri)
        except ProxyUriError as exc:
            self.proxy_status = {
                "running": False, "endpoint": "", "socks": "",
                "error": f"分享链接非法：{exc}", "mode": "v2ray",
            }
            return self.proxy_status

        outbound = XrayOutbound(ep, socks_port=int(cfg["proxy"]["socks_port"]) or None)
        try:
            proc = outbound.start()
        except XrayError as exc:
            self.proxy_status = {
                "running": False, "endpoint": ep.tag, "socks": "",
                "error": str(exc), "mode": "v2ray",
            }
            return self.proxy_status

        self.outbound = outbound
        self.tg.proxy_url = outbound.socks_url
        self.proxy_status = {
            "running": True,
            "endpoint": ep.tag,
            "socks": proc.socks_url,
            "error": "",
            "mode": "v2ray",
            "fingerprint": ep.fingerprint,
            "needs_utls": ep.needs_utls,
        }
        return self.proxy_status

    def stop_proxy(self) -> None:
        if self.outbound:
            self.outbound.stop()
            self.outbound = None

    # ---- 下载队列 ----
    def setup_downloads(self) -> None:
        """按配置建任务库与下载队列（路径变更时重建）。"""
        from .db import TaskDB
        from .downloader import MediaDownloader, on_media_message_factory
        from .queue import DownloadQueue

        cfg = self.config.load()
        db_path = Path(DATA_DIR) / "tasks.sqlite"
        if self.db is None or str(getattr(self.db, "path", "")) != str(db_path):
            if self.db is not None:
                try:
                    self.db.close()
                except Exception:
                    pass
            self.db = TaskDB(db_path)
            # 回收上次进程遗留的僵尸 running 任务（否则面板永远显示"下载中"）
            n = self.db.recover_zombies()
            if n:
                log.info("回收 %d 个中断的下载任务，将重新排队", n)

        downloader = MediaDownloader(self.tg, self.config)
        downloader.db = self.db  # 让下载器能写进度
        self.queue = DownloadQueue(
            self.db, downloader,
            concurrency=int(cfg["download"].get("max_concurrent", 1) or 1),
        )
        self.media_handler = on_media_message_factory(
            self.tg, self.db, self.queue, self.config
        )

    def restart_tg_from_config(self) -> None:
        """配置热更新后重建 TG 客户端（凭据/代理可能都变了）。"""
        self.load_from_config()
        self.tg._drop_client()


STATE = AppState()

# TG 连接失败后的后台重试间隔（秒）
TG_RETRY_SECONDS = float(os.environ.get("TGV_TG_RETRY_SECONDS", "60"))
_tg_retry_task: asyncio.Task[Any] | None = None
_mem_watch_task: asyncio.Task[Any] | None = None


async def restore_tg_session() -> bool:
    """恢复 TG 连接，并按配置拉起下载队列 + 收藏夹监听。成功返回 True。

    ⚠️⚠️ 真机踩坑（2026-10-07，1.74GB 内存事故的连带损失，务必保留此注释）：
    旧实现把「连接 + 启动队列 + 启动监听 + 补收」全塞进同一个 try，
    `ensure_connected()` 一失败就整块跳过 —— 10-05 那次启动时 TG 连接超时之后，
    **下载队列与收藏夹监听整整两天没启动**（日志只有一行 warning，面板完全看不出来）。
    故现在拆开：连接失败只算「本轮失败」，由调用方起后台重试，连上后再补启动。
    连接失败路径本身也必须丢弃半连接客户端（见 `TgClientManager.abort_client`），
    否则会留下能收不能发的僵尸客户端，内存 ~50MB/h 只涨不落。
    """
    try:
        await STATE.tg.ensure_connected()
    except Exception as exc:
        log.warning("TG 登录态恢复失败：%s", exc)
        STATE.last_error = str(exc)
        return False

    log.info("TG 登录态恢复成功")
    STATE.last_error = ""
    cfg = STATE.config.load()
    if not cfg["behavior"]["enabled"]:
        log.info("收藏夹监听已关闭（behavior.enabled=false）：仅恢复连接，不启动队列")
        return True

    try:
        if STATE.queue is not None:
            await STATE.queue.start()
        await STATE.tg.start_monitor(STATE.media_handler)
    except Exception as exc:
        log.warning("启动下载队列/收藏夹监听失败：%s", exc)
        return False

    if cfg["behavior"].get("catch_up", True):
        try:
            n = await STATE.tg.catch_up(STATE.media_handler, limit=50)
            log.info("补收收藏夹消息 %d 条", n)
        except Exception as exc:
            log.warning("补收失败：%s", exc)
    return True


async def _tg_retry_loop() -> None:
    """连接失败后的后台重试：连上即补启动队列与监听，然后退出。"""
    while True:
        await asyncio.sleep(TG_RETRY_SECONDS)
        if await restore_tg_session():
            log.info("TG 后台重连成功：下载队列与收藏夹监听已就绪")
            return


def start_tg_retry() -> None:
    global _tg_retry_task
    if _tg_retry_task is not None and not _tg_retry_task.done():
        return
    _tg_retry_task = asyncio.get_running_loop().create_task(_tg_retry_loop(), name="tg-retry")


def start_mem_watch() -> None:
    global _mem_watch_task
    if _mem_watch_task is not None and not _mem_watch_task.done():
        return
    _mem_watch_task = asyncio.get_running_loop().create_task(rss_watch(), name="rss-watch")


async def stop_background_tasks() -> None:
    """停机：放弃后台重试/观测任务（不 await —— telethon 会吞取消，见 aio_guard）。"""
    global _tg_retry_task, _mem_watch_task
    for task in (_tg_retry_task, _mem_watch_task):
        if task is not None and not task.done():
            abandon_task(task)
    _tg_retry_task = None
    _mem_watch_task = None



# ---------------- 生命周期 ----------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logging.basicConfig(
        level=os.environ.get("TGV_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # ⚠️ 必须压低第三方库的日志级别（真机踩坑）：
    # telethon 在 DEBUG 下会把每个 MTProto 包的原始字节 dump 出来
    # （含 base64 大块），实测日志被灌到 3.5MB/4877 行，
    # 而本应用自己的日志只有 48 行 —— 排障时关键信息被彻底淹没。
    for noisy in ("telethon", "telethon.network", "telethon.client",
                  "httpx", "httpcore", "asyncio", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    STATE.load_from_config()
    STATE.setup_downloads()

    # 恢复落盘的消息缓存（真机踩坑延伸）：
    # 缓存只在进程内时，重启后排队中的旧任务只能按 message_id 重新拉取，
    # 而 Telegram 下发的某些新对象 telethon 解析不了 → 下载必然再失败。
    try:
        restored = load_message_cache()
        if restored:
            log.info("消息缓存已从磁盘恢复 %d 条，旧任务可直接命中", restored)
    except Exception as exc:
        log.warning("消息缓存恢复失败（忽略）：%s", exc)

    # 启动即尝试拉起内置 xray（失败不阻断应用启动——用户可去面板改配置）
    status = STATE.start_proxy()
    if status.get("error"):
        log.warning("xray 出站未就绪：%s", status["error"])
        STATE.last_error = status["error"]

    # 若已有 session，尝试恢复连接并开启收藏夹监听
    # （失败**不阻断**启动：只记一笔 + 起后台重试，连上后再补启动队列与监听）
    if STATE.tg.session_string:
        if not await restore_tg_session():
            start_tg_retry()
    start_mem_watch()

    try:
        yield
    finally:
        await stop_background_tasks()
        if STATE.queue is not None:
            await STATE.queue.stop()
        await STATE.tg.close()
        STATE.stop_proxy()
        try:
            save_message_cache(force=True)   # 关机前落盘，供重启后命中
        except Exception:
            log.debug("消息缓存落盘失败（忽略）", exc_info=True)
        if STATE.db is not None:
            try:
                STATE.db.close()
            except Exception:
                pass


app = FastAPI(title="tg-video-dl", version=__version__, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOW_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    allow_credentials=False,
)


def _identity(request: Request) -> dict[str, Any]:
    """从可信网关 Header 提取当前用户身份（仅网关注入，外部伪造无效）。"""
    return {
        "uid": request.headers.get("x-trim-userid"),
        "is_admin": str(request.headers.get("x-trim-isadmin", "")).lower() in ("1", "true"),
        "username": request.headers.get("x-trim-username", ""),
    }


def _err(message: str, status: int = 400, **extra: Any) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message, **extra}, status_code=status)


# ---------------- 基础 API ----------------
@app.get(f"{GATEWAY_PREFIX}/api/health")
def health() -> dict[str, Any]:
    """健康探针：服务、代理、TG 三段状态一目了然。"""
    return {
        "ok": True,
        "service": "tg-video-dl",
        "version": __version__,
        "gateway": GATEWAY_PREFIX,
        "telethon_available": TELETHON_AVAILABLE,
        "xray_binary": str(find_xray_binary() or ""),
        "proxy": STATE.proxy_status,
        "tg": STATE.tg.login_state.to_dict(),
        "tg_configured": STATE.tg.configured,
        "tg_authorized": bool(STATE.tg.session_string),
        "encryption_enabled": STATE.config.encryption_enabled,
        "rss_mb": round(rss_mb(), 1),
        "last_error": STATE.last_error,
        "download_dir": _dir_report(STATE.config.load()["download"]["dir"]),
    }


@app.get(f"{GATEWAY_PREFIX}/api/me")
def api_me(request: Request) -> dict[str, Any]:
    return {"ok": True, "identity": _identity(request)}


# ---------------- 配置 API ----------------
@app.get(f"{GATEWAY_PREFIX}/api/config")
def get_config() -> dict[str, Any]:
    """配置视图：非机密明文 + 机密仅「是否已设置」（**绝不回显机密值**）。"""
    return {"ok": True, "config": STATE.config.public_view()}


@app.post(f"{GATEWAY_PREFIX}/api/config")
async def post_config(request: Request) -> Any:
    """保存配置。请求体可含 `secrets` 段（api_id/api_hash/v2ray_uri）。

    防脱敏污染：含 `*` 的机密值一律拒绝（真实密钥不含星号），
    防止前端把回显的掩码写回覆盖真实值（fn-smart-money 的 Helius key 事故）。
    """
    try:
        body = await request.json()
    except Exception:
        return _err("请求体不是合法 JSON")
    if not isinstance(body, dict):
        return _err("请求体必须是 JSON 对象")

    config_patch = body.get("config") or {}
    secrets_patch = body.get("secrets") or {}
    # 类型防御：非对象一律 400（否则下面的 .get 会抛 AttributeError → 500，
    # 而"前端把配置传成字符串/数组"是真实可能发生的低质输入）
    if not isinstance(config_patch, dict) or not isinstance(secrets_patch, dict):
        return _err("config / secrets 必须是 JSON 对象")
    dl_patch = config_patch.get("download")
    if not isinstance(dl_patch, dict):
        dl_patch = {}

    # 文档落盘目录的**落盘前**校验（需求 6：未授权要明确报错，不能静默失败）：
    # 指向新的目录时必须在系统授权目录内，否则拒绝保存（而不是等到下载时才失败）。
    doc_dir = str(dl_patch.get("doc_dir") or "").strip()
    if doc_dir:
        try:
            ensure_dir_authorized(doc_dir)
        except PathSafetyError as exc:
            return _err(f"文档落盘目录不可用：{exc}", status=422)

    # 文档路径模板：就地渲染一次，未知占位符立刻报错（不必等到下载）
    doc_tpl = dl_patch.get("doc_path_template")
    if doc_tpl is not None and str(doc_tpl).strip():
        try:
            render_template(str(doc_tpl), filename="书名.txt", date="2026-01-01",
                            chat="saved", file_id=1)
        except PathSafetyError as exc:
            return _err(f"文档路径模板非法：{exc}", status=422)

    if config_patch:
        try:
            STATE.config.save(config_patch)
        except Exception as exc:
            return _err(f"保存配置失败：{exc}")

    if secrets_patch:
        try:
            STATE.config.save_secrets(secrets_patch)
        except ValueError as exc:
            return _err(str(exc), status=422)
        except Exception as exc:
            return _err(f"保存机密失败：{exc}")

    # 配置变更 → 重建 TG 客户端并重启出站
    STATE.load_from_config()
    STATE.tg._drop_client()
    proxy = STATE.start_proxy()

    # ⚠️ 真机踩坑（2026-10-08）：`_drop_client()` 会把**收藏夹监听的注册一并丢掉**
    # （`_monitor_started=False` / `_on_media=None`，handler 是挂在旧 client 上的）。
    # 旧实现保存完配置就返回，于是「保存设置」之后监听**静默失效**——
    # 面板看着一切正常，实际转发到收藏夹不再有任何反应，直到重启应用。
    # 故保存后按配置重新拉起（连接 → 队列 → 监听 → 补收），走既有且已测的
    # `restore_tg_session()`；放后台跑，避免网络不通时把保存请求拖住 25 秒。
    #
    # 注意：判断「是否已登录」要看**机密里的 session**——上面 `load_from_config()`
    # 刚把 `tg.session_string` 重置成配置里的值，不能拿旧的内存状态做判据。
    monitor_on = bool(STATE.config.load()["behavior"].get("enabled")) and bool(
        STATE.config.load_secrets()["telegram"]["session"]
    )
    if monitor_on:
        asyncio.get_running_loop().create_task(_rearm_after_config(), name="tg-rearm")

    return {
        "ok": True,
        "config": STATE.config.public_view(),
        "proxy": proxy,
        "need_relogin": bool(secrets_patch.get("telegram", {}).get("api_id")),
        "monitor_rearmed": monitor_on,
    }


async def _rearm_after_config() -> None:
    """配置保存后重新拉起 TG 连接 + 下载队列 + 收藏夹监听（失败退化为后台重试）。"""
    try:
        if not await restore_tg_session():
            start_tg_retry()
    except Exception:
        log.exception("配置保存后重新拉起收藏夹监听失败")
        try:
            start_tg_retry()
        except Exception:
            log.debug("启动后台重试失败", exc_info=True)


@app.post(f"{GATEWAY_PREFIX}/api/config/validate")
async def validate_config(request: Request) -> Any:
    """只校验不保存：确认分享链接 / 路径模板 / 并发参数合法。"""
    try:
        body = await request.json()
    except Exception:
        return _err("请求体不是合法 JSON")

    result: dict[str, Any] = {"ok": True, "checks": []}

    uri = (body.get("v2ray_uri") or "").strip()
    if uri:
        try:
            ep = parse_v2ray_uri(uri)
            result["checks"].append({
                "name": "v2ray 链接", "ok": True,
                "detail": f"{ep.tag}｜传输 {ep.network}｜安全 {ep.security}"
                          + ("｜需要 TLS 指纹（走 xray）" if ep.needs_utls else ""),
            })
        except ProxyUriError as exc:
            result["checks"].append({"name": "v2ray 链接", "ok": False, "detail": str(exc)})
            result["ok"] = False

    tpl = body.get("path_template")
    if tpl:
        try:
            out = render_template(str(tpl), filename="测试.mp4", date="2026-01-01", chat="saved", file_id=1)
            result["checks"].append({"name": "路径模板", "ok": True, "detail": f"示例：{out}"})
        except PathSafetyError as exc:
            result["checks"].append({"name": "路径模板", "ok": False, "detail": str(exc)})
            result["ok"] = False

    # ---- 文档下载（doc_dir / doc_path_template / doc_exts）----
    doc_tpl = body.get("doc_path_template")
    if doc_tpl is not None and str(doc_tpl).strip():
        try:
            out = render_template(str(doc_tpl), filename="书名.txt", date="2026-01-01",
                                  chat="saved", file_id=1)
            result["checks"].append({"name": "文档路径模板", "ok": True, "detail": f"示例：{out}"})
        except PathSafetyError as exc:
            result["checks"].append({"name": "文档路径模板", "ok": False, "detail": str(exc)})
            result["ok"] = False

    if body.get("doc_exts") is not None:
        from .downloader import parse_doc_exts

        exts = parse_doc_exts(body.get("doc_exts"))
        result["checks"].append({
            "name": "文档后缀白名单", "ok": True,
            "detail": "、".join(sorted(exts)) + ("（留空＝只下 .txt）" if not str(body.get("doc_exts")).strip() else ""),
        })

    doc_dir = str(body.get("doc_dir") or "").strip()
    if doc_dir:
        try:
            ensure_dir_authorized(doc_dir)
            result["checks"].append({
                "name": "文档落盘目录", "ok": True,
                "detail": f"{doc_dir} 在系统授权目录内",
            })
        except PathSafetyError as exc:
            result["checks"].append({"name": "文档落盘目录", "ok": False, "detail": str(exc)})
            result["ok"] = False

    conc = body.get("max_concurrent")
    if conc is not None:
        try:
            n = int(conc)
            ok = 1 <= n <= 5
            result["checks"].append({
                "name": "并发数", "ok": ok,
                "detail": f"{n}" + ("" if ok else "（建议 1-2；飞影实测调高反而更易触发限流）"),
            })
            result["ok"] = result["ok"] and ok
        except (TypeError, ValueError):
            result["checks"].append({"name": "并发数", "ok": False, "detail": "不是整数"})
            result["ok"] = False

    return result


# ---------------- 代理 API ----------------
@app.get(f"{GATEWAY_PREFIX}/api/proxy/status")
def proxy_status() -> dict[str, Any]:
    return {"ok": True, "proxy": STATE.proxy_status, "xray_binary": str(find_xray_binary() or "")}


@app.post(f"{GATEWAY_PREFIX}/api/proxy/restart")
def proxy_restart() -> dict[str, Any]:
    status = STATE.start_proxy()
    return {"ok": not status.get("error"), "proxy": status, **({"error": status["error"]} if status.get("error") else {})}


@app.post(f"{GATEWAY_PREFIX}/api/proxy/test")
async def proxy_test(request: Request) -> Any:
    """连通性自检：**分层**定位，而不是笼统报"连不上"。

    真机踩过的坑：httpx 走 socks5 需要 socksio 包，缺失时抛 ImportError。
    旧实现把它归入"连接失败"，还附一句"无法访问 api.telegram.org"，
    现象看起来像网络故障，实际是缺依赖 —— 极难反推。故现在分四层检查：

        L1 xray 进程是否运行
        L2 socks 端口是否可连（TCP）
        L3 httpx 是否有 socks 支持（依赖检查）
        L4 经 socks 实际访问目标
    """
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    timeout = float(body.get("timeout") or 15)
    target = str(body.get("target") or "https://api.telegram.org")

    proxy_url = None
    if STATE.outbound and STATE.outbound.running:
        proxy_url = STATE.outbound.socks_url

    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, fatal: bool = False) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "fatal": fatal and not ok})

    # ---- L1：xray 进程 ----
    running = bool(STATE.outbound and STATE.outbound.running)
    add("xray 进程", running,
        "运行中（" + (STATE.outbound.socks_url if running else "") + "）" if running
        else "未运行：请先在「代理」区保存并启动")

    # ---- L2：socks 端口可连 ----
    if running:
        import socket as _socket

        port = STATE.outbound.socks_port
        err = ""
        try:
            with _socket.create_connection(("127.0.0.1", port), timeout=3):
                sock_ok = True
        except OSError as exc:
            sock_ok = False
            err = str(exc)
        add("SOCKS 端口", sock_ok,
            f"127.0.0.1:{port} 可连接" if sock_ok else f"127.0.0.1:{port} 不可连：{err}")

    # ---- L3：httpx 是否有 socks 支持 ----
    import httpx

    socks_ready = True
    socks_why = ""
    if proxy_url:
        try:
            import socksio  # noqa: F401
        except Exception:
            socks_ready = False
            socks_why = (
                "缺少 socksio 依赖：httpx 走 socks5 需要它。"
                "请在应用 venv 中执行 `pip install \"httpx[socks]\"` 后重启服务。"
            )
        add("httpx SOCKS 支持", socks_ready, "socksio 已安装" if socks_ready else socks_why)

    # 前三层有硬伤就不必打网络了（快速失败 + 指明原因）
    if not proxy_url and STATE.proxy_status.get("mode") != "direct":
        return {
            "ok": False, "checks": checks, "via": "未配置",
            "detail": "代理未就绪：请先在第 1 步填写 v2ray 分享链接并点「保存并启动代理」。",
        }
    if proxy_url and not socks_ready:
        return {
            "ok": False, "checks": checks, "via": proxy_url,
            "detail": "代理链路本身正常，但服务端缺少 socksio 依赖，无法发起 socks 请求。",
            "error": socks_why,
        }

    # ---- L4：实际访问 ----
    started = asyncio.get_event_loop().time()
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout) as client:
            resp = await client.get(target)
        elapsed = round(asyncio.get_event_loop().time() - started, 2)
        add("访问目标", True, f"HTTP {resp.status_code}（{elapsed}s）")
        return {
            "ok": True, "status_code": resp.status_code, "elapsed": elapsed,
            "via": proxy_url or "direct", "checks": checks,
            "detail": f"经 {proxy_url or '直连'} 访问 {target} → HTTP {resp.status_code}（{elapsed}s）",
        }
    except Exception as exc:
        elapsed = round(asyncio.get_event_loop().time() - started, 2)
        # 区分"瞬断"（配置/依赖问题）与"超时"（节点不通），帮助快速定位
        name = exc.__class__.__name__
        if elapsed < 1:
            hint = "瞬时失败，多为代理进程配置问题或本地依赖缺失（非节点故障）"
        elif elapsed >= timeout * 0.9:
            hint = "等待超时，多为节点不通或被墙"
        else:
            hint = "中途失败，节点可能不稳定"
        add("访问目标", False, f"{name}: {exc}（{elapsed}s，{hint}）")
        return {
            "ok": False, "via": proxy_url or "direct", "elapsed": elapsed,
            "checks": checks,
            "error": f"{name}: {exc}",
            "detail": f"经 {proxy_url or '直连'} 无法访问 {target}（{elapsed}s，{hint}）。",
        }


# ---------------- Telegram 登录 API ----------------
@app.get(f"{GATEWAY_PREFIX}/api/tg/status")
async def tg_status() -> dict[str, Any]:
    info: dict[str, Any] = {
        "ok": True,
        "telethon_available": TELETHON_AVAILABLE,
        "configured": STATE.tg.configured,
        "authorized": bool(STATE.tg.session_string),
        "login": STATE.tg.login_state.to_dict(),
    }
    if STATE.tg.session_string:
        try:
            info["account"] = await STATE.tg.me()
        except TgError as exc:
            info["account_error"] = str(exc)
        except asyncio.CancelledError:
            # ⚠️ 真机踩坑（2026-10-12）：保存凭据会 `_drop_client()` 断开旧客户端，
            # 而 telethon 断开时会**取消在途请求** —— 正在 await 的 `me()` 于是抛
            # CancelledError 冒到 ASGI 顶层，把前端每 5s 轮询一次的 /tg/status
            # 打成 500（UI 闪一下错误，下一次轮询自愈，但日志里留一串假故障）。
            # 只有「本任务真的被取消」（进程退出 / 客户端断连）才该原样抛出：
            # 用 Task.cancelling()（3.11+）区分二者。
            task = asyncio.current_task()
            if task is not None and getattr(task, "cancelling", lambda: 0)() > 0:
                raise
            info["account_error"] = "客户端正在重建，请稍后刷新"
    return info


@app.post(f"{GATEWAY_PREFIX}/api/tg/login/send_code")
async def tg_send_code(request: Request) -> Any:
    try:
        body = await request.json()
    except Exception:
        return _err("请求体不是合法 JSON")
    phone = (body.get("phone") or "").strip()
    if not phone:
        return _err("请填写手机号（带国际区号，如 +8613800138000）")
    try:
        state = await STATE.tg.send_code(phone)
    except TgNotConfigured as exc:
        return _err(str(exc), status=409, need_config=True)
    except TgUnreachable as exc:
        # 网络不可达是可预期的高频故障：504 + 可操作提示，而不是 500
        return _err(str(exc), status=504, unreachable=True)
    except TgError as exc:
        return _err(str(exc), status=502)
    # 顺手把手机号存进非机密配置，方便下次回显
    STATE.config.save({"telegram": {"phone": phone}})
    return {"ok": True, "login": state.to_dict()}


@app.post(f"{GATEWAY_PREFIX}/api/tg/login/verify")
async def tg_verify(request: Request) -> Any:
    try:
        body = await request.json()
    except Exception:
        return _err("请求体不是合法 JSON")
    code = (body.get("code") or "").strip()
    password = (body.get("password") or "").strip()
    try:
        state = await STATE.tg.complete_login(code, password)
    except TgError as exc:
        return _err(str(exc), status=502)

    login = state.to_dict()
    authorized = state.authorized
    if authorized:
        # 登录用的是**独立临时客户端**（见 tg_client.send_code 的踩坑注释），此刻工作
        # 客户端还跑在旧 session 上。故先切到新 session，再按配置重拉收藏夹监听
        # ——切换会作废工作客户端，不重拉就会「重登之后转发毫无反应」
        # （与 2026-10-08 那次「保存配置后监听失效」同一类事故）。
        await STATE.tg.adopt_login_client()
        if bool(STATE.config.load()["behavior"].get("enabled")):
            asyncio.get_running_loop().create_task(
                _rearm_after_config(), name="tg-rearm-after-login"
            )

    return {"ok": True, "login": login, "authorized": authorized}


@app.post(f"{GATEWAY_PREFIX}/api/tg/logout")
async def tg_logout() -> dict[str, Any]:
    """退出登录：吊销授权 + 清空加密 session。"""
    await STATE.tg.sign_out()
    return {"ok": True, "authorized": False}


# ---------------- 收藏夹监听开关（M1 功能，M0 先暴露开关） ----------------
@app.post(f"{GATEWAY_PREFIX}/api/monitor/toggle")
async def monitor_toggle(request: Request) -> Any:
    try:
        body = await request.json()
    except Exception:
        return _err("请求体不是合法 JSON")
    enabled = bool(body.get("enabled"))

    STATE.config.save({"behavior": {"enabled": enabled}})
    if not enabled:
        return {"ok": True, "enabled": False}

    try:
        await STATE.queue.start()
        await STATE.tg.start_monitor(STATE.media_handler)
    except TgError as exc:
        STATE.config.save({"behavior": {"enabled": False}})
        return _err(str(exc), status=502)
    return {"ok": True, "enabled": True}


# ---------------- 任务 API（M1） ----------------
@app.get(f"{GATEWAY_PREFIX}/api/tasks")
def list_tasks(state: str = "", limit: int = 100) -> dict[str, Any]:
    """任务列表 + 队列统计。"""
    if STATE.db is None:
        return {"ok": True, "tasks": [], "stats": {}}
    tasks = STATE.db.list(state=state or None, limit=max(1, min(500, limit)))
    return {
        "ok": True,
        "tasks": [t.to_dict() for t in tasks],
        "stats": STATE.queue.stats.to_dict() if STATE.queue else {},
    }


@app.post(f"{GATEWAY_PREFIX}/api/tasks/{{task_id}}/retry")
def retry_task(task_id: int) -> Any:
    """手动重试失败任务。"""
    if STATE.db is None:
        return _err("任务库未初始化", status=503)
    rec = STATE.db.get(task_id)
    if rec is None:
        return _err("任务不存在", status=404)
    STATE.db.reset_for_retry(task_id)
    if STATE.queue:
        STATE.queue.notify()
    return {"ok": True, "task": STATE.db.get(task_id).to_dict()}


@app.post(f"{GATEWAY_PREFIX}/api/tasks/clear")
async def clear_tasks(request: Request) -> Any:
    """清理已完成/失败记录（保留正在进行的）。"""
    if STATE.db is None:
        return _err("任务库未初始化", status=503)
    try:
        body = await request.json()
    except Exception:
        body = {}
    which = str(body.get("state") or "done")
    n = STATE.db.delete_by_state(which)
    return {"ok": True, "deleted": n}


# ---------------- 目录预检 API ----------------
# 为什么需要：用户可以把落盘目录指向媒体库，但应用以 package 用户运行，
# **不一定有写权限**（fnOS 用户目录通常是 700，属主是那个用户）。
# 若等到下载时才失败，用户只会看到"任务失败"，不知所以然。
# 故提供一个显式预检：能不能建目录、能不能写、剩余空间多少。


def _dir_report(path_str: str, *, create: bool = False, require_auth: bool = False) -> dict[str, Any]:
    """检查一个落盘目录的可用性。返回结构化结果，不抛异常。

    `require_auth=True` 用于**文档落盘目录**：它必须落在系统授权目录内
    （需求：未授权要给明确错误，而不是等下载时才静默失败）。
    视频目录沿用原有语义（只报告 authorized 事实，不阻断）。
    """
    raw = (path_str or "").strip()
    if not raw:
        return {"ok": False, "path": "", "error": "目录为空"}

    path = Path(raw).expanduser()
    out: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "created": False,
        # 授权信息在所有分支都要带上：UI 靠它给正确的操作指引
        "authorized": is_authorized(str(path)),
        "authorized_paths": accessible_paths(),
    }

    # 1) 不存在则尝试创建（连同父目录）
    if not path.exists():
        if not create:
            out.update(ok=False, error=f"目录不存在：{path}（勾选「自动创建」可让应用创建）")
            return out
        try:
            path.mkdir(parents=True, exist_ok=True)
            out["created"] = True
        except OSError as exc:
            out.update(ok=False, error=f"无法创建目录：{exc}")
            return out

    # 2) 必须是目录
    if not path.is_dir():
        out.update(ok=False, error=f"该路径不是目录：{path}")
        return out

    # 2.5) 授权闸门（仅文档目录要求）：拒绝 `..` / 符号链接逃逸由 ensure_dir_authorized
    #      的 resolve() 比较兜住；这里只回答"在不在系统授权目录内"。
    if require_auth:
        try:
            ensure_dir_authorized(str(path))
        except PathSafetyError as exc:
            out.update(ok=False, error=str(exc), need_auth=True)
            return out

    # 3) 可写性：真写一个临时文件（比 os.access 可靠，能穿透 ACL）
    probe = path / ".tgvdl_write_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        out["writable"] = True
    except OSError as exc:
        out["writable"] = False
        out.update(
            ok=False,
            error=(
                f"目录不可写：{exc.strerror or exc}。"
                "若想让应用写入此目录，请在 fnOS「设置 → 应用 → TG 视频下载」"
                "里授权该目录（授权后可尝试重启应用）；"
                f"或改用应用私有目录（{DOWNLOAD_DIR}）。"
            ),
        )
        return out

    # 4) 剩余空间
    try:
        import shutil as _shutil

        usage = _shutil.disk_usage(path)
        out["free_gb"] = round(usage.free / (1024 ** 3), 1)
        out["total_gb"] = round(usage.total / (1024 ** 3), 1)
    except OSError:
        pass

    out["ok"] = True
    return out


@app.post(f"{GATEWAY_PREFIX}/api/download/check-dir")
async def check_download_dir(request: Request) -> Any:
    """预检落盘目录：是否存在/可写/剩余空间。

    `require_auth=true` 时额外要求"必须落在系统授权目录内"（文档目录用）。
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    target = body.get("dir")
    if not target:
        target = STATE.config.load()["download"]["dir"]
    return {
        "ok": True,
        "result": _dir_report(
            str(target),
            create=bool(body.get("create")),
            require_auth=bool(body.get("require_auth")),
        ),
    }


# ---------------- 系统授权信息 ----------------
# fnOS 的目录授权机制（真机核实，参照 qBittorrent 的 env）：
#   用户在「设置 → 应用」勾选目录 → 系统在**启动应用时**注入
#   TRIM_DATA_ACCESSIBLE_PATHS=/vol1/1000/media/影视
# 应用不"申请"授权，只读取并遵守。故这里只提供查询，不提供申请端点。


@app.get(f"{GATEWAY_PREFIX}/api/auth/paths")
def auth_paths() -> dict[str, Any]:
    """当前系统授权给本应用的目录（供面板展示与指引）。"""
    return {
        "ok": True,
        "accessible": accessible_paths(),
        "share": share_paths(),
        "download_dir_authorized": is_authorized(str(Path(DOWNLOAD_DIR))),
    }


# ---------------- 日志 API ----------------

# 日志脱敏：绝不把机密泄漏到前端/浏览器缓存。
# 日志理论上不该含机密（我们从不打印它们），但防御性过滤成本极低。
_SECRET_PATTERNS = [
    re.compile(r"(?:vless|vmess|trojan|ss)://\S+", re.I),   # 分享链接
    re.compile(r"\b[0-9a-f]{32}\b", re.I),                   # 疑似 api_hash
]


def _redact(line: str) -> str:
    """把日志行里可能的机密替换为掩码。"""
    out = line
    for pat in _SECRET_PATTERNS:
        out = pat.sub("«已隐藏»", out)
    return out


def _tail_file(path: Path, lines: int) -> list[str]:
    """读取文件尾部 N 行（大文件时按块倒读，避免整文件载入）。"""
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
        block = 8192
        data = b""
        with open(path, "rb") as fh:
            pos = size
            # 最多回读 512KB，够 1000 行
            read_total = 0
            while pos > 0 and read_total < 512 * 1024:
                step = min(block, pos)
                pos -= step
                read_total += step
                fh.seek(pos)
                data = fh.read(step) + data
                if data.count(b"\n") > lines:
                    break
        text = data.decode("utf-8", "replace")
        return text.splitlines()[-lines:]
    except OSError:
        return []


@app.get(f"{GATEWAY_PREFIX}/api/logs")
def get_logs(source: str = "app", lines: int = 300) -> Any:
    """读取应用日志或 xray 输出（已脱敏）。

    为什么需要它：真机排障时此前必须登 NAS 翻文件，效率极低。
    """
    n = max(10, min(2000, int(lines or 300)))
    log_dir = Path(os.environ.get("TGV_LOG_DIR", "") or (Path(DATA_DIR).parent / "logs"))

    if source == "xray":
        candidates = [log_dir / "xray-stderr.log"]
    else:
        # 应用主日志：优先 $TGV_LOG_DIR，其次 PKGVAR 根（cmd/main 写在那里）
        candidates = [
            log_dir / "tg-video-dl.log",
            Path(DATA_DIR).parent / "tg-video-dl.log",
        ]

    for path in candidates:
        if path.is_file():
            raw = _tail_file(path, n)
            return {
                "ok": True, "source": source, "file": str(path),
                "lines": [_redact(x) for x in raw],
                "truncated": len(raw) >= n,
            }
    return {
        "ok": False, "source": source,
        "error": f"未找到日志文件（查找位置：{', '.join(str(c) for c in candidates)}）",
    }


# ---------------- FN Connect 防护 + 静态托管 ----------------
# 无尾斜杠根路径：StaticFiles 的 redirect_slashes 会返回 307 且 Location 用请求 Host
# 拼绝对地址；FN Connect 隧道下 Host=localhost → 浏览器被带去 http://localhost/...
# 报「拒绝连接」。显式路由优先命中，Location 用相对路径。
@app.get(GATEWAY_PREFIX, include_in_schema=False)
def gateway_root_redirect() -> RedirectResponse:
    return RedirectResponse(f"{GATEWAY_PREFIX}/", status_code=307)


if os.path.isdir(WWW_DIR):
    from fastapi.staticfiles import StaticFiles

    # ⚠️ 必须放在所有 API/WS 注册之后：StaticFiles 是贪心匹配，挂前面会吞掉 /api/*
    app.mount(GATEWAY_PREFIX, StaticFiles(directory=WWW_DIR, html=True), name="www")
else:  # pragma: no cover
    @app.get(f"{GATEWAY_PREFIX}/")
    async def index_placeholder() -> dict[str, Any]:
        return {"service": "tg-video-dl", "note": "前端 www/ 缺失"}
