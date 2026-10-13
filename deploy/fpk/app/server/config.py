"""配置读写：非机密 config.yaml + 机密 .secrets.yaml（可选 AES-GCM 加密）。

设计依据（复用 fn-crypto-trader / fn-smart-money 的经验）：

1. **机密与非机密分离**：`config.yaml` 可回显，`.secrets.yaml` 永不回显明文。
   机密含：TG session、v2ray 分享链接、（未来的）任何 token。
2. **防脱敏污染**（fn-smart-money 的 Helius key 事故）：
   配置 GET 接口**不回显**机密值，只回显掩码与"是否已设置"；
   写入侧**拒绝**任何含 `*` 的机密值——否则前端把 `aa25***6b1d` 这种掩码写回，
   真实密钥被覆盖，表现为全部请求 401 且极难排查。
3. **加密可选**：设置 `TGV_SECRET_KEY` 时用 AES-GCM 加密落盘；未设置时明文
   落盘但目录权限 600。fnOS 上建议在 install_callback 里生成随机密钥。
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------- 路径解析（不硬编码，遵循 fnOS 约定）----------------
# cmd/main 会导出 TGV_CONFIG_DIR / TGV_DATA_DIR 等指向 TRIM_PKGVAR。
# 本地开发未设置时回落到仓库内相对目录，保证 `run.sh dev` 直接可用。


def _env_path(env: str, default: Path) -> Path:
    raw = os.environ.get(env, "").strip()
    return Path(raw) if raw else default


# ⚠️ 真机踩坑（2026-10-08，v0.4.1 修复）：fnOS 注入的授权目录列表用 **":"** 分隔！
# 用户在「设置 → 应用」里勾选**第二个**目录后，环境变量变成
#     TRIM_DATA_ACCESSIBLE_PATHS=/vol4/.../TG:/vol4/.../books
# 而旧实现只按 "," 切 → 整个字符串被当成一个不存在的路径，
# 结果 **所有** 授权判断（连原来能用的那个目录）全部失效，
# 面板表现为「明明已在系统里授权，却报未授权」。
# 分隔符按 , ; : 与换行都切（路径里不会出现这些字符）。
_PATH_SEP_RE = re.compile(r"[,;:\r\n]+")


def _split_paths(raw: str) -> list[str]:
    """把系统注入的路径列表切成干净条目（兼容 , ; : 与换行分隔）。"""
    return [p.strip() for p in _PATH_SEP_RE.split(raw or "") if p.strip()]


_APP_DIR = Path(__file__).resolve().parent.parent  # deploy/fpk/app
_REPO_DIR = _APP_DIR.parent.parent.parent  # 仓库根

CONFIG_DIR = _env_path("TGV_CONFIG_DIR", _REPO_DIR / "deploy" / "fpk" / "app" / "config")
DATA_DIR = _env_path("TGV_DATA_DIR", _REPO_DIR / "data")
LOG_DIR = _env_path("TGV_LOG_DIR", _REPO_DIR / "logs")
DOWNLOAD_DIR = _env_path("TGV_DOWNLOAD_DIR", _REPO_DIR / "downloads")
TMP_DIR = _env_path("TGV_TMP_DIR", _REPO_DIR / "tmp")

CONFIG_FILE = CONFIG_DIR / "config.yaml"
SECRETS_FILE = CONFIG_DIR / ".secrets.yaml"

SECRET_KEY_ENV = "TGV_SECRET_KEY"

# 系统授权给本应用的目录列表（fnOS 在「设置 → 应用授权」里由用户勾选，
# 启动时通过该环境变量注入；未授权时为空的）。
DATA_ACCESSIBLE_PATHS_ENV = "TRIM_DATA_ACCESSIBLE_PATHS"
# 应用专属共享目录（由 config/resource 的 data-share 声明，系统创建）
DATA_SHARE_PATHS_ENV = "TRIM_DATA_SHARE_PATHS"

# 文档（电子书等）后缀白名单的**默认值**（唯一来源，downloader 引用它）。
# 用户在配置页可改；留空 = 只下 .txt（download.doc_exts 的空值语义）。
DEFAULT_DOC_EXTS = (".txt", ".epub", ".pdf", ".mobi", ".azw3")
DEFAULT_DOC_EXTS_STR = ",".join(DEFAULT_DOC_EXTS)


def accessible_paths() -> list[str]:
    """系统授权给本应用的目录（可能多个，分隔符不固定）。"""
    return _split_paths(os.environ.get(DATA_ACCESSIBLE_PATHS_ENV, ""))


def share_paths() -> list[str]:
    """应用专属共享目录（data-share 声明后由系统提供）。"""
    return _split_paths(os.environ.get(DATA_SHARE_PATHS_ENV, ""))


def is_authorized(path: str) -> bool:
    """判断某路径是否**明确落在系统通过环境变量告知的授权范围内**。

    ⚠️⚠️ 重要（真机实测，别误用）：这**不是**"能不能写"的判据！
    在 fnOS 上实测到：用户在「设置 → 应用」授权目录后，
      - `TRIM_DATA_ACCESSIBLE_PATHS` 仍为**空**（系统未同步该变量）；
      - 但应用用户已被加入 `TrimApiUsers` 组，**实际可以写入**该目录。
    即授权可能只体现在组/ACL 层，不体现在环境变量里。

    故本函数**只回答"是否在 env 声明的授权路径内"**，返回 False **不代表没有权限**。
    判断能否写入必须用真实写探针（见 main._dir_report 的 writable）。
    """
    try:
        target = Path(path).expanduser().resolve()
    except OSError:
        return False
    for root in accessible_paths() + share_paths():
        try:
            target.relative_to(Path(root).resolve())
            return True
        except (ValueError, OSError):
            continue
    return False

# ---------------- 默认配置 ----------------


def default_config() -> dict[str, Any]:
    """可回显的非机密配置。"""
    return {
        "proxy": {
            # direct = 直连（仅当网络本身可达 TG 时可用）；v2ray = 内置 xray 出网
            "network": "v2ray",
            # 分享链接本体是机密，存 .secrets.yaml；此处只保存"是否已配置"的元信息
            "socks_port": 10808,  # 内置 xray 暴露的本机 socks5 端口
        },
        "telegram": {
            # api_id 不是高敏感值（它是"应用标识"），但 api_hash 是机密。
            # 为简化前端交互，两者都放机密区，此处只留展示用的掩码元信息。
            "phone": "",  # 登录用的手机号（+8613800138000）
        },
        "download": {
            # 落盘目录；一期默认应用私有目录，M4 接目录授权后可指向媒体库
            "dir": str(DOWNLOAD_DIR),
            # 路径模板，支持 {date} {chat} {filename} {ext} {id}
            "path_template": "{date}/{filename}",
            "max_concurrent": 1,  # 参考飞影实测：调高反而更易触发 flood-wait
            # ---- 文档（电子书等）下载（与视频链路分开，互不影响）----
            # 文档落盘目录。**留空＝回落到 download.dir**（与视频同目录）。
            # 指向「新的目录」时，该目录必须落在系统授权目录内，
            # 否则拒绝落盘并在面板/日志给出明确原因（见 paths/downloader 的授权闸门）。
            "doc_dir": "",
            # 文档路径模板（独立于视频的 path_template）。
            # 默认 {filename}：只保留 TG 里的原文件名，方便下游（如 xread）按名导入。
            "doc_path_template": "{filename}",
            # 文档后缀白名单（逗号/空白分隔，写 .txt 或 txt 都认）。
            # 留空 = 只下 .txt。白名单外的文档仍然忽略并记日志。
            # ⚠️ 字幕/封面等附属后缀（.srt/.jpg/.nfo…）是硬拒绝清单，永远不下。
            "doc_exts": DEFAULT_DOC_EXTS_STR,
        },
        "behavior": {
            "enabled": False,  # 收藏夹监听总开关（登录成功后由用户显式开启）
            "catch_up": True,  # 断线重连后补收漏掉的消息
            "overwrite": False,  # 同名文件是否覆盖（默认重命名而非覆盖）
            "notify_progress": True,  # 视频：在收藏夹里回报下载进度（编辑同一条消息）
            "disk_min_free_gb": 5,  # 磁盘水位检查：低于此值拒绝下载
            "resume": True,  # 断点续传：中断后从 .part 已下载位置继续
            # 文档通知：默认**只报「完成」**，避免电子书这类小文件把收藏夹刷屏
            "notify_docs": True,  # 文档完成后在收藏夹回报
            "notify_doc_progress": False,  # 文档也回报下载进度（默认关）
        },
        "log": {"level": "INFO", "keep_days": 7},
    }


def default_secrets() -> dict[str, Any]:
    """机密配置。绝不回显、绝不入日志。"""
    return {
        "telegram": {
            "api_id": "",
            "api_hash": "",
            "session": "",  # telethon StringSession（登录后写入）
        },
        "proxy": {
            "v2ray_uri": "",  # vless:// vmess:// trojan:// ss://
        },
    }


# ---------------- 加密（AES-GCM，默认开启）----------------

# 自动生成的密钥落在这里（$TRIM_PKGVAR/config/.secret_key，600）。
# 与用户显式设置的 TGV_SECRET_KEY 二选一：环境变量优先。
SECRET_KEY_FILE = "secret.key"


def resolve_secret_key(config_dir: Path | None = None) -> str:
    """取得加密密钥，**缺失时自动生成并持久化**。

    为什么默认生成而不是默认明文（真机踩到的设计缺陷）：
    原实现把加密做成"设了环境变量才开"，结果真机装完面板显示
    「session 加密：未启用（明文 + 600 权限）」——用户不会去设这个变量，
    等于默认不加密。而 session 是「拿到即控号」的凭据，不该依赖用户手动开启。

    现在：环境变量 > 密钥文件 > 新生成并落盘。密钥文件损坏时重新生成
    （代价是已有密文解不开，需重新登录，但不会让服务起不来）。
    """
    env = os.environ.get(SECRET_KEY_ENV, "").strip()
    if env:
        return env

    base = Path(config_dir) if config_dir else CONFIG_DIR
    key_file = base / SECRET_KEY_FILE
    try:
        if key_file.is_file():
            existing = key_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        # 生成 32 字节随机密钥（base64 存储，避免 YAML/日志里的转义问题）
        new_key = base64.b64encode(os.urandom(32)).decode("ascii")
        base.mkdir(parents=True, exist_ok=True)
        tmp = key_file.with_suffix(".tmp")
        tmp.write_text(new_key, encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 600
        tmp.replace(key_file)
        try:
            os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        # 归属修正：本函数可能在特权上下文（保持 root 的进程）里被首次调用，
        # 生成的文件会归 root，导致以 package 用户运行的服务后续读写失败。
        # 若父目录已有属主（fnOS 会设为 package 用户），让密钥文件跟随它。
        try:
            st = base.stat()
            if os.geteuid() == 0 and st.st_uid != 0:
                os.chown(key_file, st.st_uid, st.st_gid)
        except OSError:
            pass
        return new_key
    except OSError:
        # 磁盘不可写等极端情况：不阻断启动，退化为明文（上层会如实显示"未启用"）
        return ""


class SecretBox:
    """AES-GCM 封装。密钥由 resolve_secret_key 提供（默认自动生成）。"""

    def __init__(self, key_material: str | None = None, config_dir: Path | None = None) -> None:
        self.key_material = (
            key_material if key_material is not None else resolve_secret_key(config_dir)
        ).strip()
        self._aes = None
        if self.key_material:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                digest = hashlib.sha256(self.key_material.encode("utf-8")).digest()
                self._aes = AESGCM(digest)
            except Exception:
                # 加密库缺失时不让应用起不来：降级为明文 + 600 权限，并在上层告警
                self._aes = None

    @property
    def enabled(self) -> bool:
        return self._aes is not None

    def encrypt(self, plaintext: str) -> str:
        if not self._aes:
            return plaintext
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return "enc:v1:" + base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, value: str) -> str:
        if not isinstance(value, str) or not value.startswith("enc:v1:"):
            return value  # 明文或未加密
        if not self._aes:
            raise RuntimeError(
                "机密以密文存储但未提供 TGV_SECRET_KEY，无法解密。"
                "请在环境中设置与应用安装时一致的密钥。"
            )
        raw = base64.b64decode(value[len("enc:v1:"):])
        nonce, ct = raw[:12], raw[12:]
        return self._aes.decrypt(nonce, ct, None).decode("utf-8")


# ---------------- 掩码与污染防护 ----------------

MASK = "********"


def looks_like_mask(value: str) -> bool:
    """判断前端是否把掩码值回写了。

    这是 fn-smart-money 事故的直接防线：真实密钥绝不含 `*`。
    只对"机密字段"启用该检查（普通文本允许有 `*`）。
    """
    if not isinstance(value, str):
        return False
    if value == MASK:
        return True
    # `aa25***6b1d` 形态：中间带连续星号
    return "***" in value or (value.startswith("*") and value.endswith("*"))


def mask(value: str) -> str:
    """用于回显的掩码：只暴露长度，不暴露任何字符。"""
    if not value:
        return ""
    return MASK


# ---------------- 读写 ----------------


def _secure_write(path: Path, text: str) -> None:
    """原子写 + 600 权限。先写临时文件再 rename，避免半截配置。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 600
    tmp.replace(path)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """override 合进 base（只覆盖已知键，忽略未知键——防前端塞垃圾字段）。"""
    out = dict(base)
    for k, v in (override or {}).items():
        if k not in out:
            continue
        if isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        elif v is not None:
            out[k] = v
    return out


@dataclass
class Config:
    """配置门面：读/写 config.yaml 与 .secrets.yaml，并负责机密脱敏。"""

    config_dir: Path = field(default_factory=lambda: CONFIG_DIR)
    secret_key: str | None = None
    _box: SecretBox = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # 先建目录，再解析密钥（密钥文件要落在同一个 config_dir 里）
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._box = SecretBox(self.secret_key, config_dir=self.config_dir)

    # ---- 文件位置 ----
    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.yaml"

    @property
    def secrets_file(self) -> Path:
        return self.config_dir / ".secrets.yaml"

    @property
    def encryption_enabled(self) -> bool:
        return self._box.enabled

    # ---- 非机密 ----
    def load(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if self.config_file.is_file():
            try:
                data = yaml.safe_load(self.config_file.read_text(encoding="utf-8")) or {}
            except Exception:
                data = {}
        return _deep_merge(default_config(), data)

    def save(self, patch: dict[str, Any]) -> dict[str, Any]:
        merged = _deep_merge(self.load(), patch)
        _secure_write(self.config_file, yaml.safe_dump(merged, allow_unicode=True, sort_keys=False))
        return merged

    # ---- 机密 ----
    def load_secrets(self) -> dict[str, Any]:
        raw: dict[str, Any] = {}
        if self.secrets_file.is_file():
            try:
                raw = yaml.safe_load(self.secrets_file.read_text(encoding="utf-8")) or {}
            except Exception:
                raw = {}
        out = _deep_merge(default_secrets(), raw)
        # 逐字段解密（保持结构与默认一致）
        for section, fields in default_secrets().items():
            for key in fields:
                try:
                    out[section][key] = self._box.decrypt(out[section][key])
                except Exception:
                    out[section][key] = ""
        return out

    def save_secrets(self, patch: dict[str, Any]) -> None:
        """写入机密。含 `*` 的值一律拒绝（防脱敏污染）。"""
        current = self.load_secrets()
        for section, fields in (patch or {}).items():
            if section not in current or not isinstance(fields, dict):
                continue
            for key, value in fields.items():
                if key not in current[section]:
                    continue
                if value is None or value == "":
                    continue  # 空值 = 不修改（前端不回显机密，空即"未改"）
                if isinstance(value, str) and looks_like_mask(value):
                    raise ValueError(
                        f"拒绝写入机密 {section}.{key}：值疑似脱敏掩码（含 `*`）。"
                        "请填写真实值，或留空表示不修改。"
                    )
                current[section][key] = value

        enc: dict[str, Any] = {}
        for section, fields in current.items():
            enc[section] = {}
            for key, value in fields.items():
                enc[section][key] = self._box.encrypt(value) if value else ""
        _secure_write(
            self.secrets_file,
            yaml.safe_dump(enc, allow_unicode=True, sort_keys=False),
        )

    # ---- 面向 Web 的安全视图 ----
    def public_view(self) -> dict[str, Any]:
        """给前端的合并视图：非机密明文 + 机密仅掩码与"是否已设置"。"""
        cfg = self.load()
        sec = self.load_secrets()
        cfg["secrets_state"] = {
            "encryption_enabled": self._box.enabled,
            "telegram": {
                "api_id_set": bool(sec["telegram"]["api_id"]),
                "api_id_masked": mask(sec["telegram"]["api_id"]),
                "api_hash_set": bool(sec["telegram"]["api_hash"]),
                "session_set": bool(sec["telegram"]["session"]),
            },
            "proxy": {
                "v2ray_uri_set": bool(sec["proxy"]["v2ray_uri"]),
            },
        }
        return cfg


__all__ = [
    "Config",
    "SecretBox",
    "DEFAULT_DOC_EXTS",
    "DEFAULT_DOC_EXTS_STR",
    "accessible_paths",
    "default_config",
    "default_secrets",
    "is_authorized",
    "looks_like_mask",
    "mask",
    "resolve_secret_key",
    "share_paths",
    "CONFIG_DIR",
    "DATA_DIR",
    "LOG_DIR",
    "DOWNLOAD_DIR",
    "TMP_DIR",
]
