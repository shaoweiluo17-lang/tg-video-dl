"""v2ray 分享链接解析 → ProxyEndpoint（纯函数，无副作用）。

复用 fn-crypto-trader `proxy_uri.py` 的思路（ADR-002）：
用户只填一条标准分享链接，应用自己解析并生成本机 xray 出站配置，
**不依赖外部代理软件、不出现 ip:port 形态的手填字段**。

支持协议：`vless://` `vmess://` `trojan://` `ss://`
支持传输：tcp / ws / grpc / httpupgrade / xhttp
支持安全层：none / tls / reality
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse


class ProxyUriError(ValueError):
    """分享链接非法。校验期即报错，不落到运行期。"""


@dataclass
class ProxyEndpoint:
    """标准化后的出站端点。字段语义对齐 xray outbound 的 streamSettings。"""

    protocol: str  # vless / vmess / trojan / ss
    address: str
    port: int
    # 凭据（按协议取用其一）
    uuid: str = ""
    password: str = ""
    method: str = ""  # ss 加密方式
    # 传输层
    network: str = "tcp"  # tcp / ws / grpc / httpupgrade / xhttp
    ws_path: str = "/"
    ws_host: str = ""
    grpc_service: str = ""
    # 安全层
    security: str = "none"  # none / tls / reality
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    fingerprint: str = ""  # fp=，有值时必须走 xray（纯 Python 过不去）
    allow_insecure: bool = False
    # reality
    public_key: str = ""
    short_id: str = ""
    spider_x: str = ""
    # 其它透传
    flow: str = ""
    raw: str = ""

    @property
    def needs_utls(self) -> bool:
        """带 TLS 指纹要求（fp=）的节点纯 Python 握手过不去，必须走 xray。"""
        return bool(self.fingerprint)

    @property
    def tag(self) -> str:
        return f"{self.protocol}://{self.address}:{self.port}"


def _b64decode_any(data: str) -> str:
    """宽容的 base64 解码（vmess 链接常见缺省 padding 与 urlsafe 变体）。"""
    s = data.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except (binascii.Error, ValueError) as exc:
        raise ProxyUriError(f"base64 解码失败：{exc}") from exc


def _as_int(value: object, field_name: str) -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ProxyUriError(f"字段 {field_name} 不是合法端口：{value!r}") from exc
    if not (0 < port < 65536):
        raise ProxyUriError(f"字段 {field_name} 端口越界：{port}")
    return port


def _q(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    """按优先级取第一个存在的查询参数。"""
    for n in names:
        if n in query and query[n]:
            return query[n][0]
    return default


def parse_v2ray_uri(uri: str) -> ProxyEndpoint:
    """解析分享链接。非法链接抛 ProxyUriError。

    >>> ep = parse_v2ray_uri("vless://uuid@example.com:443?security=tls&sni=a.com&type=ws&path=/x#n")
    >>> ep.protocol, ep.address, ep.port, ep.network, ep.security
    ('vless', 'example.com', 443, 'ws', 'tls')
    """
    raw = (uri or "").strip()
    if not raw:
        raise ProxyUriError("分享链接为空")

    low = raw.lower()
    try:
        if low.startswith("vmess://"):
            return _parse_vmess(raw)
        if low.startswith("vless://"):
            return _parse_vless(raw)
        if low.startswith("trojan://"):
            return _parse_trojan(raw)
        if low.startswith("ss://"):
            return _parse_ss(raw)
    except ProxyUriError:
        raise
    except Exception as exc:  # 任何解析异常都收敛成显式错误
        raise ProxyUriError(f"解析失败：{exc}") from exc

    raise ProxyUriError(
        "不支持的协议；仅支持 vless:// vmess:// trojan:// ss://（socks5:// 请用直连或系统代理）"
    )


def _parse_vmess(raw: str) -> ProxyEndpoint:
    """vmess://<base64(json)>（也兼容部分客户端 vmess://uuid@host:port 形态）。"""
    body = raw[len("vmess://"):].strip()

    if "@" in body and not body.startswith("ey"):  # 非 base64 的新式写法
        return _parse_vless_like(raw, "vmess")

    try:
        obj = json.loads(_b64decode_any(body))
    except json.JSONDecodeError as exc:
        raise ProxyUriError(f"vmess 链接内的 JSON 非法：{exc}") from exc
    if not isinstance(obj, dict):
        raise ProxyUriError("vmess 链接内容不是 JSON 对象")

    address = str(obj.get("add") or "").strip()
    if not address:
        raise ProxyUriError("vmess 链接缺少服务器地址 (add)")
    net = str(obj.get("net") or "tcp").strip().lower()
    tls = str(obj.get("tls") or "").strip().lower()
    security = "tls" if tls in ("tls", "reality") else "none"

    return ProxyEndpoint(
        protocol="vmess",
        address=address,
        port=_as_int(obj.get("port"), "port"),
        uuid=str(obj.get("id") or "").strip(),
        network=net or "tcp",
        ws_path=str(obj.get("path") or "/"),
        ws_host=str(obj.get("host") or ""),
        grpc_service=str(obj.get("path") or ""),
        security=security,
        sni=str(obj.get("sni") or obj.get("host") or ""),
        alpn=[a for a in str(obj.get("alpn") or "").split(",") if a],
        fingerprint=str(obj.get("fp") or ""),
        allow_insecure=bool(obj.get("allowInsecure") or obj.get("skip-cert-verify")),
        raw=raw,
    )


def _parse_vless_like(raw: str, protocol: str) -> ProxyEndpoint:
    """vless / trojan / vmess(新式) 共用：userinfo@host:port?query#remark。"""
    parsed = urlparse(raw)
    address = parsed.hostname or ""
    if not address:
        raise ProxyUriError(f"{protocol} 链接缺少服务器地址")
    if not parsed.port:
        raise ProxyUriError(f"{protocol} 链接缺少端口")
    query = parse_qs(parsed.query or "")

    net = _q(query, "type", "net", default="tcp").lower()
    security = _q(query, "security", default="none").lower()
    if security not in ("none", "tls", "reality", "xtls"):
        security = "tls"

    userinfo = unquote(parsed.username or "")

    return ProxyEndpoint(
        protocol=protocol,
        address=address,
        port=parsed.port,
        uuid=userinfo if protocol in ("vless", "vmess") else "",
        password=userinfo if protocol == "trojan" else "",
        network=net,
        ws_path=_q(query, "path", default="/"),
        ws_host=_q(query, "host", "sni", default=""),
        grpc_service=_q(query, "serviceName", "servicename", default=""),
        security=security,
        sni=_q(query, "sni", "peer", default=""),
        alpn=[a for a in _q(query, "alpn").split(",") if a],
        fingerprint=_q(query, "fp", default=""),
        allow_insecure=_q(query, "allowInsecure", "insecure", default="0") in ("1", "true"),
        public_key=_q(query, "pbk", "publicKey", default=""),
        short_id=_q(query, "sid", "shortId", default=""),
        spider_x=_q(query, "spx", default=""),
        flow=_q(query, "flow", default=""),
        raw=raw,
    )


def _parse_vless(raw: str) -> ProxyEndpoint:
    ep = _parse_vless_like(raw, "vless")
    if not ep.uuid:
        raise ProxyUriError("vless 链接缺少 UUID")
    if ep.security == "reality" and not ep.public_key:
        raise ProxyUriError("reality 节点缺少 pbk（公钥）")
    return ep


def _parse_trojan(raw: str) -> ProxyEndpoint:
    ep = _parse_vless_like(raw, "trojan")
    if not ep.password:
        raise ProxyUriError("trojan 链接缺少密码")
    if ep.security == "none":
        ep.security = "tls"  # trojan 默认走 TLS
    return ep


def _parse_ss(raw: str) -> ProxyEndpoint:
    """ss:// 两种形态：base64(method:pass)@host:port 与 ss://base64(method:pass@host:port)。"""
    body = raw[len("ss://"):]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)

    if "@" in body:
        userinfo, hostpart = body.rsplit("@", 1)
        try:
            decoded = _b64decode_any(userinfo)
        except ProxyUriError:
            decoded = unquote(userinfo)
    else:
        decoded_full = _b64decode_any(body)
        if "@" not in decoded_full:
            raise ProxyUriError("ss 链接格式无法识别（缺少 host:port）")
        decoded, hostpart = decoded_full.rsplit("@", 1)

    if ":" not in decoded:
        raise ProxyUriError("ss 链接缺少 method:password")
    method, password = decoded.split(":", 1)

    if ":" not in hostpart:
        raise ProxyUriError("ss 链接缺少端口")
    address, port_s = hostpart.rsplit(":", 1)

    ep = ProxyEndpoint(
        protocol="ss",
        address=address.strip("[]"),
        port=_as_int(port_s, "port"),
        password=password,
        method=method,
        security="none",
        raw=raw,
    )
    if query:
        qs = parse_qs(query)
        if _q(qs, "type", default="tcp") == "ws":
            ep.network = "ws"
            ep.ws_path = _q(qs, "path", default="/")
            ep.ws_host = _q(qs, "host", default="")
        if _q(qs, "security", default="none") == "tls":
            ep.security = "tls"
            ep.sni = _q(qs, "sni", default="")
    _ = fragment  # 备注名，不参与连接
    return ep


__all__ = ["ProxyEndpoint", "ProxyUriError", "parse_v2ray_uri"]
