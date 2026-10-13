"""代理链接解析与 xray 配置生成测试。"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.proxy_uri import ProxyEndpoint, ProxyUriError, parse_v2ray_uri  # noqa: E402
from server.xray_outbound import build_xray_config  # noqa: E402


class TestVless:
    def test_reality_full_params(self) -> None:
        ep = parse_v2ray_uri(
            "vless://11111111-2222-3333-4444-555555555555@ex.com:443"
            "?security=reality&pbk=PUBKEY&sid=ab&fp=chrome&type=tcp"
            "&sni=www.microsoft.com&flow=xtls-rprx-vision#node"
        )
        assert ep.protocol == "vless"
        assert ep.address == "ex.com"
        assert ep.port == 443
        assert ep.security == "reality"
        assert ep.public_key == "PUBKEY"
        assert ep.short_id == "ab"
        assert ep.fingerprint == "chrome"
        assert ep.flow == "xtls-rprx-vision"
        assert ep.needs_utls is True  # fp= → 必须走 xray

    def test_ws_tls(self) -> None:
        ep = parse_v2ray_uri(
            "vless://uuid@1.2.3.4:8443?type=ws&path=%2Fpath&host=a.com"
            "&security=tls&sni=b.com&alpn=h2,http/1.1#n"
        )
        assert ep.network == "ws"
        assert ep.ws_path == "/path"
        assert ep.ws_host == "a.com"
        assert ep.sni == "b.com"
        assert ep.alpn == ["h2", "http/1.1"]

    def test_missing_uuid_rejected(self) -> None:
        with pytest.raises(ProxyUriError, match="UUID"):
            parse_v2ray_uri("vless://@host:443")

    def test_reality_without_pbk_rejected(self) -> None:
        with pytest.raises(ProxyUriError, match="pbk"):
            parse_v2ray_uri("vless://uuid@host:443?security=reality")


class TestVmess:
    def test_base64_json(self) -> None:
        obj = {
            "v": "2", "ps": "t", "add": "5.6.7.8", "port": "10086",
            "id": "uuid-y", "net": "ws", "path": "/v", "host": "h.com", "tls": "tls",
        }
        b64 = base64.b64encode(json.dumps(obj).encode()).decode()
        ep = parse_v2ray_uri("vmess://" + b64)
        assert ep.protocol == "vmess"
        assert ep.address == "5.6.7.8"
        assert ep.port == 10086
        assert ep.network == "ws"
        assert ep.security == "tls"

    def test_missing_address_rejected(self) -> None:
        b64 = base64.b64encode(json.dumps({"port": "443"}).encode()).decode()
        with pytest.raises(ProxyUriError, match="add"):
            parse_v2ray_uri("vmess://" + b64)

    def test_bad_port_rejected(self) -> None:
        b64 = base64.b64encode(
            json.dumps({"add": "h", "port": "not-a-port"}).encode()
        ).decode()
        with pytest.raises(ProxyUriError, match="端口"):
            parse_v2ray_uri("vmess://" + b64)


class TestTrojanAndSS:
    def test_trojan_defaults_to_tls(self) -> None:
        ep = parse_v2ray_uri("trojan://pass123@t.com:443#tj")
        assert ep.protocol == "trojan"
        assert ep.password == "pass123"
        assert ep.security == "tls"

    def test_trojan_missing_password(self) -> None:
        with pytest.raises(ProxyUriError, match="密码"):
            parse_v2ray_uri("trojan://@t.com:443")

    def test_ss_userinfo_form(self) -> None:
        ui = base64.b64encode(b"aes-256-gcm:pw").decode()
        ep = parse_v2ray_uri(f"ss://{ui}@s.com:8388#ss")
        assert ep.protocol == "ss"
        assert ep.method == "aes-256-gcm"
        assert ep.password == "pw"
        assert ep.address == "s.com"
        assert ep.port == 8388

    def test_ss_whole_payload_form(self) -> None:
        payload = base64.b64encode(b"aes-128-gcm:pw2@1.1.1.1:9999").decode()
        ep = parse_v2ray_uri(f"ss://{payload}")
        assert ep.address == "1.1.1.1"
        assert ep.port == 9999


class TestRejections:
    @pytest.mark.parametrize("bad", ["", "http://x", "socks5://1.2.3.4:1080", "reality://x", "garbage"])
    def test_unsupported_rejected(self, bad: str) -> None:
        with pytest.raises(ProxyUriError):
            parse_v2ray_uri(bad)

    def test_port_out_of_range(self) -> None:
        b64 = base64.b64encode(json.dumps({"add": "h", "port": "99999"}).encode()).decode()
        with pytest.raises(ProxyUriError, match="越界"):
            parse_v2ray_uri("vmess://" + b64)


class TestXrayConfig:
    def test_reality_uses_reality_settings(self) -> None:
        ep = parse_v2ray_uri(
            "vless://uuid@ex.com:443?security=reality&pbk=PK&sid=ab&fp=chrome&sni=s.com#n"
        )
        cfg = build_xray_config(ep, 10808)
        out = cfg["outbounds"][0]
        stream = out["streamSettings"]
        assert stream["security"] == "reality"
        assert stream["tlsSettings"]["realitySettings"]["publicKey"] == "PK"
        assert stream["tlsSettings"]["fingerprint"] == "chrome"
        assert cfg["inbounds"][0]["port"] == 10808
        assert cfg["inbounds"][0]["listen"] == "127.0.0.1"

    def test_no_allow_insecure_key(self) -> None:
        """新版 Xray(≥26) 已移除 allowInsecure，写了会导致启动失败。"""
        ep = parse_v2ray_uri("trojan://pw@t.com:443?security=tls#x")
        cfg = build_xray_config(ep, 1)
        assert "allowInsecure" not in json.dumps(cfg)

    def test_ws_headers_only_when_host_given(self) -> None:
        ep = parse_v2ray_uri("vless://u@h:443?type=ws&path=/p&security=tls#x")
        cfg = build_xray_config(ep, 1)
        assert "headers" not in cfg["outbounds"][0]["streamSettings"]["wsSettings"]

    @pytest.mark.parametrize(
        "uri,proto",
        [
            ("vless://u@h:443?security=tls#x", "vless"),
            ("trojan://p@h:443#x", "trojan"),
            ("ss://" + base64.b64encode(b"aes-256-gcm:p").decode() + "@h:8388#x", "shadowsocks"),
        ],
    )
    def test_protocol_mapping(self, uri: str, proto: str) -> None:
        ep = parse_v2ray_uri(uri)
        cfg = build_xray_config(ep, 1)
        assert cfg["outbounds"][0]["protocol"] == proto

    def test_config_is_json_serializable(self) -> None:
        ep = parse_v2ray_uri("vless://u@h:443?security=tls&type=grpc&serviceName=gs#x")
        cfg = build_xray_config(ep, 1)
        json.dumps(cfg)  # 不抛异常即通过
        assert cfg["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"] == "gs"


class TestEndpointFlags:
    def test_needs_utls_false_without_fingerprint(self) -> None:
        ep = parse_v2ray_uri("vless://u@h:443?security=tls#x")
        assert ep.needs_utls is False

    def test_tag_readable(self) -> None:
        ep = ProxyEndpoint(protocol="vless", address="a.com", port=443)
        assert ep.tag == "vless://a.com:443"
