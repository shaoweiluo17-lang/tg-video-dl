"""配置机密处理测试：防脱敏污染是 fn-smart-money 事故的直接防线。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "fpk" / "app"))

from server.config import (  # noqa: E402
    Config,
    SecretBox,
    accessible_paths,
    is_authorized,
    looks_like_mask,
)


class TestMaskDetection:
    @pytest.mark.parametrize(
        "value",
        ["********", "aa25***6b1d", "***", "*abc*", "a***b"],
    )
    def test_detects_masks(self, value: str) -> None:
        assert looks_like_mask(value) is True

    @pytest.mark.parametrize(
        "value",
        ["", "abcdef0123456789", "sk-1234567890", "a*b", "normal-value"],
    )
    def test_allows_real_values(self, value: str) -> None:
        assert looks_like_mask(value) is False


class TestSecretBox:
    def test_roundtrip_with_key(self) -> None:
        box = SecretBox("my-key")
        assert box.enabled
        ct = box.encrypt("secret-value")
        assert ct.startswith("enc:v1:")
        assert "secret-value" not in ct  # 密文里不能有明文
        assert box.decrypt(ct) == "secret-value"

    def test_plaintext_when_no_key(self) -> None:
        box = SecretBox("")
        assert not box.enabled
        assert box.encrypt("v") == "v"
        assert box.decrypt("v") == "v"

    def test_ciphertext_without_key_raises(self) -> None:
        """密文落盘后密钥丢失必须显式报错，而不是静默返回垃圾。"""
        ct = SecretBox("k").encrypt("v")
        with pytest.raises(RuntimeError):
            SecretBox("").decrypt(ct)

    def test_wrong_key_raises(self) -> None:
        """密钥不对必须抛（cryptography 抛 InvalidTag），不能静默返回垃圾数据。"""
        from cryptography.exceptions import InvalidTag

        ct = SecretBox("k1").encrypt("v")
        with pytest.raises(InvalidTag):
            SecretBox("k2").decrypt(ct)


@pytest.fixture()
def cfg(tmp_path: Path) -> Config:
    return Config(config_dir=tmp_path, secret_key="test-key")


class TestConfig:
    def test_defaults(self, cfg: Config) -> None:
        c = cfg.load()
        assert c["proxy"]["network"] == "v2ray"
        assert c["download"]["max_concurrent"] == 1
        assert c["behavior"]["enabled"] is False

    def test_save_and_reload(self, cfg: Config) -> None:
        cfg.save({"download": {"max_concurrent": 2}})
        assert cfg.load()["download"]["max_concurrent"] == 2

    def test_unknown_keys_ignored(self, cfg: Config) -> None:
        """前端塞未知字段不应污染配置。"""
        cfg.save({"evil": {"x": 1}, "download": {"injected": "y"}})
        c = cfg.load()
        assert "evil" not in c
        assert "injected" not in c["download"]

    def test_secrets_roundtrip(self, cfg: Config) -> None:
        cfg.save_secrets({"telegram": {"api_id": "123", "api_hash": "abc"}})
        s = cfg.load_secrets()
        assert s["telegram"]["api_id"] == "123"
        assert s["telegram"]["api_hash"] == "abc"

    def test_rejects_mask_writeback(self, cfg: Config) -> None:
        """核心防线：掩码值写回必须被拒绝（Helius key 事故）。"""
        cfg.save_secrets({"telegram": {"api_hash": "real-hash-value"}})
        with pytest.raises(ValueError):
            cfg.save_secrets({"telegram": {"api_hash": "aa25***6b1d"}})
        # 真实值必须完好
        assert cfg.load_secrets()["telegram"]["api_hash"] == "real-hash-value"

    def test_empty_value_means_no_change(self, cfg: Config) -> None:
        """前端不回显机密，因此空值语义必须是「不修改」而非「清空」。"""
        cfg.save_secrets({"telegram": {"api_hash": "keep-me"}})
        cfg.save_secrets({"telegram": {"api_hash": ""}})
        assert cfg.load_secrets()["telegram"]["api_hash"] == "keep-me"

    def test_secrets_encrypted_on_disk(self, cfg: Config) -> None:
        cfg.save_secrets({"telegram": {"api_hash": "plaintext-must-not-appear"}})
        raw = cfg.secrets_file.read_text(encoding="utf-8")
        assert "plaintext-must-not-appear" not in raw
        assert "enc:v1:" in raw

    def test_secrets_file_permissions(self, cfg: Config) -> None:
        cfg.save_secrets({"telegram": {"api_hash": "x"}})
        mode = cfg.secrets_file.stat().st_mode & 0o777
        assert mode == 0o600, f"机密文件权限应为 600，实际 {oct(mode)}"

    def test_public_view_never_leaks_secret(self, cfg: Config) -> None:
        cfg.save_secrets({
            "telegram": {"api_id": "1234567", "api_hash": "top-secret-hash"},
            "proxy": {"v2ray_uri": "vless://uuid@host:443#n"},
        })
        view = cfg.public_view()
        blob = repr(view)
        assert "top-secret-hash" not in blob
        assert "vless://uuid@host:443" not in blob
        st = view["secrets_state"]
        assert st["telegram"]["api_id_set"] is True
        assert st["proxy"]["v2ray_uri_set"] is True
        # 掩码不含任何原文片段
        assert "1234567" not in st["telegram"]["api_id_masked"]


class TestAuthorizedPathsParsing:
    """缺陷（真机 2026-10-08）：fnOS 用 **":"** 分隔多个授权目录。

    旧实现只按 "," 切 → 勾选第二个目录后整个串变成一个无效路径，
    **所有**授权判断（含原本可用的目录）一起失效，面板报"明明授权了却说未授权"。
    """

    ROOT = "/vol1/1000/media/downloads"

    def test_colon_separated_two_dirs(self, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{self.ROOT}/TG:{self.ROOT}/books")
        assert accessible_paths() == [f"{self.ROOT}/TG", f"{self.ROOT}/books"]

    def test_single_dir_unchanged(self, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{self.ROOT}/TG")
        assert accessible_paths() == [f"{self.ROOT}/TG"]

    @pytest.mark.parametrize("sep", [",", ";", ":", "\n", ", ", " ; "])
    def test_any_separator(self, monkeypatch, sep: str) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{self.ROOT}/a{sep}{self.ROOT}/b")
        assert accessible_paths() == [f"{self.ROOT}/a", f"{self.ROOT}/b"]

    def test_trailing_and_duplicate_separators_ignored(self, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f":{self.ROOT}/a::{self.ROOT}/b:")
        assert accessible_paths() == [f"{self.ROOT}/a", f"{self.ROOT}/b"]

    def test_empty_env(self, monkeypatch) -> None:
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", "")
        assert accessible_paths() == []

    def test_share_paths_parsed_too(self, monkeypatch) -> None:
        from server.config import share_paths

        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "/vol2/@appshare/a:/vol2/@appshare/b")
        assert share_paths() == ["/vol2/@appshare/a", "/vol2/@appshare/b"]

    def test_is_authorized_with_two_dirs(self, monkeypatch) -> None:
        """★回归：第二个目录（以及原有目录）都必须判为已授权。"""
        monkeypatch.setenv("TRIM_DATA_ACCESSIBLE_PATHS", f"{self.ROOT}/TG:{self.ROOT}/books")
        monkeypatch.setenv("TRIM_DATA_SHARE_PATHS", "")
        assert is_authorized(f"{self.ROOT}/TG") is True
        assert is_authorized(f"{self.ROOT}/books") is True
        assert is_authorized(f"{self.ROOT}/TG/2026-10-08") is True
        assert is_authorized(f"{self.ROOT}/other") is False
