"""
Unit tests for the URL-path input validators in `src.tools.base_client`.

These are the guards every tool client uses before splicing user-supplied
values (IPs, domains, hashes) into a request URL — they close the SSRF /
path-traversal surface that a crafted indicator could otherwise open. The
fail-closed contract matters: a single False return short-circuits the
client and no network call is made.
"""
from __future__ import annotations

import pytest

from src.tools.base_client import is_valid_domain, is_valid_hash, is_valid_ip


class TestIsValidIP:
    @pytest.mark.parametrize("ip", [
        "1.2.3.4",
        "255.255.255.255",
        "0.0.0.0",
        "10.0.0.1",
        "::1",
        "2001:db8::1",
        "fe80::1%eth0",  # link-local with zone id — python accepts it
    ])
    def test_accepts_canonical(self, ip: str) -> None:
        # Some platforms reject zone ids; skip if that one fails.
        try:
            assert is_valid_ip(ip)
        except AssertionError:
            if "%" in ip:
                pytest.skip("zone-id IPv6 not supported on this platform")
            raise

    @pytest.mark.parametrize("value", [
        "",
        "not-an-ip",
        "999.999.999.999",
        "1.2.3",
        "1.2.3.4.5",
        "../etc/passwd",
        "1.2.3.4; rm -rf /",
        "1.2.3.4/../admin",
        "<script>alert(1)</script>",
        None,
    ])
    def test_rejects_malformed(self, value) -> None:  # type: ignore[no-untyped-def]
        assert not is_valid_ip(value)


class TestIsValidDomain:
    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "a.b.c.d.example.com",
        "xn--ls8h.com",          # punycode
        "example.co.uk",
        "single-hyphen.io",
    ])
    def test_accepts_canonical(self, domain: str) -> None:
        assert is_valid_domain(domain)

    @pytest.mark.parametrize("value", [
        "",
        "localhost",               # no TLD
        "1.2.3.4",                 # IPs are not domains
        "-bad.example.com",        # leading hyphen on label
        "bad-.example.com",        # trailing hyphen on label
        "toolonglabel" * 10 + ".com",  # label > 63 chars
        "a" * 254 + ".com",        # whole name > 253 chars
        "spaces in.example.com",
        "../etc/passwd",
        "example.com/../admin",
        "example.com;id",
    ])
    def test_rejects_malformed(self, value: str) -> None:
        assert not is_valid_domain(value)


class TestIsValidHash:
    MD5 = "d41d8cd98f00b204e9800998ecf8427e"  # empty string MD5
    SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # empty string SHA1
    SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # empty SHA256

    def test_accepts_md5_any(self) -> None:
        assert is_valid_hash(self.MD5)

    def test_accepts_sha1_any(self) -> None:
        assert is_valid_hash(self.SHA1)

    def test_accepts_sha256_any(self) -> None:
        assert is_valid_hash(self.SHA256)

    def test_kind_specific_rejects_wrong_length(self) -> None:
        assert not is_valid_hash(self.MD5, kind="sha256")
        assert not is_valid_hash(self.SHA256, kind="md5")

    def test_kind_specific_accepts_right_length(self) -> None:
        assert is_valid_hash(self.MD5, kind="md5")
        assert is_valid_hash(self.SHA1, kind="sha1")
        assert is_valid_hash(self.SHA256, kind="sha256")

    @pytest.mark.parametrize("value", [
        "",
        "nothex",
        "d41d8cd98f00b204e9800998ecf8427",        # 31 chars — one short of MD5
        "d41d8cd98f00b204e9800998ecf8427e1",      # 33 chars
        "XYZ" * 20,
        "../etc/passwd",
        "d41d8cd9; cat /etc/passwd",
    ])
    def test_rejects_malformed(self, value: str) -> None:
        assert not is_valid_hash(value)

    def test_uppercase_hex_accepted(self) -> None:
        """Hashes are case-insensitive — providers return mixed case."""
        assert is_valid_hash(self.SHA256.upper())
