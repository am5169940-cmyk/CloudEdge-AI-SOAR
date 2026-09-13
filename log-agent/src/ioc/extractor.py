"""
ioc/extractor.py
Extracts Indicators of Compromise (IOCs) from raw or parsed log text:
  - IPv4 / IPv6 addresses
  - MD5 / SHA1 / SHA256 hashes
  - Domain names

Design notes:
  - Hash regexes use word boundaries + hex-only charset; MD5 (32), SHA1 (40),
    and SHA256 (64) are disambiguated purely by length since all are hex.
  - IPv4 regex validates octet ranges (0-255) rather than a naive \\d{1,3}
    pattern, to avoid false positives like "999.999.999.999".
  - Private/loopback/link-local IPv4 ranges are flagged separately (still
    returned, since internal C2 pivoting is a real threat) but exposed via
    `is_private_ipv4` so the caller/gateway can weight severity.
  - Domain extraction deliberately excludes bare IPs and requires a known-
    shape TLD (2-24 alpha chars) to cut down on noise from things like
    "e.g." or version strings.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from models import IOCMatch, IOCType

# --- IPv4: validates each octet is 0-255 -----------------------------------
_IPV4_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_RE = re.compile(
    rf"\b{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}\b"
)

# --- IPv6: full + compressed forms (good-enough coverage for log text) -----
IPV6_RE = re.compile(
    r"\b("
    r"([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                     # full form
    r"|([0-9A-Fa-f]{1,4}:){1,7}:"                                  # trailing ::
    r"|([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2}"
    r"|([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3}"
    r"|([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4}"
    r"|([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6})"
    r"|:((:[0-9A-Fa-f]{1,4}){1,7}|:)"                              # leading ::
    r")\b"
)

# --- Hashes: hex-only, exact length, word-bounded ---------------------------
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

# --- Domains: label.label.tld, TLD must be alphabetic 2-24 chars -----------
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

# Common false-positive TLD-shaped suffixes seen in log noise (file exts, etc.)
_DOMAIN_TLD_BLOCKLIST = {
    "log", "conf", "txt", "json", "yaml", "yml", "py", "js", "ts",
    "gz", "tar", "zip", "bak", "old", "so", "pyc", "html", "css",
}

_PRIVATE_NETS = [
    ipaddress.ip_network(net) for net in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",
    )
]


def _is_private_ipv4(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


@dataclass(slots=True)
class ExtractorStats:
    lines_scanned: int = 0
    matches_found: int = 0


class IOCExtractor:
    """Stateless-per-call regex engine; safe to share across threads."""

    def __init__(self, exclude_private_ips: bool = False):
        self.exclude_private_ips = exclude_private_ips
        self.stats = ExtractorStats()

    def extract(self, text: str) -> list[IOCMatch]:
        self.stats.lines_scanned += 1
        matches: list[IOCMatch] = []
        seen: set[tuple[str, str]] = set()

        def add(ioc_type: IOCType, value: str):
            key = (ioc_type.value, value)
            if key in seen:
                return
            seen.add(key)
            start = max(text.find(value) - 20, 0)
            end = min(text.find(value) + len(value) + 20, len(text))
            matches.append(IOCMatch(ioc_type=ioc_type, value=value, context=text[start:end].strip()))

        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            if self.exclude_private_ips and _is_private_ipv4(ip):
                continue
            add(IOCType.IPV4, ip)

        for m in IPV6_RE.finditer(text):
            candidate = m.group(0)
            if candidate.count(":") < 2:
                continue  # filters accidental matches like a bare "::"
            add(IOCType.IPV6, candidate)

        for m in HASH_RE.finditer(text):
            h = m.group(0)
            length = len(h)
            if length == 32:
                add(IOCType.MD5, h.lower())
            elif length == 40:
                add(IOCType.SHA1, h.lower())
            elif length == 64:
                add(IOCType.SHA256, h.lower())
            # other lengths (33-63 minus 40) are ignored — not a standard hash

        for m in DOMAIN_RE.finditer(text):
            domain = m.group(0)
            tld = domain.rsplit(".", 1)[-1].lower()
            if tld in _DOMAIN_TLD_BLOCKLIST:
                continue
            if IPV4_RE.fullmatch(domain):
                continue  # dotted-quad, not a domain
            add(IOCType.DOMAIN, domain.lower())

        self.stats.matches_found += len(matches)
        return matches
