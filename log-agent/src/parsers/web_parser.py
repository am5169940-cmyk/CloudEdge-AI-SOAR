"""
parsers/web_parser.py
Parses nginx/Apache access logs in Combined Log Format (CLF + referer/UA):

    127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0"
    200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I)"

Also tolerates plain Common Log Format (no referer/user-agent fields).

Flags a set of common web-attack signatures in the request line/status code
(SQLi, path traversal, XSS, sensitive-file probing) via `attack_signatures`,
which the LLM classifier downstream uses as a strong prior.
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Optional

from models import RawLogLine, ParsedEvent
from .base import BaseParser

# Combined Log Format, with referer/UA optional to also match plain CLF.
_CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

_ATTACK_PATTERNS: dict[str, re.Pattern] = {
    "sql_injection": re.compile(
        r"(\bunion\b.{0,40}\bselect\b|\bor\b\s+1\s*=\s*1|--\s|;--|/\*.*\*/|"
        r"\bxp_cmdshell\b|\bsleep\(\d+\))", re.IGNORECASE,
    ),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)", re.IGNORECASE),
    "xss_attempt": re.compile(r"(<script|%3Cscript|onerror=|onload=|javascript:)", re.IGNORECASE),
    "sensitive_file_probe": re.compile(
        r"(\.env$|wp-config\.php|\.git/config|\.ssh/id_rsa|/etc/passwd|"
        r"phpmyadmin|/\.aws/credentials)", re.IGNORECASE,
    ),
    "command_injection": re.compile(r"(;\s*cat\s|;\s*wget\s|;\s*curl\s|\$\(.*\)|`.*`)"),
}


class WebParser(BaseParser):
    def parse(self, raw: RawLogLine) -> Optional[ParsedEvent]:
        line = raw.raw_line.strip()
        if not line:
            return None

        m = _CLF_RE.match(line)
        if not m:
            return self._base_event(
                raw, message=line, timestamp=time.time(), malformed=True,
            )

        gd = m.groupdict()
        ts = self._parse_time(gd["time"])
        status = int(gd["status"])
        request_line = f'{gd["method"]} {gd["path"]} {gd["protocol"]}'

        signatures = [
            name for name, pattern in _ATTACK_PATTERNS.items()
            if pattern.search(gd["path"]) or pattern.search(line)
        ]

        severity = "info"
        if status >= 500:
            severity = "err"
        elif status in (401, 403):
            severity = "warning"
        elif status == 404 and signatures:
            severity = "warning"

        return self._base_event(
            raw,
            message=request_line,
            severity=severity,
            timestamp=ts,
            client_ip=gd["ip"],
            remote_user=None if gd["user"] == "-" else gd["user"],
            http_method=gd["method"],
            path=gd["path"],
            protocol=gd["protocol"],
            status_code=status,
            response_size=None if gd["size"] == "-" else int(gd["size"]),
            referer=gd.get("referer"),
            user_agent=gd.get("user_agent"),
            attack_signatures=signatures,
        )

    @staticmethod
    def _parse_time(raw_time: str) -> float:
        try:
            return datetime.strptime(raw_time, _TIME_FMT).timestamp()
        except ValueError:
            return time.time()
