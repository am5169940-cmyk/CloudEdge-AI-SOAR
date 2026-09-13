"""
parsers/syslog_parser.py
Parses BSD-style syslog (RFC 3164), which is what /var/log/syslog and
/var/log/messages use on the vast majority of Linux distros.

Format:
    <PRI>Mmm dd hh:mm:ss hostname process[pid]: message
    <PRI>Mmm  d hh:mm:ss hostname process[pid]: message   (single-digit day)

Example:
    <34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for user on /dev/pts/8

Also tolerates syslog lines with no PRI (already stripped by rsyslog/journald
forwarding), falling back to facility/severity = None.
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Optional

from models import RawLogLine, ParsedEvent
from .base import BaseParser

_FACILITIES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
_SEVERITIES = [
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
]

_LINE_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<host>[\w.\-]+)\s+"
    r"(?P<process>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _decode_pri(pri: int) -> tuple[str, str]:
    facility_idx = pri // 8
    severity_idx = pri % 8
    facility = _FACILITIES[facility_idx] if facility_idx < len(_FACILITIES) else str(facility_idx)
    severity = _SEVERITIES[severity_idx] if severity_idx < len(_SEVERITIES) else str(severity_idx)
    return facility, severity


def _to_epoch(month: str, day: str, hour: str, minute: str, second: str) -> float:
    """RFC3164 has no year field, so we assume the current year. To handle
    the December-31/January-1 rollover correctly, if the resulting date is
    more than a day in the future we roll back one year."""
    now = datetime.now()
    month_num = _MONTHS.get(month, now.month)
    try:
        dt = datetime(
            year=now.year, month=month_num, day=int(day),
            hour=int(hour), minute=int(minute), second=int(second),
        )
    except ValueError:
        return time.time()
    if dt.timestamp() > time.time() + 86400:
        dt = dt.replace(year=now.year - 1)
    return dt.timestamp()


class SyslogParser(BaseParser):
    def parse(self, raw: RawLogLine) -> Optional[ParsedEvent]:
        line = raw.raw_line.strip()
        if not line:
            return None

        m = _LINE_RE.match(line)
        if not m:
            # Not a recognizable syslog line — still forward it as a low
            # confidence event rather than silently dropping data that
            # might be security-relevant.
            return self._base_event(
                raw, message=line, facility=None, severity=None,
                process=None, timestamp=time.time(), malformed=True,
            )

        gd = m.groupdict()
        facility = severity = None
        if gd["pri"] is not None:
            facility, severity = _decode_pri(int(gd["pri"]))

        ts = _to_epoch(gd["month"], gd["day"], gd["hour"], gd["minute"], gd["second"])

        return self._base_event(
            raw,
            message=gd["message"],
            facility=facility,
            severity=severity,
            process=gd["process"],
            pid=int(gd["pid"]) if gd["pid"] else None,
            timestamp=ts,
        )
