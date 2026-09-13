"""
parsers/auth_parser.py
Parses /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS).
These are syslog-framed, so we reuse SyslogParser for the envelope
(timestamp/host/process/pid) and then apply auth-specific sub-parsers to
`message` to extract structured security fields:

  - sshd: Failed/Accepted password or publickey, invalid user, disconnects
  - sudo: COMMAND= invocations, authentication failures
  - su:   session open/fail for a target user

Each recognized pattern sets `fields['event_subtype']` plus relevant
structured fields (username, source_ip, source_port, auth_method), which
downstream the Cloud Edge Gateway's LLM classifier uses as strong signal
features rather than having to re-derive them from free text.
"""
from __future__ import annotations

import re
from typing import Optional

from models import RawLogLine, ParsedEvent
from .base import BaseParser
from .syslog_parser import SyslogParser

_SSH_FAILED_PW = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)(?: ssh\d?)?"
)
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive) for "
    r"(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)"
)
_SSH_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)(?: port (?P<port>\d+))?"
)
_SSH_DISCONNECT = re.compile(
    r"^Disconnected from (?:invalid user )?(?:(?P<user>\S+) )?"
    r"(?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)"
)
_SSH_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F.:]+)"
)
_SUDO_COMMAND = re.compile(
    r"^\s*(?P<runner>\S+)\s*:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)
_SUDO_AUTH_FAIL = re.compile(
    r"^\s*(?P<runner>\S+)\s*:\s*\d+ incorrect password attempt"
)
_SU_SESSION = re.compile(
    r"^(?:Successful su for (?P<user_ok>\S+)|FAILED su for (?P<user_fail>\S+))"
    r"(?: by (?P<by>\S+))?"
)


class AuthParser(BaseParser):
    """Wraps SyslogParser and layers auth-domain extraction on top."""

    def __init__(self):
        self._syslog = SyslogParser()

    def parse(self, raw: RawLogLine) -> Optional[ParsedEvent]:
        event = self._syslog.parse(raw)
        if event is None:
            return None

        process = (event.process or "").lower()
        msg = event.message

        if process.startswith("sshd"):
            self._enrich_sshd(event, msg)
        elif process.startswith("sudo"):
            self._enrich_sudo(event, msg)
        elif process.startswith("su"):
            self._enrich_su(event, msg)

        event.fields.setdefault("event_subtype", "auth_generic")
        return event

    @staticmethod
    def _enrich_sshd(event: ParsedEvent, msg: str) -> None:
        if m := _SSH_FAILED_PW.match(msg):
            event.fields.update(
                event_subtype="ssh_failed_login",
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")),
                outcome="failure",
            )
        elif m := _SSH_ACCEPTED.match(msg):
            event.fields.update(
                event_subtype="ssh_successful_login",
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")),
                auth_method=m.group("method"),
                outcome="success",
            )
        elif m := _SSH_MAX_AUTH.match(msg):
            event.fields.update(
                event_subtype="ssh_brute_force_suspected",
                username=m.group("user"),
                source_ip=m.group("ip"),
                outcome="failure",
            )
        elif m := _SSH_INVALID_USER.match(msg):
            event.fields.update(
                event_subtype="ssh_invalid_user",
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")) if m.group("port") else None,
                outcome="failure",
            )
        elif m := _SSH_DISCONNECT.match(msg):
            event.fields.update(
                event_subtype="ssh_disconnect",
                username=m.group("user"),
                source_ip=m.group("ip"),
                source_port=int(m.group("port")),
            )

    @staticmethod
    def _enrich_sudo(event: ParsedEvent, msg: str) -> None:
        if m := _SUDO_COMMAND.match(msg):
            event.fields.update(
                event_subtype="sudo_command",
                runner=m.group("runner"),
                target_user=m.group("target_user"),
                command=m.group("command"),
                outcome="success",
            )
        elif _SUDO_AUTH_FAIL.match(msg):
            event.fields.update(
                event_subtype="sudo_auth_failure",
                outcome="failure",
            )

    @staticmethod
    def _enrich_su(event: ParsedEvent, msg: str) -> None:
        if m := _SU_SESSION.match(msg):
            if m.group("user_ok"):
                event.fields.update(
                    event_subtype="su_success",
                    target_user=m.group("user_ok"),
                    by=m.group("by"),
                    outcome="success",
                )
            else:
                event.fields.update(
                    event_subtype="su_failure",
                    target_user=m.group("user_fail"),
                    by=m.group("by"),
                    outcome="failure",
                )
