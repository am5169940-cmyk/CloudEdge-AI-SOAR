"""
parsers package
Central registry mapping source type strings (from config.yaml) to parser
instances/classes. main.py and collector.py pull from PARSER_REGISTRY
rather than importing individual parser classes, so adding a new log
format later means: write the parser, add one line here.
"""
from __future__ import annotations

from .auth_parser import AuthParser
from .base import BaseParser
from .syslog_parser import SyslogParser
from .web_parser import WebParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "syslog": SyslogParser,
    "auth": AuthParser,
    "web": WebParser,
}

__all__ = ["BaseParser", "SyslogParser", "AuthParser", "WebParser", "PARSER_REGISTRY"]
