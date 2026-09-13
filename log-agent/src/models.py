"""
models.py
Core data structures shared across the collector, parsers, and shipper.
Using slots-based dataclasses keeps memory overhead low under high log volume.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class SourceType(str, Enum):
    SYSLOG = "syslog"
    AUTH = "auth"
    WEB = "web"


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    DOMAIN = "domain"


@dataclass(slots=True)
class IOCMatch:
    ioc_type: IOCType
    value: str
    context: str  # short excerpt of the line the IOC was found in

    def to_dict(self) -> dict:
        return {"type": self.ioc_type.value, "value": self.value, "context": self.context}


@dataclass(slots=True)
class RawLogLine:
    """A single unparsed line read off disk, tagged with its origin."""
    source_type: SourceType
    source_path: str
    hostname: str
    raw_line: str
    read_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class ParsedEvent:
    """
    Normalized event produced by a parser. This is the unit that gets
    IOC-enriched and shipped to the Cloud Edge Gateway.
    """
    event_id: str
    source_type: SourceType
    hostname: str
    timestamp: float
    facility: Optional[str]
    severity: Optional[str]
    process: Optional[str]
    message: str
    raw_line: str
    fields: dict = field(default_factory=dict)      # parser-specific structured fields
    iocs: list[IOCMatch] = field(default_factory=list)

    @staticmethod
    def new_id(raw_line: str) -> str:
        # Deterministic-ish id: uuid4 for uniqueness, but keep a content hash
        # too so the gateway can dedupe retried/duplicate deliveries.
        return str(uuid.uuid4())

    def content_hash(self) -> str:
        return hashlib.sha256(self.raw_line.encode("utf-8", errors="replace")).hexdigest()

    def to_json(self) -> str:
        d = asdict(self)
        d["source_type"] = self.source_type.value
        d["iocs"] = [m.to_dict() for m in self.iocs]
        d["content_hash"] = self.content_hash()
        return json.dumps(d, separators=(",", ":"), ensure_ascii=False)
