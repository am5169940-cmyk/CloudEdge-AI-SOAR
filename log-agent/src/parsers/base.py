"""
parsers/base.py
Abstract interface all log parsers must implement. Keeping parsers stateless
and pure (line-in, ParsedEvent-out) makes them trivially unit-testable and
safe to call concurrently from multiple collector threads.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from models import ParsedEvent, RawLogLine


class BaseParser(ABC):
    """Every parser turns one raw log line into one ParsedEvent, or None
    if the line doesn't match the expected format (e.g. a continuation
    line, blank line, or garbage)."""

    @abstractmethod
    def parse(self, raw: RawLogLine) -> Optional[ParsedEvent]:
        raise NotImplementedError

    @staticmethod
    def _base_event(raw: RawLogLine, message: str, **fields) -> ParsedEvent:
        import time as _time
        from models import ParsedEvent as _PE

        return _PE(
            event_id=_PE.new_id(raw.raw_line),
            source_type=raw.source_type,
            hostname=raw.hostname,
            timestamp=fields.pop("timestamp", _time.time()),
            facility=fields.pop("facility", None),
            severity=fields.pop("severity", None),
            process=fields.pop("process", None),
            message=message,
            raw_line=raw.raw_line,
            fields=fields,
        )
