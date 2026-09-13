"""
state.py
Tracks per-file read offsets + inode so the collector can resume exactly
where it left off after a restart, and correctly detect log rotation
(new inode at the same path => start from 0).

State is persisted as JSON and written atomically (write-to-temp + rename)
so a crash mid-write never corrupts the file.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass(slots=True)
class FileState:
    path: str
    inode: int
    offset: int


class StateManager:
    """Thread-safe, disk-backed offset tracker keyed by source path."""

    def __init__(self, state_file: str):
        self._state_file = Path(state_file)
        self._lock = threading.Lock()
        self._state: dict[str, FileState] = {}
        self._load()

    def _load(self) -> None:
        if not self._state_file.exists():
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            return
        try:
            with self._state_file.open("r", encoding="utf-8") as fh:
                raw = json.load(fh)
            for path, entry in raw.items():
                self._state[path] = FileState(**entry)
        except (json.JSONDecodeError, OSError, TypeError) as exc:
            # Corrupt or unreadable state file — start clean rather than crash.
            # We log to stderr since the logging subsystem may not be up yet.
            import sys
            print(f"[state] warning: could not load state file ({exc}); starting fresh",
                  file=sys.stderr)
            self._state = {}

    def get(self, path: str) -> Optional[FileState]:
        with self._lock:
            return self._state.get(path)

    def update(self, path: str, inode: int, offset: int) -> None:
        with self._lock:
            self._state[path] = FileState(path=path, inode=inode, offset=offset)

    def flush(self) -> None:
        """Atomically persist current state to disk."""
        with self._lock:
            snapshot = {p: asdict(s) for p, s in self._state.items()}

        tmp_path = self._state_file.with_suffix(".tmp")
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, self._state_file)
