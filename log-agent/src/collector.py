"""
collector.py
Multi-threaded log collector. One daemon thread is spawned per configured
source; each thread tails its file (like `tail -F`), handing completed
lines to the appropriate parser, enriching the result with IOCs, and
pushing the finished ParsedEvent onto a shared, bounded, thread-safe
queue that the shipper drains.

Rotation handling: on each poll we stat() the file. If the inode changed
(or the file shrank — truncated in place, e.g. logrotate `copytruncate`),
we reopen from offset 0. This is the same strategy filebeat/promtail use.
"""
from __future__ import annotations

import logging
import os
import queue
import threading
import time
from pathlib import Path

from config import AgentConfig, SourceConfig
from ioc import IOCExtractor
from models import ParsedEvent, RawLogLine, SourceType
from parsers import PARSER_REGISTRY
from state import StateManager

logger = logging.getLogger("cloudedge.collector")


class SourceWorker(threading.Thread):
    """One thread per log source. Tails the file and emits ParsedEvents."""

    def __init__(
        self,
        source: SourceConfig,
        out_queue: "queue.Queue[ParsedEvent]",
        state: StateManager,
        ioc_extractor: IOCExtractor,
        hostname: str,
        poll_interval: float,
        read_chunk_bytes: int,
        stop_event: threading.Event,
    ):
        super().__init__(name=f"collector-{source.name}", daemon=True)
        self.source = source
        self.out_queue = out_queue
        self.state = state
        self.ioc_extractor = ioc_extractor
        self.hostname = hostname
        self.poll_interval = poll_interval
        self.read_chunk_bytes = read_chunk_bytes
        self.stop_event = stop_event

        try:
            parser_cls = PARSER_REGISTRY[source.type]
        except KeyError:
            raise ValueError(f"no parser registered for source type '{source.type}'")
        self.parser = parser_cls()

        self._fh = None  # open file handle
        self._inode: int | None = None
        self._buffer = ""  # holds a trailing partial line between reads

        self.lines_processed = 0
        self.events_emitted = 0
        self.last_error: str | None = None

    def run(self) -> None:
        logger.info("starting collector for source '%s' (%s)", self.source.name, self.source.path)
        self._open_or_resume()

        while not self.stop_event.is_set():
            try:
                self._poll_once()
            except Exception as exc:  # noqa: BLE001 - a single source must not kill the process
                self.last_error = str(exc)
                logger.exception("error polling source '%s': %s", self.source.name, exc)
                time.sleep(self.poll_interval * 2)
            self.stop_event.wait(self.poll_interval)

        self._close()
        logger.info("stopped collector for source '%s'", self.source.name)

    # -- file lifecycle -------------------------------------------------

    def _open_or_resume(self) -> None:
        path = Path(self.source.path)
        if not path.exists():
            logger.warning("source path does not exist yet: %s (will retry)", path)
            return

        st = path.stat()
        saved = self.state.get(self.source.path)

        self._fh = open(path, "r", encoding="utf-8", errors="replace")
        self._inode = st.st_ino

        if saved and saved.inode == st.st_ino and saved.offset <= st.st_size:
            self._fh.seek(saved.offset)
            logger.info("resuming '%s' at offset %d", self.source.path, saved.offset)
        else:
            # New file, rotated file, or truncated file — start at EOF so we
            # only ship *new* events rather than re-ingesting the whole
            # historical file on first run (avoids alert storms on deploy).
            if saved is None:
                self._fh.seek(0, os.SEEK_END)
                logger.info("first run for '%s', starting at EOF", self.source.path)
            else:
                self._fh.seek(0)
                logger.info("rotation/truncation detected for '%s', starting at offset 0",
                             self.source.path)

    def _reopen_if_rotated(self) -> bool:
        path = Path(self.source.path)
        if not path.exists():
            return False
        try:
            st = path.stat()
        except OSError:
            return False

        rotated = self._fh is None or st.st_ino != self._inode
        truncated = (
            self._fh is not None
            and st.st_ino == self._inode
            and st.st_size < self._fh.tell()
        )
        if rotated or truncated:
            self._close()
            self._fh = open(path, "r", encoding="utf-8", errors="replace")
            self._inode = st.st_ino
            self._fh.seek(0)
            self._buffer = ""
            logger.info("reopened '%s' (rotated=%s truncated=%s)", path, rotated, truncated)
        return True

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    # -- polling ----------------------------------------------------------

    def _poll_once(self) -> None:
        if self._fh is None:
            self._open_or_resume()
            if self._fh is None:
                return  # still doesn't exist

        if not self._reopen_if_rotated():
            return

        chunk = self._fh.read(self.read_chunk_bytes)
        if not chunk:
            return

        self._buffer += chunk
        *complete_lines, self._buffer = self._buffer.split("\n")

        for line in complete_lines:
            if not line:
                continue
            self._handle_line(line)

        # persist offset after each successful poll batch
        self.state.update(self.source.path, self._inode, self._fh.tell())

    def _handle_line(self, line: str) -> None:
        self.lines_processed += 1
        raw = RawLogLine(
            source_type=SourceType(self.source.type),
            source_path=self.source.path,
            hostname=self.hostname,
            raw_line=line,
        )
        event = self.parser.parse(raw)
        if event is None:
            return

        event.iocs = self.ioc_extractor.extract(line)

        try:
            self.out_queue.put(event, timeout=1.0)
            self.events_emitted += 1
        except queue.Full:
            logger.warning(
                "output queue full — dropping event from '%s' (backpressure)",
                self.source.name,
            )


class CollectorManager:
    """Owns the worker pool and the shared output queue."""

    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.out_queue: "queue.Queue[ParsedEvent]" = queue.Queue(maxsize=cfg.queue_max_size)
        self.state = StateManager(cfg.state_file)
        self.stop_event = threading.Event()
        self._workers: list[SourceWorker] = []
        # exclude_private_ips=False: internal lateral movement IPs are still
        # valuable IOCs for a SOC, so we keep them and let the classifier weigh them.
        self._ioc_extractor = IOCExtractor(exclude_private_ips=False)

    def start(self) -> None:
        active_sources = [s for s in self.cfg.sources if s.enabled]
        if not active_sources:
            raise RuntimeError("no enabled sources to collect from")

        for source in active_sources:
            worker = SourceWorker(
                source=source,
                out_queue=self.out_queue,
                state=self.state,
                ioc_extractor=self._ioc_extractor,
                hostname=self.cfg.hostname,
                poll_interval=self.cfg.poll_interval_seconds,
                read_chunk_bytes=self.cfg.read_chunk_bytes,
                stop_event=self.stop_event,
            )
            worker.start()
            self._workers.append(worker)

        logger.info("started %d collector thread(s)", len(self._workers))

    def stop(self, timeout: float = 5.0) -> None:
        logger.info("stopping collectors...")
        self.stop_event.set()
        for w in self._workers:
            w.join(timeout=timeout)
        self.state.flush()
        logger.info("all collectors stopped, state flushed")

    def health(self) -> dict:
        return {
            "workers": [
                {
                    "source": w.source.name,
                    "alive": w.is_alive(),
                    "lines_processed": w.lines_processed,
                    "events_emitted": w.events_emitted,
                    "last_error": w.last_error,
                }
                for w in self._workers
            ],
            "queue_depth": self.out_queue.qsize(),
        }
