"""
shipper.py
Drains the collector's output queue, batches events, and ships them to the
Cloud Edge Gateway (Cloudflare Worker) over HTTPS.

Security properties:
  - Confidentiality: each batch payload is encrypted client-side with
    AES-256-GCM (authenticated encryption) before it ever leaves the host.
    The gateway holds the same symmetric key to decrypt.
  - Integrity/authenticity: a second, independent HMAC-SHA256 signature is
    computed over the ciphertext + timestamp + nonce, so the gateway can
    reject replayed or tampered requests before even attempting decryption.
  - Replay resistance: each request carries a fresh random nonce and a
    unix timestamp; the gateway is expected to reject requests outside a
    +/- 5 minute window (implemented on the Worker side).

Reliability:
  - Batches flush on whichever comes first: batch_size reached, or
    batch_interval_seconds elapsed (so low-volume hosts still ship promptly).
  - Failed sends retry with exponential backoff + jitter up to max_retries.
  - If a batch exhausts all retries, it's appended to a local dead-letter
    file (NDJSON) instead of being silently dropped, so no security event
    is lost even during a prolonged gateway outage.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import queue
import random
import threading
import time
from pathlib import Path

import requests

from config import ShipperConfig
from models import ParsedEvent

logger = logging.getLogger("cloudedge.shipper")

_NONCE_BYTES = 12  # 96-bit nonce, standard for AES-GCM


class _AESGCMCipher:
    """Thin wrapper so we only import `cryptography` in one place and fail
    with a clear error if the dependency is missing."""

    def __init__(self, key_b64: str):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "the 'cryptography' package is required for payload encryption "
                "(pip install cryptography)"
            ) from exc

        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise ValueError(
                f"shipper.aes_key_b64 must decode to 32 bytes for AES-256, got {len(key)}"
            )
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext


class Shipper(threading.Thread):
    def __init__(
        self,
        cfg: ShipperConfig,
        in_queue: "queue.Queue[ParsedEvent]",
        stop_event: threading.Event,
        dead_letter_path: str = "/var/lib/cloudedge-agent/dead_letter.ndjson",
    ):
        super().__init__(name="shipper", daemon=True)
        self.cfg = cfg
        self.in_queue = in_queue
        self.stop_event = stop_event
        self.dead_letter_path = Path(dead_letter_path)
        self._cipher = _AESGCMCipher(cfg.aes_key_b64)
        self._session = requests.Session()

        self.batches_sent = 0
        self.batches_failed = 0
        self.events_sent = 0

    def run(self) -> None:
        logger.info("shipper started (endpoint=%s, batch_size=%d)",
                     self.cfg.endpoint, self.cfg.batch_size)
        buffer: list[ParsedEvent] = []
        last_flush = time.monotonic()

        while not self.stop_event.is_set() or not self.in_queue.empty() or buffer:
            timeout = max(0.0, self.cfg.batch_interval_seconds - (time.monotonic() - last_flush))
            try:
                event = self.in_queue.get(timeout=min(timeout, 1.0) or 0.1)
                buffer.append(event)
            except queue.Empty:
                pass

            should_flush = (
                len(buffer) >= self.cfg.batch_size
                or (buffer and time.monotonic() - last_flush >= self.cfg.batch_interval_seconds)
                or (self.stop_event.is_set() and buffer and self.in_queue.empty())
            )
            if should_flush and buffer:
                self._flush(buffer)
                buffer = []
                last_flush = time.monotonic()

        logger.info("shipper stopped (sent=%d batches / %d events, failed=%d batches)",
                     self.batches_sent, self.events_sent, self.batches_failed)

    # -- core send path ---------------------------------------------------

    def _flush(self, batch: list[ParsedEvent]) -> None:
        payload = json.dumps(
            {"events": [json.loads(e.to_json()) for e in batch]},
            separators=(",", ":"),
        ).encode("utf-8")

        if self._send_with_retry(payload):
            self.batches_sent += 1
            self.events_sent += len(batch)
        else:
            self.batches_failed += 1
            self._write_dead_letter(payload)

    def _send_with_retry(self, payload: bytes) -> bool:
        for attempt in range(1, self.cfg.max_retries + 1):
            try:
                if self._send_once(payload):
                    return True
            except requests.RequestException as exc:
                logger.warning("send attempt %d/%d failed: %s",
                                attempt, self.cfg.max_retries, exc)

            if attempt < self.cfg.max_retries:
                backoff = self.cfg.backoff_base_seconds * (2 ** (attempt - 1))
                backoff += random.uniform(0, backoff * 0.25)  # jitter
                self.stop_event.wait(backoff)
        return False

    def _send_once(self, payload: bytes) -> bool:
        timestamp = str(int(time.time()))
        nonce, ciphertext = self._cipher.encrypt(payload, associated_data=timestamp.encode())

        signature = self._sign(ciphertext, nonce, timestamp)

        body = json.dumps({
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "timestamp": timestamp,
        }).encode("utf-8")

        resp = self._session.post(
            self.cfg.endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-CloudEdge-Signature": signature,
                "X-CloudEdge-Timestamp": timestamp,
                "X-CloudEdge-Agent-Version": "1.0.0",
            },
            timeout=self.cfg.request_timeout_seconds,
            verify=self.cfg.verify_tls,
        )

        if resp.status_code == 200:
            return True
        if 400 <= resp.status_code < 500:
            # Client error (bad signature, malformed body) — retrying won't
            # help without a code/config fix. Log loudly, don't retry forever.
            logger.error("gateway rejected batch (HTTP %d): %s", resp.status_code, resp.text[:500])
            return False
        # 5xx / other — transient, let the retry loop handle it.
        resp.raise_for_status()
        return False

    def _sign(self, ciphertext: bytes, nonce: bytes, timestamp: str) -> str:
        mac = hmac.new(
            self.cfg.hmac_secret.encode("utf-8"),
            digestmod=hashlib.sha256,
        )
        mac.update(nonce)
        mac.update(ciphertext)
        mac.update(timestamp.encode("utf-8"))
        return base64.b64encode(mac.digest()).decode()

    def _write_dead_letter(self, payload: bytes) -> None:
        try:
            self.dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
            with self.dead_letter_path.open("ab") as fh:
                fh.write(payload)
                fh.write(b"\n")
            logger.error(
                "batch exhausted retries, wrote %d bytes to dead-letter file %s",
                len(payload), self.dead_letter_path,
            )
        except OSError as exc:
            logger.critical("FAILED TO WRITE DEAD LETTER — EVENTS LOST: %s", exc)
