"""
main.py
Entry point for the CloudEdge-AI-SOAR log agent.

Usage:
    python main.py --config config/config.yaml
    CLOUDEDGE_ENDPOINT=... CLOUDEDGE_HMAC_SECRET=... CLOUDEDGE_AES_KEY_B64=... python main.py

Responsibilities:
  - parse CLI args, load + validate config (fail fast on bad config)
  - configure structured logging
  - start CollectorManager (one thread per log source)
  - start Shipper (drains the shared queue, ships to Cloud Edge Gateway)
  - handle SIGINT/SIGTERM for graceful shutdown (flush state, drain queue)
  - periodically log a health summary
"""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time

from collector import CollectorManager
from config import ConfigError, load_config
from shipper import Shipper


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
    )
    # requests/urllib3 are noisy at DEBUG; keep them at WARNING regardless.
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cloudedge-agent",
        description="CloudEdge-AI-SOAR local log collector",
    )
    p.add_argument(
        "--config", default="config/config.yaml",
        help="path to YAML config file (default: config/config.yaml)",
    )
    p.add_argument(
        "--health-interval", type=float, default=60.0,
        help="seconds between health summary log lines (default: 60)",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        # Logging isn't configured yet — this is a startup config problem,
        # print directly to stderr and exit non-zero for systemd/Docker.
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    _setup_logging(cfg.log_level)
    logger = logging.getLogger("cloudedge.main")
    logger.info("CloudEdge-AI-SOAR log agent starting up (hostname=%s)", cfg.hostname)
    logger.info("configured sources: %s", ", ".join(s.name for s in cfg.sources if s.enabled))

    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        logger.info("received signal %s, shutting down gracefully...", signal.Signals(signum).name)
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    collector_mgr = CollectorManager(cfg)
    try:
        collector_mgr.start()
    except RuntimeError as exc:
        logger.error("failed to start collectors: %s", exc)
        return 1

    shipper = Shipper(
        cfg=cfg.shipper,
        in_queue=collector_mgr.out_queue,
        stop_event=stop_event,
        dead_letter_path=str(
            __import__("pathlib").Path(cfg.state_file).parent / "dead_letter.ndjson"
        ),
    )
    shipper.start()

    last_health_log = time.monotonic()
    last_state_flush = time.monotonic()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)

            now = time.monotonic()
            if now - last_health_log >= args.health_interval:
                health = collector_mgr.health()
                logger.info(
                    "health: queue_depth=%d workers=%s shipped=%d sent_batches=%d failed_batches=%d",
                    health["queue_depth"],
                    [(w["source"], w["alive"], w["events_emitted"]) for w in health["workers"]],
                    shipper.events_sent,
                    shipper.batches_sent,
                    shipper.batches_failed,
                )
                last_health_log = now

            if now - last_state_flush >= 10.0:
                collector_mgr.state.flush()
                last_state_flush = now

    except KeyboardInterrupt:
        stop_event.set()

    # -- graceful shutdown --------------------------------------------------
    logger.info("waiting for shipper to drain remaining events...")
    collector_mgr.stop_event.set()  # stop collector threads from reading new lines
    shipper.join(timeout=30.0)
    collector_mgr.stop(timeout=10.0)

    logger.info("shutdown complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
