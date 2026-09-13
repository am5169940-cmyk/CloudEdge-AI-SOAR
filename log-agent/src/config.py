"""
config.py
Loads and validates runtime configuration for the CloudEdge-AI-SOAR log agent.

Precedence (highest wins):
  1. Environment variables (CLOUDEDGE_*)
  2. YAML config file (--config path, default: config/config.yaml)
  3. Hardcoded defaults below

This lets the same image run in Docker/systemd with only env vars, while
still supporting a checked-in config.yaml for local development.
"""
from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing or invalid — fail fast on startup."""


@dataclass(slots=True)
class SourceConfig:
    name: str
    type: str              # "syslog" | "auth" | "web"
    path: str
    enabled: bool = True


@dataclass(slots=True)
class ShipperConfig:
    endpoint: str = ""
    hmac_secret: str = ""
    aes_key_b64: str = ""          # 32-byte key, base64-encoded, for AES-GCM
    batch_size: int = 50
    batch_interval_seconds: float = 5.0
    max_retries: int = 5
    backoff_base_seconds: float = 1.5
    request_timeout_seconds: float = 10.0
    verify_tls: bool = True


@dataclass(slots=True)
class AgentConfig:
    hostname: str = field(default_factory=socket.gethostname)
    state_file: str = "/var/lib/cloudedge-agent/state.json"
    log_level: str = "INFO"
    poll_interval_seconds: float = 1.0
    read_chunk_bytes: int = 65536
    queue_max_size: int = 10000
    sources: list[SourceConfig] = field(default_factory=list)
    shipper: ShipperConfig = field(default_factory=ShipperConfig)

    def validate(self) -> None:
        errors: list[str] = []

        if not self.sources:
            errors.append("no log sources configured under 'sources:'")

        seen_names = set()
        for s in self.sources:
            if s.type not in ("syslog", "auth", "web"):
                errors.append(f"source '{s.name}': unknown type '{s.type}'")
            if s.name in seen_names:
                errors.append(f"duplicate source name '{s.name}'")
            seen_names.add(s.name)

        if not self.shipper.endpoint:
            errors.append("shipper.endpoint is required (Cloud Edge Gateway URL)")
        elif not self.shipper.endpoint.startswith(("https://", "http://")):
            errors.append("shipper.endpoint must be a valid http(s) URL")

        if not self.shipper.hmac_secret:
            errors.append("shipper.hmac_secret is required for request signing")

        if not self.shipper.aes_key_b64:
            errors.append("shipper.aes_key_b64 is required for payload encryption")

        if self.shipper.batch_size <= 0:
            errors.append("shipper.batch_size must be > 0")

        if errors:
            raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(errors))


def _env_override(cfg: dict[str, Any]) -> dict[str, Any]:
    """Apply CLOUDEDGE_* environment variable overrides onto a raw config dict."""
    mapping = {
        "CLOUDEDGE_ENDPOINT": ("shipper", "endpoint"),
        "CLOUDEDGE_HMAC_SECRET": ("shipper", "hmac_secret"),
        "CLOUDEDGE_AES_KEY_B64": ("shipper", "aes_key_b64"),
        "CLOUDEDGE_LOG_LEVEL": ("agent", "log_level"),
        "CLOUDEDGE_STATE_FILE": ("agent", "state_file"),
        "CLOUDEDGE_HOSTNAME": ("agent", "hostname"),
    }
    for env_var, (section, key) in mapping.items():
        val = os.environ.get(env_var)
        if val is None:
            continue
        cfg.setdefault(section, {})
        cfg[section][key] = val
    return cfg


def load_config(path: str | Path = "config/config.yaml") -> AgentConfig:
    path = Path(path)
    raw: dict[str, Any] = {}

    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    else:
        print(f"[config] warning: '{path}' not found, relying on env vars + defaults",
              file=sys.stderr)

    raw = _env_override(raw)

    agent_raw = raw.get("agent", {}) or {}
    shipper_raw = raw.get("shipper", {}) or {}
    sources_raw = raw.get("sources", []) or []

    sources = [
        SourceConfig(
            name=s["name"],
            type=s["type"],
            path=s["path"],
            enabled=s.get("enabled", True),
        )
        for s in sources_raw
    ]

    shipper = ShipperConfig(
        endpoint=shipper_raw.get("endpoint", ""),
        hmac_secret=shipper_raw.get("hmac_secret", ""),
        aes_key_b64=shipper_raw.get("aes_key_b64", ""),
        batch_size=int(shipper_raw.get("batch_size", 50)),
        batch_interval_seconds=float(shipper_raw.get("batch_interval_seconds", 5.0)),
        max_retries=int(shipper_raw.get("max_retries", 5)),
        backoff_base_seconds=float(shipper_raw.get("backoff_base_seconds", 1.5)),
        request_timeout_seconds=float(shipper_raw.get("request_timeout_seconds", 10.0)),
        verify_tls=bool(shipper_raw.get("verify_tls", True)),
    )

    cfg = AgentConfig(
        hostname=agent_raw.get("hostname", socket.gethostname()),
        state_file=agent_raw.get("state_file", "/var/lib/cloudedge-agent/state.json"),
        log_level=agent_raw.get("log_level", "INFO"),
        poll_interval_seconds=float(agent_raw.get("poll_interval_seconds", 1.0)),
        read_chunk_bytes=int(agent_raw.get("read_chunk_bytes", 65536)),
        queue_max_size=int(agent_raw.get("queue_max_size", 10000)),
        sources=sources,
        shipper=shipper,
    )

    cfg.validate()
    return cfg
