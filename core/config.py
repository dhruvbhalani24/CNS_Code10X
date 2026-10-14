"""
Section 1.2 — Configuration manager.

Design: DEFAULTS dict is the single source of truth (no external file
required). If a `config.yaml` exists at project root, it is deep-merged
on top of the defaults, so users override only what they need.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:          # PyYAML is optional; defaults always work
    _HAS_YAML = False

# --------------------------------------------------------------------------- #
#                              DEFAULT SETTINGS                                #
# --------------------------------------------------------------------------- #
DEFAULTS: dict[str, Any] = {
    "general": {
        "project_name": "CodeX10 NIDS-SIEM",
        "data_dir": "data",              # SQLite DB / exported JSON live here
        "db_path": "data/nids.db",
        "batch_size": 100,
    },
    "sensors": {
        "zeek_log_dir": "logs/zeek",     # folder with conn.log / dns.log / http.log
        "tail": False,                   # True = follow logs like `tail -f`
        "tail_poll_seconds": 1.0,
        "pcap_file": "",                 # optional .pcap for the replayer
    },
    "simulator": {
        "seed": 42,
        "normal_events": 600,
        "attacks": ["port_scan", "dos", "c2", "exfil"],
        "write_zeek_logs": True,         # emit real Zeek-format conn.log
        "output_dir": "logs/zeek",
    },
    "detection": {
        "port_scan": {"window": 60, "port_threshold": 15,
                      "fail_states": ["S0", "REJ", "RSTR"]},
        "dos":       {"window": 10, "rate_threshold": 80},
        "c2":        {"min_beacons": 6, "jitter": 0.30,
                      "dst_ports": [443, 8443, 8080],
                      "bad_domains": ["malware-cdn.xyz", "update-svc.tk",
                                      "beacon-panel.top"]},
        "anomaly":   {"window": 200, "zscore": 3.0},
    },
    "slips": {"enabled": False, "path": "", "timeout": 300},
    "storage": {
        "backend": "local",                          # "local" | "elasticsearch"
        "es_hosts": ["http://localhost:9200"],
        "index_prefix": "nids",
    },
    "alerting": {
        "min_severity": "MEDIUM",                    # gate for notifications
        "cooldown": 60,                              # dedup window (seconds)
        "telegram": {"enabled": False, "token": "", "chat_id": "",
                     "timeout": 10},
    },
    "dashboard": {"host": "127.0.0.1", "port": 5000, "refresh_seconds": 3},
}


class Config:
    """Read-only attribute-style wrapper around a nested dict.

    >>> cfg = Config({"a": {"b": 1}})
    >>> cfg.a.b
    1
    """

    def __init__(self, data: dict) -> None:
        object.__setattr__(self, "_data", data)

    def __getattr__(self, name: str) -> Any:
        try:
            value = self._data[name]
        except KeyError as exc:
            raise AttributeError(f"Missing config key: {name!r}") from exc
        return Config(value) if isinstance(value, dict) else value

    def __getitem__(self, key: str) -> Any:
        return self.__getattr__(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def as_dict(self) -> dict:
        return copy.deepcopy(self._data)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge `override` into `base` (in place)."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


_config: Optional[Config] = None


def get_config(path: Optional[str] = None) -> Config:
    """Singleton accessor. Loads defaults, then optional YAML overlay."""
    global _config
    if _config is None:
        merged = copy.deepcopy(DEFAULTS)
        path = path or os.environ.get("NIDS_CONFIG", "config.yaml")
        if Path(path).is_file() and _HAS_YAML:
            with open(path, "r", encoding="utf-8") as fh:
                user_cfg = yaml.safe_load(fh) or {}
            _deep_merge(merged, user_cfg)
        _config = Config(merged)
    return _config


def reset_config() -> None:
    """Force re-read of configuration (used by tests)."""
    global _config
    _config = None
