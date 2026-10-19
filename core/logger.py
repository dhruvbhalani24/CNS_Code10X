"""Section 1.5 — Centralized logging (no external dependencies)."""
from __future__ import annotations

import logging
import os
import sys

_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(name)-18s │ %(message)s"
_DATEFMT = "%H:%M:%S"
_cache: dict[str, logging.Logger] = {}


def get_logger(name: str = "nids") -> logging.Logger:
    """Return a cached, console-configured logger.

    Verbosity controlled by env var:  NIDS_LOG_LEVEL=DEBUG|INFO|WARNING
    """
    if name in _cache:
        return _cache[name]

    logger = logging.getLogger(name)
    level = os.environ.get("NIDS_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.propagate = False

    if not logger.handlers:                       # avoid duplicate lines
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
        logger.addHandler(handler)

    _cache[name] = logger
    return logger
