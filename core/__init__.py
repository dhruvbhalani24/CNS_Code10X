"""
CodeX10 NIDS-SIEM — Core Framework
==================================
Section 1: Shared foundation used by every other section.
Exports: configuration, event models, logging.
"""
from core.config import get_config, reset_config
from core.event import ConnectionEvent, Alert, severity_rank, SEVERITY_LEVELS
from core.logger import get_logger

__version__ = "1.0.0"
__all__ = [
    "get_config", "reset_config",
    "ConnectionEvent", "Alert", "severity_rank", "SEVERITY_LEVELS",
    "get_logger",
]
