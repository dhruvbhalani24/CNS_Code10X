"""
Section 4.5 — Detector registry and pipeline factory.

Builds and configures fresh instances of all registered detectors from
application configuration.
"""
from __future__ import annotations

from typing import Any, Optional

from core.config import get_config
from core.logger import get_logger
from detection.anomaly_detector import AnomalyDetector
from detection.base_detector import BaseDetector
from detection.c2_detector import C2BeaconDetector
from detection.dos_detector import DoSDetector, DosDetector
from detection.exfil_detector import ExfilDetector
from detection.port_scan_detector import PortScanDetector

_LOG = get_logger("detection.registry")


def build_detectors(cfg: Optional[Any] = None) -> list[BaseDetector]:
    """Instantiate and return fresh instances of all active detectors.

    Args:
        cfg: Optional configuration dictionary or Config object. If None,
             reads `get_config().detection`.

    Returns:
        List of fresh detector instances:
        [PortScanDetector, DosDetector, C2BeaconDetector, AnomalyDetector, ExfilDetector]
    """
    det_cfg: dict[str, Any] = {}
    try:
        if cfg is not None:
            if hasattr(cfg, "as_dict"):
                det_cfg = cfg.as_dict()
            elif isinstance(cfg, dict):
                det_cfg = dict(cfg)
        else:
            conf = get_config()
            detection_attr = getattr(conf, "detection", None)
            if detection_attr is not None:
                if hasattr(detection_attr, "as_dict"):
                    det_cfg = detection_attr.as_dict()
                elif isinstance(detection_attr, dict):
                    det_cfg = dict(detection_attr)
    except Exception as exc:
        _LOG.warning("Failed to read detection config, falling back to defaults: %s", exc)
        det_cfg = {}

    # Read sub-configs matching keys in core/config.py:
    # "port_scan", "dos", "c2", "anomaly" (ExfilDetector has no config.py entry)
    ps_cfg = det_cfg.get("port_scan")
    dos_cfg = det_cfg.get("dos")
    c2_cfg = det_cfg.get("c2") if "c2" in det_cfg else det_cfg.get("c2_beacon")
    anomaly_cfg = det_cfg.get("anomaly")
    exfil_cfg = det_cfg.get("exfil") if "exfil" in det_cfg else det_cfg.get("exfiltration")

    return [
        PortScanDetector(ps_cfg),
        DosDetector(dos_cfg),
        C2BeaconDetector(c2_cfg),
        AnomalyDetector(anomaly_cfg),
        ExfilDetector(exfil_cfg),
    ]
