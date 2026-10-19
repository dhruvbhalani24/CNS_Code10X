"""
Sections 3 & 4 — Network Intrusion Detection Engine.

Pluggable detection modules operating on normalized connection events:
  * Section 3: BaseDetector, SlidingWindow, PortScanDetector, DosDetector
  * Section 4: C2BeaconDetector, AnomalyDetector, ExfilDetector, SlipsAdapter, registry
"""
from __future__ import annotations

from detection.anomaly_detector import AnomalyDetector
from detection.base_detector import BaseDetector
from detection.c2_detector import C2BeaconDetector
from detection.dos_detector import DoSDetector, DosDetector
from detection.exfil_detector import ExfilDetector
from detection.port_scan_detector import PortScanDetector
from detection.registry import build_detectors
from detection.sliding_window import SlidingWindow, TimeWindow, prune_deque
from detection.slips_adapter import SlipsAdapter

__all__ = [
    "BaseDetector",
    "SlidingWindow",
    "TimeWindow",
    "prune_deque",
    "PortScanDetector",
    "DosDetector",
    "DoSDetector",
    "C2BeaconDetector",
    "AnomalyDetector",
    "ExfilDetector",
    "SlipsAdapter",
    "build_detectors",
]
