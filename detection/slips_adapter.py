"""
Section 4.4 — Stratosphere Slips behavioral NIDS adapter.

Bridges the pipeline to the Stratosphere Slips behavioral analysis engine:
  * In real mode (slips.enabled=True): invokes the Slips process / daemon
    via subprocess with fail-soft error handling.
  * In offline emulation mode (slips.enabled=False): performs behavioral
    anomaly scoring on failed connection ratios, port sweeps, and threat-intel hits.
"""
from __future__ import annotations

import json
import subprocess
from collections import deque
from typing import Any, Optional

from core.config import get_config
from core.event import Alert, ConnectionEvent
from core.logger import get_logger
from detection.sliding_window import prune_deque


class SlipsAdapter:
    """Adapter bridging the pipeline to Stratosphere Slips."""

    name: str = "slips"

    def __init__(self) -> None:
        self.name = "slips"
        self.log = get_logger(f"adapter.{self.name}")

        # Read slips configuration from core/config.py
        self.enabled: bool = False
        self.path: str = ""
        self.timeout: int = 10
        self.bad_domains: list[str] = []

        try:
            cfg = get_config()
            slips_cfg = getattr(cfg, "slips", None)
            if slips_cfg is not None:
                if hasattr(slips_cfg, "as_dict"):
                    s_dict = slips_cfg.as_dict()
                elif isinstance(slips_cfg, dict):
                    s_dict = slips_cfg
                else:
                    s_dict = {}
                self.enabled = bool(s_dict.get("enabled", False))
                self.path = str(s_dict.get("path", "") or "")
                self.timeout = int(s_dict.get("timeout", 10) or 10)

            # Read bad domains from detection.c2_beacon or detection.c2
            det_cfg = getattr(cfg, "detection", None)
            if det_cfg is not None:
                c2_cfg = getattr(det_cfg, "c2_beacon", None) or getattr(det_cfg, "c2", None)
                if c2_cfg is not None:
                    if hasattr(c2_cfg, "bad_domains"):
                        raw_domains = c2_cfg.bad_domains
                    elif isinstance(c2_cfg, dict):
                        raw_domains = c2_cfg.get("bad_domains", [])
                    else:
                        raw_domains = []
                    self.bad_domains = [
                        str(d).strip().lower().rstrip(".") for d in raw_domains if d
                    ]
        except Exception as exc:
            self.log.warning("Failed to load Slips configuration, defaulting to disabled: %s", exc)
            self.enabled = False

        # State for behavioral emulation:
        # Maps src_ip -> deque of (ts, dst_ip, dst_port, conn_state, threat_hit)
        self.window: float = 300.0
        self._history: dict[str, deque[tuple[float, str, int, str, bool]]] = {}
        self._last_seen: dict[str, float] = {}
        self._last_alert: dict[str, float] = {}
        self._max_sources: int = 5_000

    def analyze(self, events: list[ConnectionEvent]) -> list[Alert]:
        """Analyze a batch of connection events. Never raises exceptions."""
        try:
            alerts: list[Alert] = []
            for event in events:
                alerts.extend(self._process_single_event(event))
            return alerts
        except Exception as exc:
            self.log.warning("Slips analysis failed unexpectedly: %s", exc)
            return []

    def _process_single_event(self, event: ConnectionEvent) -> list[Alert]:
        if self.enabled:
            return self._run_slips_command(event)
        return self._emulate_behavior(event)

    # ------------------------------------------------------------------ #
    #  Behavioral emulation mode (slips.enabled == False)                  #
    # ------------------------------------------------------------------ #
    def _emulate_behavior(self, event: ConnectionEvent) -> list[Alert]:
        src_ip = getattr(event, "src_ip", "")
        dst_ip = getattr(event, "dst_ip", "")
        dst_port = int(getattr(event, "dst_port", 0) or 0)
        conn_state = (getattr(event, "conn_state", "") or "").upper()
        ts = float(getattr(event, "ts", 0.0))

        # Check threat intel
        query = str(getattr(event, "dns_query", "") or "").strip().lower().rstrip(".")
        host = str(getattr(event, "http_host", "") or "").strip().lower().rstrip(".")
        threat_hit = False
        matched_domain = ""
        for d in (query, host):
            if not d:
                continue
            for bad in self.bad_domains:
                if d == bad or d.endswith("." + bad):
                    threat_hit = True
                    matched_domain = bad
                    break
            if threat_hit:
                break

        # Track per-src_ip history
        if src_ip not in self._history:
            if len(self._history) >= self._max_sources:
                self._evict_stale_sources(ts)
            self._history[src_ip] = deque()

        dq = self._history[src_ip]
        dq.append((ts, dst_ip, dst_port, conn_state, threat_hit))
        self._last_seen[src_ip] = ts
        prune_deque(dq, ts, self.window, ts_extractor=lambda entry: entry[0])

        # Evaluate signals
        conns_count = len(dq)
        failed_conns = [entry for entry in dq if entry[3] in ("S0", "REJ", "RSTR")]
        failed_ratio = len(failed_conns) / conns_count if conns_count else 0.0
        distinct_failed_ports = len({entry[2] for entry in failed_conns})
        has_threat_intel_hit = any(entry[4] for entry in dq)

        signal_failed_ratio = conns_count >= 20 and failed_ratio >= 0.8
        signal_port_scan = distinct_failed_ports >= 15
        signal_threat_intel = has_threat_intel_hit

        signals_fired: list[str] = []
        if signal_failed_ratio:
            signals_fired.append(f"failed_conn_ratio ({failed_ratio:.2f} >= 0.8 across {conns_count} conns)")
        if signal_port_scan:
            signals_fired.append(f"distinct_failed_ports ({distinct_failed_ports} >= 15)")
        if signal_threat_intel:
            signals_fired.append(f"threat_intel_match ({matched_domain})")

        if not signals_fired:
            return []

        # Check per-source 300s cooldown
        last_alert_ts = self._last_alert.get(src_ip)
        if last_alert_ts is not None and 0.0 <= (ts - last_alert_ts) < self.window:
            return []

        self.mark_alerted(src_ip, ts)

        severity = "CRITICAL" if signal_threat_intel else "HIGH"
        evidence = {
            "signals_fired": signals_fired,
            "window": self.window,
            "conns_in_window": conns_count,
            "failed_ratio": round(failed_ratio, 3),
            "distinct_failed_ports": distinct_failed_ports,
            "threat_hit": threat_hit,
        }

        alert = Alert(
            event_type="slips_behavior",
            severity=severity,
            description=(
                f"Slips behavioral anomaly from {src_ip}: {', '.join(signals_fired)}"
            ),
            src_ip=src_ip,
            dst_ip=dst_ip,
            detected_by="slips",
            evidence=evidence,
            ts=ts,
        )
        return [alert]

    def mark_alerted(self, src_ip: str, ts: float) -> None:
        """Record alert timestamp and prune cooldown records."""
        if len(self._last_alert) >= self._max_sources:
            expired = [ip for ip, lts in self._last_alert.items() if (ts - lts) >= self.window]
            for ip in expired:
                self._last_alert.pop(ip, None)
            if len(self._last_alert) >= self._max_sources:
                sorted_keys = sorted(self._last_alert.items(), key=lambda kv: kv[1])
                for ip, _ in sorted_keys[: max(1, len(sorted_keys) // 10)]:
                    self._last_alert.pop(ip, None)
        self._last_alert[src_ip] = ts

    def _evict_stale_sources(self, current_ts: float) -> None:
        """Evict empty or oldest sources to respect max_sources capacity."""
        keys = list(self._history.keys())
        for k in keys:
            dq = self._history[k]
            prune_deque(dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
            if not dq:
                self._history.pop(k, None)
                self._last_seen.pop(k, None)

        if len(self._history) >= self._max_sources:
            sorted_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            for k, _ in sorted_keys[: max(1, len(sorted_keys) // 10)]:
                self._history.pop(k, None)
                self._last_seen.pop(k, None)

    # ------------------------------------------------------------------ #
    #  Live Slips execution mode (slips.enabled == True)                   #
    # ------------------------------------------------------------------ #
    def _run_slips_command(self, event: ConnectionEvent) -> list[Alert]:
        """Invoke external Slips tool with soft-fail exception handling."""
        try:
            cmd = self.path or "slips"
            payload = json.dumps(event.to_dict())
            res = subprocess.run(
                cmd if isinstance(cmd, list) else [cmd],
                input=payload,
                capture_output=True,
                text=True,
                timeout=min(self.timeout, 10),
            )
            if res.returncode != 0 or not res.stdout.strip():
                return []

            alerts: list[Alert] = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    alerts.append(
                        Alert(
                            event_type="slips_behavior",
                            severity=data.get("severity", "HIGH"),
                            description=data.get("description", "Slips alert"),
                            src_ip=data.get("src_ip", event.src_ip),
                            dst_ip=data.get("dst_ip", event.dst_ip),
                            detected_by="slips",
                            evidence=data.get("evidence", {}),
                            ts=float(data.get("ts", event.ts)),
                        )
                    )
                except Exception:
                    continue
            return alerts
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return []

    def reset(self) -> None:
        """Reset internal state (useful between test runs)."""
        self._history.clear()
        self._last_seen.clear()
        self._last_alert.clear()
