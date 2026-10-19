"""
Section 10.2 — Unit tests for the detection engine (Sections 3 & 4) and
alerting machinery (Section 7).  Run:  pytest -q   (from project root)
"""
from __future__ import annotations

from core.event import Alert, ConnectionEvent
from detection.anomaly_detector import AnomalyDetector
from detection.c2_detector import C2BeaconDetector
from detection.dos_detector import DosDetector
from detection.exfil_detector import ExfilDetector
from detection.port_scan_detector import PortScanDetector
from alerting.alert_manager import AlertManager
from alerting.escalation import EscalationPolicy


def ev(ts=1000.0, src="10.0.1.50", dst="10.0.0.10", port=80, state="SF",
       ob=1_000, proto="tcp", service="-", dns_query="", http_host=""):
    return ConnectionEvent(ts=ts, src_ip=src, dst_ip=dst, dst_port=port,
                           proto=proto, service=service, conn_state=state,
                           orig_bytes=ob, dns_query=dns_query,
                           http_host=http_host, sensor="test", label="test")


# ------------------------------ port scan --------------------------------- #
def test_port_scan_detected():
    det = PortScanDetector({"window": 60, "port_threshold": 10,
                            "fail_states": ["S0", "REJ"]})
    alerts = []
    for i in range(15):
        alerts += det.process(ev(ts=1000 + i * 0.5, port=1000 + i, state="S0"))
    assert any(a.event_type == "port_scan" for a in alerts)


def test_port_scan_not_flagged_for_normal_browsing():
    det = PortScanDetector({"window": 60, "port_threshold": 10,
                            "fail_states": ["S0", "REJ"]})
    alerts = []
    for i in range(15):
        alerts += det.process(ev(ts=1000 + i * 0.5, port=1000 + i,
                                 state="SF", ob=50_000))   # successful conns
    assert not alerts


# ---------------------------------- DoS ------------------------------------ #
def test_dos_flood_detected():
    det = DosDetector({"window": 10, "rate_threshold": 50})
    alerts = []
    for i in range(60):
        alerts += det.process(ev(ts=1000 + i * 0.05, state="S0", ob=0))
    assert any(a.event_type == "dos" for a in alerts)


def test_dos_not_flagged_for_light_traffic():
    det = DosDetector({"window": 10, "rate_threshold": 50})
    alerts = [a for i in range(20)
              for a in det.process(ev(ts=1000 + i * 0.5))]
    assert not alerts


# ---------------------------------- C2 ------------------------------------- #
def test_c2_beaconing_detected():
    det = C2BeaconDetector({"min_beacons": 6, "jitter": 0.30,
                            "dst_ports": [443], "bad_domains": []})
    alerts = []
    for i in range(8):
        alerts += det.process(ev(ts=1000 + i * 30.0, port=443, ob=512))
    assert any(a.event_type == "c2_beacon" for a in alerts)


def test_c2_irregular_traffic_not_flagged():
    det = C2BeaconDetector({"min_beacons": 6, "jitter": 0.30,
                            "dst_ports": [443], "bad_domains": []})
    alerts, t = [], 1000.0
    for gap in (10, 90, 5, 120, 60, 40, 15, 80):        # human-like
        t += gap
        alerts += det.process(ev(ts=t, port=443, ob=512))
    assert not [a for a in alerts if a.event_type == "c2_beacon"]


def test_c2_threat_intel_domain_hit():
    det = C2BeaconDetector({"min_beacons": 99, "jitter": 0.3,
                            "dst_ports": [443],
                            "bad_domains": ["malware-cdn.xyz"]})
    hits = det.process(ev(dns_query="cdn.malware-cdn.xyz", port=53))
    assert hits and hits[0].severity == "CRITICAL"


# ------------------------------- anomaly ----------------------------------- #
def test_anomaly_volume_spike_detected():
    det = AnomalyDetector({"window": 200, "zscore": 3.0})
    for i in range(30):                                   # learn baseline
        det.process(ev(ts=1000 + i, ob=900 + (i % 7) * 20))
    alerts = det.process(ev(ts=1031, ob=50_000_000))      # 50 MB spike
    assert any(a.event_type == "anomaly" for a in alerts)


def test_anomaly_normal_traffic_not_flagged():
    det = AnomalyDetector({"window": 200, "zscore": 3.0})
    alerts = []
    for i in range(40):
        alerts += det.process(ev(ts=1000 + i, ob=900 + (i % 7) * 20))
    assert not alerts


# ------------------------------ exfiltration ------------------------------- #
def test_exfil_detected():
    det = ExfilDetector({"window": 600, "bytes_threshold": 100_000_000,
                         "min_connections": 3})
    alerts = []
    for i in range(4):
        alerts += det.process(ev(ts=1000 + i * 10, src="10.0.1.5",
                                 dst="45.33.10.99", port=8443,
                                 ob=30_000_000))
    assert any(a.event_type == "exfiltration" for a in alerts)


def test_exfil_ignored_for_internal_traffic():
    det = ExfilDetector({"window": 600, "bytes_threshold": 100_000_000,
                         "min_connections": 3})
    alerts = []
    for i in range(4):
        alerts += det.process(ev(ts=1000 + i * 10, src="10.0.1.5",
                                 dst="10.0.0.10", ob=30_000_000))
    assert not alerts


# --------------------------- alerting machinery ---------------------------- #
def test_escalation_policy_bumps_severity():
    pol = EscalationPolicy(repeats_per_level=3, window_seconds=600)
    alert = Alert(event_type="anomaly", severity="MEDIUM",
                  description="x", src_ip="10.0.1.9")
    escalated = False
    for _ in range(3):
        alert, esc = pol.apply(alert)
        escalated = escalated or esc
    assert escalated and alert.severity in ("HIGH", "CRITICAL")


def test_alert_manager_gates_and_dedups():
    mgr = AlertManager(min_severity="HIGH", cooldown=300, channels=[])
    low = Alert(event_type="x", severity="LOW", description="d",
                src_ip="1.1.1.1")
    high = Alert(event_type="y", severity="HIGH", description="d",
                 src_ip="2.2.2.2")
    assert mgr.handle(low) is False            # below gate
    assert mgr.handle(high) is True            # delivered
    dup = Alert(event_type="y", severity="HIGH", description="d",
                src_ip="2.2.2.2")
    assert mgr.handle(dup) is False            # cooldown dedup
