"""
Section 9.2 — Metric computation & text reporting.

Pure functions over ScenarioResult objects — no I/O, fully unit-testable.
Latency note: event timestamps are SIMULATED epochs, so alert latency is
measured in WALL-CLOCK time from 'first malicious event processed' to
'first matching alert raised' — the honest end-to-end number.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScenarioResult:
    """Outcome of pushing one scenario through the pipeline."""
    name: str
    labels: list[str]
    n_events: int
    n_alerts: int
    matched: bool                        # ≥1 alert on a malicious source
    latency_ms: Optional[float] = None   # first malicious event → alert
    avg_proc_ms: float = 0.0
    max_proc_ms: float = 0.0
    false_alerts: int = 0                # alerts in a normal-only run
    eps: float = 0.0                     # events / second throughput
    attack_categories: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------- #
def summarize(results: list[ScenarioResult]) -> dict:
    """Aggregate scenario outcomes into the project's evaluation metrics."""
    attacks = [r for r in results if r.attack_categories]
    baseline = next((r for r in results if not r.attack_categories), None)
    matched = [r for r in attacks if r.matched]
    latencies = [r.latency_ms for r in matched if r.latency_ms is not None]

    return {
        "scenarios_run": len(results),
        "attack_scenarios": len(attacks),
        "attack_scenarios_detected": len(matched),
        "detection_rate_pct":
            round(100.0 * len(matched) / len(attacks), 1) if attacks else 0.0,
        "baseline_clean": bool(baseline and baseline.n_alerts == 0),
        "false_positive_alerts": baseline.false_alerts if baseline else 0,
        "fpr_per_1000_events":
            round(1000.0 * baseline.false_alerts / baseline.n_events, 2)
            if baseline and baseline.n_events else 0.0,
        "avg_alert_latency_ms":
            round(sum(latencies) / len(latencies), 2) if latencies else None,
        "avg_processing_ms": round(
            sum(r.avg_proc_ms for r in results) / len(results), 3)
            if results else 0.0,
        "max_processing_ms": round(
            max((r.max_proc_ms for r in results), default=0.0), 3),
        "avg_throughput_eps": round(
            sum(r.eps for r in results) / len(results), 1)
            if results else 0.0,
        "total_events": sum(r.n_events for r in results),
        "total_alerts": sum(r.n_alerts for r in results),
        "categories": [
            {"category": c, "scenario": r.name, "detected": r.matched,
             "alerts": r.n_alerts,
             "latency_ms": r.latency_ms}
            for r in attacks for c in r.attack_categories
        ],
    }


# ------------------------------------------------------------------------- #
def format_text_report(m: dict) -> str:
    """Pretty console block (also embedded at the top of the MD report)."""
    tick = lambda ok: "✔ YES" if ok else "✘ NO"                    # noqa: E731
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════════╗",
        "║          CodeX10 NIDS-SIEM · EVALUATION RESULTS                  ║",
        "╠══════════════════════════════════════════════════════════════════╣",
        f"║  Scenarios run           : {m['scenarios_run']:>37}   ║",
        f"║  Total events processed  : {m['total_events']:>37}   ║",
        f"║  Total alerts raised     : {m['total_alerts']:>37}   ║",
        "╠══════════════════════════════════════════════════════════════════╣",
        f"║  DETECTION RATE          : {m['detection_rate_pct']:>6}%  "
        f"({m['attack_scenarios_detected']}/{m['attack_scenarios']})        ║",
        f"║  Baseline clean (no FPs) : {tick(m['baseline_clean']):>33}   ║",
        f"║  False positives / 1000  : {m['fpr_per_1000_events']:>37}   ║",
        f"║  Avg alert latency       : "
        + (f"{m['avg_alert_latency_ms']:>12.2f} ms"
           if m["avg_alert_latency_ms"] is not None else "          n/a")
        + "            ║",
        f"║  Avg event processing    : {m['avg_processing_ms']:>12.3f} ms"
        "            ║",
        f"║  Max event processing    : {m['max_processing_ms']:>12.3f} ms"
        "            ║",
        f"║  Avg throughput          : {m['avg_throughput_eps']:>12.1f} eps"
        "            ║",
        "╠══════════════════════════════════════════════════════════════════╣",
        "║  ATTACK CATEGORY DETECTION                                       ║",
    ]
    for c in m["categories"]:
        status = "DETECTED ✔" if c["detected"] else "MISSED  ✘"
        lines.append(f"║   {c['category']:<14} {status:<12} "
                     f"alerts={c['alerts']:<4}                     ║")
    lines.append("╚══════════════════════════════════════════════════════════════════╝")
    return "\n".join(lines)
