"""
Section 9.4 — Markdown report generator.

Writes reports/evaluation_report_<timestamp>.md containing every metric
from the project specification, ready to drop into the final report /
show the examiner. Includes the manual "Dashboard Visibility" checklist
(spec requirement) for the team to tick after the live demo.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from core.config import get_config
from evaluation.metrics import ScenarioResult, format_text_report

DASHBOARD_CHECKLIST = [
    "Total network events card populates and updates",
    "Alert count + critical-alert cards populate",
    "Alerts-over-time chart shows spikes during attacks",
    "Source / destination IP distribution charts render",
    "Frequently targeted ports chart highlights scanned ports",
    "Protocol distribution visible (severity doughnut)",
    "Alert table shows type, IPs, detector, severity, timestamp",
    "Event table supports search by IP / domain",
    "One-click attack injection reflects on dashboard within seconds",
    "Severity colour coding matches alert severity",
]


def write_markdown_report(metrics: dict,
                          results: list[ScenarioResult],
                          out_dir: str = "reports") -> Path:
    cfg = get_config()
    now = datetime.now(timezone.utc)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"evaluation_report_{now.strftime('%Y%m%d_%H%M%S')}.md"

    lat = metrics["avg_alert_latency_ms"]
    md = [
        "# CodeX10 NIDS-SIEM — Evaluation Report",
        f"*Generated {now.strftime('%Y-%m-%d %H:%M:%S UTC')} · "
        f"backend: `{metrics.get('backend', 'sqlite')}`*",
        "",
        "## 1. Summary",
        "```",
        format_text_report(metrics).strip(),
        "```",
        "",
        "## 2. Metrics (as per project specification)",
        "| Metric | Value |",
        "|---|---|",
        f"| Detection Rate | **{metrics['detection_rate_pct']}%** "
        f"({metrics['attack_scenarios_detected']}/{metrics['attack_scenarios']}) |",
        f"| False Positive Rate | {metrics['fpr_per_1000_events']} alerts "
        f"per 1000 normal events |",
        f"| Baseline clean | {'YES ✔' if metrics['baseline_clean'] else 'NO ✘'} |",
        f"| Alert Generation Latency (avg) | "
        + (f"{lat:.2f} ms" if lat is not None else "n/a") + " |",
        f"| Event Processing Time (avg / max) | "
        f"{metrics['avg_processing_ms']:.3f} ms / "
        f"{metrics['max_processing_ms']:.3f} ms |",
        f"| Throughput (avg) | {metrics['avg_throughput_eps']:.1f} events/sec |",
        f"| Total events / alerts | {metrics['total_events']} / "
        f"{metrics['total_alerts']} |",
        "",
        "## 3. Attack Category Detection",
        "| Category | Scenario | Detected | Alerts | Latency (ms) |",
        "|---|---|---|---|---|",
    ]
    for c in metrics["categories"]:
        md.append(f"| {c['category']} | {c['scenario']} | "
                   f"{'✔ YES' if c['detected'] else '✘ NO'} | {c['alerts']} | "
                   f"{c['latency_ms']:.1f} |" if c["latency_ms"] is not None
                   else f"| {c['category']} | {c['scenario']} | "
                        f"{'✔ YES' if c['detected'] else '✘ NO'} | "
                        f"{c['alerts']} | n/a |")

    md += [
        "",
        "## 4. Per-Scenario Detail",
        "| Scenario | Events | Alerts | Matched | Avg proc (ms) | EPS |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        md.append(f"| {r.name} | {r.n_events} | {r.n_alerts} | "
                  f"{'✔' if r.matched else '✘'} | {r.avg_proc_ms:.3f} | "
                  f"{r.eps:.0f} |")

    md += [
        "",
        "## 5. Dashboard Visibility (manual checklist — tick after live demo)",
    ]
    md += [f"- [ ] {item}" for item in DASHBOARD_CHECKLIST]

    md += [
        "",
        "## 6. Configuration Snapshot",
        "```yaml",
        f"storage backend : {cfg.storage.backend}",
        f"detectors        : port_scan, dos, c2, anomaly, exfil (+slips bridge)",
        f"telegram alerting: {'enabled' if cfg.alerting.telegram.enabled else 'disabled'}",
        "```",
        "",
        "---",
        f"*CodeX10 — Applied Cryptography and Network Security Design "
        f"Challenge (ACNS-DC), SPIT · CE305/CS305*",
    ]

    path.write_text("\n".join(md), encoding="utf-8")
    return path
