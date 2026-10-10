#!/usr/bin/env python3
"""
CodeX10 NIDS-SIEM — Command Line Interface
==========================================
Section 10.1 — Single entry point for the whole system.

Usage:
  python main.py simulate  [--attacks port_scan dos c2 exfil] [--normal 400]
  python main.py ingest    <zeek_log_dir>
  python main.py live      [--zeek-dir logs/zeek]
  python main.py dashboard
  python main.py evaluate
  python main.py stats
"""
from __future__ import annotations

import argparse
import json
import sys

from core.config import get_config
from core.logger import get_logger

BANNER = """
  ██████╗ ███████╗ ██████╗██╗   ██╗██╗  ██╗
 ██╔═══██╗██╔════╝██╔════╝██║   ██║╚██╗██╔╝
 ██║   ██║███████╗██║     ██║   ██║ ╚███╔╝
 ██║   ██║╚════██║██║     ██║   ██║ ██╔██╗
 ╚██████╔╝███████║╚██████╔╝╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝  NIDS-SIEM
"""

ATTACK_CHOICES = ["port_scan", "dos", "c2", "exfil"]


# --------------------------------------------------------------------------- #
#  Shared runtime builder                                                      #
# --------------------------------------------------------------------------- #
def build_runtime_pipeline(store):
    """Assemble the full live pipeline over a persistent store."""
    from alerting.alert_manager import AlertManager
    from core.pipeline import Pipeline
    from detection.registry import build_detectors
    from detection.slips_adapter import SlipsAdapter
    from processing.enrichers import Enricher
    from processing.normalizer import Normalizer

    return Pipeline(
        normalizer=Normalizer(),
        enricher=Enricher(),
        detectors=build_detectors(),
        slips_adapter=SlipsAdapter(),
        store=store,
        alert_manager=AlertManager.default(),
    )


# --------------------------------------------------------------------------- #
#  Commands                                                                    #
# --------------------------------------------------------------------------- #
def cmd_simulate(args) -> int:
    """Run the attack simulator through the live pipeline into the index."""
    from sensors.traffic_simulator import TrafficSimulator
    from storage.base_store import get_store

    log = get_logger("cli")
    store = get_store()
    pipeline = build_runtime_pipeline(store)

    simulator = TrafficSimulator(normal_events=args.normal,
                                 attacks=args.attacks)
    if args.write_logs:
        out = simulator.write_zeek_logs()
        log.info("Zeek-format logs written to %s (re-ingestible!)", out)

    pipeline.sensor = simulator
    stats = pipeline.run()
    print(json.dumps({"pipeline": stats, "store": store.stats()},
                     indent=2, default=str))
    return 0


def cmd_ingest(args) -> int:
    """Ingest an existing Zeek log directory (Logstash layer)."""
    from processing.logstash_pipeline import LogstashEngine
    from storage.base_store import get_store

    store = get_store()
    engine = (LogstashEngine.default()
              .add_output(store.index_event))
    stats = engine.process_zeek_dir(args.dir)
    print(json.dumps({"logstash": stats, "store": store.stats()},
                     indent=2, default=str))
    return 0


def cmd_live(args) -> int:
    """Tail Zeek logs live (like a real sensor deployment)."""
    from sensors.zeek_sensor import ZeekSensor
    from storage.base_store import get_store

    store = get_store()
    pipeline = build_runtime_pipeline(store)
    pipeline.sensor = ZeekSensor(args.zeek_dir, tail=True)
    print(">> live mode — processing Zeek logs as they appear "
          "(Ctrl+C to stop)")
    try:
        pipeline.run()
    except KeyboardInterrupt:
        print("\n>> stopped.")
    return 0


def cmd_dashboard(args) -> int:
    """Serve the SOC dashboard (mini-Kibana)."""
    from dashboard.app import create_app

    cfg = get_config()
    app = create_app()
    print(f">> dashboard: http://{cfg.dashboard.host}:{cfg.dashboard.port}")
    app.run(host=cfg.dashboard.host, port=cfg.dashboard.port,
            threaded=True, debug=False)
    return 0


def cmd_evaluate(args) -> int:
    """Run the full evaluation suite and write the report."""
    from evaluation.evaluate import Evaluator
    from evaluation.metrics import format_text_report, summarize
    from evaluation.report import write_markdown_report

    results = Evaluator().run_all()
    metrics = summarize(results)
    print(format_text_report(metrics))
    path = write_markdown_report(metrics, results)
    print(f"\n  📄 Full report saved → {path}\n")
    return 0


def cmd_stats(args) -> int:
    """Print current index statistics."""
    from storage.base_store import get_store
    print(json.dumps(get_store().stats(), indent=2, default=str))
    return 0


# --------------------------------------------------------------------------- #
#  Argument parsing                                                            #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="CodeX10 NIDS-SIEM — Zeek-style sensing + behavioral "
                    "detection + SIEM dashboard")
    parser.add_argument("--version", action="version",
                        version="CodeX10 NIDS-SIEM 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("simulate", help="run simulated attacks through "
                                        "the pipeline")
    p.add_argument("--attacks", nargs="*", default=ATTACK_CHOICES,
                   choices=ATTACK_CHOICES, metavar="ATTACK",
                   help="attacks to inject (default: all)")
    p.add_argument("--normal", type=int, default=400,
                   help="normal traffic events (default 400)")
    p.add_argument("--write-logs", action="store_true",
                   help="also write Zeek-format conn.log")
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("ingest", help="ingest a Zeek log directory")
    p.add_argument("dir", help="path containing conn.log / dns.log / http.log")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("live", help="tail Zeek logs in real time")
    p.add_argument("--zeek-dir", default=None, help="Zeek log directory")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("dashboard", help="launch the SOC web dashboard")
    p.set_defaults(func=cmd_dashboard)

    p = sub.add_parser("evaluate", help="run evaluation suite + report")
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("stats", help="index statistics")
    p.set_defaults(func=cmd_stats)

    return parser


def main() -> int:
    print(BANNER)
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
