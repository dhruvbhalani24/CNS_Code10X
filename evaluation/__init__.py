"""
Section 9 — Evaluation framework.

Implements every metric from the project specification:
  * Detection Rate            (per attack category)
  * False Positive Rate       (alerts per 1000 normal events)
  * Alert Generation Latency  (malicious event → matching alert, wall clock)
  * Event Processing Time     (per-event pipeline cost)
  * Attack Category Detection (table per simulated attack)
  * Dashboard Visibility      (manual checklist in the generated report)
"""
from evaluation.attack_scenarios import Scenario, SCENARIOS, build_scenario, ground_truth
from evaluation.metrics import ScenarioResult, summarize, format_text_report
from evaluation.evaluate import Evaluator
from evaluation.report import write_markdown_report

__all__ = ["Scenario", "SCENARIOS", "build_scenario", "ground_truth",
           "ScenarioResult", "summarize", "format_text_report",
           "Evaluator", "write_markdown_report"]
