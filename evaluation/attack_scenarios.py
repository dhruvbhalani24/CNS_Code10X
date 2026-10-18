"""
Section 9.1 — Labelled attack scenarios (ground truth definitions).

Each scenario runs the deterministic simulator (Section 2) with a fixed
seed, so results are 100% reproducible. Ground truth is derived from
event labels — self-syncing with the simulator, never hardcoded IPs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core.event import ConnectionEvent
from core.logger import get_logger
from sensors.traffic_simulator import TrafficSimulator

_LOG = get_logger("scenarios")


@dataclass
class Scenario:
    """One evaluation run: a traffic mix with known ground truth."""
    name: str
    attacks: list[str] = field(default_factory=list)
    normal_events: int = 150
    description: str = ""
    seed: int = 1000                       # unique seed per scenario

    @property
    def is_baseline(self) -> bool:
        return not self.attacks


# --------------------------------------------------------------------------- #
#  The evaluation suite (mirrors the attacks named in the project PDF)         #
# --------------------------------------------------------------------------- #
SCENARIOS: list[Scenario] = [
    Scenario("baseline_normal", [], 500,
             "Pure normal traffic — measures the false positive rate",
             seed=1001),
    Scenario("port_scan", ["port_scan"], 150,
             "Vertical port scan against an internal server", seed=1002),
    Scenario("dos", ["dos"], 150,
             "Connection flood (DoS) against a web server", seed=1003),
    Scenario("c2_beacon", ["c2"], 150,
             "Periodic command-and-control beaconing", seed=1004),
    Scenario("exfiltration", ["exfil"], 150,
             "Bulk outbound data transfer", seed=1005),
    Scenario("mixed_attack", ["port_scan", "dos", "c2", "exfil"], 250,
             "All attacks interleaved with normal traffic", seed=1006),
]

# attack categories reported individually (single-attack scenarios)
CATEGORY_SCENARIOS = [s for s in SCENARIOS if len(s.attacks) == 1]


def build_scenario(scenario: Scenario) -> list[ConnectionEvent]:
    """Generate the labelled event stream for one scenario."""
    sim = TrafficSimulator(seed=scenario.seed,
                           normal_events=scenario.normal_events,
                           attacks=list(scenario.attacks))
    events = sim.build()
    _LOG.info("scenario %-16s → %5d events, attacks=%s",
              scenario.name, len(events), scenario.attacks or "none")
    return events


def ground_truth(events: list[ConnectionEvent]) -> dict:
    """Derive ground truth from labels (src IPs that performed attacks)."""
    malicious_srcs = {e.src_ip for e in events if e.label != "normal"}
    labels = sorted({e.label for e in events})
    return {"malicious_srcs": malicious_srcs,
            "labels": labels,
            "malicious_events": sum(1 for e in events if e.label != "normal")}
