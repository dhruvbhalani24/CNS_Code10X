"""
Section 2.3 — Offline traffic & attack simulator.

Generates a realistic, REPRODUCIBLE (seeded) mix of:
  * normal traffic    — office-like browsing, DNS, SSH
  * port_scan         — one host sweeping hundreds of ports (S0/REJ)
  * dos               — connection flood against one service
  * c2                — regular-interval beaconing to a C2 server
  * exfil             — abnormal outbound data volume

Every event is ground-truth labeled (`label=`) so the evaluation section
can compute detection rate / false positive rate. Can also WRITE real
Zeek-format conn.log files so the ZeekSensor can re-read them — proving
the full pipeline end-to-end without a lab network.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Iterator, Optional

from core.config import get_config
from core.event import ConnectionEvent
from core.logger import get_logger
from sensors.base_sensor import BaseSensor

INTERNAL_HOSTS = [f"10.0.1.{i}" for i in range(2, 30)]
SERVERS = ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
EXTERNAL = ["93.184.216.34", "142.250.183.14", "104.16.132.229"]
C2_SERVER = "185.220.101.7"
EXFIL_SERVER = "45.33.10.99"
COMMON_PORTS = [80, 443, 53, 22, 8080]


class TrafficSimulator(BaseSensor):
    """Deterministic traffic generator — the lab network in a box."""

    name = "simulator"

    def __init__(self, seed: Optional[int] = None,
                 normal_events: Optional[int] = None,
                 attacks: Optional[list[str]] = None):
        super().__init__()
        cfg = get_config()
        self.seed = cfg.simulator.seed if seed is None else seed
        self.n_normal = cfg.simulator.normal_events if normal_events is None else normal_events
        self.attacks = cfg.simulator.attacks if attacks is None else attacks
        self._events: list[ConnectionEvent] = []
        self._built = False

    # ------------------------------------------------------------------ #
    #  Scenario builders (all append to self._events)                     #
    # ------------------------------------------------------------------ #
    def _normal(self, t: float, rng: random.Random) -> float:
        """One ordinary connection; returns next timestamp."""
        ev = ConnectionEvent(
            ts=round(t, 3),
            src_ip=rng.choice(INTERNAL_HOSTS),
            dst_ip=rng.choice(SERVERS + EXTERNAL),
            dst_port=rng.choice(COMMON_PORTS),
            proto="tcp", service="-",
            duration=round(rng.uniform(0.01, 5.0), 3),
            orig_bytes=rng.randint(200, 60_000),
            resp_bytes=rng.randint(500, 200_000),
            conn_state="SF", sensor="simulator", label="normal",
        )
        if ev.dst_port == 53:
            ev.proto, ev.service = "udp", "dns"
            ev.dns_query = rng.choice(["example.com", "google.com", "spit.ac.in"])
        self._events.append(ev)
        return t + rng.uniform(0.05, 2.0)

    def _port_scan(self, t: float, rng: random.Random) -> float:
        victim = rng.choice(SERVERS)
        attacker = "10.0.1.66"                       # rogue internal host
        for port in range(20, 20 + 120):             # 120 ports swept fast
            self._events.append(ConnectionEvent(
                ts=round(t, 3), src_ip=attacker, dst_ip=victim, dst_port=port,
                proto="tcp", service="-", duration=0.0, orig_bytes=0,
                resp_bytes=0, conn_state=rng.choice(["S0", "REJ"]),
                sensor="simulator", label="port_scan",
            ))
            t += rng.uniform(0.01, 0.08)
        return t

    def _dos(self, t: float, rng: random.Random) -> float:
        victim, port = SERVERS[0], 80
        for _ in range(250):                          # flood burst
            self._events.append(ConnectionEvent(
                ts=round(t, 3), src_ip="203.0.113.9", dst_ip=victim,
                dst_port=port, proto="tcp", service="-", duration=0.0,
                orig_bytes=0, resp_bytes=0, conn_state="S0",
                sensor="simulator", label="dos",
            ))
            t += rng.uniform(0.005, 0.03)
        return t

    def _c2(self, t: float, rng: random.Random) -> float:
        interval = 30.0                               # beacon period (s)
        payload = 512                                 # near-constant size
        for i in range(10):                           # 10 beacons
            jitter = rng.uniform(-2.0, 2.0)
            self._events.append(ConnectionEvent(
                ts=round(t + i * interval + jitter, 3),
                src_ip=INTERNAL_HOSTS[3], dst_ip=C2_SERVER, dst_port=443,
                proto="tcp", service="ssl",
                duration=round(rng.uniform(0.5, 1.5), 3),
                orig_bytes=payload + rng.randint(-30, 30),
                resp_bytes=rng.randint(400, 700),
                conn_state="SF", sensor="simulator", label="c2",
            ))
        return t + 10 * interval + 5

    def _exfil(self, t: float, rng: random.Random) -> float:
        for _ in range(6):                            # huge outbound bursts
            self._events.append(ConnectionEvent(
                ts=round(t, 3), src_ip=INTERNAL_HOSTS[7],
                dst_ip=EXFIL_SERVER, dst_port=8443,
                proto="tcp", service="ssl",
                duration=round(rng.uniform(20, 60), 3),
                orig_bytes=rng.randint(40_000_000, 90_000_000),  # ~50 MB!
                resp_bytes=rng.randint(0, 500),
                conn_state="SF", sensor="simulator", label="exfil",
            ))
            t += rng.uniform(30, 60)
        return t

    # ------------------------------------------------------------------ #
    def build(self) -> list[ConnectionEvent]:
        """Generate the full scenario once, time-ordered and labeled."""
        if self._built:
            return self._events
        rng = random.Random(self.seed)                # reproducibility
        builders = {"port_scan": self._port_scan, "dos": self._dos,
                    "c2": self._c2, "exfil": self._exfil}
        t = 1_700_000_000.0                           # fixed epoch base
        for _ in range(self.n_normal):
            t = self._normal(t, rng)
        for attack in self.attacks:
            self.log.info("injecting attack: %s", attack)
            t = builders[attack](t, rng) + rng.uniform(5, 30)
            for _ in range(rng.randint(20, 40)):      # cool-down normal traffic
                t = self._normal(t, rng)
        self._events.sort(key=lambda e: e.ts)         # global time order
        self._built = True
        self.log.info("scenario built: %d events (%d attacks)",
                      len(self._events), len(self.attacks))
        return self._events

    # ------------------------------------------------------------------ #
    #  BaseSensor interface                                                #
    # ------------------------------------------------------------------ #
    def stream(self) -> Iterator[ConnectionEvent]:
        yield from self.build()

    # ------------------------------------------------------------------ #
    def write_zeek_logs(self, out_dir: Optional[str] = None) -> Path:
        """Write events as a genuine Zeek TSV conn.log (round-trip proof)."""
        cfg = get_config()
        out = Path(out_dir or cfg.simulator.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        fields = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                  "proto", "service", "duration", "orig_bytes", "resp_bytes",
                  "conn_state"]
        header = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(none)\n"
                  "#fields\t" + "\t".join(fields) + "\n")
        rng = random.Random(self.seed)
        with open(out / "conn.log", "w", encoding="utf-8") as fh:
            fh.write(header)
            for i, ev in enumerate(self.build(), 1):
                row = [f"{ev.ts:.6f}", ev.src_ip, 40000 + i, ev.dst_ip,
                       str(ev.dst_port), ev.proto, ev.service,
                       f"{ev.duration:.3f}", str(ev.orig_bytes),
                       str(ev.resp_bytes), ev.conn_state]
                fh.write("\t".join(row) + "\n")
        self.log.info("wrote Zeek conn.log -> %s (%d rows)",
                      out / "conn.log", len(self._events))
        return out
