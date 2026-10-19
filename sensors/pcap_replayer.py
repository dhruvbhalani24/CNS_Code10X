"""
Section 2.4 — PCAP replayer (optional sensor).

Converts a raw .pcap capture into ConnectionEvents by simple per-packet
flow aggregation. Requires `scapy` — degrades gracefully with a clear
message if it is not installed, so the rest of the system never breaks.
"""
from __future__ import annotations

from typing import Iterator

from core.event import ConnectionEvent
from core.logger import get_logger
from sensors.base_sensor import BaseSensor

try:
    from scapy.all import PcapReader, IP, TCP, UDP       # type: ignore
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False


class PcapSensor(BaseSensor):
    """Replays a pcap file as a stream of connection events."""

    name = "pcap"

    def __init__(self, pcap_path: str):
        super().__init__()
        if not _HAS_SCAPY:
            raise ImportError(
                "scapy is required for pcap replay:  pip install scapy")
        self.pcap_path = pcap_path

    def stream(self) -> Iterator[ConnectionEvent]:
        """Yield one ConnectionEvent per TCP/UDP packet (flow-lite)."""
        self._running = True
        n = 0
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                if not self._running or IP not in pkt:
                    continue
                if TCP in pkt:
                    l4, sport, dport, proto = pkt[TCP], pkt[TCP].sport, pkt[TCP].dport, "tcp"
                elif UDP in pkt:
                    l4, sport, dport, proto = pkt[UDP], pkt[UDP].sport, pkt[UDP].dport, "udp"
                else:
                    continue
                yield ConnectionEvent(
                    ts=float(pkt.time),
                    src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                    dst_port=int(dport), proto=proto,
                    service="-", duration=0.0,
                    orig_bytes=int(len(l4)),
                    resp_bytes=0,
                    conn_state="SF", sensor="pcap",
                )
                n += 1
        self.log.info("replayed %d packets from %s", n, self.pcap_path)
