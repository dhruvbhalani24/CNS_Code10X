"""
Section 2 — Network Sensors.

Three interchangeable traffic sources, all producing ConnectionEvent:
  * ZeekSensor       — reads (or tails) real Zeek logs: conn/dns/http.log
  * TrafficSimulator — generates labeled normal + attack traffic offline
  * PcapSensor       — replays a .pcap file (requires scapy, optional)
"""
from sensors.base_sensor import BaseSensor
from sensors.zeek_sensor import ZeekSensor
from sensors.traffic_simulator import TrafficSimulator

__all__ = ["BaseSensor", "ZeekSensor", "TrafficSimulator"]
