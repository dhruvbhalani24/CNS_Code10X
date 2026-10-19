"""
Section 5 — Log Processing (the "Logstash layer").

Mirrors Logstash's input → filter → output architecture in pure Python:
  * parsers.py       — INPUT:  Zeek TSV/JSON + generic log parsing
  * normalizer.py    — FILTER: type coercion + field canonicalization
  * enrichers.py     — FILTER: tags, direction, threat-intel, geo
  * logstash_pipeline.py — the engine wiring inputs/filters/outputs
"""
from processing.parsers import LogParser, ZeekDirectoryIngester, record_to_event
from processing.normalizer import Normalizer
from processing.enrichers import Enricher
from processing.logstash_pipeline import LogstashEngine

__all__ = ["LogParser", "ZeekDirectoryIngester", "record_to_event",
           "Normalizer", "Enricher", "LogstashEngine"]
