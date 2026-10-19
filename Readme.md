# 🛡 CodeX10 NIDS-SIEM

**Network Intrusion Detection & Security Information Event Management system**
Applied Cryptography and Network Security Design Challenge (ACNS-DC)
Bharatiya Vidya Bhavan's Sardar Patel Institute of Technology · CE305/CS305

A complete, working SIEM built in pure Python that mirrors the
Zeek → Slips → Logstash → Elasticsearch → Kibana → Telegram architecture
from the project specification — with a pluggable design that supports
**real** Zeek logs, **real** Elasticsearch and **real** Slips, while
running fully offline out of the box.

---

## Architecture

```
┌──────────────┐   ┌──────────────┐   ┌───────────────────┐
│ Traffic      │──▶│ Sensors      │──▶│ Logstash layer    │
│ simulator /  │   │ Zeek logs /  │   │ parse → normalize │
│ lab pcap     │   │ pcap replay  │   │ → enrich          │
└──────────────┘   └──────────────┘   └─────────┬─────────┘
                                                ▼
┌──────────────┐   ┌──────────────┐   ┌───────────────────┐
│ Telegram +   │◀──│ Alert Manager│◀──│ Detection engine  │
│ console/JSONL│   │ gate/esc/dup │   │ scan·DoS·C2·anomaly│
└──────────────┘   └──────────────┘   │ exfil + Slips     │
                                      └─────────┬─────────┘
                          ┌──────────────┐      ▼
                          │ Dashboard    │◀─┌──────────────┐
                          │ (mini-Kibana)│  │ Storage      │
                          │ live SSE     │  │ SQLite / ES  │
                          └──────────────┘  └──────────────┘
```

## Team structure — 10 sections, 10 owners

| Section | Module | Owner | Files |
|---|---|---|---|
| 1 | `core/` — config, event models, pipeline orchestrator | Member 1 | 5 |
| 2 | `sensors/` — Zeek sensor, attack simulator, pcap replay | Member 2 | 5 |
| 3 | `detection/` — port scan & DoS detectors | Member 3 | 5 |
| 4 | `detection/` — C2, anomaly, exfil, Slips bridge, registry | Member 4 | 5 |
| 5 | `processing/` — parsers, normalizer, enricher, Logstash engine | Member 5 | 5 |
| 6 | `storage/` — SQLite index, Elasticsearch backend, analytics | Member 6 | 5 |
| 7 | `alerting/` — manager, escalation, Telegram bot | Member 7 | 5 |
| 8 | `dashboard/` — Flask app, REST API, SSE, SOC frontend | Member 8 | 5 |
| 9 | `evaluation/` — scenarios, metrics, reports | Member 9 | 5 |
| 10 | root — CLI, tests, docs, requirements | Member 10 | 5 |

## Quickstart

```bash
pip install -r requirements.txt

# 1. generate traffic + attacks through the full pipeline
python main.py simulate --attacks port_scan dos c2 exfil --write-logs

# 2. launch the SOC dashboard  →  http://127.0.0.1:5000
python main.py dashboard
```
Then click **⚡ Full Attack** in the dashboard header — events, charts,
alerts and KPI cards update live.

## CLI reference

| Command | Purpose |
|---|---|
| `python main.py simulate` | Run simulated attacks through the pipeline |
| `python main.py ingest <dir>` | Ingest real Zeek logs (conn/dns/http.log) |
| `python main.py live` | Tail Zeek logs in real time |
| `python main.py dashboard` | Serve the web SIEM dashboard |
| `python main.py evaluate` | Full evaluation suite → `reports/*.md` |
| `python main.py stats` | Index statistics |

## Evaluation (spec metrics)

`python main.py evaluate` measures **detection rate, false-positive rate,
alert-generation latency, event-processing time and per-category
detection**, then writes a timestamped Markdown report into `reports/`.

## Telegram alerting (optional)

1. Chat with **@BotFather** → `/newbot` → copy the token
2. Message your bot once, get your chat ID (e.g. via @userinfobot)
3. Create `config.yaml` at project root:
```yaml
alerting:
  min_severity: HIGH
  telegram: {enabled: true, token: "123:ABC", chat_id: "456789"}
```

## Going fully "real" (lab deployment)

| Component | Offline default | Real deployment |
|---|---|---|
| Traffic source | built-in simulator | lab network / pcap |
| Zeek | simulator writes Zeek-format logs | `zeek -i eth0` → `logs/zeek/` |
| Slips | behavioural emulation | set `slips.enabled: true` + path |
| Storage | SQLite (`data/nids.db`) | `storage.backend: elasticsearch` |
| Dashboard | built-in mini-Kibana | Kibana on the same ES cluster |

## Testing

```bash
pytest -q          # 20+ unit & integration tests
```

## Project structure — 50 files

```
CodeX10-NIDS-SIEM/
├── main.py  requirements.txt  README.md
├── core/          (5)   ├── detection/     (10)
├── sensors/       (5)   ├── processing/    (5)
├── storage/       (5)   ├── alerting/      (5)
├── dashboard/     (5)   ├── evaluation/    (5)
└── tests/         (2)   └── dashboard/templates/index.html
```
