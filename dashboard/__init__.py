"""
Section 8 — Dashboard (the "Kibana layer").

  * app.py            — Flask application factory
  * api.py            — REST API (search, aggregations, demo trigger)
  * live.py           — Server-Sent-Events live alert stream
  * templates/index.html — the mini-Kibana SOC frontend

Run with:  python -m dashboard.app     (or `python main.py dashboard`)
"""
from dashboard.app import create_app

__all__ = ["create_app"]
