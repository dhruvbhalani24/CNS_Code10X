"""
Section 8.1 — Flask application factory.

Serves the SOC dashboard (dark mini-Kibana UI) and mounts:
  * /api/...      → REST blueprint  (api.py)
  * /api/live/... → SSE live stream (live.py)

The store is created once per process and cached — the SQLite backend
is thread-safe by design (Section 6).
"""
from __future__ import annotations

from flask import Flask, render_template

from core.config import get_config
from core.logger import get_logger


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.config["JSON_SORT_KEYS"] = False
    log = get_logger("dashboard")

    # ---- blueprints (imported lazily to avoid circulars) -----------------
    from dashboard.api import api_bp
    from dashboard.live import live_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(live_bp)

    # ---- main page --------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/health")
    def health():
        return {"status": "ok", "service": "CodeX10 NIDS-SIEM dashboard"}

    log.info("dashboard app created")
    return app


# ------------------------------------------------------------------------- #
if __name__ == "__main__":
    cfg = get_config()
    create_app().run(host=cfg.dashboard.host,
                     port=cfg.dashboard.port,
                     threaded=True, debug=False)
