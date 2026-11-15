import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = "/data/incidents.sqlite3"


def prepare_database():
    with sqlite3.connect(DB) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                event_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                alert_name TEXT NOT NULL,
                status TEXT NOT NULL,
                namespace TEXT,
                pod TEXT,
                container TEXT,
                fingerprint TEXT,
                starts_at TEXT,
                ends_at TEXT,
                values_json TEXT,
                alert_json TEXT NOT NULL
            )
        """)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        if self.path != "/health":
            super().log_message(fmt, *args)

    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        if self.path != "/alerts":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if not 0 < size <= 1000000:
            self.send_error(413)
            return
        try:
            payload = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeDecodeError):
            self.send_error(400)
            return
        if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
            self.send_error(400)
            return

        received_at = datetime.now(timezone.utc).isoformat()
        saved = 0
        try:
            with sqlite3.connect(DB, timeout=10) as db:
                for alert in payload["alerts"]:
                    if not isinstance(alert, dict):
                        continue
                    labels = alert.get("labels") or {}
                    if not isinstance(labels, dict):
                        continue
                    status = alert.get("status") or payload.get("status") or "unknown"
                    starts_at = alert.get("startsAt") or ""
                    ends_at = alert.get("endsAt") or ""
                    fingerprint = alert.get("fingerprint") or hashlib.sha256(
                        json.dumps(labels, sort_keys=True).encode()
                    ).hexdigest()
                    event_id = hashlib.sha256(
                        json.dumps([fingerprint, status, starts_at, ends_at]).encode()
                    ).hexdigest()
                    cursor = db.execute(
                        "INSERT OR IGNORE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            event_id, received_at, labels.get("alertname", "unknown"),
                            status, labels.get("namespace"), labels.get("pod"),
                            labels.get("container"), fingerprint, starts_at, ends_at,
                            json.dumps(alert.get("values"), sort_keys=True),
                            json.dumps(alert, sort_keys=True),
                        ),
                    )
                    saved += cursor.rowcount
        except sqlite3.Error as exc:
            print("Database write failed:", str(exc), flush=True)
            self.send_error(503)
            return

        print(json.dumps({"received_at": received_at, "saved": saved,
                          "notification_status": payload.get("status")}), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"received")


prepare_database()
ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
