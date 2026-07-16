"""
We Mental Health — backend API

Endpoints:
  GET  /api/resources?country=NG      -> crisis resource directory for a country
  POST /api/support                   -> submit a support request (encrypted at rest)
  GET  /admin                         -> password-protected list of submissions
  GET  /admin/submission/<id>         -> password-protected single submission (decrypted)

Run locally for testing:
  pip install -r requirements.txt
  export ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
  export ADMIN_USERNAME=admin
  export ADMIN_PASSWORD=changeme
  python3 app.py
"""
import os
import json
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, g, Response
from werkzeug.security import check_password_hash, generate_password_hash

import encryption

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "data", "support.db"))
RESOURCES_PATH = os.path.join(BASE_DIR, "resources.json")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
# Prefer a pre-hashed password (ADMIN_PASSWORD_HASH); fall back to hashing
# ADMIN_PASSWORD at startup for convenience in early setup.
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    _plain = os.environ.get("ADMIN_PASSWORD")
    ADMIN_PASSWORD_HASH = generate_password_hash(_plain) if _plain else None

ALLOWED_TOPICS = {
    "Sexual abuse (coach, colleagues, home, or senior players)",
    "Physical abuse (coach, colleagues, home, or senior players)",
    "Anxiety",
    "Pressure",
    "Depression",
    "Personal / family issues",
    "Career decisions",
}

MAX_DETAILS_LEN = 4000
MAX_NAME_LEN = 200
MAX_CONTACT_LEN = 300

app = Flask(__name__)

# ---------------------------------------------------------------------------
# very small in-memory rate limiter (per-process; fine for a single instance)
# ---------------------------------------------------------------------------
_submission_log = {}  # ip -> list of timestamps
RATE_LIMIT_WINDOW = 60 * 10   # 10 minutes
RATE_LIMIT_MAX = 5            # max 5 submissions per window per IP


def rate_limited(ip: str) -> bool:
    now = time.time()
    hits = [t for t in _submission_log.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    _submission_log[ip] = hits
    if len(hits) >= RATE_LIMIT_MAX:
        return True
    hits.append(now)
    _submission_log[ip] = hits
    return False


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            topics TEXT NOT NULL,
            country TEXT,
            anonymous INTEGER NOT NULL DEFAULT 0,
            details_enc TEXT,
            name_enc TEXT,
            contact_enc TEXT,
            reviewed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# resources
# ---------------------------------------------------------------------------
def load_resources():
    with open(RESOURCES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/resources")
def get_resources():
    country = (request.args.get("country") or "GLOBAL").upper()
    data = load_resources()
    entry = data.get(country, data["GLOBAL"])
    return jsonify({"country": country, **entry})


# ---------------------------------------------------------------------------
# support submission
# ---------------------------------------------------------------------------
@app.post("/api/support")
def submit_support():
    if not encryption.is_configured():
        return jsonify({"error": "Server is not configured to store data securely yet."}), 503

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if rate_limited(ip):
        return jsonify({"error": "Too many submissions. Please try again later."}), 429

    payload = request.get_json(silent=True) or {}

    topics = payload.get("topics") or []
    if not isinstance(topics, list):
        return jsonify({"error": "topics must be a list"}), 400
    topics = [t for t in topics if t in ALLOWED_TOPICS]

    details = str(payload.get("details") or "")[:MAX_DETAILS_LEN]
    name = str(payload.get("name") or "")[:MAX_NAME_LEN]
    contact = str(payload.get("contact") or "")[:MAX_CONTACT_LEN]
    anonymous = bool(payload.get("anonymous"))
    country = str(payload.get("country") or "")[:5].upper()

    if not topics and not details:
        return jsonify({"error": "Please select at least one topic or share a message."}), 400

    if anonymous:
        name = ""
        contact = ""

    db = get_db()
    db.execute(
        """
        INSERT INTO submissions (created_at, topics, country, anonymous, details_enc, name_enc, contact_enc)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            json.dumps(topics),
            country,
            1 if anonymous else 0,
            encryption.encrypt(details),
            encryption.encrypt(name),
            encryption.encrypt(contact),
        ),
    )
    db.commit()

    return jsonify({"status": "received"}), 201


# ---------------------------------------------------------------------------
# admin (basic auth, decrypts on view only)
# ---------------------------------------------------------------------------
def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.authorization
        if (
            not ADMIN_PASSWORD_HASH
            or not auth
            or auth.username != ADMIN_USERNAME
            or not check_password_hash(ADMIN_PASSWORD_HASH, auth.password)
        ):
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="We Mental Health Admin"'},
            )
        return view(*args, **kwargs)
    return wrapped


@app.get("/admin")
@require_admin
def admin_list():
    db = get_db()
    rows = db.execute(
        "SELECT id, created_at, topics, country, anonymous, reviewed FROM submissions ORDER BY id DESC"
    ).fetchall()

    items = "".join(
        f"""<tr>
              <td>{r['id']}</td>
              <td>{r['created_at']}</td>
              <td>{', '.join(json.loads(r['topics']))}</td>
              <td>{r['country'] or '-'}</td>
              <td>{'yes' if r['anonymous'] else 'no'}</td>
              <td>{'✔' if r['reviewed'] else ''}</td>
              <td><a href="/admin/submission/{r['id']}">view</a></td>
            </tr>"""
        for r in rows
    )

    html = f"""
    <html><head><title>Submissions</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 30px; color: #333; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 0.9rem; }}
      th {{ background: #6a4c93; color: white; }}
    </style></head>
    <body>
      <h2>Support Submissions ({len(rows)})</h2>
      <table>
        <tr><th>ID</th><th>Received</th><th>Topics</th><th>Country</th><th>Anonymous</th><th>Reviewed</th><th></th></tr>
        {items}
      </table>
    </body></html>
    """
    return Response(html, mimetype="text/html")


@app.get("/admin/submission/<int:sub_id>")
@require_admin
def admin_detail(sub_id):
    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id = ?", (sub_id,)).fetchone()
    if not row:
        return Response("Not found", 404)

    db.execute("UPDATE submissions SET reviewed = 1 WHERE id = ?", (sub_id,))
    db.commit()

    details = encryption.decrypt(row["details_enc"])
    name = encryption.decrypt(row["name_enc"])
    contact = encryption.decrypt(row["contact_enc"])

    html = f"""
    <html><head><title>Submission #{sub_id}</title>
    <style>body {{ font-family: Arial, sans-serif; margin: 30px; color: #333; max-width: 700px; }}
    dt {{ font-weight: bold; margin-top: 14px; }}</style></head>
    <body>
      <p><a href="/admin">&larr; Back to list</a></p>
      <h2>Submission #{sub_id}</h2>
      <dl>
        <dt>Received</dt><dd>{row['created_at']}</dd>
        <dt>Topics</dt><dd>{', '.join(json.loads(row['topics']))}</dd>
        <dt>Country</dt><dd>{row['country'] or '-'}</dd>
        <dt>Anonymous</dt><dd>{'yes' if row['anonymous'] else 'no'}</dd>
        <dt>Name</dt><dd>{name or '(not provided)'}</dd>
        <dt>Contact</dt><dd>{contact or '(not provided)'}</dd>
        <dt>Message</dt><dd style="white-space: pre-wrap;">{details or '(no message)'}</dd>
      </dl>
    </body></html>
    """
    return Response(html, mimetype="text/html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "encryption_configured": encryption.is_configured()})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
  
else:
    init_db() 
