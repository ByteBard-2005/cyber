from flask import Flask, request, jsonify, send_from_directory, Response, session, redirect
from flask_cors import CORS
import sqlite3
import os
import csv
import io
from datetime import datetime, timedelta


from backend.database import init_db
from backend.models import create_user, get_user_by_username, get_user_by_id, save_scan
from backend.auth import login_user, logout_user, is_authenticated, login_required, admin_required
from backend.services.scan_service import run_url_scan, run_email_scan, run_file_scan
from backend.services.dashboard_service import get_dashboard_data
from backend.services.history_service import get_user_history

# --------------------------------------------------
# PATH CONFIG
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))              # backend/
PROJECT_DIR = os.path.dirname(BASE_DIR)                            # phishguard-pro/
PUBLIC_DIR = os.path.join(PROJECT_DIR, "public")                  # public/
CSS_DIR = os.path.join(PUBLIC_DIR, "css")                         # public/css
JS_DIR = os.path.join(PUBLIC_DIR, "js")                           # public/js
DB_PATH = os.path.join(BASE_DIR, "phishguard_big.db")             # backend/phishguard_big.db

# --------------------------------------------------
# APP CONFIG
# --------------------------------------------------
app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("SECRET_KEY", "phishguard_secret_key")
CORS(app)


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table for register/login
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    # URL scans
    cur.execute("""
        CREATE TABLE IF NOT EXISTS url_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            flags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Email scans
    cur.execute("""
        CREATE TABLE IF NOT EXISTS email_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            sender TEXT,
            subject TEXT,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            flags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # File scans
    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT NOT NULL,
            verdict TEXT NOT NULL,
            risk_score REAL NOT NULL,
            flags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Blacklist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            added_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# --------------------------------------------------
# USER HELPERS
# --------------------------------------------------
def create_user(full_name, username, email, password, role="user"):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO users (full_name, username, email, password, role, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        full_name,
        username,
        email,
        password,
        role,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return user


# --------------------------------------------------
# SCAN SAVE HELPERS
# --------------------------------------------------
def save_url_scan(user_id, url, verdict, risk_score, flags):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO url_scans (user_id, url, verdict, risk_score, flags, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        url,
        verdict,
        risk_score,
        ", ".join(flags),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def save_email_scan(user_id, sender, subject, verdict, risk_score, flags):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO email_scans (user_id, sender, subject, verdict, risk_score, flags, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        sender,
        subject,
        verdict,
        risk_score,
        ", ".join(flags),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def save_file_scan(user_id, filename, verdict, risk_score, flags):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO file_scans (user_id, filename, verdict, risk_score, flags, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        filename,
        verdict,
        risk_score,
        ", ".join(flags),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


# --------------------------------------------------
# AUTH HELPERS
# --------------------------------------------------
def check_auth():
    return "user_id" in session


def check_admin():
    return session.get("role") == "admin"


# --------------------------------------------------
# PAGE ROUTES
# --------------------------------------------------
@app.route("/")
def home():
    if not check_auth():
        return redirect("/login")
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.route("/login")
def login_page():
    if check_auth():
        return redirect("/")
    return send_from_directory(PUBLIC_DIR, "login.html")


@app.route("/register")
def register_page():
    if check_auth():
        return redirect("/")
    return send_from_directory(PUBLIC_DIR, "register.html")


@app.route("/dashboard")
def dashboard_page():
    if not check_auth():
        return redirect("/login")
    return send_from_directory(PUBLIC_DIR, "dashboard.html")


@app.route("/history")
def history_page():
    if not check_auth():
        return redirect("/login")
    return send_from_directory(PUBLIC_DIR, "history.html")


@app.route("/admin")
def admin_page():
    if not check_auth():
        return redirect("/login")
    return send_from_directory(PUBLIC_DIR, "admin.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# --------------------------------------------------
# STATIC ROUTES
# --------------------------------------------------
@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(CSS_DIR, filename)


@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(JS_DIR, filename)


# --------------------------------------------------
# AUTH APIs
# --------------------------------------------------
@app.route("/api/register", methods=["POST"])
def register_api():
    data = request.get_json() or {}

    full_name = (data.get("full_name") or "").strip()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    if not full_name or not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400

    try:
        create_user(full_name, username, email, password)
        return jsonify({"message": "Registration successful"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def login_api():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    user = get_user_by_username(username)

    if not user:
        return jsonify({"error": "User not found"}), 404

    if user["password"] != password:
        return jsonify({"error": "Invalid password"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "username": user["username"],
            "role": user["role"]
        }
    })


@app.route("/api/me", methods=["GET"])
def me_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    user = get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user": {
            "id": user["id"],
            "full_name": user["full_name"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"]
        }
    })


# --------------------------------------------------
# URL ANALYSIS API
# --------------------------------------------------
@app.route("/api/analyze", methods=["POST"])
def analyze():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Check blacklist first
    domain = url.split("/")[2].lower()

    conn = get_db_connection()
    blocked = conn.execute(
        "SELECT * FROM blacklist WHERE domain = ?",
        (domain,)
    ).fetchone()
    conn.close()

    if blocked:
        result = {
            "url": url,
            "verdict": "phishing",
            "risk_score": 0.95,
            "flags": ["domain_blacklisted"]
        }

        save_url_scan(session["user_id"], url, "phishing", 0.95, ["domain_blacklisted"])
        return jsonify(result)

    # ✅ MAIN FIX HERE
    result = run_url_scan(url)

    save_url_scan(
        session["user_id"],
        url,
        result["verdict"],
        result["risk_score"],
        result["flags"]
    )

    return jsonify(result)


# --------------------------------------------------
# EMAIL API
# --------------------------------------------------
@app.route("/api/analyze-email", methods=["POST"])
def analyze_email_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    subject = data.get("subject", "")
    sender = data.get("sender", "")
    body = data.get("body", "")

    # ✅ correct call
    result = run_email_scan(subject, sender, body)

    save_email_scan(
        session["user_id"],
        sender,
        subject,
        result["verdict"],
        result["risk_score"],
        result["flags"]
    )

    return jsonify(result)
# --------------------------------------------------
# FILE API
# --------------------------------------------------
@app.route("/api/analyze-file", methods=["POST"])
def analyze_file_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    filename = data.get("filename", "").strip()

    if not filename:
        return jsonify({"error": "Filename is required"}), 400

    result = run_file_scan(filename)

    save_file_scan(
        session["user_id"],
        filename,
        result["verdict"],
        result["risk_score"],
        result["flags"]
    )

    return jsonify(result)

# --------------------------------------------------
# DASHBOARD API
# --------------------------------------------------
@app.route("/api/dashboard", methods=["GET"])
def dashboard_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()

    total_url = conn.execute("SELECT COUNT(*) AS c FROM url_scans").fetchone()["c"]
    total_email = conn.execute("SELECT COUNT(*) AS c FROM email_scans").fetchone()["c"]
    total_file = conn.execute("SELECT COUNT(*) AS c FROM file_scans").fetchone()["c"]

    phishing = conn.execute("""
        SELECT
          (SELECT COUNT(*) FROM url_scans WHERE verdict='phishing') +
          (SELECT COUNT(*) FROM email_scans WHERE verdict='phishing') +
          (SELECT COUNT(*) FROM file_scans WHERE verdict='phishing') AS c
    """).fetchone()["c"]

    suspicious = conn.execute("""
        SELECT
          (SELECT COUNT(*) FROM url_scans WHERE verdict='suspicious') +
          (SELECT COUNT(*) FROM email_scans WHERE verdict='suspicious') +
          (SELECT COUNT(*) FROM file_scans WHERE verdict='suspicious') AS c
    """).fetchone()["c"]

    safe = conn.execute("""
        SELECT
          (SELECT COUNT(*) FROM url_scans WHERE verdict='safe') +
          (SELECT COUNT(*) FROM email_scans WHERE verdict='safe') +
          (SELECT COUNT(*) FROM file_scans WHERE verdict='safe') AS c
    """).fetchone()["c"]

    recent_rows = conn.execute("""
        SELECT 'URL' AS type, url AS target, verdict, risk_score, flags, created_at
        FROM url_scans
        UNION ALL
        SELECT 'EMAIL' AS type, sender || ' | ' || subject AS target, verdict, risk_score, flags, created_at
        FROM email_scans
        UNION ALL
        SELECT 'FILE' AS type, filename AS target, verdict, risk_score, flags, created_at
        FROM file_scans
        ORDER BY created_at DESC
        LIMIT 10
    """).fetchall()

    blacklist = conn.execute("SELECT domain, added_at FROM blacklist ORDER BY id DESC").fetchall()

    today = datetime.now().date()
    labels = []
    phishing_series = []
    suspicious_series = []
    safe_series = []

    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        labels.append(day.strftime("%a"))

        p = conn.execute("""
            SELECT
              (SELECT COUNT(*) FROM url_scans WHERE date(created_at)=? AND verdict='phishing') +
              (SELECT COUNT(*) FROM email_scans WHERE date(created_at)=? AND verdict='phishing') +
              (SELECT COUNT(*) FROM file_scans WHERE date(created_at)=? AND verdict='phishing') AS c
        """, (day_str, day_str, day_str)).fetchone()["c"]

        s = conn.execute("""
            SELECT
              (SELECT COUNT(*) FROM url_scans WHERE date(created_at)=? AND verdict='suspicious') +
              (SELECT COUNT(*) FROM email_scans WHERE date(created_at)=? AND verdict='suspicious') +
              (SELECT COUNT(*) FROM file_scans WHERE date(created_at)=? AND verdict='suspicious') AS c
        """, (day_str, day_str, day_str)).fetchone()["c"]

        sf = conn.execute("""
            SELECT
              (SELECT COUNT(*) FROM url_scans WHERE date(created_at)=? AND verdict='safe') +
              (SELECT COUNT(*) FROM email_scans WHERE date(created_at)=? AND verdict='safe') +
              (SELECT COUNT(*) FROM file_scans WHERE date(created_at)=? AND verdict='safe') AS c
        """, (day_str, day_str, day_str)).fetchone()["c"]

        phishing_series.append(p)
        suspicious_series.append(s)
        safe_series.append(sf)

    conn.close()

    return jsonify({
        "cards": {
            "total_url_scans": total_url,
            "total_email_scans": total_email,
            "total_file_scans": total_file,
            "total_scans": total_url + total_email + total_file,
            "phishing": phishing,
            "suspicious": suspicious,
            "safe": safe
        },
        "chart": {
            "labels": labels,
            "phishing": phishing_series,
            "suspicious": suspicious_series,
            "safe": safe_series
        },
        "recent": [dict(row) for row in recent_rows],
        "blacklist": [dict(row) for row in blacklist]
    })


# --------------------------------------------------
# HISTORY API
# --------------------------------------------------
@app.route("/api/history", methods=["GET"])
def history_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    q = (request.args.get("search") or "").lower()

    conn = get_db_connection()
    rows = conn.execute("""
        SELECT 'URL' as type, url as target, verdict, risk_score, flags, created_at FROM url_scans
        UNION ALL
        SELECT 'EMAIL' as type, sender || ' | ' || subject as target, verdict, risk_score, flags, created_at FROM email_scans
        UNION ALL
        SELECT 'FILE' as type, filename as target, verdict, risk_score, flags, created_at FROM file_scans
        ORDER BY created_at DESC
        LIMIT 100
    """).fetchall()
    conn.close()

    items = [dict(r) for r in rows]

    if q:
        items = [
            item for item in items
            if q in (item["target"] or "").lower() or q in (item["flags"] or "").lower()
        ]

    return jsonify({"history": items})


# --------------------------------------------------
# BLACKLIST API
# --------------------------------------------------
@app.route("/api/blacklist", methods=["GET", "POST"])
def blacklist_api():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()

    if request.method == "POST":
        data = request.get_json() or {}
        domain = (data.get("domain") or "").strip().lower()

        if not domain:
            conn.close()
            return jsonify({"error": "Domain required"}), 400

        try:
            conn.execute(
                "INSERT INTO blacklist (domain, added_at) VALUES (?, ?)",
                (domain, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    rows = conn.execute("SELECT * FROM blacklist ORDER BY id DESC").fetchall()
    conn.close()

    return jsonify({"items": [dict(r) for r in rows]})


# --------------------------------------------------
# EXPORT API
# --------------------------------------------------
@app.route("/api/export/url-scans", methods=["GET"])
def export_url_scans():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM url_scans ORDER BY id DESC").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user_id", "url", "verdict", "risk_score", "flags", "created_at"])

    for row in rows:
        writer.writerow([
            row["id"],
            row["user_id"],
            row["url"],
            row["verdict"],
            row["risk_score"],
            row["flags"],
            row["created_at"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=url_scans.csv"}
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)