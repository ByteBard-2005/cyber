from backend.database import get_connection

def create_user(full_name, username, email, password, role="user"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (full_name, username, email, password, role)
        VALUES (?, ?, ?, ?, ?)
    """, (full_name, username, email, password, role))
    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user

def save_scan(user_id, scan_type, target, verdict, risk_score, flags):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scans (user_id, scan_type, target, verdict, risk_score, flags)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, scan_type, target, verdict, risk_score, ", ".join(flags)))
    conn.commit()
    conn.close()

def get_recent_scans(limit=50):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT scans.*, users.username
        FROM scans
        JOIN users ON scans.user_id = users.id
        ORDER BY scans.id DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_user_scans(user_id, limit=100):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_scan_counts():
    conn = get_connection()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    phishing = cur.execute("SELECT COUNT(*) AS c FROM scans WHERE verdict='phishing'").fetchone()["c"]
    suspicious = cur.execute("SELECT COUNT(*) AS c FROM scans WHERE verdict='suspicious'").fetchone()["c"]
    safe = cur.execute("SELECT COUNT(*) AS c FROM scans WHERE verdict='safe'").fetchone()["c"]

    conn.close()
    return {
        "total": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe
    }