# db/database.py
import sqlite3
import os
from datetime import datetime
from utils.config import DB_PATH

def get_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_connection()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()
    print("✅ Database initialized!")

# ── Monitoring inserts ────────────────────────────────────────

def insert_login_event(username, ip, device, status, login_hour, is_off_hours):
    conn = get_connection()
    conn.execute("""
        INSERT INTO login_events (username,ip_address,device,status,login_hour,is_off_hours)
        VALUES (?,?,?,?,?,?)
    """, (username, ip, device, status, login_hour, is_off_hours))
    conn.commit(); conn.close()

def insert_file_access(username, file_path, action, is_sensitive):
    conn = get_connection()
    conn.execute("""
        INSERT INTO file_access_events (username,file_path,action,is_sensitive)
        VALUES (?,?,?,?)
    """, (username, file_path, action, is_sensitive))
    conn.commit(); conn.close()

def insert_privilege_event(username, change_type, old_val, new_val):
    conn = get_connection()
    conn.execute("""
        INSERT INTO privilege_events (username,change_type,old_value,new_value)
        VALUES (?,?,?,?)
    """, (username, change_type, old_val, new_val))
    conn.commit(); conn.close()

def insert_risk_score(username, score, risk_level, reason, ai_score=0):
    conn = get_connection()
    conn.execute("""
        INSERT INTO risk_scores (username,score,ai_score,risk_level,reason)
        VALUES (?,?,?,?,?)
    """, (username, score, ai_score, risk_level, reason))
    conn.commit(); conn.close()

def insert_alert(username, alert_type, message, severity):
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts (username,alert_type,message,severity)
        VALUES (?,?,?,?)
    """, (username, alert_type, message, severity))
    conn.commit(); conn.close()

# ── Auth functions ────────────────────────────────────────────

def create_auth_user(username, email, password_hash, role='analyst'):
    conn = get_connection()
    conn.execute("""
        INSERT INTO auth_users (username,email,password_hash,role)
        VALUES (?,?,?,?)
    """, (username, email, password_hash, role))
    conn.commit(); conn.close()

def get_auth_user(username):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM auth_users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

def update_last_login(username):
    conn = get_connection()
    conn.execute(
        "UPDATE auth_users SET last_login=?, failed_attempts=0 WHERE username=?",
        (datetime.now().isoformat(), username)
    )
    conn.commit(); conn.close()

def increment_failed_attempts(username):
    conn = get_connection()
    conn.execute(
        "UPDATE auth_users SET failed_attempts = failed_attempts + 1 WHERE username=?",
        (username,)
    )
    conn.commit(); conn.close()

def reset_failed_attempts(username):
    conn = get_connection()
    conn.execute(
        "UPDATE auth_users SET failed_attempts=0, locked_until=NULL WHERE username=?",
        (username,)
    )
    conn.commit(); conn.close()

def lock_user(username, until_iso):
    conn = get_connection()
    conn.execute(
        "UPDATE auth_users SET locked_until=? WHERE username=?",
        (until_iso, username)
    )
    conn.commit(); conn.close()

# ── Feature extraction for AI model ──────────────────────────

def get_user_events_from_db(username):
    conn = get_connection()

    failed_logins = conn.execute(
        "SELECT COUNT(*) FROM login_events WHERE username=? AND status='failed'",
        (username,)
    ).fetchone()[0]

    off_hours_count = conn.execute(
        "SELECT COUNT(*) FROM login_events WHERE username=? AND is_off_hours=1",
        (username,)
    ).fetchone()[0]

    last_login = conn.execute(
        "SELECT login_hour FROM login_events WHERE username=? ORDER BY id DESC LIMIT 1",
        (username,)
    ).fetchone()

    file_count = conn.execute(
        "SELECT COUNT(*) FROM file_access_events WHERE username=?",
        (username,)
    ).fetchone()[0]

    sensitive_count = conn.execute(
        "SELECT COUNT(*) FROM file_access_events WHERE username=? AND is_sensitive=1",
        (username,)
    ).fetchone()[0]

    priv_count = conn.execute(
        "SELECT COUNT(*) FROM privilege_events WHERE username=?",
        (username,)
    ).fetchone()[0]

    conn.close()
    return {
        "failed_logins":     failed_logins,
        "off_hours_login":   off_hours_count > 0,
        "login_hour":        last_login[0] if last_login else 10,
        "file_access_count": file_count,
        "sensitive_count":   sensitive_count,
        "privilege_change":  priv_count > 0,
    }

def get_all_feature_vectors():
    """All users ka data AI training ke liye"""
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            u.username,
            COUNT(DISTINCT l.id)                                       AS total_logins,
            SUM(CASE WHEN l.status='failed'     THEN 1 ELSE 0 END)    AS failed_logins,
            SUM(CASE WHEN l.is_off_hours=1      THEN 1 ELSE 0 END)    AS off_hours,
            COALESCE(AVG(l.login_hour), 9)                             AS avg_hour,
            COUNT(DISTINCT f.id)                                       AS total_files,
            SUM(CASE WHEN f.is_sensitive=1      THEN 1 ELSE 0 END)    AS sensitive_files,
            COUNT(DISTINCT p.id)                                       AS priv_changes
        FROM users u
        LEFT JOIN login_events       l ON u.username = l.username
        LEFT JOIN file_access_events f ON u.username = f.username
        LEFT JOIN privilege_events   p ON u.username = p.username
        GROUP BY u.username
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_users_summary():
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            u.username, u.role,
            COUNT(DISTINCT l.id)                                    AS total_logins,
            SUM(CASE WHEN l.status='failed' THEN 1 ELSE 0 END)     AS failed_logins,
            COUNT(DISTINCT f.id)                                    AS file_accesses,
            MAX(r.score)                                            AS risk_score,
            MAX(r.risk_level)                                       AS risk_level
        FROM users u
        LEFT JOIN login_events       l ON u.username = l.username
        LEFT JOIN file_access_events f ON u.username = f.username
        LEFT JOIN risk_scores        r ON u.username = r.username
        GROUP BY u.username
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]