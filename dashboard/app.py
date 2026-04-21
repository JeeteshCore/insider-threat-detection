# dashboard/app.py
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, make_response)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sys, os, csv, io, threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db.database import (
    get_connection, initialize_database,
    create_auth_user, get_auth_user,
    update_last_login, increment_failed_attempts,
    reset_failed_attempts, lock_user
)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cybershield-dev-secret-2024')
app.permanent_session_lifetime = timedelta(hours=2)

# ── Initialize DB on startup ──────────────────────────────────
initialize_database()

# ── Auto-start background monitoring scheduler ────────────────
def start_background_scheduler():
    """Start continuous monitoring in a background thread."""
    try:
        from utils.scheduler import scheduler
        scheduler.start(interval_seconds=30)  # scan every 30 seconds
        print("🔄 Background scheduler started — scanning every 30 seconds.")
    except Exception as e:
        print(f"⚠️  Scheduler start error: {e}")

# Start scheduler once using threading to avoid duplicate starts
_scheduler_started = False
_scheduler_lock = threading.Lock()

def ensure_scheduler():
    global _scheduler_started
    with _scheduler_lock:
        if not _scheduler_started:
            t = threading.Thread(target=start_background_scheduler, daemon=True)
            t.start()
            _scheduler_started = True

ensure_scheduler()

# ── Auth decorator ────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# ── Auth Routes ───────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if 'user' in session:
        return redirect(url_for('home'))

    error      = None
    active_tab = 'signin'

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            error = "All fields are required."
        else:
            user = get_auth_user(username)
            if not user:
                error = "Invalid username or password."
            else:
                # Check lockout
                if user.get('locked_until'):
                    try:
                        locked_dt = datetime.fromisoformat(user['locked_until'])
                        if datetime.now() < locked_dt:
                            remaining = int((locked_dt - datetime.now()).total_seconds() / 60) + 1
                            error = f"Account locked. Try again in {remaining} minute(s)."
                            return render_template('login.html', error=error, active_tab=active_tab)
                        else:
                            reset_failed_attempts(username)
                    except Exception:
                        reset_failed_attempts(username)

                if check_password_hash(user['password_hash'], password):
                    reset_failed_attempts(username)
                    update_last_login(username)
                    session.permanent = True
                    session['user']   = username
                    session['role']   = user['role']
                    return redirect(url_for('home'))
                else:
                    increment_failed_attempts(username)
                    fresh_user = get_auth_user(username)
                    attempts   = fresh_user['failed_attempts'] if fresh_user else 0
                    if attempts >= 5:
                        until = (datetime.now() + timedelta(minutes=15)).isoformat()
                        lock_user(username, until)
                        error = "Too many failed attempts. Account locked for 15 minutes."
                    else:
                        left  = 5 - attempts
                        error = f"Invalid credentials. {left} attempt(s) remaining."

    return render_template('login.html', error=error, active_tab=active_tab)


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username', '').strip()
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm  = request.form.get('confirm_password', '')
    role     = request.form.get('role', 'analyst')
    error    = None

    if not all([username, email, password, confirm]):
        error = "All fields are required."
    elif len(username) < 3:
        error = "Username must be at least 3 characters."
    elif '@' not in email or '.' not in email:
        error = "Enter a valid email address."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."
    elif not any(c.isupper() for c in password):
        error = "Password must have at least one uppercase letter."
    elif not any(c.isdigit() for c in password):
        error = "Password must have at least one number."
    elif password != confirm:
        error = "Passwords do not match."
    else:
        existing = get_auth_user(username)
        if existing:
            error = "Username already exists. Please choose another."
        else:
            try:
                pw_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
                create_auth_user(username, email, pw_hash, role)
                session.permanent = True
                session['user']   = username
                session['role']   = role
                return redirect(url_for('home'))
            except Exception as e:
                # Handle duplicate email
                if 'UNIQUE' in str(e):
                    error = "Email already registered. Please use another email."
                else:
                    error = "Registration failed. Please try again."

    return render_template('login.html', error=error, active_tab='signup')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ── Dashboard Data Helper ─────────────────────────────────────

def fetch_dashboard_data(search='', filter_level='all'):
    conn = get_connection()

    # FIXED: Use parameterized queries to prevent SQL injection
    base_query = """
        SELECT username, score, ai_score, risk_level, reason, calculated_at AS timestamp
        FROM risk_scores
        WHERE id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
    """
    params = []

    if filter_level != 'all':
        base_query += " AND risk_level = ?"
        params.append(filter_level)
    if search:
        base_query += " AND username LIKE ?"
        params.append(f'%{search}%')

    base_query += " ORDER BY score DESC"

    users  = conn.execute(base_query, params).fetchall()

    alerts = conn.execute("""
        SELECT username, alert_type, message, severity, created_at AS timestamp
        FROM alerts ORDER BY id DESC LIMIT 20
    """).fetchall()

    # Stats
    total_users   = conn.execute("SELECT COUNT(DISTINCT username) FROM risk_scores").fetchone()[0]
    high_risk     = conn.execute("""
        SELECT COUNT(*) FROM risk_scores WHERE risk_level='high'
        AND id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
    """).fetchone()[0]
    medium_risk   = conn.execute("""
        SELECT COUNT(*) FROM risk_scores WHERE risk_level='medium'
        AND id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
    """).fetchone()[0]
    low_risk      = conn.execute("""
        SELECT COUNT(*) FROM risk_scores WHERE risk_level='low'
        AND id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
    """).fetchone()[0]
    total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    total_events  = conn.execute("SELECT COUNT(*) FROM login_events").fetchone()[0]
    failed_logins = conn.execute("SELECT COUNT(*) FROM login_events WHERE status='failed'").fetchone()[0]
    off_hours     = conn.execute("SELECT COUNT(*) FROM login_events WHERE is_off_hours=1").fetchone()[0]
    sensitive_hits= conn.execute("SELECT COUNT(*) FROM file_access_events WHERE is_sensitive=1").fetchone()[0]
    priv_events   = conn.execute("SELECT COUNT(*) FROM privilege_events").fetchone()[0]
    file_events   = conn.execute("SELECT COUNT(*) FROM file_access_events").fetchone()[0]

    conn.close()

    stats = dict(
        total_users=total_users, high_risk=high_risk,
        medium_risk=medium_risk, low_risk=low_risk,
        total_alerts=total_alerts, total_events=total_events,
        failed_logins=failed_logins, off_hours=off_hours,
        sensitive_hits=sensitive_hits, priv_events=priv_events,
        file_events=file_events
    )
    return [dict(u) for u in users], [dict(a) for a in alerts], stats

# ── Main Dashboard ────────────────────────────────────────────

@app.route('/')
@login_required
def home():
    search       = request.args.get('search', '').strip()
    filter_level = request.args.get('level', 'all')
    users, alerts, stats = fetch_dashboard_data(search, filter_level)
    return render_template('index.html',
        users=users, alerts=alerts, stats=stats,
        current_user=session.get('user'),
        current_role=session.get('role'),
        search=search, filter_level=filter_level
    )

# ── Chart Data API ────────────────────────────────────────────

@app.route('/api/chart-data')
@login_required
def api_chart_data():
    users, _, stats = fetch_dashboard_data()

    bar_labels, bar_scores, bar_colors = [], [], []
    for u in users:
        lvl = u.get('risk_level', 'low')
        bar_labels.append(u['username'])
        bar_scores.append(u.get('score', 0))
        bar_colors.append(
            'rgba(255,41,82,0.85)'  if lvl == 'high'   else
            'rgba(255,140,0,0.85)'  if lvl == 'medium' else
            'rgba(0,255,163,0.85)'
        )

    total   = max(stats['total_events'], 1)
    radar_d = [
        min(int((stats['failed_logins']  / max(total * 0.1, 1)) * 100), 100),
        min(int((stats['off_hours']      / max(total * 0.1, 1)) * 100), 100),
        min(int((stats['file_events']    / max(total,        1)) * 100), 100),
        min(int((stats['sensitive_hits'] / max(total * 0.05, 1)) * 100), 100),
        min(int((stats['priv_events']    / max(total * 0.02, 1)) * 100), 100),
    ]

    return jsonify({
        "bar":      {"labels": bar_labels, "scores": bar_scores, "colors": bar_colors},
        "doughnut": {
            "labels": ["High Risk", "Medium Risk", "Low Risk"],
            "data":   [stats['high_risk'], stats['medium_risk'], stats['low_risk']],
            "colors": ["#ff2952", "#ff8c00", "#00ffa3"]
        },
        "radar": {
            "labels": ["Failed Logins","Off-Hours","File Access","Sensitive Files","Priv Changes"],
            "data":   radar_d
        },
        "stats": stats
    })


@app.route('/api/scores')
@login_required
def api_scores():
    conn  = get_connection()
    users = conn.execute("""
        SELECT username, score, ai_score, risk_level
        FROM risk_scores
        WHERE id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
        ORDER BY score DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route('/api/user/<username>')
@login_required
def api_user_detail(username):
    conn = get_connection()

    score_row = conn.execute("""
        SELECT score, ai_score, risk_level, reason, calculated_at
        FROM risk_scores WHERE username=? ORDER BY id DESC LIMIT 1
    """, (username,)).fetchone()

    logins = conn.execute("""
        SELECT status, login_hour, ip_address, device, is_off_hours, login_time
        FROM login_events WHERE username=? ORDER BY id DESC LIMIT 10
    """, (username,)).fetchall()

    files = conn.execute("""
        SELECT file_path, action, is_sensitive, access_time
        FROM file_access_events WHERE username=? ORDER BY id DESC LIMIT 10
    """, (username,)).fetchall()

    privs = conn.execute("""
        SELECT change_type, old_value, new_value, changed_at
        FROM privilege_events WHERE username=? ORDER BY id DESC LIMIT 5
    """, (username,)).fetchall()

    failed_count    = conn.execute("SELECT COUNT(*) FROM login_events WHERE username=? AND status='failed'", (username,)).fetchone()[0]
    sensitive_count = conn.execute("SELECT COUNT(*) FROM file_access_events WHERE username=? AND is_sensitive=1", (username,)).fetchone()[0]
    file_total      = conn.execute("SELECT COUNT(*) FROM file_access_events WHERE username=?", (username,)).fetchone()[0]
    off_hrs_count   = conn.execute("SELECT COUNT(*) FROM login_events WHERE username=? AND is_off_hours=1", (username,)).fetchone()[0]

    conn.close()

    return jsonify({
        "username":    username,
        "score":       score_row["score"]       if score_row else 0,
        "ai_score":    score_row["ai_score"]    if score_row else 0,
        "risk_level":  score_row["risk_level"]  if score_row else "low",
        "reason":      score_row["reason"]      if score_row else "No data",
        "last_updated":score_row["calculated_at"] if score_row else "N/A",
        "stats": {
            "failed_logins":   failed_count,
            "sensitive_files": sensitive_count,
            "total_files":     file_total,
            "off_hours":       off_hrs_count,
        },
        "recent_logins":      [dict(l) for l in logins],
        "recent_files":       [dict(f) for f in files],
        "privilege_changes":  [dict(p) for p in privs],
    })


@app.route('/api/trend/<username>')
@login_required
def api_trend(username):
    conn = get_connection()
    rows = conn.execute("""
        SELECT score, ai_score, risk_level, calculated_at AS ts
        FROM risk_scores WHERE username=?
        ORDER BY id ASC LIMIT 30
    """, (username,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Live stats API for dashboard auto-refresh ─────────────────
@app.route('/api/live-stats')
@login_required
def api_live_stats():
    """Returns latest stats + user scores for dashboard live update (no full page reload)."""
    try:
        users, alerts, stats = fetch_dashboard_data()
        return jsonify({
            "stats": stats,
            "users": users,
            "alerts": alerts[:5],  # latest 5 alerts
            "timestamp": datetime.now().strftime('%H:%M:%S')
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Export CSV ────────────────────────────────────────────────

@app.route('/export/csv')
@login_required
def export_csv():
    conn  = get_connection()
    users = conn.execute("""
        SELECT username, score, ai_score, risk_level, reason, calculated_at
        FROM risk_scores
        WHERE id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
        ORDER BY score DESC
    """).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Username","Rule Score","AI Score","Risk Level","Reason","Timestamp"])
    for u in users:
        writer.writerow([u['username'], u['score'], u['ai_score'],
                         u['risk_level'], u['reason'], u['calculated_at']])

    response = make_response(output.getvalue())
    response.headers['Content-Type']        = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=cybershield_report_{datetime.now().strftime("%Y%m%d_%H%M")}.csv'
    return response

# ── Export PDF ────────────────────────────────────────────────

@app.route('/export/pdf')
@login_required
def export_pdf():
    try:
        from fpdf import FPDF

        conn  = get_connection()
        users = conn.execute("""
            SELECT username, score, ai_score, risk_level, reason, calculated_at
            FROM risk_scores
            WHERE id IN (SELECT MAX(id) FROM risk_scores GROUP BY username)
            ORDER BY score DESC
        """).fetchall()
        alerts = conn.execute("""
            SELECT username, alert_type, severity, created_at
            FROM alerts ORDER BY id DESC LIMIT 15
        """).fetchall()
        conn.close()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Header
        pdf.set_fill_color(5, 10, 15)
        pdf.rect(0, 0, 210, 40, 'F')
        pdf.set_text_color(0, 229, 255)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_y(10)
        pdf.cell(0, 10, "CYBERSHIELD", align='C', ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 150, 180)
        pdf.cell(0, 6, "Insider Threat Detection System — Security Report", align='C', ln=True)
        pdf.cell(0, 6,
                 f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Analyst: {session.get('user','N/A')}",
                 align='C', ln=True)
        pdf.ln(15)

        # User Risk Table
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "User Risk Analysis", ln=True)
        pdf.set_draw_color(0, 180, 220)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

        pdf.set_fill_color(20, 40, 60)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        col_w = [38, 28, 25, 28, 71]
        for h, w in zip(["Username","Rule Score","AI Score","Risk Level","Reason"], col_w):
            pdf.cell(w, 8, h, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for u in users:
            lvl = (u['risk_level'] or 'low').lower()
            if lvl == 'high':
                pdf.set_fill_color(255, 230, 235); pdf.set_text_color(180, 0, 30)
            elif lvl == 'medium':
                pdf.set_fill_color(255, 245, 225); pdf.set_text_color(160, 80, 0)
            else:
                pdf.set_fill_color(230, 255, 245); pdf.set_text_color(0, 100, 60)

            reason_short = (u['reason'] or '')[:45] + ('...' if len(u['reason'] or '') > 45 else '')
            for val, w in zip([u['username'], str(u['score']), str(u['ai_score']),
                                lvl.upper(), reason_short], col_w):
                pdf.cell(w, 7, val, border=1, fill=True)
            pdf.ln()

        pdf.ln(8)

        # Alerts
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Recent Alerts", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

        pdf.set_fill_color(20, 40, 60)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        for h, w in [("Username",38),("Alert Type",60),("Severity",30),("Timestamp",62)]:
            pdf.cell(w, 8, h, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for a in alerts:
            sev = (a['severity'] or 'medium').lower()
            if sev == 'critical':
                pdf.set_fill_color(255,230,235); pdf.set_text_color(180,0,30)
            else:
                pdf.set_fill_color(255,245,225); pdf.set_text_color(160,80,0)
            for val, w in zip([a['username'], a['alert_type'] or '',
                                sev.upper(), (a['created_at'] or '')[:16]],
                               [38,60,30,62]):
                pdf.cell(w, 7, val, border=1, fill=True)
            pdf.ln()

        pdf.ln(10)
        pdf.set_text_color(120, 150, 170)
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(0, 6,
                 "CONFIDENTIAL — CyberShield v2.0 | AI-Powered UEBA | Do not distribute",
                 align='C', ln=True)

        pdf_bytes = pdf.output(dest='S')
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode('latin-1')

        response = make_response(pdf_bytes)
        response.headers['Content-Type']        = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=cybershield_report_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
        return response

    except Exception as e:
        return f"PDF generation error: {e}", 500


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)  # FIXED: use_reloader=False prevents double scheduler start
