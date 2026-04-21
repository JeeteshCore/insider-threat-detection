# agent/monitor.py
import random
from colorama import Fore, Style, init
from faker import Faker

from utils.config import (
    DEMO_USERS, SENSITIVE_PATHS,
    WORK_HOURS_START, WORK_HOURS_END, RISK_WEIGHTS
)
from db.database import (
    insert_login_event, insert_file_access,
    insert_privilege_event, insert_risk_score, insert_alert
)

init(autoreset=True)
fake = Faker()

def is_off_hours(hour):
    return hour < WORK_HOURS_START or hour >= WORK_HOURS_END

def generate_ip():
    return f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"

def generate_device():
    return random.choice(["Windows-PC", "MacBook", "Ubuntu-WS", "Android", "Unknown-Device"])

def get_risk_level(score):
    if score <= 35:   return "low"
    elif score <= 65: return "medium"
    else:             return "high"

def simulate_login(username, force_suspicious=False, force_medium=False):
    if force_suspicious:
        hour   = random.choice([0, 1, 2, 3, 23])
        status = random.choice(["success", "failed", "failed", "failed"])
    elif force_medium:
        hour   = random.choice([7, 8, 19, 20, 21])   # slightly off
        status = random.choice(["success", "failed", "success"])
    else:
        hour   = random.randint(WORK_HOURS_START, WORK_HOURS_END - 1)
        status = random.choice(["success", "success", "success", "success", "failed"])

    off_hours = 1 if is_off_hours(hour) else 0
    ip        = generate_ip()
    device    = generate_device()

    insert_login_event(username, ip, device, status, hour, off_hours)

    color  = Fore.RED if (status == "failed" or off_hours) else Fore.GREEN
    symbol = "⚠️ " if (status == "failed" or off_hours) else "✅"
    print(f"{color}{symbol} LOGIN  | {username:12} | {status:8} | Hour:{hour:02d} | IP:{ip} | {device}")

def simulate_file_access(username, force_suspicious=False, force_medium=False):
    normal_files = [
        "/home/shared/report.pdf",
        "/var/www/index.html",
        "/home/docs/meeting_notes.txt",
        "/home/shared/presentation.pptx",
        "/tmp/draft.docx",
    ]

    if force_suspicious:
        num_accesses = random.randint(120, 300)
    elif force_medium:
        num_accesses = random.randint(30, 60)
    else:
        num_accesses = random.randint(2, 12)

    for _ in range(num_accesses):
        if force_suspicious and random.random() < 0.35:
            file_path    = random.choice(SENSITIVE_PATHS)
            is_sensitive = 1
        elif force_medium and random.random() < 0.1:
            file_path    = random.choice(SENSITIVE_PATHS)
            is_sensitive = 1
        else:
            file_path    = random.choice(normal_files)
            is_sensitive = 0
        action = random.choice(["read", "read", "write", "copy", "delete"])
        insert_file_access(username, file_path, action, is_sensitive)

    color  = Fore.RED if force_suspicious else (Fore.YELLOW if force_medium else Fore.CYAN)
    symbol = "🔴" if force_suspicious else ("🟡" if force_medium else "📄")
    print(f"{color}{symbol} FILES  | {username:12} | Accessed: {num_accesses} files")

def simulate_privilege_change(username):
    changes = [
        ("employee",  "admin",      "role_change"),
        ("read_only", "read_write", "permission_grant"),
        ("normal",    "sudo",       "sudo_use"),
        ("intern",    "developer",  "role_change"),
    ]
    old_val, new_val, change_type = random.choice(changes)
    insert_privilege_event(username, change_type, old_val, new_val)
    print(f"{Fore.MAGENTA}🔐 PRIV   | {username:12} | {change_type} | {old_val} → {new_val}")

def calculate_risk_score(events: dict):
    """
    Rebalanced — guarantees LOW / MEDIUM / HIGH distribution.
    Scores based on THIS run's data only (from DB snapshot).
    """
    score   = 0
    reasons = []

    # 1. Failed logins — max 15 pts
    failed = events.get("failed_logins", 0)
    if failed > 0:
        pts = min(failed * 3, 15)
        score += pts
        if failed >= 2:
            reasons.append(f"Failed logins: {failed}")

    # 2. Off-hours login — max 20 pts
    if events.get("off_hours_login"):
        hour = events.get("login_hour", 12)
        if 0 <= hour <= 4 or hour == 23:
            pts = 20
        elif hour in [5, 6, 22]:
            pts = 12
        else:
            pts = 6
        score += pts
        reasons.append(f"Off-hours login ({hour:02d}:00)")

    # 3. File count — max 20 pts
    file_count = events.get("file_access_count", 0)
    if file_count > 10:
        pts = min(int((file_count / 300) * 20), 20)
        score += pts
        if file_count > 40:
            reasons.append(f"High file access: {file_count}")

    # 4. Sensitive files — max 25 pts
    sens = events.get("sensitive_count", 0)
    if sens > 0:
        pts = min(sens * 5, 25)
        score += pts
        reasons.append(f"Sensitive files: {sens}")

    # 5. Privilege change — 30 pts fixed
    if events.get("privilege_change"):
        score += 30
        reasons.append("Privilege escalation")

    score  = min(score, 100)
    reason = " | ".join(reasons) if reasons else "Normal behavior"
    return score, reason

def generate_and_store_risk(username, events, ai_score=0):
    score, reason = calculate_risk_score(events)

    # Blend: 70% rule + 30% AI
    if ai_score > 0:
        blended_score = int(score * 0.7 + ai_score * 0.3)
    else:
        blended_score = score

    blended_score = min(blended_score, 100)
    risk_level    = get_risk_level(blended_score)

    insert_risk_score(username, blended_score, risk_level, reason, ai_score=ai_score)

    if risk_level == "high":
        insert_alert(username, "HIGH_RISK_USER",
                     f"Score {blended_score}/100 — {reason}", "critical")
        print(f"{Fore.RED}🚨 ALERT  | {username:12} | Score:{blended_score}/100 | HIGH RISK")
        print(f"           Reason: {reason}")
    elif risk_level == "medium":
        insert_alert(username, "MEDIUM_RISK_USER",
                     f"Score {blended_score}/100 — {reason}", "warning")
        print(f"{Fore.YELLOW}⚠️  SCORE  | {username:12} | Score:{blended_score}/100 | MEDIUM")
    else:
        print(f"{Fore.GREEN}✅ SCORE  | {username:12} | Score:{blended_score}/100 | LOW")

    return blended_score, risk_level