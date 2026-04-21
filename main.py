# main.py
import random
from colorama import Fore, Style, init
from tabulate import tabulate

from db.database import initialize_database, get_connection, get_user_events_from_db
from agent.monitor import (
    simulate_login, simulate_file_access,
    simulate_privilege_change, generate_and_store_risk
)
from models.anomaly_model import detector
from utils.config import DEMO_USERS

init(autoreset=True)

def seed_users():
    conn = get_connection()
    users_data = [
        ("vikas",     "admin",    "cybersecurity"),
        ("amit",      "employee", "finance"),
        ("priya",     "employee", "hr"),
        ("rahul",     "employee", "development"),
        ("sneha",     "employee", "marketing"),
        ("admin",     "admin",    "it"),
        ("dev_user",  "employee", "development"),
        ("intern_01", "intern",   "general"),
    ]
    for u, r, d in users_data:
        try:
            conn.execute(
                "INSERT OR IGNORE INTO users (username,role,department) VALUES (?,?,?)",
                (u, r, d)
            )
        except Exception:
            pass
    conn.commit()
    conn.close()
    print(f"{Fore.CYAN}👥 Users seeded.")

def run_simulation():
    print(f"\n{Fore.YELLOW}{'='*60}")
    print("   🛡️  INSIDER THREAT DETECTION — SIMULATION")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    # Always assign 3 tiers for realistic distribution
    all_users       = list(DEMO_USERS)
    random.shuffle(all_users)

    high_users   = all_users[:2]    # 2 HIGH risk
    medium_users = all_users[2:4]   # 2 MEDIUM risk
    low_users    = all_users[4:]    # 4 LOW risk

    print(f"{Fore.RED}🔴 HIGH risk this round:   {high_users}")
    print(f"{Fore.YELLOW}🟡 MEDIUM risk this round: {medium_users}")
    print(f"{Fore.GREEN}🟢 LOW risk this round:    {low_users}\n")

    # Simulate activity per tier
    for user in all_users:
        print(f"\n{Fore.WHITE}--- {user} ---")

        if user in high_users:
            simulate_login(user, force_suspicious=True)
            simulate_file_access(user, force_suspicious=True)
            if random.random() < 0.7:
                simulate_privilege_change(user)

        elif user in medium_users:
            simulate_login(user, force_medium=True)
            simulate_file_access(user, force_medium=True)

        else:
            simulate_login(user)
            simulate_file_access(user)

    # Train AI model
    print(f"\n{Fore.CYAN}🤖 Training Isolation Forest AI model...")
    detector.train()

    # Calculate scores from real DB
    print(f"\n{Fore.YELLOW}{'='*60}")
    print("   📊 RISK SCORES (Rule + AI Blended)")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    results = []
    for user in all_users:
        events               = get_user_events_from_db(user)
        ai_score, is_anomaly = detector.predict(user)
        events['ai_score']   = ai_score

        score, level = generate_and_store_risk(user, events, ai_score=ai_score)
        ai_tag       = "⚠️ ANOMALY" if is_anomaly else "✅ Normal"
        results.append([user, score, ai_score, level.upper(), ai_tag])

    # Summary
    print(f"\n{Fore.CYAN}{'='*60}")
    print("   📋 FINAL SUMMARY")
    print(f"{'='*60}{Style.RESET_ALL}")
    sorted_r = sorted(results, key=lambda x: x[1], reverse=True)
    print(tabulate(sorted_r,
                   headers=["Username","Rule Score","AI Score","Level","AI Status"],
                   tablefmt="rounded_outline"))

    print(f"\n{Fore.GREEN}✅ Done!")
    print(f"{Fore.CYAN}💡 Dashboard: python -m dashboard.app → http://127.0.0.1:5000\n")

if __name__ == "__main__":
    print(f"{Fore.CYAN}🔧 Initializing...")
    initialize_database()
    seed_users()
    run_simulation()