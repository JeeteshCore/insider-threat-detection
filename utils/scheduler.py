# utils/scheduler.py — Background Auto-Monitoring (Fixed)
import time
import threading
import random
from colorama import Fore, init

init(autoreset=True)

class MonitoringScheduler:
    def __init__(self):
        self.running  = False
        self.thread   = None
        self.interval = 5  # seconds between scans

    def start(self, interval_seconds=5):
        if self.running:
            print(f"{Fore.YELLOW}⚠️  Scheduler already running.")
            return
        self.interval = interval_seconds
        self.running  = True
        self.thread   = threading.Thread(target=self._loop, daemon=True, name="CyberShield-Monitor")
        self.thread.start()
        print(f"{Fore.GREEN}🔄 Auto-monitor thread started — scanning every {interval_seconds}s")

    def stop(self):
        self.running = False
        print(f"{Fore.YELLOW}⏹️  Auto-monitor stopped.")

    def _loop(self):
        """Main loop — runs continuously in background."""
        time.sleep(10)
        while self.running:
            try:
                self._monitor_cycle()
            except Exception as e:
                print(f"{Fore.RED}⚠️  Scheduler cycle error: {e}")
            time.sleep(self.interval)

    def _monitor_cycle(self):
        try:
            from utils.config import DEMO_USERS
            from agent.monitor import (
                simulate_login, simulate_file_access,
                simulate_privilege_change, generate_and_store_risk
            )
            from db.database import get_user_events_from_db, get_connection

            conn = get_connection()
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.close()

            if user_count == 0:
                print(f"{Fore.YELLOW}⚠️  No users in DB yet — skipping scan cycle.")
                return

            num_to_scan = random.randint(2, 3)
            users_to_scan = random.sample(DEMO_USERS, min(num_to_scan, len(DEMO_USERS)))

            suspicious = random.random() < 0.15
            sus_user   = random.choice(users_to_scan) if suspicious else None

            print(f"\n{Fore.CYAN}🔄 Auto-scan cycle | Users: {', '.join(users_to_scan)}" +
                  (f" | Suspicious: {sus_user}" if sus_user else ""))

            for user in users_to_scan:
                is_sus = (user == sus_user)
                simulate_login(user, force_suspicious=is_sus)
                simulate_file_access(user, force_suspicious=is_sus)

                if is_sus and random.random() < 0.3:
                    simulate_privilege_change(user)

            if random.random() < 0.20:
                try:
                    from models.anomaly_model import detector
                    detector.train()
                    print(f"{Fore.CYAN}🤖 AI model retrained on latest data.")
                except Exception as e:
                    print(f"{Fore.YELLOW}⚠️  AI retrain skipped: {e}")

            try:
                from models.anomaly_model import detector
                ai_available = detector.is_trained
            except Exception:
                ai_available = False

            for user in users_to_scan:
                events = get_user_events_from_db(user)
                ai_score = 0
                if ai_available:
                    try:
                        from models.anomaly_model import detector
                        ai_score, _ = detector.predict(user)
                    except Exception:
                        ai_score = 0
                events['ai_score'] = ai_score
                generate_and_store_risk(user, events, ai_score=ai_score)

            print(f"{Fore.GREEN}✅ Scan cycle complete.")

        except Exception as e:
            print(f"{Fore.RED}⚠️  Monitor cycle failed: {e}")
            import traceback
            traceback.print_exc()

# Singleton — import and call .start() once
scheduler = MonitoringScheduler()