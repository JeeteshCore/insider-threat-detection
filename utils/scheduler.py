# utils/scheduler.py
import schedule
import time
import threading
import random
from colorama import Fore, init

init(autoreset=True)

class MonitoringScheduler:
    def __init__(self):
        self.running = False
        self.thread  = None

    def start(self, interval_seconds=60):
        if self.running:
            return
        self.running = True
        schedule.every(interval_seconds).seconds.do(self._monitor_cycle)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        print(f"🔄 Auto-monitor started (every {interval_seconds}s)")

    def stop(self):
        self.running = False
        schedule.clear()

    def _loop(self):
        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def _monitor_cycle(self):
        try:
            from utils.config import DEMO_USERS
            from agent.monitor import (
                simulate_login, simulate_file_access,
                simulate_privilege_change, generate_and_store_risk
            )
            from db.database import get_user_events_from_db

            all_users    = list(DEMO_USERS)
            random.shuffle(all_users)

            # Every cycle — randomly assign risk tiers
            high_users   = all_users[:1]    # 1 high
            medium_users = all_users[1:3]   # 2 medium
            low_users    = all_users[3:]    # rest low

            print(f"\n🔄 CYCLE | HIGH:{high_users} | MED:{medium_users}")

            # Simulate 3 random users per cycle (not all — realistic)
            selected = random.sample(all_users, 3)

            for user in selected:
                is_high   = user in high_users
                is_medium = user in medium_users

                if is_high:
                    simulate_login(user, force_suspicious=True)
                    simulate_file_access(user, force_suspicious=True)
                    if random.random() < 0.5:
                        simulate_privilege_change(user)
                elif is_medium:
                    simulate_login(user, force_medium=True)
                    simulate_file_access(user, force_medium=True)
                else:
                    simulate_login(user)
                    simulate_file_access(user)

            # Retrain AI + recalculate scores for ALL users
            try:
                from models.anomaly_model import detector
                detector.train()
            except Exception as e:
                print(f"⚠️ AI retrain skipped: {e}")

            for user in all_users:
                try:
                    events = get_user_events_from_db(user)
                    try:
                        from models.anomaly_model import detector
                        ai_score, _ = detector.predict(user)
                    except Exception:
                        ai_score = 0
                    events['ai_score'] = ai_score
                    generate_and_store_risk(user, events, ai_score=ai_score)
                except Exception as e:
                    print(f"⚠️ Score error {user}: {e}")

            print(f"✅ Cycle complete — scores updated!")

        except Exception as e:
            print(f"❌ Scheduler error: {e}")
            import traceback
            traceback.print_exc()

# Singleton
scheduler = MonitoringScheduler()