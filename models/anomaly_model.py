# models/anomaly_model.py — Isolation Forest AI Model
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from colorama import Fore, init

init(autoreset=True)

MODEL_PATH = "models/threat_model.pkl"

class ThreatDetector:
    def __init__(self):
        self.model       = None
        self.is_trained  = False
        self._try_load()

    def _try_load(self):
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, 'rb') as f:
                    self.model      = pickle.load(f)
                    self.is_trained = True
                print(f"{Fore.CYAN}🤖 AI model loaded from disk.")
            except Exception:
                self.model      = None
                self.is_trained = False

    def _extract_features(self, rows):
        features = []
        for r in rows:
            features.append([
                float(r.get('total_logins',   0) or 0),
                float(r.get('failed_logins',  0) or 0),
                float(r.get('off_hours',       0) or 0),
                float(r.get('avg_hour',        9) or 9),
                float(r.get('total_files',     0) or 0),
                float(r.get('sensitive_files', 0) or 0),
                float(r.get('priv_changes',    0) or 0),
            ])
        return np.array(features)

    def train(self):
        from db.database import get_all_feature_vectors
        rows = get_all_feature_vectors()

        if len(rows) < 3:
            print(f"{Fore.YELLOW}⚠️  Not enough data to train AI model (need ≥3 users)")
            return False

        X = self._extract_features(rows)
        self.model = IsolationForest(
            contamination=0.15,
            n_estimators=200,
            max_samples='auto',
            random_state=42
        )
        self.model.fit(X)
        self.is_trained = True

        os.makedirs("models", exist_ok=True)
        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self.model, f)

        print(f"{Fore.GREEN}✅ AI model trained on {len(rows)} users and saved.")
        return True

    def predict(self, username):
        """
        Returns (ai_score 0-100, is_anomaly bool)
        0  = completely normal
        100 = extreme anomaly
        """
        if not self.is_trained:
            return 0, False

        from db.database import get_all_feature_vectors
        all_rows = get_all_feature_vectors()
        user_row = next((r for r in all_rows if r['username'] == username), None)

        if not user_row:
            return 0, False

        X = self._extract_features([user_row])

        prediction    = self.model.predict(X)[0]         # -1=anomaly, 1=normal
        raw_score     = self.model.score_samples(X)[0]   # more negative = more anomalous

        is_anomaly    = prediction == -1
        # Normalize: raw_score is typically -0.7 to 0.1
        # We map it: score ≈ 0 (normal) to 100 (anomaly)
        ai_score      = max(0, min(100, int((-raw_score - 0.1) * 150)))

        return ai_score, is_anomaly

# Singleton instance
detector = ThreatDetector()