import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyEngine:
    def __init__(self):
        # Normalized synthetic TLS behavior features.
        normal = np.array([
            [1.0, 1.0, 1.0, 1.0, 1.0],
            [1.0, 0.9, 1.0, 1.0, 1.0],
            [0.9, 1.0, 1.0, 0.9, 1.0],
            [1.0, 1.0, 0.9, 1.0, 1.0],
            [0.95, 1.0, 1.0, 1.0, 0.95],
            [0.9, 0.95, 1.0, 0.9, 1.0],
            [1.0, 0.9, 1.0, 1.0, 0.9],
            [0.95, 1.0, 0.95, 1.0, 1.0],
        ])
        self.model = IsolationForest(contamination=0.18, random_state=42, n_estimators=100)
        self.model.fit(normal)

    def score(self, session):
        tls = session.get("tls", {}) or {}
        cert = session.get("certificate", {}) or {}
        version = str(tls.get("version") or "").upper()
        cipher = str(tls.get("cipher_suite") or "").upper()
        key_len = int(cert.get("key_length") or 0)

        x = np.array([[
            1.0 if version in {"TLS 1.2","TLS 1.3"} else 0.2,
            1.0 if cipher and not any(w in cipher for w in ("3DES","DES","RC4","NULL","EXPORT","MD5","RC2")) else 0.2,
            1.0 if not cert.get("expired") else 0.1,
            1.0 if key_len >= 2048 or key_len == 0 else 0.2,
            1.0 if tls.get("forward_secrecy") is True else 0.3,
        ]])
        raw = float(self.model.decision_function(x)[0])
        # Map roughly to 0-100 anomaly score.
        score = int(max(0, min(100, 50 - raw * 90)))
        label = "SUSPICIOUS" if score >= 60 else "NORMAL"
        return {"anomaly_score": score, "label": label, "model": "IsolationForest"}
