import numpy as np
from sklearn.ensemble import RandomForestClassifier

FEATURES = [
    "legacy_tls", "weak_cipher", "expired_cert", "weak_key",
    "no_pfs", "starttls", "certificate_valid", "anomaly_hint"
]

class RiskEngine:
    def __init__(self):
        # Synthetic, transparent prototype training set.
        X = np.array([
            [0,0,0,0,0,1,1,0],
            [0,0,0,0,0,1,1,0],
            [1,0,0,0,0,1,1,0],
            [1,1,0,1,1,1,1,1],
            [0,1,0,0,0,1,1,1],
            [0,0,1,0,0,1,0,1],
            [1,1,1,1,1,1,0,1],
            [0,0,0,1,1,1,1,0],
            [1,0,1,0,1,1,1,1],
            [0,1,1,0,0,1,0,1],
            [0,0,0,0,1,1,1,0],
            [1,1,1,1,1,0,0,1],
        ], dtype=float)
        y = np.array(["LOW","LOW","HIGH","CRITICAL","MEDIUM","HIGH","CRITICAL","MEDIUM","HIGH","HIGH","MEDIUM","CRITICAL"])
        self.model = RandomForestClassifier(n_estimators=120, random_state=42, class_weight="balanced")
        self.model.fit(X, y)

    def vector(self, session, findings=None, anomaly_score=0):
        tls = session.get("tls", {}) or {}
        cert = session.get("certificate", {}) or {}
        version = str(tls.get("version") or "").upper()
        cipher = str(tls.get("cipher_suite") or "").upper()
        key_len = int(cert.get("key_length") or 0)
        legacy = int(version in {"TLS 1.0","TLS 1.1","SSL 3.0"})
        weak_cipher = int(any(x in cipher for x in ("3DES","DES","RC4","NULL","EXPORT","MD5","RC2")))
        expired = int(cert.get("expired") is True)
        weak_key = int(key_len and key_len < 2048)
        no_pfs = int(tls.get("forward_secrecy") is False or str(tls.get("key_exchange","")).upper() in {"RSA","STATIC RSA"})
        starttls = int(bool(session.get("starttls_detected")))
        valid = int(not expired and bool(cert.get("subject") or cert.get("valid_to")))
        anomaly = int(anomaly_score >= 60)
        return np.array([[legacy, weak_cipher, expired, weak_key, no_pfs, starttls, valid, anomaly]], dtype=float)

    def predict(self, session, findings=None, anomaly_score=0):
        x = self.vector(session, findings, anomaly_score)
        pred = str(self.model.predict(x)[0])
        proba = self.model.predict_proba(x)[0]
        classes = list(self.model.classes_)
        confidence = round(float(max(proba)) * 100, 1)

        # Evidence-weighted posture score. ML label is shown separately.
        penalties = {"CRITICAL": 35, "HIGH": 22, "MEDIUM": 10, "LOW": 4}
        score = 100
        for f in findings or []:
            score -= penalties.get(f.get("severity"), 0)
        score -= max(0, int((anomaly_score - 70) * 0.15))
        score = max(0, min(100, int(score)))

        if score < 35:
            posture = "CRITICAL"
        elif score < 60:
            posture = "HIGH"
        elif score < 80:
            posture = "MODERATE"
        else:
            posture = "GOOD"

        return {
            "ml_label": pred,
            "ml_confidence": confidence,
            "posture_score": score,
            "posture": posture,
            "model": "RandomForestClassifier (synthetic prototype training set)",
            "features": {FEATURES[i]: int(x[0][i]) for i in range(len(FEATURES))}
        }
