import json
from pathlib import Path
from datetime import datetime, timezone
from analysis.rules_engine import evaluate, summarize
from analysis.risk_engine import RiskEngine
from analysis.anomaly_engine import AnomalyEngine
from pcap.parser import PCAPParser

risk_engine = RiskEngine()
anomaly_engine = AnomalyEngine()

def analyze_sessions(base, sessions):
    all_findings = []
    for session in sessions:
        anomaly = anomaly_engine.score(session)
        findings = evaluate(session)
        risk = risk_engine.predict(session, findings, anomaly["anomaly_score"])
        session["anomaly"] = anomaly
        session["risk"] = risk
        for f in findings:
            all_findings.append(f)
    counts = summarize(all_findings)

    scores = [s["risk"]["posture_score"] for s in sessions] or [100]
    overall = int(round(sum(scores) / len(scores)))
    if overall < 35: posture = "CRITICAL"
    elif overall < 60: posture = "HIGH"
    elif overall < 80: posture = "MODERATE"
    else: posture = "GOOD"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": base,
        "sessions": sessions,
        "findings": all_findings,
        "finding_counts": counts,
        "overall_score": overall,
        "overall_posture": posture,
        "protocol_counts": {
            p: sum(1 for s in sessions if s.get("protocol") == p)
            for p in ("SMTP","IMAP","POP3")
        },
        "ai_summary": (
            f"Overall cryptographic posture is {posture.lower()} at {overall}/100. "
            f"The ML layer classified individual sessions and the anomaly model highlighted unusual TLS behavior. "
            f"Deterministic rules provide evidence-backed remediation findings."
        )
    }

def analyze_pcap(path):
    parsed = PCAPParser(path).parse()
    return analyze_sessions(parsed["file_name"], parsed["sessions"])

def load_fixture(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return analyze_sessions(data.get("file_name", Path(path).name), data.get("sessions", []))
