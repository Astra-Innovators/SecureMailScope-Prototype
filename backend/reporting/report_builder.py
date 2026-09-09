from pathlib import Path
import html
import json

def build_html(result, ledger=None):
    score = result.get("overall_score", 0)
    posture = result.get("overall_posture", "UNKNOWN")
    findings = result.get("findings", [])
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{html.escape(f.get('severity',''))}</td>"
            f"<td>{html.escape(f.get('title',''))}</td>"
            f"<td>{html.escape(f.get('evidence',''))}</td>"
            f"<td>{html.escape(f.get('recommendation',''))}</td></tr>"
        )
    ledger_text = json.dumps(ledger or {}, indent=2)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SecureMailScope Forensic Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#162033}}h1{{color:#0b7285}}
.score{{font-size:48px;font-weight:700}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:10px;text-align:left}}pre{{background:#f5f7fa;padding:16px;overflow:auto}}
</style></head><body>
<h1>SecureMailScope — Forensic Report</h1>
<p><b>Source:</b> {html.escape(str(result.get('source','')))}</p>
<p><b>Generated:</b> {html.escape(str(result.get('generated_at','')))}</p>
<div class="score">{score}/100 — {html.escape(posture)}</div>
<h2>Protocol Coverage</h2><pre>{html.escape(json.dumps(result.get('protocol_counts',{}), indent=2))}</pre>
<h2>AI Summary</h2><p>{html.escape(result.get('ai_summary',''))}</p>
<h2>Prioritized Findings</h2>
<table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>
{''.join(rows)}</table>
<h2>Evidence Integrity Ledger</h2><pre>{html.escape(ledger_text)}</pre>
</body></html>"""

def save_json(result, path):
    Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")
