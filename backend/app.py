# pyright: reportMissingImports=false
from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import tempfile, hashlib, json, uuid
from datetime import datetime, timezone

from config import REPORT_DIR, MAX_UPLOAD_MB, ALLOWED_EXTENSIONS
from analyzer import analyze_pcap, load_fixture
from reporting.report_builder import build_html, save_json
from reporting.pdf_builder import save_pdf

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
LAST_RESULT = None
LAST_LEDGER = None
CHAIN = []

def make_ledger(result):
    evidence = json.dumps(result.get("sessions", []), sort_keys=True).encode()
    evidence_hash = hashlib.sha256(evidence).hexdigest()
    report_payload = json.dumps({
        "overall_score": result.get("overall_score"),
        "findings": result.get("findings", []),
        "protocol_counts": result.get("protocol_counts", {})
    }, sort_keys=True).encode()
    report_hash = hashlib.sha256(report_payload).hexdigest()
    previous = CHAIN[-1]["current_hash"] if CHAIN else "GENESIS"
    current = hashlib.sha256((previous + evidence_hash + report_hash).encode()).hexdigest()
    block = {
        "block_number": len(CHAIN),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence_hash": evidence_hash,
        "report_hash": report_hash,
        "previous_hash": previous,
        "current_hash": current,
        "integrity": "VERIFIED"
    }
    CHAIN.append(block)
    return block

def finalize(result):
    global LAST_RESULT, LAST_LEDGER
    LAST_RESULT = result
    LAST_LEDGER = make_ledger(result)
    result["ledger"] = LAST_LEDGER
    return result

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status":"online","service":"SecureMailScope"})

@app.route("/api/demo/<kind>")
def demo(kind):
    if kind not in {"secure","vulnerable"}:
        return jsonify({"error":"Unknown demo"}), 404
    path = Path(__file__).resolve().parent.parent / "test_data" / f"{kind}_demo.json"
    try:
        return jsonify(finalize(load_fixture(path)))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error":"No PCAP file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error":"No filename"}), 400
    suffix = Path(f.filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        return jsonify({"error":"Only .pcap and .pcapng are supported"}), 400
    tmp = Path(tempfile.gettempdir()) / f"securescope_{uuid.uuid4().hex}{suffix}"
    f.save(tmp)
    try:
        result = finalize(analyze_pcap(tmp))
        result["uploaded_sha256"] = hashlib.sha256(tmp.read_bytes()).hexdigest()
        result["analysis_source"] = "REAL_UPLOADED_PCAP"
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        try: tmp.unlink(missing_ok=True)
        except Exception: pass

@app.route("/api/report/<fmt>")
def report(fmt):
    if LAST_RESULT is None:
        return jsonify({"error":"Run an analysis first"}), 400
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        p = REPORT_DIR / f"SecureMailScope_{stamp}.json"
        save_json(LAST_RESULT, p)
        return send_file(p, as_attachment=True, download_name=p.name)
    if fmt == "html":
        p = REPORT_DIR / f"SecureMailScope_{stamp}.html"
        p.write_text(build_html(LAST_RESULT, LAST_LEDGER), encoding="utf-8")
        return send_file(p, as_attachment=True, download_name=p.name)
    if fmt == "pdf":
        p = REPORT_DIR / f"SecureMailScope_{stamp}.pdf"
        save_pdf(LAST_RESULT, LAST_LEDGER, p)
        return send_file(p, as_attachment=True, download_name=p.name)
    return jsonify({"error":"Unsupported report format"}), 400

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
