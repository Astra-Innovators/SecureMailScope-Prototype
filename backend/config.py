from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_MB = 50
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
