from pathlib import Path
import tempfile

BASE_DIR = Path(__file__).resolve().parent.parent
# Vercel/serverless filesystems are ephemeral; /tmp is the writable location.
REPORT_DIR = Path(tempfile.gettempdir()) / "securescope_reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_MB = 50
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
