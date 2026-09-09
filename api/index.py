import sys
from pathlib import Path

# Make the existing backend package importable without changing its internal imports.
BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import app
