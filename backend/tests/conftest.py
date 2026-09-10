"""
Ensures `backend/` (the directory containing the `app` package) is on
sys.path regardless of how pytest is invoked or what the current working
directory is, so `from app...` imports in test modules always resolve.
"""

import sys
from pathlib import Path

_BACKEND_ROOT = str(Path(__file__).resolve().parent.parent)
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)
