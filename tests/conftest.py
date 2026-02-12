from __future__ import annotations

import sys
from pathlib import Path

# Ensure test imports can resolve the top-level superscp.py module
# across pytest import modes and virtualenv launchers.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
