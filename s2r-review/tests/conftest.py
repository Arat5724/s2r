import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'worker'))
# Set before importing the server: tests never read or modify real analysis history.
_data = tempfile.TemporaryDirectory(prefix='s2r-review-tests-')
os.environ['S2R_REVIEW_DATA'] = _data.name
