from __future__ import annotations

import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

# The repository deliberately uses a src layout and requires no installation.
# Keep the documented bare unittest command runnable without changing global
# interpreter state or downloading a build dependency.
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@contextmanager
def project_temp_dir() -> Iterator[Path]:
    """Create test scratch space inside the repository boundary."""

    with tempfile.TemporaryDirectory(prefix=".tc-guard-test-", dir=ROOT) as directory:
        yield Path(directory)
