"""Local-only configuration for the synthetic fixture."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    runtime_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        default = Path(__file__).resolve().parents[2] / "techlab-runtime"
        return cls(runtime_dir=Path(os.environ.get("TECHLAB_RUNTIME_DIR", default)).resolve())

