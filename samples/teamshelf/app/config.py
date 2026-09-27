import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    profile: str = "baseline"
    enable_reports: bool = False
    revision: str = "teamshelf-1.0.0"

    def __post_init__(self):
        if self.profile not in {"baseline", "hardened"}:
            raise ValueError("TEAMSHELF_PROFILE must be baseline or hardened")

    @classmethod
    def from_env(cls):
        default_dir = Path(__file__).resolve().parents[2] / "teamshelf-runtime"
        return cls(
            data_dir=Path(os.getenv("TEAMSHELF_DATA_DIR", str(default_dir))).resolve(),
            profile=os.getenv("TEAMSHELF_PROFILE", "baseline"),
            enable_reports=os.getenv("TEAMSHELF_ENABLE_REPORTS", "0") == "1",
        )
