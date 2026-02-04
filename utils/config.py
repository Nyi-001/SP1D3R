from pathlib import Path
from typing import Dict, Any

import yaml


def load_config(path: str) -> Dict[str, Any]:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with cfg_path.open() as f:
        config = yaml.safe_load(f) or {}

    # minimal defaults
    config.setdefault("scanning", {})
    config["scanning"].setdefault("threads", 50)
    config["scanning"].setdefault("timeout", 30)

    return config
