# utils/config.py
import yaml
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG = {
    "scanning": {
        "threads": 50,
        "timeout": 30,
        "rate_limit": None,
        "user_agent": "AutomatedPentestTool/1.0",
        "stealth_mode": False,
    }
}

def load_config(path: str) -> Dict[str, Any]:
    cfg_path = Path(path)
    if not cfg_path.exists():
        # fall back to defaults if no config file
        return DEFAULT_CONFIG.copy()

    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # merge with defaults
    cfg = DEFAULT_CONFIG.copy()
    cfg.update(data)
    if "scanning" in data:
        cfg["scanning"].update(data["scanning"])
    return cfg
