import logging
import sys
from pathlib import Path

from colorama import init, Fore, Style

init(autoreset=True)

BANNER = r"""
   _   _           _            _           _              _             
  /_\ | |_ ___ ___| |_ ___  ___| |_ ___ ___| |_ _ _  __ _| |__  ___ _ _ 
 / _ \|  _/ -_) -_)  _/ _ \/ _ \  _/ -_)___|  _| ' \/ _` | '_ \/ -_) '_|
/_/ \_\\__\___\___|\__\___/\___/\__\___|    \__|_||_\__,_|_.__/\___|_|  
"""

def log_banner():
    print(BANNER)
    print(" Automated Penetration Testing Tool")
    print(" Author: Pangerkumzuk Longkumer | NEXUSCIPHERGUARD INDIA\n")

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("automated-pentest-tool")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
    ch.setFormatter(fmt)

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    fh = logging.FileHandler(log_dir / "pentest.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger


def log_banner():
    banner = (
        f"{Fore.CYAN}{Style.BRIGHT}"
        "=== Automated Penetration Testing Tool ==="
        f"{Style.RESET_ALL}"
    )
    print(banner)
