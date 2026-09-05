import logging
import sys
from pathlib import Path

from colorama import init, Fore, Style

init(autoreset=True)


class TerminalFormatter(logging.Formatter):
    """Readable level-aware formatter for interactive terminal output."""

    def __init__(self, fmt: str, datefmt: str, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        if not self.use_color:
            return rendered

        message = record.getMessage().lstrip()
        if message.startswith('[FINDING]'):
            if 'CRITICAL' in message or 'HIGH' in message:
                color = Fore.RED + Style.BRIGHT
            elif 'MEDIUM' in message:
                color = Fore.YELLOW + Style.BRIGHT
            elif 'LOW' in message:
                color = Fore.GREEN
            else:
                color = Fore.WHITE
        elif record.levelno >= logging.ERROR:
            color = Fore.RED + Style.BRIGHT
        elif record.levelno >= logging.WARNING:
            color = Fore.YELLOW + Style.BRIGHT
        elif record.levelno <= logging.DEBUG:
            color = Fore.MAGENTA
        elif message.startswith('[+]') or 'found' in message.lower() or 'detected' in message.lower():
            color = Fore.GREEN
        elif message.startswith('[*]') or message.startswith('Starting') or 'scanning' in message.lower():
            color = Fore.CYAN
        else:
            color = Fore.WHITE
        return f"{color}{rendered}{Style.RESET_ALL}"

SP1D3R_WORDMARK = r"""
██████╗  ██████╗  ██╗  ██████╗  ██████╗  ██████╗
██╔════╝ ██╔══██╗ ██║ ██╔══██╗ ╚════██╗ ██╔══██╗
██║      ██║  ██║ ██║ ██║  ██║  █████╔╝ ██║  ██║
╚█████╗  ██████╔╝ ██║ ██║  ██║  ╚═══██╗ ██████╔╝
 ╚═══██╗ ██╔═══╝  ██║ ██║  ██║      ██║ ██╔══██╗
██████╔╝ ██║      ██║ ██████╔╝ ██████╔╝ ██║  ██║
╚═════╝  ╚═╝      ╚═╝ ╚═════╝  ╚═════╝  ╚═╝  ╚═╝
"""

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("sp1d3r")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)

    format_string = "[%(asctime)s] [%(levelname)s] %(message)s"
    plain_formatter = logging.Formatter(format_string, "%H:%M:%S")
    ch.setFormatter(TerminalFormatter(format_string, "%H:%M:%S", use_color=sys.stdout.isatty()))

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    fh = logging.FileHandler(log_dir / "pentest.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(plain_formatter)

    logger.addHandler(ch)
    logger.addHandler(fh)
    logger.propagate = False

    return logger


def log_banner():
    print(f"{Fore.RED}{Style.BRIGHT}{SP1D3R_WORDMARK}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT} SPID3R — Web Security Testing Assistant{Style.RESET_ALL}")
    print(f"{Fore.YELLOW} Authorized testing only{Style.RESET_ALL}\n")
