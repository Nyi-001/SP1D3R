import logging

from utils.logger import TerminalFormatter


def test_terminal_formatter_adds_color_for_errors() -> None:
    formatter = TerminalFormatter("[%(levelname)s] %(message)s", "%H:%M:%S", use_color=True)
    rendered = formatter.format(logging.LogRecord("test", logging.ERROR, "", 0, "failed", (), None))
    assert "failed" in rendered
    assert "\x1b[" in rendered


def test_terminal_formatter_can_remain_plain_for_non_terminal_output() -> None:
    formatter = TerminalFormatter("[%(levelname)s] %(message)s", "%H:%M:%S", use_color=False)
    rendered = formatter.format(logging.LogRecord("test", logging.INFO, "", 0, "scan", (), None))
    assert rendered == "[INFO] scan"
