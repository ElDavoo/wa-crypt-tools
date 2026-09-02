from __future__ import annotations

import logging
from typing import ClassVar


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    # Not called `format`: that is `logging.Formatter.format`, the method overridden below, and
    # a class attribute of that name is both a shadowed method and a redefinition in the same
    # body -- which is what mypy was complaining about twice over.
    LINE = "%(filename)s:%(lineno)d \t: [%(levelname).1s] %(message)s"

    FORMATS: ClassVar[dict[int, str]] = {
        logging.DEBUG: grey + LINE + reset,
        logging.INFO: grey + LINE + reset,
        logging.WARNING: yellow + LINE + reset,
        logging.ERROR: red + LINE + reset,
        logging.CRITICAL: bold_red + LINE + reset,
    }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging(*loggers: logging.Logger, verbose: bool = False) -> logging.Handler:
    """
    Installs the coloured formatter on the given loggers and on the library's own.

    The tools all need this: library-level log.error(...) is what the user actually reads,
    so the "wa_crypt_tools.lib" logger has to carry a handler too, not just the script's.
    """
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(CustomFormatter())
    for logger in (*loggers, logging.getLogger("wa_crypt_tools.lib")):
        logger.addHandler(handler)
        logger.setLevel(level)
    return handler
