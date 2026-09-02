"""
The logging set-up every console script installs.

Library modules only ever call log.error(...); whether the user sees anything at all is
decided here.
"""

from __future__ import annotations

import logging

from wa_crypt_tools.lib.logformat import CustomFormatter, setup_logging


def record(level: int) -> logging.LogRecord:
    return logging.LogRecord("wa_crypt_tools.lib.test", level, "utils.py", 42, "boom", None, None)


class TestCustomFormatter:
    def test_each_level_gets_its_own_colour(self):
        formatter = CustomFormatter()
        coloured = {
            formatter.format(record(level)) for level in (logging.DEBUG, logging.WARNING, logging.ERROR, logging.CRITICAL)
        }
        # DEBUG and INFO share grey, so four distinct levels give four distinct strings only
        # because the colours differ; the message is identical in all of them.
        assert len(coloured) == 4
        assert all("boom" in line for line in coloured)

    def test_the_format_carries_the_file_the_line_and_the_level(self):
        line = CustomFormatter().format(record(logging.ERROR))
        assert "utils.py:42" in line
        assert "[E]" in line


class TestSetupLogging:
    def teardown_method(self):
        # setup_logging adds a handler to a module-level logger, which outlives the test.
        library = logging.getLogger("wa_crypt_tools.lib")
        for handler in list(library.handlers):
            library.removeHandler(handler)
        library.setLevel(logging.NOTSET)

    def test_the_library_logger_gets_a_handler_even_when_only_the_script_is_named(self):
        script = logging.getLogger("test_logformat.script")
        try:
            handler = setup_logging(script)
            assert handler in script.handlers
            assert handler in logging.getLogger("wa_crypt_tools.lib").handlers
            assert isinstance(handler.formatter, CustomFormatter)
        finally:
            script.removeHandler(handler)
            script.setLevel(logging.NOTSET)

    def test_verbose_switches_to_debug(self):
        assert setup_logging(verbose=False).level == logging.INFO
        assert logging.getLogger("wa_crypt_tools.lib").level == logging.INFO
        assert setup_logging(verbose=True).level == logging.DEBUG
        assert logging.getLogger("wa_crypt_tools.lib").level == logging.DEBUG
