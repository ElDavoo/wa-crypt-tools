from __future__ import annotations

import io
import logging
import re
import sys
from types import SimpleNamespace

import wa_crypt_tools.wadecrypt as wadecrypt


class TTYStream(io.StringIO):
    def isatty(self):
        return True


class NonSeekable:
    def tell(self):
        raise io.UnsupportedOperation("not seekable")

    def seek(self, *args):
        raise io.UnsupportedOperation("not seekable")


def test_progress_is_disabled_for_redirected_stderr(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(wadecrypt, "sys", SimpleNamespace(stderr=stream))

    progress = wadecrypt.ProgressBar(io.BytesIO(b"ciphertext"))
    progress.close()

    assert not progress.visible
    assert stream.getvalue() == ""


def test_progress_is_disabled_for_non_seekable_input(monkeypatch):
    stream = TTYStream()
    monkeypatch.setattr(wadecrypt, "sys", SimpleNamespace(stderr=stream))

    progress = wadecrypt.ProgressBar(NonSeekable())
    progress.close()

    assert not progress.visible
    assert stream.getvalue() == ""


def test_progress_is_disabled_when_tqdm_is_not_installed(monkeypatch):
    stream = TTYStream()
    monkeypatch.setattr(wadecrypt, "sys", SimpleNamespace(stderr=stream))
    monkeypatch.setitem(sys.modules, "tqdm", None)

    progress = wadecrypt.ProgressBar(io.BytesIO(b"ciphertext"))
    progress.close()

    assert not progress.visible
    assert stream.getvalue() == ""


def test_log_messages_do_not_overwrite_the_progress_line(monkeypatch):
    stream = TTYStream()
    monkeypatch.setattr(wadecrypt, "sys", SimpleNamespace(stderr=stream))
    loggers = [wadecrypt.log, logging.getLogger("wa_crypt_tools.lib")]
    old_state = [(logger, list(logger.handlers), logger.level, logger.propagate) for logger in loggers]
    for logger in loggers:
        logger.handlers.clear()
        logger.addHandler(logging.StreamHandler(stream))
        logger.setLevel(logging.ERROR)
        logger.propagate = False

    encrypted = io.BytesIO(b"ciphertext")
    progress = wadecrypt.ProgressBar(encrypted)
    try:
        encrypted.seek(3)
        progress.update(encrypted)
        wadecrypt.log.error("Backup is corrupted.")
        encrypted.seek(10)
        progress.update(encrypted, finished=True)
    finally:
        progress.close()
        for logger, handlers, level, propagate in old_state:
            logger.handlers.clear()
            logger.handlers.extend(handlers)
            logger.setLevel(level)
            logger.propagate = propagate

    output = stream.getvalue()
    assert "Backup is corrupted." in output
    assert not re.search(r"%Backup is corrupted\.", output)
    assert output.endswith("\n")
