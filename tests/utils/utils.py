from __future__ import annotations

from hashlib import sha512
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen


def Propen(command):
    if isinstance(command, str):
        command = command.split()
    # split the command string in a list
    p = Popen(command, stdout=PIPE, stderr=STDOUT, text=True)
    return p.communicate()[0], p.returncode


def cmp_files(file1: str, file2: str):
    with open(file1, "rb") as f:
        keyb_digest = sha512(f.read()).digest()
    with open(file2, "rb") as f:
        orig_check = sha512(f.read()).digest()
    return keyb_digest == orig_check


def rm_if_found(file: str):
    path = Path(file)
    if path.is_file():
        path.unlink(missing_ok=True)


def requires_ocr():
    """
    Skips the calling test unless a key can actually be read off a screenshot.

    That needs both halves of the optional [ocr] extra -- the Python packages and the
    tesseract binary they shell out to -- and either can be missing on a perfectly good
    machine, so this skips rather than fails.
    """
    import pytest

    pytest.importorskip("pytesseract", reason="needs the [ocr] extra")
    pytest.importorskip("PIL", reason="needs the [ocr] extra")
    import pytesseract

    try:
        pytesseract.get_tesseract_version()
    except Exception:  # noqa: BLE001 -- a skip guard; anything that goes wrong here means
        # tesseract cannot be used, and what exactly went wrong is not this test's business.
        pytest.skip("the tesseract binary is not installed or not on PATH")
