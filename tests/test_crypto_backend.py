"""
The AES import party at the top of wadecrypt and waguess.

Both tools open with the same twenty lines: try pycryptodomex, fall back to pycryptodome,
and tell the user what to install if what they have is the ancient pycrypto or nothing at
all. It is the first thing anyone sees when their environment is wrong, and it could not be
reached from a suite that only ever runs in an environment where it is right -- so every
branch of it was uncovered, and the two copies were free to drift apart. One of those
branches turned out to be unreachable in both: the "you installed pycrypto" message was
raised inside a `try` whose own `except ModuleNotFoundError` swallowed it and reported the
other message instead. That is what these tests found, and why the check now sits outside.

The module is executed again from its own file under a patched importer rather than reloaded
in place: `sys.modules` keeps the real one, so nothing another test imported changes, and a
failed import here cannot leave a half-initialised module behind.
"""

from __future__ import annotations

import builtins
import importlib.util
import sys
import types
from pathlib import Path

import pytest

import wa_crypt_tools

#: The two tools that carry a copy of it. They have to say the same thing.
TOOLS = ["wadecrypt", "waguess"]


def reimport(name: str):
    """Runs wa_crypt_tools/<name>.py again as a module of its own."""
    path = Path(wa_crypt_tools.__file__).parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"reimported_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hide(monkeypatch, *hidden: str) -> None:
    """Makes the named top-level packages look like they are not installed."""
    real_import = builtins.__import__

    def refusing(name, *args, **kwargs):
        if name.split(".")[0] in hidden:
            raise ModuleNotFoundError(f"No module named {name.split('.')[0]!r}", name=name.split(".")[0])
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refusing)


def install_fake_pycrypto(monkeypatch, *, gcm: bool) -> types.ModuleType:
    """Puts a stand-in `Crypto.Cipher.AES` where the fallback will find it."""
    aes = types.ModuleType("Crypto.Cipher.AES")
    if gcm:
        aes.MODE_GCM = 11
    cipher = types.ModuleType("Crypto.Cipher")
    cipher.AES = aes
    package = types.ModuleType("Crypto")
    package.Cipher = cipher
    for full_name, module in [("Crypto", package), ("Crypto.Cipher", cipher), ("Crypto.Cipher.AES", aes)]:
        monkeypatch.setitem(sys.modules, full_name, module)
    return aes


@pytest.mark.parametrize("tool", TOOLS)
class TestTheAesImportParty:
    def test_pycryptodomex_is_what_is_normally_used(self, tool):
        from Cryptodome.Cipher import AES

        assert reimport(tool).AES is AES

    def test_pycryptodome_is_accepted_instead(self, tool, monkeypatch):
        # The same implementation under its other distribution name. Nothing else changes.
        fake = install_fake_pycrypto(monkeypatch, gcm=True)
        hide(monkeypatch, "Cryptodome")
        assert reimport(tool).AES is fake

    def test_pycrypto_is_named_and_refused(self, tool, monkeypatch):
        # The trap this exists for: `import Crypto` succeeds, so without the MODE_GCM check
        # the tool would get all the way to decrypting before failing on a missing attribute.
        install_fake_pycrypto(monkeypatch, gcm=False)
        hide(monkeypatch, "Cryptodome")
        with pytest.raises(ModuleNotFoundError, match="You installed pycrypto and not pycryptodome"):
            reimport(tool)

    def test_nothing_at_all_says_what_to_install(self, tool, monkeypatch):
        hide(monkeypatch, "Cryptodome", "Crypto")
        with pytest.raises(ModuleNotFoundError, match="You need pycryptodome"):
            reimport(tool)
