"""The graphical front end: one window for decrypting a backup."""

# `main` is re-exported lazily rather than imported here. gui/app.py imports tkinter at module
# level, so an eager import would drag the display half of this package into every import of
# the display-free half -- which is exactly what core.py was split out to avoid, and what made
# tests/gui/test_core.py fail to collect on a Python built without _tkinter rather than run as
# it is meant to. The entry point in pyproject.toml is `wa_crypt_tools.gui:main`, so the name
# still has to be reachable from the package; PEP 562 lets it be reachable without being eager.

from __future__ import annotations


def __getattr__(name: str):
    if name == "main":
        from wa_crypt_tools.gui.app import main

        return main
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["main"]
