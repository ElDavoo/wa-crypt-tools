# PyInstaller spec for the wagui binaries attached to each GitHub Release.
#
# Committed rather than assembled from flags in the workflow so that a local
#     pyinstaller packaging/wagui.spec
# builds the same thing CI does. That matters: the failures this guards against -- a protobuf
# module the analyser did not see, missing package metadata -- appear only in the frozen
# binary and never in a test run.
#
# Written for PyInstaller 6.x, which dropped block_cipher, a.zipfiles and the win_* Analysis
# arguments that older specs still carry.

import os
import sys

from PyInstaller.utils.hooks import collect_submodules, copy_metadata

root = os.path.dirname(SPECPATH)  # noqa: F821 - injected by PyInstaller

# dbfactory.py imports the generated protobuf modules inside from_file(), and they import each
# other through the relative imports fix_imports.py rewrites. A missing _pb2 module is the kind
# of error that only surfaces when a user double-clicks the binary, so they are collected
# explicitly rather than left to inference.
hiddenimports = collect_submodules("wa_crypt_tools.proto")
# The gui package re-exports main() lazily so that gui.core can be imported without tkinter.
# wagui_entry.py imports gui.app directly for that reason; this is the belt to that brace, and
# it keeps the binary working if anything ever reaches main() through the package again.
hiddenimports.append("wa_crypt_tools.gui.app")

a = Analysis(  # noqa: F821
    [os.path.join(root, "packaging", "wagui_entry.py")],
    pathex=[os.path.join(root, "src")],
    binaries=[],
    # --version reads the version through importlib.metadata, so the dist-info has to travel
    # with the binary -- that flag is how CI proves the build imports cleanly.
    datas=copy_metadata("wa-crypt-tools"),
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Nothing here draws a chart or serves a page. Excluding the usual passengers keeps the
    # download to something a non-technical user will actually wait for.
    excludes=["numpy", "matplotlib", "PIL", "pytest", "setuptools", "pip", "unittest"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

# Two shapes, because macOS cannot have both. Everywhere else a single file is the whole point
# -- one thing to download, one thing to double-click, nothing to install. A .app bundle is a
# directory by definition, so onefile and BUNDLE contradict each other (PyInstaller deprecated
# the combination and makes it an error in v7), and macOS security rejects a windowed onefile
# anyway. So macOS gets onedir inside a .app, which is what Finder wants there regardless, and
# the release workflow zips it.
onefile = sys.platform != "darwin"

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    *([a.binaries, a.datas] if onefile else []),
    [],
    exclude_binaries=not onefile,
    name="wagui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    # No console window: this is a double-click program, and a terminal flashing up behind it
    # is exactly what the GUI exists to spare people.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

if not onefile:
    collected = COLLECT(  # noqa: F821
        exe, a.binaries, a.datas, strip=False, upx=False, upx_exclude=[], name="wagui",
    )
    # Unsigned, so Gatekeeper needs a right-click -> Open the first time. The README says so.
    app = BUNDLE(  # noqa: F821
        collected,
        name="wagui.app",
        icon=None,
        bundle_identifier="it.davidepalma.wacrypttools.wagui",
    )
