"""
PyInstaller's entry script.

The console scripts pip generates do not exist in a frozen binary, so the spec needs a real
file to point at; this is it. It does nothing but call the same main() that `wagui` does.

Imported from gui.app rather than through the gui package's own re-export of it, which is lazy
(PEP 562) so that importing gui.core does not pull tkinter in. A lazy re-export is invisible to
PyInstaller's analyser, so going through it would leave app.py out of the bundle -- the same
failure the spec collects the protobuf modules by hand to avoid.
"""

import sys

from wa_crypt_tools.gui.app import main

if __name__ == "__main__":
    sys.exit(main())
