"""
PyInstaller's entry script.

The console scripts pip generates do not exist in a frozen binary, so the spec needs a real
file to point at; this is it. It does nothing but call the same main() that `wagui` does.
"""

import sys

from wa_crypt_tools.gui import main

if __name__ == "__main__":
    sys.exit(main())
