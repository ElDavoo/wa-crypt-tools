from __future__ import annotations

import logging
from pathlib import Path

import javaobj.v2 as javaobj

from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.ocr import key_from_image, looks_like_image
from wa_crypt_tools.lib.utils import hexstring2bytes, javaintlist2bytes

log = logging.getLogger(__name__)


class KeyFactory:
    @staticmethod
    def new(file: Path) -> Key14 | Key15:
        """Tries to load the key from a file, a screenshot of it, or a hex string."""
        if looks_like_image(file):
            # Sniffed before anything else so a PNG never reaches javaobj, which would
            # report it as a malformed key file rather than as the screenshot it is.
            return KeyFactory.from_image(file)
        try:
            return KeyFactory.from_file(file)
        except OSError:
            # Only a genuine open() failure gets here: the argument is not a file we can
            # read, so try it as a raw hex key instead. InvalidKeyError is not an OSError
            # precisely so that an unreadable *keyfile* is not retried as a hex string.
            return KeyFactory.from_hex(str(file))

    @staticmethod
    def from_file(file: Path) -> Key14 | Key15:
        log.debug("Reading keyfile...")

        # Try to open the keyfile.
        # The stream must be closed explicitly: javaobj keeps references to it,
        # and a lingering open handle prevents deleting the file on Windows.
        with Path(file).open("rb") as key_file_stream:
            try:
                # Deserialize the byte object written in the file
                jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
                # Convert from a list of Int8 to a byte array
                keyfile: bytes = javaintlist2bytes(jarr)

            except (ValueError, RuntimeError) as e:
                raise InvalidKeyError(f"The keyfile is not a valid Java object: {e}") from e

        # We guess the key type from its length
        if len(keyfile) == 131:
            return Key14(keyarray=keyfile)
        if len(keyfile) == 32:
            return Key15(keyarray=keyfile)
        raise InvalidKeyError(
            f"Unrecognized key file format: the key is {len(keyfile)} bytes long, expected 131 (crypt14) or 32 (crypt15)."
        )

    @staticmethod
    def from_hex(hexstring: str) -> Key15:
        if hexstring is None or len(hexstring) != 64:
            raise InvalidKeyError(
                "The key file specified does not exist, and it is not a valid key either.\n    "
                "If you tried to specify the key directly, note it should be "
                f"64 characters long and not {0 if hexstring is None else len(hexstring)} characters long."
            )
        barr: bytes = hexstring2bytes(hexstring)
        if len(barr) != 32:
            raise InvalidKeyError("The key is invalid or of the wrong length.")
        return Key15(keyarray=barr)

    @staticmethod
    def from_image(file: Path) -> Key15:
        """Reads the 64-digit key off a screenshot of WhatsApp's encryption key screen.

        Always a Key15: that screen only exists for crypt15 backups, and WhatsApp never
        displays a crypt14 key at all. Routing through from_hex re-checks the length and
        the alphabet, which costs nothing and makes the OCR answer prove itself.
        """
        return KeyFactory.from_hex(key_from_image(file))
