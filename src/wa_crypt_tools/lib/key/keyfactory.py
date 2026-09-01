import logging
from pathlib import Path

import javaobj.v2 as javaobj

from wa_crypt_tools.lib.errors import InvalidKeyError
from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.utils import hexstring2bytes, javaintlist2bytes

log = logging.getLogger(__name__)
class KeyFactory:
    @staticmethod
    def new(file: Path):
        """Tries to load the key from a file, or if it fails, from a hex string."""
        try:
            return KeyFactory.from_file(file)
        except OSError:
            # Only a genuine open() failure gets here: the argument is not a file we can
            # read, so try it as a raw hex key instead. InvalidKeyError is not an OSError
            # precisely so that an unreadable *keyfile* is not retried as a hex string.
            return KeyFactory.from_hex(str(file))

    @staticmethod
    def from_file(file: Path):
        log.debug("Reading keyfile...")

        # Try to open the keyfile.
        # The stream must be closed explicitly: javaobj keeps references to it,
        # and a lingering open handle prevents deleting the file on Windows.
        with open(file, 'rb') as key_file_stream:
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
        raise InvalidKeyError(f"Unrecognized key file format: the key is {len(keyfile)} bytes long, "
                              "expected 131 (crypt14) or 32 (crypt15).")

    @staticmethod
    def from_hex(hexstring: str) -> Key15:
        if hexstring is None or len(hexstring) != 64:
            raise InvalidKeyError("The key file specified does not exist, and it is not a valid key either.\n    "
                                  "If you tried to specify the key directly, note it should be "
                                  f"64 characters long and not {0 if hexstring is None else len(hexstring)} characters long."
                                  )
        barr: bytes = hexstring2bytes(hexstring)
        if len(barr) != 32:
            raise InvalidKeyError("The key is invalid or of the wrong length.")
        return Key15(keyarray=barr)
