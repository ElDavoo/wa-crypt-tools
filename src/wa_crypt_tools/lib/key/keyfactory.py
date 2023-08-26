from pathlib import Path

import javaobj.v2 as javaobj

from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.key15 import Key15

import logging

from wa_crypt_tools.lib.utils import javaintlist2bytes, hexstring2bytes

l = logging.getLogger(__name__)
class KeyFactory:
    @staticmethod
    def new(file: Path):
        """Tries to load the key from a file, or if it fails, from a hex string."""
        try:
            return KeyFactory.from_file(file)
        except OSError:
            try:
                return KeyFactory.from_hex(str(file))
            except ValueError:
                l.critical("The key file specified does not exist.\n    "
                           "If you tried to specify the key directly, note it should be "
                           "64 characters long and not {} characters long.".format(len(str(file))))

    @staticmethod
    def from_file(file: Path):
        keyfile: bytes = b''

        l.debug("Reading keyfile...")

        # Try to open the keyfile.
        try:
            key_file_stream = open(file, 'rb')
            try:
                # Deserialize the byte object written in the file
                jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
                # Convert from a list of Int8 to a byte array
                keyfile: bytes = javaintlist2bytes(jarr)

            except (ValueError, RuntimeError) as e:
                l.critical("The keyfile is not a valid Java object: {}".format(e))

        except OSError:
            l.info("The keyfile could not be opened.")
            raise OSError

        # We guess the key type from its length
        if len(keyfile) == 131:
            return Key14(keyarray=keyfile)
        elif len(keyfile) == 32:
            return Key15(keyarray=keyfile)
        else:
            l.critical("Unrecognized key file format.")

    @staticmethod
    def from_hex(hexstring: str) -> Key15:
        if hexstring is None or len(hexstring) != 64:
            raise ValueError("The key is invalid or of the wrong length.")
        barr: bytes = hexstring2bytes(hexstring)
        if barr is None or len(barr) != 32:
            raise ValueError("The key is invalid or of the wrong length.")
        return Key15(keyarray=barr)