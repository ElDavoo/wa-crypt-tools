import hmac
from hashlib import sha256
from os import urandom
from pathlib import Path

from javaobj import JavaObjectMarshaller

from wa_crypt_tools.lib.utils import create_jba, encryptionloop

from wa_crypt_tools.lib.key.key import Key
import logging

l = logging.getLogger(__name__)


class Key15(Key):
    # This constant is only used with crypt15 keys.
    BACKUP_ENCRYPTION = b'backup encryption'

    def __init__(self, keyarray: bytes = None, key: bytes = None):
        """Extracts the key from a loaded crypt15 key file."""
        # encrypted_backup.key file format and encoding explanation:
        # The E2E key file is actually a serialized byte[] object.

        # After deserialization, we will have the root key (32 bytes).
        # The root key is further encoded with three different strings, depending on what you want to do.
        # These three ways are "backup encryption";
        # "metadata encryption" and "metadata authentication", for Google Drive E2E encrypted metadata.
        # We are only interested in the local backup encryption.

        # Why the \x01 at the end of the BACKUP_ENCRYPTION constant?
        # Whatsapp uses a nested encryption function to encrypt many times the same data.
        # The iteration counter is appended to the end of the encrypted data. However,
        # since the loop is actually executed only one time, we will only have one interaction,
        # and thus a \x01 at the end.
        # Take a look at utils/wa_hmacsha256_loop.java that is the original code.

        if keyarray is None:
            # Randomly generated key or with supplied parameters
            if key is None:
                self.__key = urandom(32)
            else:
                if len(key) != 32:
                    l.error("Invalid key length: {}".format(key.hex()))
                self.__key = key
            return

        if not isinstance(keyarray, bytes):
            raise ValueError("keyarray is not a byte array!")

        if len(keyarray) != 32:
            raise ValueError("Invalid key length")
        l.debug("Root key: {}".format(keyarray.hex()))
        # Save the root key in the class
        self.__key = keyarray

        l.info("Crypt15 / Raw key loaded")

    def get(self) -> bytes:
        """
        Returns the key used for encryption, that is not the root key.
        """
        return encryptionloop(
            first_iteration_data=self.__key,
            message=b'backup encryption',
            output_bytes=32)

    def get_root(self) -> bytes:
        """
        Returns the root key.
        """
        return self.__key

    def get_metadata_encryption(self) -> bytes:
        """
        Returns the key used for metadata encryption
        """
        return encryptionloop(
            first_iteration_data=self.__key,
            message=b'metadata encryption',
            output_bytes=32)

    def get_metadata_authentication(self) -> bytes:
        """
        Returns the key used for metadata authentication
        """
        return encryptionloop(
            first_iteration_data=self.__key,
            message=b'metadata authentication',
            output_bytes=32)

    def dump(self) -> bytes:
        """Dumps the key"""
        return JavaObjectMarshaller().dump(create_jba(self.__key))

    def file_dump(self, file: Path):
        with open(file, 'wb') as f:
            f.write(self.dump())

    def __str__(self) -> str:
        """Returns a string representation of the key"""
        try:
            string: str = "Key15("
            if self.__key is not None:
                string += "key: {}".format(self.__key.hex())
            return string + ")"
        except Exception as e:
            return "Exception printing key: {}".format(e)

    def __repr__(self) -> str:
        # TODO
        return self.__str__()
