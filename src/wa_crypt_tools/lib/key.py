from __future__ import annotations

import abc
import hmac
from hashlib import sha256
from pathlib import Path

# noinspection PyPackageRequirements
# This is from javaobj-py3
import javaobj.v2 as javaobj

from wa_crypt_tools.lib.log import SimpleLog
from wa_crypt_tools.lib.utils import javaintlist2bytes


class Key(abc.ABC):
    @abc.abstractmethod
    def __init__(self, logger: SimpleLog, keyarray: bytes):
        pass

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def get(self) -> bytes:
        pass

    @staticmethod
    def from_file(logger: SimpleLog, file: Path):
        keyfile: bytes = b''

        logger.v("Reading keyfile...")

        # Try to open the keyfile.
        try:
            key_file_stream = open(file, 'rb')
            try:
                # Deserialize the byte object written in the file
                jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
                # Convert from a list of Int8 to a byte array
                keyfile: bytes = javaintlist2bytes(jarr)

            except (ValueError, RuntimeError) as e:
                logger.f("The keyfile is not a valid Java object: {}".format(e))

        except OSError:
            logger.f("The keyfile could not be opened.")

        # We guess the key type from its length
        if len(keyfile) == 131:
            return Key14(logger, keyarray=keyfile)
        elif len(keyfile) == 32:
            return Key15(logger, keyarray=keyfile)
        else:
            logger.f("Unrecognized key file format.")


class Key14(Key):
    # These constants are only used with crypt12/14 keys.
    __SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    __SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']

    def __init__(self, logger: SimpleLog, keyarray: bytes):
        """Extracts the fields from a crypt14 loaded key file."""
        # key file format and encoding explanation:
        # The key file is actually a serialized byte[] object.

        # After deserialization, we will have a byte[] object that we have to split in:
        # 1) The cipher version (2 bytes). Known values are 0x0000 and 0x0001. So far we only support the latter.
        # SUPPORTED_CIPHER_VERSION = b'\x00\x01'
        # 2) The key version (1 byte). All the known versions are supported.
        # SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']
        # Looks like nothing actually changes between the versions.
        # 3) Server salt (32 bytes)
        # 4) googleIdSalt (unused?) (16 bytes)
        # 5) hashedGoogleID (The SHA-256 hash of googleIdSalt) (32 bytes)
        # 6) encryption IV (zeroed out, as it is read from the database) (16 bytes)
        # 7) cipherKey (The actual AES-256 decryption key) (32 bytes)

        # Check if the keyfile has a supported cipher version
        self.__cipher_version = keyarray[:len(self.__SUPPORTED_CIPHER_VERSION)]
        if self.__SUPPORTED_CIPHER_VERSION != self.__cipher_version:
            logger.e("Invalid keyfile: Unsupported cipher version {}"
                     .format(keyarray[:len(self.__SUPPORTED_CIPHER_VERSION)].hex()))
        index = len(self.__SUPPORTED_CIPHER_VERSION)

        # Check if the keyfile has a supported key version
        version_supported = False
        for v in self.__SUPPORTED_KEY_VERSIONS:
            if v == keyarray[index:index + len(self.__SUPPORTED_KEY_VERSIONS[0])]:
                version_supported = True
                self.key_version = v
                break
        if not version_supported:
            logger.e('Invalid keyfile: Unsupported key version {}'
                     .format(keyarray[index:index + len(self.__SUPPORTED_KEY_VERSIONS[0])].hex()))

        self.__serversalt = keyarray[3:35]

        # Check the SHA-256 of the salt
        self.__googleid = keyarray[35:51]
        expected_digest = sha256(self.__googleid).digest()
        actual_digest = keyarray[51:83]
        if expected_digest != actual_digest:
            logger.e("Invalid keyfile: Invalid SHA-256 of salt.\n    "
                     "Expected: {}\n    Got:{}".format(expected_digest, actual_digest))

        __padding = keyarray[83:99]

        # Check if IV is made of zeroes
        for byte in __padding:
            if byte:
                logger.e("Invalid keyfile: IV is not zeroed out but is: {}".format(__padding.hex()))
                break

        self.__key = keyarray[99:]

        logger.i("Crypt12/14 key loaded")

    def get(self) -> bytes:
        return self.__key

    def get_serversalt(self) -> bytes:
        return self.__serversalt

    def get_googleid(self) -> bytes:
        return self.__googleid

    def get_cipher_version(self) -> bytes:
        return self.__cipher_version

    def get_key_version(self) -> bytes:
        return self.key_version


    def __str__(self) -> str:
        """Returns a string representation of the key"""
        try:
            string: str = "Key14("
            if self.__key is not None:
                string += "key: {}".format(self.__key.hex())
            if self.__serversalt is not None:
                string += " , serversalt: {}".format(self.__serversalt.hex())
            if self.__googleid is not None:
                string += " , googleid: {}".format(self.__googleid.hex())
            if self.key_version is not None:
                string += " , key_version: {}".format(self.key_version.hex())
            if self.__cipher_version is not None:
                string += " , cipher_version: {}".format(self.__cipher_version.hex())
            return string + ")"
        except Exception as e:
            return "Exception printing key: {}".format(e)

    def __repr__(self) -> str:
        # TODO
        return self.__str__()


class Key15(Key):
    # This constant is only used with crypt15 keys.
    @property
    def __key(self):
        return self.___key

    BACKUP_ENCRYPTION = b'backup encryption\x01'

    def __init__(self, logger: SimpleLog, keyarray: bytes):
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

        if len(keyarray) != 32:
            logger.f("Crypt15 loader trying to load a crypt14 key")
        # First do the HMACSHA256 hash of the file with an empty private key
        self.__key: bytes = hmac.new(b'\x00' * 32, keyarray, sha256).digest()
        # Then do the HMACSHA256 using the previous result as key and ("backup encryption" + iteration count) as data
        self.__key = hmac.new(self.__key, self.BACKUP_ENCRYPTION, sha256).digest()

        logger.i("Crypt15 / Raw key loaded")

    def get(self) -> bytes:
        return self.__key

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

    @__key.setter
    def __key(self, value):
        self.___key = value