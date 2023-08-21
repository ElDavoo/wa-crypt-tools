from __future__ import annotations

import abc
import hmac
from hashlib import sha256
from pathlib import Path
from os import urandom

from javaobj.v1.marshaller import JavaObjectMarshaller

import logging

from wa_crypt_tools.lib.utils import create_jba

l = logging.getLogger(__name__)
class Key(abc.ABC):
    @abc.abstractmethod
    def __init__(self, keyarray: bytes = None):
        pass

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def get(self) -> bytes:
        pass

    @abc.abstractmethod
    def dump(self) -> bytes:
        pass

# Thanks to python, these all have to go to the same file
class Key14(Key):
    # These constants are only used with crypt12/14 keys.
    __SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    __SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']

    def __init__(self, keyarray: bytes = None,
                 cipher_version: bytes = None, key_version: bytes = None,
                    serversalt: bytes = None, googleid: bytes = None, hashedgoogleid: bytes = None,
                 iv: bytes = None, key: bytes = None):
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

        if keyarray is None:
            # Randomly generated key or with supplied parameters
            if cipher_version is None:
                self.__cipher_version = self.__SUPPORTED_CIPHER_VERSION
            else:
                if cipher_version != self.__SUPPORTED_CIPHER_VERSION:
                    l.error("Invalid cipher version: {}".format(cipher_version.hex()))
            if key_version is None:
                self.__key_version = self.__SUPPORTED_KEY_VERSIONS[-1]
            else:
                if key_version not in self.__SUPPORTED_KEY_VERSIONS:
                    l.error("Invalid key version: {}".format(key_version.hex()))
                self.__key_version = key_version
            if serversalt is None:
                self.__serversalt = urandom(32)
            else:
                if len(serversalt) != 32:
                    l.error("Invalid server salt length: {}".format(serversalt.hex()))
                self.__serversalt = serversalt
            if googleid is None:
                self.__googleid = urandom(16)
            else:
                if len(googleid) != 16:
                    l.error("Invalid google id length: {}".format(googleid.hex()))
                self.__googleid = googleid
            if hashedgoogleid is None:
                self.__hashedgoogleid = sha256(self.__googleid).digest()
            else:
                l.warning("Using supplied hashed google id")
                if len(hashedgoogleid) != 32:
                    l.error("Invalid hashed google id length: {}".format(hashedgoogleid.hex()))
                self.__hashedgoogleid = hashedgoogleid
            if iv is None:
                self.__padding = b'\x00' * 16
            else:
                if len(iv) != 16:
                    l.error("Invalid IV length: {}".format(iv.hex()))
                if iv != b'\x00' * 16:
                    l.warning("IV should be empty")
                self.__padding = iv
            if key is None:
                self.__key = urandom(32)
            else:
                if len(key) != 32:
                    l.error("Invalid key length: {}".format(key.hex()))
                self.__key = key
            return
        # Check if the keyfile has a supported cipher version
        self.__cipher_version = keyarray[:len(self.__SUPPORTED_CIPHER_VERSION)]
        if self.__SUPPORTED_CIPHER_VERSION != self.__cipher_version:
            l.error("Invalid keyfile: Unsupported cipher version {}"
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
            l.error('Invalid keyfile: Unsupported key version {}'
                     .format(keyarray[index:index + len(self.__SUPPORTED_KEY_VERSIONS[0])].hex()))

        self.__serversalt = keyarray[3:35]

        # Check the SHA-256 of the salt
        self.__googleid = keyarray[35:51]
        expected_digest = sha256(self.__googleid).digest()
        actual_digest = keyarray[51:83]
        if expected_digest != actual_digest:
            l.error("Invalid keyfile: Invalid SHA-256 of salt.\n    "
                     "Expected: {}\n    Got:{}".format(expected_digest, actual_digest))

        self.__hashedgoogleid = actual_digest

        self.__padding = keyarray[83:99]

        # Check if IV is made of zeroes
        for byte in self.__padding:
            if byte:
                l.error("Invalid keyfile: IV is not zeroed out but is: {}".format(self.__padding.hex()))
                break

        self.__key = keyarray[99:]

        l.info("Crypt12/14 key loaded")

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
            if self.__key_version is not None:
                string += " , key_version: {}".format(self.__key_version.hex())
            if self.__cipher_version is not None:
                string += " , cipher_version: {}".format(self.__cipher_version.hex())
            return string + ")"
        except Exception as e:
            return "Exception printing key: {}".format(e)

    def __repr__(self) -> str:
        # TODO
        return self.__str__()

    def dump(self) -> bytes:
        """Dumps the key to a file"""
        out: bytes = b''
        out += self.__cipher_version
        out += self.__key_version
        out += self.__serversalt
        out += self.__googleid
        out += self.__hashedgoogleid
        out += self.__padding
        out += self.__key
        return JavaObjectMarshaller().dump(create_jba(out))

    def file_dump(self, file: Path):
        with open(file, 'wb') as f:
            f.write(self.dump())

class Key15(Key):
    # This constant is only used with crypt15 keys.
    BACKUP_ENCRYPTION = b'backup encryption\x01'

    def __init__(self, keyarray: bytes=None, key: bytes=None):
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

        if len(keyarray) != 32:
            l.critical("Crypt15 loader trying to load a crypt14 key")
        l.debug("Root key: {}".format(keyarray.hex()))
        # Save the root key in the class
        self.__key = keyarray

        l.info("Crypt15 / Raw key loaded")

    def get(self) -> bytes:
        """
        Returns the key used for encryption, that is not the root key.
        """
        # First do the HMACSHA256 hash of the file with an empty private key
        key: bytes = hmac.new(b'\x00' * 32, self.__key, sha256).digest()
        # Then do the HMACSHA256 using the previous result as key and ("backup encryption" + iteration count) as data
        key = hmac.new(key, self.BACKUP_ENCRYPTION, sha256).digest()
        return key

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
