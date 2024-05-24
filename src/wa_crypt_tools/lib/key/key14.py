from hashlib import sha256
from os import urandom
from pathlib import Path

from javaobj import JavaObjectMarshaller

from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.utils import create_jba

import logging

log = logging.getLogger(__name__)


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
                    log.error("Invalid cipher version: {}".format(cipher_version.hex()))
                self.__cipher_version = cipher_version
            if key_version is None:
                self.__key_version = self.__SUPPORTED_KEY_VERSIONS[-1]
            else:
                if key_version not in self.__SUPPORTED_KEY_VERSIONS:
                    log.error("Invalid key version: {}".format(key_version.hex()))
                self.__key_version = key_version
            if serversalt is None:
                self.__serversalt = urandom(32)
            else:
                if len(serversalt) != 32:
                    log.error("Invalid server salt length: {}".format(serversalt.hex()))
                self.__serversalt = serversalt
            if googleid is None:
                self.__googleid = urandom(16)
            else:
                if len(googleid) != 16:
                    log.error("Invalid google id length: {}".format(googleid.hex()))
                self.__googleid = googleid
            if hashedgoogleid is None:
                self.__hashedgoogleid = sha256(self.__googleid).digest()
            else:
                log.warning("Using supplied hashed google id")
                if len(hashedgoogleid) != 32:
                    log.error("Invalid hashed google id length: {}".format(hashedgoogleid.hex()))
                self.__hashedgoogleid = hashedgoogleid
            if iv is None:
                self.__padding = b'\x00' * 16
            else:
                if len(iv) != 16:
                    log.error("Invalid IV length: {}".format(iv.hex()))
                if iv != b'\x00' * 16:
                    log.warning("IV should be empty")
                self.__padding = iv
            if key is None:
                self.__key = urandom(32)
            else:
                if len(key) != 32:
                    log.error("Invalid key length: {}".format(key.hex()))
                self.__key = key
            return
        # Check if the keyfile has a supported cipher version
        self.__cipher_version = keyarray[:len(self.__SUPPORTED_CIPHER_VERSION)]
        if self.__SUPPORTED_CIPHER_VERSION != self.__cipher_version:
            log.error("Invalid keyfile: Unsupported cipher version {}"
                      .format(keyarray[:len(self.__SUPPORTED_CIPHER_VERSION)].hex()))
        index = len(self.__SUPPORTED_CIPHER_VERSION)

        # Check if the keyfile has a supported key version
        version_supported = False
        for v in self.__SUPPORTED_KEY_VERSIONS:
            if v == keyarray[index:index + len(self.__SUPPORTED_KEY_VERSIONS[0])]:
                version_supported = True
                self.__key_version = v
                break
        if not version_supported:
            log.error('Invalid keyfile: Unsupported key version {}'
                      .format(keyarray[index:index + len(self.__SUPPORTED_KEY_VERSIONS[0])].hex()))

        self.__serversalt = keyarray[3:35]

        # Check the SHA-256 of the salt
        self.__googleid = keyarray[35:51]
        expected_digest = sha256(self.__googleid).digest()
        actual_digest = keyarray[51:83]
        if expected_digest != actual_digest:
            log.error("Invalid keyfile: Invalid SHA-256 of salt.\n    "
                      "Expected: {}\n    Got:{}".format(expected_digest, actual_digest))

        self.__hashedgoogleid = actual_digest

        self.__padding = keyarray[83:99]

        # Check if IV is made of zeroes
        for byte in self.__padding:
            if byte:
                log.error("Invalid keyfile: IV is not zeroed out but is: {}".format(self.__padding.hex()))
                break

        self.__key = keyarray[99:]

        log.info("Crypt12/14 key loaded")

    def get(self) -> bytes:
        return self.__key

    def get_serversalt(self) -> bytes:
        return self.__serversalt

    def get_googleid(self) -> bytes:
        return self.__googleid

    def get_cipher_version(self) -> bytes:
        return self.__cipher_version

    def get_key_version(self) -> bytes:
        return self.__key_version

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
