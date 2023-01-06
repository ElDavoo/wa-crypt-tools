from __future__ import annotations

import hmac
from hashlib import sha256
# noinspection PyPackageRequirements
# This is from javaobj-py3
from javaobj import v2 as javaobj

from src.lib.common_utils import from_hex, javaintlist2bytes


class Key:
    """ This class represents a key used to decrypt the DB.
    Only the key is mandatory. The other parameters are optional, and if they are not None,
    means that the key type is crypt14."""
    # These constants are only used with crypt14 keys.
    SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02', b'\x03']

    # This constant is only used with crypt15 keys.
    BACKUP_ENCRYPTION = b'backup encryption\x01'

    def __str__(self):
        """Returns a string representation of the key"""
        try:
            string: str = "Key("
            if self.key is not None:
                string += "key: {}".format(self.key.hex())
            if self.serversalt is not None:
                string += " , serversalt: {}".format(self.serversalt.hex())
            if self.googleid is not None:
                string += " , googleid: {}".format(self.googleid.hex())
            if self.key_version is not None:
                string += " , key_version: {}".format(self.key_version.hex())
            if self.cipher_version is not None:
                string += " , cipher_version: {}".format(self.cipher_version.hex())
            return string + ")"
        except Exception as e:
            return "Exception printing key: {}".format(e)

    def __init__(self, logger, key_file_name):
        """Deserializes a key file into a byte array."""
        self.key = None
        self.serversalt = None
        self.googleid = None
        self.key_version = None
        self.cipher_version = None

        keyfile: bytes = b''

        logger.v("Reading keyfile...")

        # Try to open the keyfile.
        try:
            key_file_stream = open(key_file_name, 'rb')
            try:
                # Deserialize the byte object written in the file
                jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
                # Convert from a list of Int8 to a byte array
                keyfile: bytes = javaintlist2bytes(jarr)

            except (ValueError, RuntimeError) as e:
                logger.f("The keyfile is not a valid Java object: {}".format(e))

        except OSError:
            # Try to see if it is a hex-encoded key.
            keyfile = from_hex(logger, key_file_name)

        # We guess the key type from its length
        if len(keyfile) == 131:
            self.load_crypt14(logger, keyfile=keyfile)
        elif len(keyfile) == 32:
            self.load_crypt15(logger, keyfile=keyfile)
        else:
            logger.f("Unrecognized key file format.")

    def load_crypt14(self, logger, keyfile: bytes):
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
        self.cipher_version = keyfile[:len(self.SUPPORTED_CIPHER_VERSION)]
        if self.SUPPORTED_CIPHER_VERSION != self.cipher_version:
            logger.e("Invalid keyfile: Unsupported cipher version {}"
                     .format(keyfile[:len(self.SUPPORTED_CIPHER_VERSION)].hex()))
        index = len(self.SUPPORTED_CIPHER_VERSION)

        # Check if the keyfile has a supported key version
        version_supported = False
        for v in self.SUPPORTED_KEY_VERSIONS:
            if v == keyfile[index:index + len(self.SUPPORTED_KEY_VERSIONS[0])]:
                version_supported = True
                self.key_version = v
                break
        if not version_supported:
            logger.e('Invalid keyfile: Unsupported key version {}'
                     .format(keyfile[index:index + len(self.SUPPORTED_KEY_VERSIONS[0])].hex()))

        self.serversalt = keyfile[3:35]

        # Check the SHA-256 of the salt
        self.googleid = keyfile[35:51]
        expected_digest = sha256(self.googleid).digest()
        actual_digest = keyfile[51:83]
        if expected_digest != actual_digest:
            logger.e("Invalid keyfile: Invalid SHA-256 of salt.\n    "
                     "Expected: {}\n    Got:{}".format(expected_digest, actual_digest))

        padding = keyfile[83:99]

        # Check if IV is made of zeroes
        for byte in padding:
            if byte:
                logger.e("Invalid keyfile: IV is not zeroed out but is: {}".format(padding.hex()))
                break

        self.key = keyfile[99:]

        logger.i("Crypt12/14 key loaded")

    def load_crypt15(self, logger, keyfile: bytes):
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

        if len(keyfile) != 32:
            logger.f("Crypt15 loader trying to load a crypt14 key")

        # First do the HMACSHA256 hash of the file with an empty private key
        self.key: bytes = hmac.new(b'\x00' * 32, keyfile, sha256).digest()
        # Then do the HMACSHA256 using the previous result as key and ("backup encryption" + iteration count) as data
        self.key = hmac.new(self.key, self.BACKUP_ENCRYPTION, sha256).digest()

        logger.i("Crypt15 / Raw key loaded")
