#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt14 or Crypt15.
"""

from __future__ import annotations

# AES import party!
# pycryptodome and PyCryptodomex's implementations of AES are the same,
# so we try to import one of these twos.
try:
    # pycryptodomex
    from Cryptodome.Cipher import AES
except ModuleNotFoundError:
    try:
        # pycryptodome
        # noinspection PyUnresolvedReferences
        from Crypto.Cipher import AES

        if not hasattr(AES, 'MODE_GCM'):
            # pycrypto
            print("You installed pycrypto and not pycryptodome(x).")
            print("Pycrypto is old, deprecated and not supported.")
            print("Run: python -m pip uninstall pycrypto")
            print("And: python -m pip install pycryptodomex")
            print("Or:  python -m pip install pycryptodome")
            exit(1)
    except ModuleNotFoundError:
        # crypto (or nothing)
        print("You need pycryptodome(x) to run this script")
        print("python -m pip install pycryptodomex")
        print("Or: python -m pip install pycryptodome")
        print("You can also remove \"crypto\" if you have it installed")
        print("python -m pip uninstall crypto")
        exit(1)

# noinspection PyPackageRequirements
# This is from javaobj-py3
import javaobj.v2 as javaobj

# noinspection PyPackageRequirements
from google.protobuf.message import DecodeError

import collections
from hashlib import sha256,md5
from io import DEFAULT_BUFFER_SIZE, BufferedReader
from re import findall
from sys import exit, maxsize
from time import sleep
from datetime import date

import argparse
import hmac
import zlib

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2022'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '6.0'

# These constants are only used by the guessing logic.

# zlib magic header is 78 01 (Low Compression).
# The first two bytes of the decrypted data should be those,
# in case of single file backup, or PK in case of multi file.
ZLIB_HEADERS = [
    b'x\x01',
    b'PK'
]
ZIP_HEADER = b'PK\x03\x04'

# Size of bytes to test (number chosen arbitrarily, but values less than ~310 makes test_decompression fail)
HEADER_SIZE = 384
DEFAULT_DATA_OFFSET = 122
DEFAULT_IV_OFFSET = 8


class SimpleLog:
    """Simple logger class. Supports 4 verbosity levels."""

    def __init__(self, verbose: bool, force: bool):
        self.verbose = verbose
        self.force = force

    def v(self, msg: str):
        """Will only print message if verbose mode is enabled."""
        if self.verbose:
            print('[V] {}'.format(msg))

    @staticmethod
    def i(msg: str):
        """Always prints message."""
        print('[I] {}'.format(msg))

    def e(self, msg: str):
        """Prints message and exit, unless force is enabled."""
        print('[E] {}'.format(msg))
        if not self.force:
            print("To bypass checks, use the \"--force\" parameter")
            exit(1)

    @staticmethod
    def f(msg: str):
        """Always prints message and exit."""
        print('[F] {}'.format(msg))
        exit(1)


def from_hex(logger, string: str) -> bytes:
    """Converts a hex string into a bytes array"""
    if len(string) != 64:
        logger.f("The key file specified does not exist.\n    "
                 "If you tried to specify the key directly, note it should be "
                 "64 characters long and not {} characters long.".format(len(string)))

    barr = None
    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        logger.f("Couldn't convert the hex string.\n    "
                 "Exception: {}".format(e))
    if len(barr) != 32:
        logger.e("The key is not 32 bytes long but {} bytes long.".format(len(barr)))
    return barr


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp backup files'
                                                 ' encrypted with Crypt14 or Crypt15')
    parser.add_argument('keyfile', nargs='?', type=str, default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file or the hex encoded key. '
                             'Default: encrypted_backup.key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt15 or crypt14 file. Default: msgstore.db.crypt15')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db",
                        help='The decrypted output file. Default: msgstore.db')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Makes errors non fatal. Default: false')
    parser.add_argument('-nm', '--no-mem', action='store_true',
                        help='Does not load files in RAM, stresses the disk more. '
                             'Default: load files into RAM')
    parser.add_argument('-bs', '--buffer-size', type=int, help='How many bytes of data to process at a time. '
                                                               'Implies -nm. Default: {}'.format(DEFAULT_BUFFER_SIZE))
    parser.add_argument('-ng', '--no-guess', action='store_true',
                        help='Does not try to guess the offsets, only protobuf parsing.')
    parser.add_argument('-np', '--no-protobuf', action='store_true',
                        help='Does not try to parse the protobuf message, only offset guessing.')
    parser.add_argument('-ivo', '--iv-offset', type=int, default=DEFAULT_IV_OFFSET,
                        help='The default offset of the IV in the encrypted file. '
                             'Only relevant in offset guessing mode. '
                             'Default: {}'.format(DEFAULT_IV_OFFSET))
    parser.add_argument('-do', '--data-offset', type=int, default=DEFAULT_DATA_OFFSET,
                        help='The default offset of the encrypted data in the encrypted file. '
                             'Only relevant in offset guessing mode. '
                             'Default: {}'.format(DEFAULT_DATA_OFFSET))
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')

    return parser.parse_args()


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


def oscillate(n: int, n_min: int, n_max: int) -> collections.Iterable:
    """Yields n, n-1, n+1, n-2, n+2..., with constraints:
    - n is in [min, max]
    - n is never negative
    Reverts to range() when n touches min or max. Example:
    oscillate(8, 2, 10) => 8, 7, 9, 6, 10, 5, 4, 3, 2
    """

    if n_min < 0:
        n_min = 0

    i = n
    c = 1

    # First phase (n, n-1, n+1...)
    while True:

        if i == n_max:
            break
        yield i
        i = i - c
        c = c + 1

        if i == 0 or i == n_min:
            break
        yield i
        i = i + c
        c = c + 1

    # Second phase (range of remaining numbers)
    # n != i/2 fixes a bug where we would yield min and max two times if n == (max-min)/2
    if i == n_min and n != i / 2:

        yield i
        i = i + c
        for j in range(i, n_max + 1):
            yield j

    if i == n_max and n != i / 2:

        yield n_max
        i = i - c
        for j in range(i, n_min - 1, -1):
            yield j


def test_decompression(logger, test_data: bytes) -> bool:
    """Returns true if the SQLite header is valid.
    It is assumed that the data are valid.
    (If it is valid, it also means the decryption and decompression were successful.)"""

    # If we get a ZIP file header, return true
    if test_data[:4] == ZIP_HEADER:
        return True

    try:
        zlib_obj = zlib.decompressobj().decompress(test_data)
        # These two errors should never happen
        if len(zlib_obj) < 16:
            logger.e("Test decompression: chunk too small")
            return False
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            logger.e("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return logger.force
        else:
            return True
    except zlib.error:
        return False


def find_data_offset(logger, header: bytes, iv_offset: int, key: bytes, starting_data_offset: int) -> int:
    """Tries to find the offset in which the encrypted data starts.
    Returns the offset or -1 if the offset is not found.
    Only works with ZLIB stream, not with ZIP file."""

    iv = header[iv_offset:iv_offset + 16]

    # oscillate ensures we try the closest values to the default value first.
    for i in oscillate(n=starting_data_offset, n_min=iv_offset + len(iv), n_max=HEADER_SIZE - 128):

        cipher = AES.new(key, AES.MODE_GCM, iv)

        # We only decrypt the first two bytes.
        test_bytes = cipher.decrypt(header[i:i + 2])

        for zheader in ZLIB_HEADERS:

            if test_bytes == zheader:
                # We found a match, but this might also happen by chance.
                # Let's run another test by decrypting some hundreds of bytes.
                # We need to reinitialize the cipher everytime as it has an internal status.
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(header[i:])
                if test_decompression(logger, decrypted):
                    return i
    return -1


def guess_offsets(logger, key: bytes, encrypted: BufferedReader, def_iv_offset: int, def_data_offset: int):
    """Gets the IV, shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by guessing the offset."""

    # Assign variables to suppress warnings
    db_header, data_offset, iv_offset = None, None, None

    # Restart the file stream
    encrypted.seek(0)

    db_header = encrypted.read(HEADER_SIZE)
    if len(db_header) < HEADER_SIZE:
        logger.f("The encrypted database is too small.\n    "
                 "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            logger.e("The database file is not encrypted.\n    "
                     "Did you swap the input and the output files by mistake?")
    except ValueError:
        pass

    # Finding WhatsApp's version is nice
    version = findall(b"\\d(?:\\.\\d{1,3}){3}", db_header)
    if len(version) != 1:
        logger.i('WhatsApp version not found (Crypt12?)')
    else:
        logger.v("WhatsApp version: {}".format(version[0].decode('ascii')))

    # Determine IV offset and data offset.
    for iv_offset in oscillate(n=def_iv_offset, n_min=0, n_max=HEADER_SIZE - 128):
        data_offset = find_data_offset(logger, db_header, iv_offset, key, def_data_offset)
        if data_offset != -1:
            logger.i("Offsets guessed (IV: {}, data: {}).".format(iv_offset, data_offset))
            if iv_offset != def_iv_offset or data_offset != def_data_offset:
                logger.i("Next time, use -ivo {} -do {} for guess-free decryption".format(iv_offset, data_offset))
            break
    if data_offset == -1:
        return None

    iv = db_header[iv_offset:iv_offset + 16]

    encrypted.seek(data_offset)

    file_hash.update(db_header[:data_offset])

    return AES.new(key, AES.MODE_GCM, iv)


def javaintlist2bytes(barr: javaobj.beans.JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out


def parse_protobuf(logger, key: Key, encrypted):
    """Parses the database header, gets the IV,
     shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by parsing the protobuf message."""

    try:
        import proto.prefix_pb2 as prefix
        import proto.key_type_pb2 as key_type
    except ImportError as e:
        logger.e("Could not import the proto classes: {}".format(e))
        if str(e).startswith("cannot import name 'builder' from 'google.protobuf.internal'"):
            logger.e("You need to upgrade the protobuf library to at least 3.20.0.\n"
                     "    python -m pip install --upgrade protobuf")
        elif str(e).startswith("no module named"):
            logger.e("Please download them and put them in the \"proto\" sub folder.")
        return None
    except AttributeError as e:
        logger.e("Could not import the proto classes: {}\n    ".format(e) +
                 "Your protobuf library is probably too old.\n    "
                 "Please upgrade to at least version 3.20.0 , by running:\n    "
                 "python -m pip install --upgrade protobuf")
        return None

    p = prefix.prefix()

    logger.v("Parsing database header...")

    try:

        # The first byte is the size of the upcoming protobuf message
        protobuf_size = encrypted.read(1)
        file_hash.update(protobuf_size)
        protobuf_size = int.from_bytes(protobuf_size, byteorder='big')

        # It is my guess this is the backup type.
        # Looks like it is 1 for msgstore and 8 for other types.
        backup_type_raw = encrypted.read(1)
        backup_type = int.from_bytes(backup_type_raw, byteorder='big')
        if backup_type != 1:
            if backup_type == 8:
                logger.v("Not a (recent) msgstore database")
                # For some reason we need to go backward one byte
                encrypted.seek(-1, 1)
            else:
                logger.e("Unexpected backup type: {}".format(backup_type))
        else:
            file_hash.update(backup_type_raw)

        try:

            protobuf_raw = encrypted.read(protobuf_size)
            file_hash.update(protobuf_raw)

            if p.ParseFromString(protobuf_raw) != protobuf_size:
                logger.e("Protobuf message not fully read. Please report a bug.")
            else:

                # Checking and printing WA version and phone number
                version = findall(r"\d(?:\.\d{1,3}){3}", p.info.whatsapp_version)
                if len(version) != 1:
                    logger.e('WhatsApp version not found')
                else:
                    logger.v("WhatsApp version: {}".format(version[0]))
                if len(p.info.substringedUserJid) != 2:
                    logger.e("The phone number end is not 2 characters long")
                logger.v("Your phone number ends with {}".format(p.info.substringedUserJid))

                if len(p.c15_iv.IV) != 0:
                    # DB Header is crypt15
                    if key.key_version is not None:
                        logger.e("You are using a crypt14 key file with a crypt15 backup.")
                    if len(p.c15_iv.IV) != 16:
                        logger.e("IV is not 16 bytes long but is {} bytes long".format(len(p.c15_iv.IV)))
                    iv = p.c15_iv.IV

                elif len(p.c14_cipher.IV) != 0:

                    # DB Header is crypt14
                    if key.key_version is None:
                        logger.f("You are using a crypt15 key file with a crypt14 backup.")

                    # if key.cipher_version != p.c14_cipher.version.cipher_version:
                    #    logger.e("Cipher version mismatch: {} != {}"
                    #    .format(key.cipher_version, p.c14_cipher.cipher_version))

                    # Fix bytes to string encoding
                    key.key_version = (key.key_version[0] + 48).to_bytes(1, byteorder='big')
                    if key.key_version != p.c14_cipher.key_version:
                        if key.key_version > p.c14_cipher.key_version:
                            logger.e("Key version mismatch: {} != {} .\n    "
                                     .format(key.key_version, p.c14_cipher.key_version) +
                                     "Your backup is too old for this key file.\n    " +
                                     "Please try using a newer backup.")
                        elif key.key_version < p.c14_cipher.key_version:
                            logger.e("Key version mismatch: {} != {} .\n    "
                                     .format(key.key_version, p.c14_cipher.key_version) +
                                     "Your backup is too new for this key file.\n    " +
                                     "Please try using an older backup, or getting the new key.")
                        else:
                            logger.e("Key version mismatch: {} != {} (?)"
                                     .format(key.key_version, p.c14_cipher.key_version))
                    if key.serversalt != p.c14_cipher.server_salt:
                        logger.e("Server salt mismatch: {} != {}".format(key.serversalt, p.c14_cipher.server_salt))
                    if key.googleid != p.c14_cipher.google_id:
                        logger.e("Google ID mismatch: {} != {}".format(key.googleid, p.c14_cipher.google_id))
                    if len(p.c14_cipher.IV) != 16:
                        logger.e("IV is not 16 bytes long but is {} bytes long".format(len(p.c14_cipher.IV)))
                    iv = p.c14_cipher.IV

                else:
                    logger.e("Could not parse the IV from the protobuf message. Please report a bug.")
                    return None

                # We are done here
                logger.i("Database header parsed")
                return AES.new(key.key, AES.MODE_GCM, iv)

        except DecodeError as e:
            print(e)

    except OSError as e:
        logger.f("Reading database header failed: {}".format(e))

    logger.e("Could not parse the protobuf message. Please report a bug.")
    return None


def decrypt(logger, cipher, encrypted, decrypted, buffer_size: int = 0):
    """Does the actual decryption."""

    z_obj = zlib.decompressobj()

    if cipher is None:
        logger.f("Could not create a decryption cipher")

    try:

        if buffer_size == 0:
            # Load the encrypted file into RAM, decrypts into RAM,
            # decompresses into RAM, writes into disk.
            # More RAM used (~x3), less I/O used
            try:
                encrypted_data = encrypted.read()
                checksum = encrypted_data[-16:]
                encrypted_data = encrypted_data[:-16]

                file_hash.update(encrypted_data)

                if file_hash.digest() != checksum:
                    logger.i("Checksum mismatch: Expected {} , got {}.\n"
                             "    If you're not decrypting stickers or wallpapers, your backup is damaged."
                             .format(file_hash.hexdigest(), checksum.hex()))
                    # Re add the truncated bytes
                    encrypted_data += checksum
                else:
                    logger.v("Checksum OK ({}). Decrypting...".format(file_hash.hexdigest()))

                output_decrypted = cipher.decrypt(encrypted_data)

                try:
                    output_file = z_obj.decompress(output_decrypted)
                    if not z_obj.eof:
                        logger.e("The encrypted database file is truncated (damaged).")
                except zlib.error:
                    output_file = output_decrypted
                    if test_decompression(logger, output_file[:DEFAULT_BUFFER_SIZE]):
                        logger.i("Decrypted data is a ZIP file that I will not decompress automatically.")
                    else:
                        logger.e("I can't recognize decrypted data. Decryption not successful.\n    "
                                 "The key probably does not match with the encrypted file.")

                decrypted.write(output_file)

            except MemoryError:
                logger.f("Out of RAM, please use -nm.")

        else:

            if buffer_size < 17:
                logger.i("Invalid buffer size, will use default of {}".format(DEFAULT_BUFFER_SIZE))
                buffer_size = DEFAULT_BUFFER_SIZE

            # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
            # Less RAM used, more I/O used
            # TODO use assignment expression, which drops compatibility with 3.7
            # while chunk := encrypted.read(DEFAULT_BUFFER_SIZE):

            is_zip = True

            chunk = None

            logger.v("Reading and decrypting...")

            while True:

                # We will need to manage two chunks at a time, because we might have
                # the checksum in both the last chunk and the chunk before that.
                # This makes the logic more complicated, but it's the only way to.

                next_chunk = None
                checksum = None

                if chunk is None:
                    # First read
                    try:
                        chunk = encrypted.read(buffer_size)
                    except MemoryError:
                        logger.f("Out of RAM, please use a smaller buffer size.")
                    if len(chunk) < buffer_size:
                        # Just error out, handling this case is too complicated.
                        # If the file is so small, the user can just load the whole thing into RAM.
                        logger.f("Buffer size too large, use a smaller buffer size or don't use a buffer.")
                    continue

                try:
                    next_chunk = encrypted.read(buffer_size)
                except MemoryError:
                    logger.f("Out of RAM, please use a smaller buffer size.")

                if len(next_chunk) <= 16:
                    # Last bytes read. Three cases:
                    # 1. The checksum is entirely in the last chunk
                    if len(next_chunk) == 16:
                        checksum = next_chunk
                    # 2. The checksum is entirely in the chunk before the last
                    elif len(next_chunk) == 0:
                        checksum = chunk[-16:]
                        chunk = chunk[:-16]
                    # 3. The checksum is split between the last two chunks
                    else:
                        checksum = chunk[-(16-len(next_chunk)):] + next_chunk
                        chunk = chunk[:-(16-len(next_chunk))]

                file_hash.update(chunk)

                decrypted_chunk = cipher.decrypt(chunk)
                if is_zip:
                    try:
                        decrypted.write(z_obj.decompress(decrypted_chunk))
                    except zlib.error:
                        if test_decompression(logger, decrypted_chunk):
                            logger.i("Decrypted data is a ZIP file that I will not decompress automatically.")
                        else:
                            logger.e("I can't recognize decrypted data. Decryption not successful.\n    "
                                     "The key probably does not match with the encrypted file.")
                        is_zip = False
                        decrypted.write(decrypted_chunk)
                else:
                    decrypted.write(decrypted_chunk)

                # The presence of the checksum tells us it's the last chunk
                if checksum is not None:
                    if file_hash.digest() != checksum:
                        if not logger.force:
                            decrypted.truncate(0)
                        logger.i("Checksum mismatch: Expected {} , got {}.\n"
                                 "    If you're not decrypting stickers or wallpapers, your backup is damaged."
                                 .format(file_hash.hexdigest(), checksum.hex()))
                        # Decrypt the checksum too, so that the file is not truncated
                        decrypted.write(cipher.decrypt(checksum))
                    else:
                        logger.v("Checksum OK ({})!".format(file_hash.hexdigest()))
                    break

                chunk = next_chunk

            if is_zip and not z_obj.eof:

                if not logger.force:
                    decrypted.truncate(0)
                logger.e("The encrypted database file is truncated (damaged).")

        decrypted.flush()

    except OSError as e:
        logger.f("I/O error: {}".format(e))

    finally:
        decrypted.close()
        encrypted.close()

file_hash = md5()
def main():
    args = parsecmdline()
    logger = SimpleLog(verbose=args.verbose, force=args.force)
    if not (0 < args.data_offset < HEADER_SIZE - 128):
        logger.f("The data offset must be between 1 and {}".format(HEADER_SIZE - 129))
    if not (0 < args.iv_offset < HEADER_SIZE - 128):
        logger.f("The IV offset must be between 1 and {}".format(HEADER_SIZE - 129))
    if args.buffer_size is not None:
        if not 1 < args.buffer_size < maxsize:
            logger.f("Invalid buffer size")
    # Get the decryption key from the key file or the hex encoded string.
    key = Key(logger, args.keyfile)
    logger.v(str(key))
    cipher = None
    # Now we have to get the IV and to guess where the data starts.
    # We have two approaches to do so.
    # First: try parsing the protobuf message.
    if not args.no_protobuf:
        cipher = parse_protobuf(logger=logger, key=key, encrypted=args.encrypted)

    if cipher is None and not args.no_guess:
        # If parsing the protobuf message failed, we try guessing the offsets.
        cipher = guess_offsets(logger=logger, key=key.key, encrypted=args.encrypted,
                               def_iv_offset=args.iv_offset, def_data_offset=args.data_offset)

    if args.buffer_size is not None:
        decrypt(logger, cipher, args.encrypted, args.decrypted, args.buffer_size)
    elif args.no_mem:
        decrypt(logger, cipher, args.encrypted, args.decrypted, DEFAULT_BUFFER_SIZE)
    else:
        decrypt(logger, cipher, args.encrypted, args.decrypted)

    if date.today().day == 1 and date.today().month == 4:
        logger.i("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        logger.i("Uploaded. The developer will now read and publish your messages!")
    else:
        logger.i("Done")


if __name__ == "__main__":
    main()
