#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt14 or Crypt15.
"""

from __future__ import annotations

# noinspection PyPackageRequirements
# This is from pycryptodome
from Crypto.Cipher import AES

# noinspection PyPackageRequirements
# This is from javaobj-py3
import javaobj.v2 as javaobj

# noinspection PyPackageRequirements
from google.protobuf.message import DecodeError

import collections
from hashlib import sha256
from io import DEFAULT_BUFFER_SIZE, BufferedReader
from re import findall
from sys import exit

import argparse
import hmac
import zlib

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2022'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '5.0'

# These constants are only used by the guessing logic.

# zlib magic header is 78 01 (Low Compression).
# The first two bytes of the decrypted data should be those.
ZLIB_HEADERS = [
    b'x\x01'
]
# Size of bytes to test (number chosen arbitrarily, but values less than ~310 makes test_decompression fail)
HEADER_SIZE = 512
DEFAULT_DATA_OFFSET = 122
DEFAULT_IV_OFFSET = 8


class Key:
    """ This class represents a key used to decrypt the DB.
    Only the key is mandatory. The other parameters are optional, and if they are not None,
    means that the key type is crypt14."""
    # These constants are only used with crypt14 keys.
    SUPPORTED_CIPHER_VERSION = b'\x00\x01'
    SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02']

    # This constant is only used with crypt15 keys.
    BACKUP_ENCRYPTION = b'backup encryption\x01'

    def __init__(self, key_file_stream):
        """Deserializes a key file into a byte array."""
        self.key = None
        self.serversalt = None
        self.googleid = None
        self.key_version = None
        self.cipher_version = None

        keyfile: bytes = b''

        log.v("Reading keyfile...")

        try:
            # Deserialize the byte object written in the file
            jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
            # Convert from a list of Int8 to a byte array
            keyfile: bytes = javaintlist2bytes(jarr)

        except OSError as e:
            log.f("Couldn't read keyfile: {}".format(e))
        except (ValueError, RuntimeError) as e:
            log.f("The keyfile is not a valid Java object: {}".format(e))

        # We guess the key type from its length
        if len(keyfile) == 131:
            self.load_crypt14(keyfile=keyfile)
        elif len(keyfile) == 32:
            self.load_crypt15(keyfile=keyfile)
        else:
            log.f("Unrecognized key file format.")

    def load_crypt14(self, keyfile: bytes):
        """Extracts the fields from a crypt14 loaded key file."""
        # key file format and encoding explanation:
        # The key file is actually a serialized byte[] object.

        # After deserialization, we will have a byte[] object that we have to split in:
        # 1) The cipher version (2 bytes). Known values are 0x0000 and 0x0001. So far we only support the latter.
        # SUPPORTED_CIPHER_VERSION = b'\x00\x01'
        # 2) The key version (1 byte). Both of the known versions are supported.
        # SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02']
        # 3) Server salt (32 bytes)
        # 4) googleIdSalt (unused?) (16 bytes)
        # 5) hashedGoogleID (The SHA-256 hash of googleIdSalt) (32 bytes)
        # 6) encryption IV (zeroed out, as it is read from the database) (16 bytes)
        # 7) cipherKey (The actual AES-256 decryption key) (32 bytes)

        # Check if the keyfile has a supported cipher version
        self.cipher_version = keyfile[:len(self.SUPPORTED_CIPHER_VERSION)]
        if self.SUPPORTED_CIPHER_VERSION != self.cipher_version:
            log.e("Invalid keyfile: Unsupported cipher version {}"
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
            log.e('Invalid keyfile: Unsupported key version {}'
                  .format(keyfile[index:index + len(self.SUPPORTED_KEY_VERSIONS[0])].hex()))

        self.serversalt = keyfile[3:35]

        # Check the SHA-256 of the salt
        self.googleid = keyfile[35:51]
        expected_digest = sha256(self.googleid).digest()
        actual_digest = keyfile[51:83]
        if expected_digest != actual_digest:
            log.e("Invalid keyfile: Invalid SHA-256 of salt.\n    "
                  "Expected: {}\n    Got:{}".format(expected_digest, actual_digest))

        padding = keyfile[83:99]

        # Check if IV is made of zeroes
        for byte in padding:
            if byte:
                log.e("Invalid keyfile: IV is not zeroed out but is: {}".format(padding.hex()))
                break

        self.key = keyfile[99:]

        log.i("Crypt14 key loaded")

    def load_crypt15(self, keyfile: bytes):
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

        if len(keyfile) != 32:
            log.f("Crypt15 loader trying to load a crypt14 key")

        # First do the HMACSHA256 hash of the file with an empty private key
        self.key: bytes = hmac.new(b'\x00' * 32, keyfile, sha256).digest()
        # Then do the HMACSHA256 using the previous result as key and ("backup encryption" + iteration count) as data
        self.key = hmac.new(self.key, self.BACKUP_ENCRYPTION, sha256).digest()

        log.i("Crypt15 key loaded")


class Log:
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


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp database backup files'
                                                 ' encrypted with Crypt14 or Crypt15')
    parser.add_argument('keyfile', nargs='?', type=argparse.FileType('rb'), default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file. Default: encrypted_backup.key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt15 database. Default: msgstore.db.crypt15')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db",
                        help='The decrypted output database file. Default: msgstore.db')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Makes errors non fatal. Default: false')
    parser.add_argument('-nm', '--no-mem', action='store_true',
                        help='Does not load files in RAM, stresses the disk more. Default: load files into RAM')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')

    return parser.parse_args()


def javaintlist2bytes(barr: javaobj.beans.JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out


def test_decompression(test_data: bytes) -> bool:
    """Returns true if the SQLite header is valid.
    It is assumed that the data are valid.
    (If it is valid, it also means the decryption and decompression were successful.)"""

    try:
        zlib_obj = zlib.decompressobj().decompress(test_data)
        # These two errors should never happen
        if len(zlib_obj) < 16:
            log.e("Test decompression: chunk too small")
            return False
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            log.e("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return log.force
        else:
            return True
    except zlib.error:
        return False


def find_data_offset(header: bytes, iv_offset: int, key: bytes, starting_data_offset: int) -> int:
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
                if test_decompression(decrypted):
                    return i

    return -1


def guess_offsets(key: bytes, encrypted: BufferedReader):
    """Gets the IV, shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by guessing the offset."""

    # Assign variables to suppress warnings
    db_header, offset, iv_offset = None, None, None
    log.i("Guessing the offsets...\n    "
          "Note: This won't work with stickers and wallpapers backup")

    # Restart the file stream
    encrypted.seek(0)

    db_header = encrypted.read(HEADER_SIZE)
    if len(db_header) < HEADER_SIZE:
        log.f("The encrypted database is too small.\n    "
              "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            log.e("The database file is not encrypted.\n    "
                  "Did you swap the input and the output files by mistake?")
    except ValueError:
        pass

    # Finding WhatsApp's version's length allows us to determine the data offset
    version = findall(b"\\d(?:\\.\\d{1,3}){3}", db_header)
    if len(version) != 1:
        log.e('WhatsApp version not found')
    else:
        log.v("WhatsApp version: {}".format(version[0].decode('ascii')))

    starting_data_offset = DEFAULT_DATA_OFFSET + len(version[0])

    # Determine IV offset and data offset.
    for iv_offset in oscillate(n=DEFAULT_IV_OFFSET, n_min=0, n_max=HEADER_SIZE - 128):
        offset = find_data_offset(db_header, iv_offset, key, starting_data_offset)
        if offset != -1:
            log.v("IV offset: {}".format(iv_offset))
            log.v("Data offset: {}".format(offset))
            break
    if offset == -1:
        return None

    iv = db_header[iv_offset:iv_offset + 16]

    encrypted.seek(offset)

    return AES.new(key, AES.MODE_GCM, iv)


def parse_protobuf(key: Key, encrypted):
    """Parses the database header, gets the IV,
     shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by parsing the protobuf message."""

    try:
        import proto.prefix_pb2 as prefix
        import proto.key_type_pb2 as key_type
    except ImportError as e:
        log.e("Could not import the proto classes: {}\n    ".format(e) +
              "Please download them and put them in the \"proto\" sub folder.")
        return None

    p = prefix.prefix()

    log.v("Parsing database header...")

    try:

        # The first byte is the size of the upcoming protobuf message
        protobuf_size = int.from_bytes(encrypted.read(1), byteorder='big')

        # It is my guess this is the backup type.
        # Looks like it is 1 for msgstore and 8 for other types.
        backup_type = int.from_bytes(encrypted.read(1), byteorder='big')
        if backup_type != 1:
            if backup_type == 8:
                log.v("Not a msgstore database")
                # For some reason we need to go backward one byte
                encrypted.seek(-1, 1)
            else:
                log.e("Unexpected backup type: {}".format(backup_type))

        try:

            if p.ParseFromString(encrypted.read(protobuf_size)) != protobuf_size:
                log.e("Protobuf message not fully read. Please report a bug.")
            else:

                # Finding WhatsApp's version's length allows us to determine the data offset
                version = findall(r"\d(?:\.\d{1,3}){3}", p.info.whatsapp_version)
                if len(version) != 1:
                    log.e('WhatsApp version not found')
                else:
                    log.v("WhatsApp version: {}".format(version[0]))
                if len(p.info.substringedUserJid) != 2:
                    log.e("The phone number end is not 2 characters long")
                log.v("Your phone number ends with {}".format(p.info.substringedUserJid))

                if len(p.c15_iv.IV) != 0:
                    # DB Header is crypt15
                    if key.key_version is not None:
                        log.e("You are using a crypt14 key file with a crypt15 backup.")
                    if len(p.c15_iv.IV) != 16:
                        log.e("IV is not 16 bytes long but is {} bytes long".format(len(p.c15_iv.IV)))
                    iv = p.c15_iv.IV

                elif len(p.c14_cipher.IV) != 0:

                    # DB Header is crypt14
                    if key.key_version is None:
                        log.f("You are using a crypt15 key file with a crypt14 backup.")

                    # if key.cipher_version != p.c14_cipher.version.cipher_version:
                    #    log.e("Cipher version mismatch: {} != {}"
                    #    .format(key.cipher_version, p.c14_cipher.cipher_version))

                    # Fix bytes to string encoding
                    key.key_version = (key.key_version[0] + 48).to_bytes(1, byteorder='big')
                    if key.key_version != p.c14_cipher.key_version:
                        log.e("Key version mismatch: {} != {}".format(key.key_version, p.c14_cipher.key_version))
                    if key.serversalt != p.c14_cipher.server_salt:
                        log.e("Server salt mismatch: {} != {}".format(key.serversalt, p.c14_cipher.server_salt))
                    if key.googleid != p.c14_cipher.google_id:
                        log.e("Google ID mismatch: {} != {}".format(key.googleid, p.c14_cipher.google_id))
                    if len(p.c14_cipher.IV) != 16:
                        log.e("IV is not 16 bytes long but is {} bytes long".format(len(p.c14_cipher.IV)))
                    iv = p.c14_cipher.IV

                else:
                    log.e("Could not parse the IV from the protobuf message. Please report a bug.")
                    return None

                # We are done here
                log.i("Database header parsed")
                return AES.new(key.key, AES.MODE_GCM, iv)

        except DecodeError as e:
            print(e)

    except OSError as e:
        log.f("Reading database header failed: {}".format(e))

    log.e("Could not parse the protobuf message. Please report a bug.")
    return None


def decrypt(cipher, encrypted, decrypted, mem_approach: bool):
    """Does the actual decryption."""

    z_obj = zlib.decompressobj()

    if cipher is None:
        log.f("Could not create a decryption cipher")

    log.v("Decrypting...")

    try:

        if mem_approach:
            # Load the encrypted file into RAM, decrypts into RAM,
            # decompresses into RAM, writes into disk.
            # More RAM used (x3), less I/O used
            output_decrypted = cipher.decrypt(encrypted.read())
            try:
                output_file = z_obj.decompress(output_decrypted)
                if not z_obj.eof:
                    log.e("The encrypted database file is truncated (damaged).")
            except zlib.error:
                log.i("Decrypted data is not a zlib stream, will not decompress automatically.\n    "
                      "The output file is probably a ZIP archive.")
                output_file = output_decrypted

            decrypted.write(output_file)

        else:

            # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
            # Less RAM used, more I/O used
            # TODO use assignment expression, which drops compatibility with 3.7
            # while chunk := encrypted.read(DEFAULT_BUFFER_SIZE):

            is_zip = True

            while True:

                chunk = encrypted.read(DEFAULT_BUFFER_SIZE)
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                if is_zip:
                    try:
                        decrypted.write(z_obj.decompress(decrypted_chunk))
                    except zlib.error:
                        log.i("Decrypted data is not a zlib stream, will not decompress automatically.\n    "
                              "The output file is probably a ZIP archive.")
                        is_zip = False
                        decrypted.write(decrypted_chunk)
                else:
                    decrypted.write(decrypted_chunk)

            if is_zip and not z_obj.eof:

                if not log.force:
                    decrypted.truncate(0)
                log.e("The encrypted database file is truncated (damaged).")

        decrypted.flush()

    except OSError as e:
        log.f("I/O error: {}".format(e))

    finally:
        decrypted.close()
        encrypted.close()


def main():
    args = parsecmdline()
    global log
    log = Log(verbose=args.verbose, force=args.force)
    # Get the decryption key from the key file.
    key = Key(args.keyfile)

    # Now we have to get the IV and to guess where the data starts.
    # We have two approaches to do so.
    # First: try parsing the protobuf message.
    cipher = parse_protobuf(key=key, encrypted=args.encrypted)
    if cipher is None:
        # If parsing the protobuf message failed, we try guessing the offsets.
        cipher = guess_offsets(key=key.key, encrypted=args.encrypted)
    decrypt(cipher, args.encrypted, args.decrypted, not args.no_mem)
    log.i("Decryption successful")


if __name__ == "__main__":
    main()
