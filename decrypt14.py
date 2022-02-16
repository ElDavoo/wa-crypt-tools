#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt14.
"""

from __future__ import annotations

# noinspection PyPackageRequirements
# This is from pycryptodome

from Crypto.Cipher import AES

# noinspection PyPackageRequirements
# This is from javaobj-py3

import javaobj.v2 as javaobj

from hashlib import sha256
from io import DEFAULT_BUFFER_SIZE
from re import findall
from sys import exit

import argparse
import zlib

__author__ = 'TripCode, ElDavo'
__copyright__ = 'Copyright (C) 2022'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '2.2'

# Key file format:
# The key file is actually a serialized byte[] object.
# For this reason we first need to deserialize the object.
# 1) The serialization header, that takes 28 bytes, but it might change.
SER_HEADER_LENGTH = 28
# 2) The cipher version (2 bytes). Known values are 0x0000 and 0x0001. So far we only support the latter.
SUPPORTED_CIPHER_VERSION = b'\x00\x01'
# 3) The key version (1 byte). Both of the known versions are supported.
SUPPORTED_KEY_VERSIONS = [b'\x01', b'\x02']

# 4) Server salt (32 bytes)
# 5) googleIdSalt (unused?) (16 bytes)
# 6) hashedGoogleID (The SHA-256 hash of googleIdSalt) (32 bytes)
# 7) encryption IV (zeroed out, as it is read from the database) (16 bytes)
# 8) cipherKey (32 bytes)
# total length = 158 bytes
KEY_LENGTH = 2 + 1 + 32 + 16 + 32 + 16 + 32

# zlib magic header is 78 01 (Low Compression).
# The first two bytes of the decrypted data should be those.
ZIP_HEADERS = [
    b'x\x01'
]

# Size of header (number chosen arbitrarily, but values less than ~310 makes test_decompression fail)
HEADER_SIZE = 512

# Actual data offset = this constant + whatsapp version string length
DEFAULT_DATA_OFFSET = 181

DEFAULT_IV_OFFSET = 67


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


def oscillate(n: int, n_min: int, n_max: int):
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


def parsecmdline():
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp database backup files encrypted with Crypt14')
    parser.add_argument('keyfile', nargs='?', type=argparse.FileType('rb'), default="key",
                        help='The WhatsApp keyfile. Default: key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt14",
                        help='The encrypted crypt14 database. Default: msgstore.db.crypt14')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db",
                        help='The decrypted output database file. Default: msgstore.db')
    parser.add_argument('-f', '--force', action='store_true', help='Makes errors non fatal. '
                                                                   'Default: false')
    parser.add_argument('-nm', '--no-mem', action='store_true', help='Does not load files in RAM, '
                                                                     'stresses the disk more. '
                                                                     'Default: load files into RAM')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')

    return parser.parse_args()


def javaintlist2bytes(barr: javaobj.beans.JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out


def get_server_salt_and_key(key_file_stream) -> tuple[bytes, bytes]:
    """Extracts server salt and key from the keyfile (a file stream)."""

    # Assign variables to suppress warnings
    keyfile: bytes = b''

    log.v("Reading keyfile...")

    try:
        jarr: javaobj.beans.JavaArray = javaobj.load(key_file_stream).data
        # Convert from a list of Int8 to a byte array
        keyfile = javaintlist2bytes(jarr)

    except OSError as e:
        log.f("Couldn't read keyfile: {}".format(e))
    except (ValueError, RuntimeError) as e:
        log.f("The keyfile is not a valid Java object: {}".format(e))

    # Check if the keyfile is big enough
    if len(keyfile) != KEY_LENGTH:
        log.f(
            "Invalid keyfile: Smaller than expected (wanted {} bytes, got {} bytes).\n"
                .format(KEY_LENGTH + SER_HEADER_LENGTH, len(keyfile) + SER_HEADER_LENGTH))

    # Check if the keyfile has a supported cipher version
    if SUPPORTED_CIPHER_VERSION != keyfile[:len(SUPPORTED_CIPHER_VERSION)]:
        log.e("Invalid keyfile: Unsupported cipher version {}"
              .format(keyfile[:len(SUPPORTED_CIPHER_VERSION)].hex()))
    index = len(SUPPORTED_CIPHER_VERSION)

    # Check if the keyfile has a supported key version
    version_supported = False
    for version in SUPPORTED_KEY_VERSIONS:
        if version == keyfile[index:index + len(SUPPORTED_KEY_VERSIONS[0])]:
            version_supported = True
            break
    if not version_supported:
        log.e('Invalid keyfile: Unsupported key version {}'
              .format(keyfile[index:index + len(SUPPORTED_KEY_VERSIONS[0])].hex()))

    server_salt = keyfile[3:35]

    # Check the SHA-256 of the salt
    googleidsalt = keyfile[35:51]
    expected_digest = sha256(googleidsalt).digest()
    actual_digest = keyfile[51:83]
    if expected_digest != actual_digest:
        log.e("Invalid keyfile: Invalid SHA-256 of salt.\n\t"
              "Expected:\t{}\n\tGot:\t\t{}".format(expected_digest, actual_digest))

    padding = keyfile[83:99]

    # Check if the padding is correct
    for byte in padding:
        if byte:
            log.e("Invalid keyfile: IV is not zeroed out but is: {}".format(padding.hex()))
            break

    key = keyfile[99:]

    log.v("Keyfile loaded")

    return server_salt, key


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
    Returns the offset or -1 if the offset is not found."""

    iv = header[iv_offset:iv_offset + 16]

    # oscillate ensures we try the closest values to the default value first.
    for i in oscillate(n=starting_data_offset, n_min=iv_offset + len(iv), n_max=HEADER_SIZE - 128):

        cipher = AES.new(key, AES.MODE_GCM, iv)

        # We only decrypt the first two bytes.
        test_bytes = cipher.decrypt(header[i:i + 2])

        for zheader in ZIP_HEADERS:

            if test_bytes == zheader:
                # We found a match, but this might also happen by chance.
                # Let's run another test by decrypting some hundreds of bytes.
                # We need to reinitialize the cipher everytime as it has an internal status.
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(header[i:])
                if test_decompression(decrypted):
                    return i

    return -1


def decrypt14(server_salt: bytes, key: bytes, encrypted, decrypted, mem_approach: bool):
    """Decrypts an encrypted database file, given the server salt and the key."""

    # Assign variables to suppress warnings
    db_header, offset, iv_offset = None, None, None

    log.v("Parsing database header...")

    # TODO actually parse the header. It is a protobuf message.

    try:
        db_header = encrypted.read(HEADER_SIZE)
    except OSError as e:
        log.f("Reading encrypted database failed: {}".format(e))

    if len(db_header) < HEADER_SIZE:
        log.f("The encrypted database is too small.\n\t"
              "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            log.e("The database file is not encrypted.\n\t"
                  "Did you swap the input and the output files by mistake?")
    except ValueError:
        pass

    result = db_header.find(server_salt)
    if result == -1:
        log.e("Server salt not found in header of crypt14 file.\n\t"
              "This probably means the key does not match the encrypted database.")
    else:
        log.v("Server salt found at offset {}".format(result))

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
        log.f("Could not find IV or data start offset")

    # Now that we have everything we can do the real job
    iv = db_header[iv_offset:iv_offset + 16]
    cipher = AES.new(key, AES.MODE_GCM, iv)
    encrypted.seek(offset)

    z_obj = zlib.decompressobj()

    log.v("Offsets found, decrypting...")

    try:

        if mem_approach:
            # Load the encrypted file into RAM
            # Decrypts into RAM
            # Decompresses into RAM
            # Writes into disk
            # More RAM used (x3), less I/O used
            output_file = z_obj.decompress((cipher.decrypt(encrypted.read())))
            if not z_obj.eof:
                log.e("The encrypted database file is truncated (damaged).")
            decrypted.write(output_file)
            decrypted.flush()

        else:
            # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
            # Less RAM used, more I/O used
            # TODO use assignment expression, which drops compatibility with 3.7
            # while chunk := encrypted.read(DEFAULT_BUFFER_SIZE):
            while True:
                chunk = encrypted.read(DEFAULT_BUFFER_SIZE)
                if not chunk:
                    break
                decrypted.write(z_obj.decompress(cipher.decrypt(chunk)))
            if not z_obj.eof:
                if not log.force:
                    decrypted.truncate(0)
                log.e("The encrypted database file is truncated (damaged).")
            decrypted.flush()

    except OSError as e:
        log.f("I/O error: {}".format(e))

    finally:
        decrypted.close()
        encrypted.close()

    log.i("Decryption successful")


def main():
    args = parsecmdline()
    global log
    log = Log(verbose=args.verbose, force=args.force)
    server_salt, key = get_server_salt_and_key(key_file_stream=args.keyfile)
    decrypt14(server_salt=server_salt, key=key,
              encrypted=args.encrypted, decrypted=args.decrypted, mem_approach=not args.no_mem)


if __name__ == "__main__":
    main()
