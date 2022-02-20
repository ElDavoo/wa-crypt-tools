#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt15.
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

__author__ = 'TripCode, ElDavo'
__copyright__ = 'Copyright (C) 2022'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '4.1'

# Why the \x01 at the end? Read the parse_protobuf() function comments...
BACKUP_ENCRYPTION = b'backup encryption\x01'

# zlib magic header is 78 01 (Low Compression).
# The first two bytes of the decrypted data should be those.
ZIP_HEADERS = [
    b'x\x01'
]

# Size of header (number chosen arbitrarily, but values less than ~310 makes test_decompression fail)
HEADER_SIZE = 512

DEFAULT_DATA_OFFSET = 122
DEFAULT_IV_OFFSET = 8


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
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp database backup files encrypted with Crypt15')
    parser.add_argument('keyfile', nargs='?', type=argparse.FileType('rb'), default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file. Default: encrypted_backup.key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt15 database. Default: msgstore.db.crypt15')
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


def get_key(key_file_stream) -> bytes:
    """Extracts the key from the encoded_backup.key (a file stream)."""
    # encrypted_backup.key file format and encoding explanation:
    # The E2E key file is actually a serialized byte[] object.
    # For this reason we first need to deserialize the object.

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
    # After that, we will have the root key (32 bytes).
    # The root key is further encoded with three different strings, depending on what you want to do.
    # These three ways are "backup encryption";
    # "metadata encryption" and "metadata authentication", for Google Drive E2E encrypted metadata.
    # We are only interested in the local backup encryption.

    # Why the \x01 at the end?
    # Whatsapp uses a nested encryption function to encrypt many times the same data.
    # The iteration counter is appended to the end of the encrypted data. However,
    # since the loop is actually executed only one time, we will only have one interaction,
    # and thus a \x01 at the end.

    # First do the HMACSHA256 hash of the file with an empty private key
    encoded_key: bytes = hmac.new(b'\x00' * 32, keyfile, sha256).digest()
    # Then do the HMACSHA256 using the previous result as key and ("backup encryption" + iteration count) as data
    encoded_key = hmac.new(encoded_key, BACKUP_ENCRYPTION, sha256).digest()

    return encoded_key


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


def guess_offsets(key: bytes, encrypted: BufferedReader):
    """Gets the IV, shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by guessing the offset."""

    # Assign variables to suppress warnings
    db_header, offset, iv_offset = None, None, None
    log.i("Guessing the offsets...\n\t"
          "Note: This won't work with stickers and wallpapers backup")

    # Restart the file stream
    encrypted.seek(0)

    db_header = encrypted.read(HEADER_SIZE)
    if len(db_header) < HEADER_SIZE:
        log.f("The encrypted database is too small.\n\t"
              "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            log.e("The database file is not encrypted.\n\t"
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


def parse_protobuf(key: bytes, encrypted: BufferedReader):
    """Parses the database header, gets the IV,
     shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by parsing the protobuf message."""

    try:
        import proto.C15_header_pb2 as Crypt15Header
    except ImportError as e:
        log.e("Could not import the proto classes: {}\n\t".format(e) +
              "Please download them and put them in the \"proto\" sub folder.")
        return None

    p = Crypt15Header.Crypt15Prefix()

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

                if p.key_type != Crypt15Header.Key_Type.HSM_CONTROLLED:
                    log.e("Key is not controlled by HSM, but is {}".format(Crypt15Header.Key_Type.Name(p.key_type)))

                log.v("WhatsApp version: {}".format(p.info.whatsapp_version))
                log.v("Your phone number ends with {}".format(p.info.substringedUserJid))

                if len(p.iv.IV) != 16:
                    log.e("IV is not 16 bytes long but is {} bytes long".format(len(p.iv.IV)))

                # We are done here
                return AES.new(key, AES.MODE_GCM, p.iv.IV)

        except DecodeError:
            pass

    except OSError as e:
        log.f("Reading database header failed: {}".format(e))

    log.e("Could not parse the protobuf message. Please report a bug.")
    return None


def decrypt15(cipher, encrypted: BufferedReader, decrypted: BufferedReader, mem_approach: bool):
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
                log.v("Decrypted data is not a zlib stream, will not decompress automatically.\n"
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
                        log.v("Decrypted data is not a ZIP stream")
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
    key = get_key(key_file_stream=args.keyfile)

    # Now we have to get the IV and to guess where the data starts.
    # We have two approaches to do so.
    # First: try parsing the protobuf message.
    cipher = parse_protobuf(key=key, encrypted=args.encrypted)
    if cipher is None:
        # If parsing the protobuf message failed, we try guessing the offsets.
        cipher = guess_offsets(key=key, encrypted=args.encrypted)
    decrypt15(cipher, args.encrypted, args.decrypted, not args.no_mem)
    log.i("Decryption successful")


if __name__ == "__main__":
    main()
