#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt12, Crypt14 or Crypt15.
"""

from __future__ import annotations

from wa_crypt_tools import l
from wa_crypt_tools.lib.databasefactory import DatabaseFactory
from wa_crypt_tools.lib.key import Key14, Key15, Key
from wa_crypt_tools.lib.keyfactory import KeyFactory

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

# noinspection PyPackageRequirements
from google.protobuf.message import DecodeError

import collections
from hashlib import md5
import io
from re import findall
from sys import exit, maxsize
from time import sleep
from datetime import date

import argparse
import zlib

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2023'
__license__ = 'GPLv3'
__status__ = 'Production'

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

import logging

l = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Decrypts WhatsApp backup files'
                                                 ' encrypted with crypt12, 14 or 15')
    parser.add_argument('keyfile', nargs='?', type=str, default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file or the hex encoded key. '
                             'Default: encrypted_backup.key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt12, 14 or 15 file. Default: msgstore.db.crypt15')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db",
                        help='The decrypted output file. Default: msgstore.db')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Makes errors non fatal. Default: false')
    parser.add_argument('-nm', '--no-mem', action='store_true',
                        help='Does not load files in RAM, stresses the disk more. '
                             'Default: load files into RAM')
    parser.add_argument('-bs', '--buffer-size', type=int, help='How many bytes of data to process at a time. '
                                                               'Implies -nm. Default: {}'.format(
        io.DEFAULT_BUFFER_SIZE))
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


def test_decompression(test_data: bytes) -> bool:
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
            l.error("Test decompression: chunk too small")
            return False
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            l.error("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return l.force
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


def guess_offsets(key: bytes, file_hash: _Hash, encrypted: io.BufferedReader, def_iv_offset: int,
                  def_data_offset: int):
    """Gets the IV, shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by guessing the offset."""

    # Assign variables to suppress warnings
    db_header, data_offset, iv_offset = None, None, None

    # Restart the file stream
    encrypted.seek(0)

    db_header = encrypted.read(HEADER_SIZE)
    if len(db_header) < HEADER_SIZE:
        l.fatal("The encrypted database is too small.\n    "
            "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            l.error("The database file is not encrypted.\n    "
                "Did you swap the input and the output files by mistake?")
    except ValueError:
        pass

    # Finding WhatsApp's version is nice
    version = findall(b"\\d(?:\\.\\d{1,3}){3}", db_header)
    if len(version) != 1:
        l.info('WhatsApp version not found (Crypt12?)')
    else:
        l.debug("WhatsApp version: {}".format(version[0].decode('ascii')))

    # Determine IV offset and data offset.
    for iv_offset in oscillate(n=def_iv_offset, n_min=0, n_max=HEADER_SIZE - 128):
        data_offset = find_data_offset(db_header, iv_offset, key, def_data_offset)
        if data_offset != -1:
            l.info("Offsets guessed (IV: {}, data: {}).".format(iv_offset, data_offset))
            if iv_offset != def_iv_offset or data_offset != def_data_offset:
                l.info("Next time, use -ivo {} -do {} for guess-free decryption".format(iv_offset, data_offset))
            break
    if data_offset == -1:
        return None

    iv = db_header[iv_offset:iv_offset + 16]

    encrypted.seek(data_offset)

    file_hash.update(db_header[:data_offset])

    return AES.new(key, AES.MODE_GCM, iv)


def check_crypt12(file_hash, key, encrypted):
    """Checks if the file is a Crypt12 file.
    Returns the cipher if it is, None otherwise."""

    """
    The crypt12 file format is similar to the crypt14 file format.
    It is a "raw" header, which means it's not a protobuf message,
    nor a serialized java object.
    Structure:
    Cipher version (2 bytes)
    Key version (1 byte)
    Server salt (32 bytes)
    Google ID (16 bytes)
    IV (16 bytes)
    ( so we finally understood why the IV is at offset 51 ... )
    """

    def quit_12():
        encrypted.seek(0)
        l.debug("Not a Crypt12 file, or corrupted")
        raise ValueError

    if type(key) is not Key14:
        quit_12()

    # We can read and discard the bytes, because the information
    # are already in the keyfile.

    test_bytes = encrypted.read(2)
    if test_bytes != key.get_cipher_version():
        quit_12()
    file_hash.update(test_bytes)

    test_bytes = encrypted.read(1)
    if test_bytes != key.get_key_version():
        quit_12()
    file_hash.update(test_bytes)

    test_bytes = encrypted.read(32)
    if test_bytes != key.get_serversalt():
        quit_12()
    file_hash.update(test_bytes)

    test_bytes = encrypted.read(16)
    if test_bytes != key.get_googleid():
        quit_12()
    file_hash.update(test_bytes)

    iv = encrypted.read(16)
    file_hash.update(iv)

    # We are done here
    l.info("Database header parsed")
    return AES.new(key.__key, AES.MODE_GCM, iv)


def parse_protobuf(file_hash: _Hash, key: Key, encrypted):
    """Parses the database header, gets the IV,
     shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by parsing the protobuf message."""

    try:
        from wa_crypt_tools.proto import prefix_pb2 as prefix
        from wa_crypt_tools.proto import key_type_pb2 as key_type
    except ImportError as e:
        l.error("Could not import the proto classes: {}".format(e))
        if str(e).startswith("cannot import name 'builder' from 'google.protobuf.internal'"):
            l.error("You need to upgrade the protobuf library to at least 3.20.0.\n"
                "    python -m pip install --upgrade protobuf")
        elif str(e).startswith("no module named"):
            l.error("Please download them and put them in the \"proto\" sub folder.")
        return None
    except AttributeError as e:
        l.error("Could not import the proto classes: {}\n    ".format(e) +
            "Your protobuf library is probably too old.\n    "
            "Please upgrade to at least version 3.20.0 , by running:\n    "
            "python -m pip install --upgrade protobuf")
        return None

    p = prefix.prefix()

    l.debug("Parsing database header...")

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
                l.debug("Not a (recent) msgstore database")
                # For some reason we need to go backward one byte
                encrypted.seek(-1, 1)
            else:
                l.error("Unexpected backup type: {}".format(backup_type))
        else:
            file_hash.update(backup_type_raw)

        try:

            protobuf_raw = encrypted.read(protobuf_size)
            file_hash.update(protobuf_raw)

            if p.ParseFromString(protobuf_raw) != protobuf_size:
                l.error("Protobuf message not fully read. Please report a bug.")
            else:

                # Checking and printing WA version and phone number
                version = findall(r"\d(?:\.\d{1,3}){3}", p.info.whatsapp_version)
                if len(version) != 1:
                    l.error('WhatsApp version not found')
                else:
                    l.debug("WhatsApp version: {}".format(version[0]))
                if len(p.info.substringedUserJid) != 2:
                    l.error("The phone number end is not 2 characters long")
                l.debug("Your phone number ends with {}".format(p.info.substringedUserJid))

                if len(p.c15_iv.IV) != 0:
                    # DB Header is crypt15
                    if type(key) is not Key15:
                        l.error("You are using a crypt14 key file with a crypt15 backup.")
                    if len(p.c15_iv.IV) != 16:
                        l.error("IV is not 16 bytes long but is {} bytes long".format(len(p.c15_iv.IV)))
                    iv = p.c15_iv.IV

                elif len(p.c14_cipher.IV) != 0:

                    # DB Header is crypt14
                    if type(key) is not Key14:
                        l.fatal("You are using a crypt15 key file with a crypt14 backup.")

                    # if key.cipher_version != p.c14_cipher.version.cipher_version:
                    #    l.error("Cipher version mismatch: {} != {}"
                    #    .format(key.cipher_version, p.c14_cipher.cipher_version))

                    # Fix bytes to string encoding
                    key.key_version = (key.key_version[0] + 48).to_bytes(1, byteorder='big')
                    if key.key_version != p.c14_cipher.key_version:
                        if key.key_version > p.c14_cipher.key_version:
                            l.error("Key version mismatch: {} != {} .\n    "
                                .format(key.key_version, p.c14_cipher.key_version) +
                                "Your backup is too old for this key file.\n    " +
                                "Please try using a newer backup.")
                        elif key.key_version < p.c14_cipher.key_version:
                            l.error("Key version mismatch: {} != {} .\n    "
                                .format(key.key_version, p.c14_cipher.key_version) +
                                "Your backup is too new for this key file.\n    " +
                                "Please try using an older backup, or getting the new key.")
                        else:
                            l.error("Key version mismatch: {} != {} (?)"
                                .format(key.key_version, p.c14_cipher.key_version))
                    if key.get_serversalt() != p.c14_cipher.server_salt:
                        l.error("Server salt mismatch: {} != {}".format(key.get_serversalt(), p.c14_cipher.server_salt))
                    if key.get_googleid() != p.c14_cipher.google_id:
                        l.error("Google ID mismatch: {} != {}".format(key.get_googleid(), p.c14_cipher.google_id))
                    if len(p.c14_cipher.IV) != 16:
                        l.error("IV is not 16 bytes long but is {} bytes long".format(len(p.c14_cipher.IV)))
                    iv = p.c14_cipher.IV

                else:
                    l.error("Could not parse the IV from the protobuf message. Please report a bug.")
                    return None

                # We are done here
                l.info("Database header parsed")
                return AES.new(key.get(), AES.MODE_GCM, iv)

        except DecodeError as e:
            print(e)

    except OSError as e:
        l.fatal("Reading database header failed: {}".format(e))

    l.error("Could not parse the protobuf message. Please report a bug.")
    return None


def decrypt(file_hash: _Hash, cipher, encrypted, decrypted, buffer_size: int = 0):
    """Does the actual decryption."""

    z_obj = zlib.decompressobj()

    if cipher is None:
        l.fatal("Could not create a decryption cipher")

    try:

        if buffer_size == 0:
            # Load the encrypted file into RAM, decrypts into RAM,
            # decompresses into RAM, writes into disk.
            # More RAM used (~x3), less I/O used
            try:
                encrypted_data = encrypted.read()
                # Crypt12 moment: the last 4 bytes are --xx, where xx
                # are the last 2 numbers of the jid (user's phone number).
                # We need to remove them.
                crypt12_footer = str(encrypted_data[-4:])
                # Looks like a complicated regex, but it's just
                # "if it's --xx or xxxx"
                jid = findall(r"(?:-|\d)(?:-|\d)(\d\d)", crypt12_footer)
                if len(jid) == 1:
                    # Confirmed to be crypt12
                    encrypted_data = encrypted_data[:-4]
                    l.debug("Your phone number ends with {}".format(jid[0]))
                checksum = encrypted_data[-16:]
                authentication_tag = encrypted_data[-32:-16]
                encrypted_data = encrypted_data[:-32]
                is_multifile_backup = False

                file_hash.update(encrypted_data)
                file_hash.update(authentication_tag)

                if file_hash.digest() != checksum:
                    # We are probably in a multifile backup, which does not have a checksum.
                    is_multifile_backup = True
                else:
                    l.debug("Checksum OK ({}). Decrypting...".format(file_hash.hexdigest()))

                try:
                    output_decrypted: bytearray = cipher.decrypt(encrypted_data)
                except ValueError as e:
                    l.fatal("Decryption failed: {}."
                        "\n    This probably means your backup is corrupted.".format(e))
                    # Dead code to make pycharm warning go away
                    exit(1)

                # Verify the authentication tag
                try:
                    if is_multifile_backup:
                        # In multifile backups, there is no checksum.
                        # This means, the last 16 bytes of the files are not the checksum,
                        # despite being called "checksum", but are the authentication tag.
                        # Same way, "authentication tag" is not the tag, but the last
                        # 16 bytes of the encrypted file.
                        output_decrypted += cipher.decrypt(authentication_tag)
                        cipher.verify(checksum)
                    else:
                        cipher.verify(authentication_tag)
                except ValueError as e:
                    l.error("Authentication tag mismatch: {}."
                        "\n    This probably means your backup is corrupted.".format(e))

                try:
                    output_file = z_obj.decompress(output_decrypted)
                    if not z_obj.eof:
                        l.error("The encrypted database file is truncated (damaged).")
                except zlib.error:
                    output_file = output_decrypted
                    if test_decompression(output_file[:io.DEFAULT_BUFFER_SIZE]):
                        l.info("Decrypted data is a ZIP file that I will not decompress automatically.")
                    else:
                        l.error("I can't recognize decrypted data. Decryption not successful.\n    "
                            "The key probably does not match with the encrypted file.\n    "
                            "Or the backup is simply empty. (check with --force)")

                decrypted.write(output_file)

            except MemoryError:
                l.fatal("Out of RAM, please use -nm.")

        else:

            if buffer_size < 17:
                l.info("Invalid buffer size, will use default of {}".format(io.DEFAULT_BUFFER_SIZE))
                buffer_size = io.DEFAULT_BUFFER_SIZE

            # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
            # Less RAM used, more I/O used
            # TODO use assignment expression, which drops compatibility with 3.7
            # while chunk := encrypted.read(DEFAULT_BUFFER_SIZE):

            is_zip = True

            chunk = None

            l.debug("Reading and decrypting...")

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
                        l.fatal("Out of RAM, please use a smaller buffer size.")
                    if len(chunk) < buffer_size:
                        # Just error out, handling this case is too complicated.
                        # If the file is so small, the user can just load the whole thing into RAM.
                        l.fatal("Buffer size too large, use a smaller buffer size or don't use a buffer.")
                    continue

                try:
                    next_chunk = encrypted.read(buffer_size)
                except MemoryError:
                    l.fatal("Out of RAM, please use a smaller buffer size.")

                if len(next_chunk) <= 36:
                    # Last bytes read. Three cases:
                    # 1. The checksum is entirely in the last chunk
                    if len(next_chunk) == 36:
                        checksum = next_chunk
                    # 2. The checksum is entirely in the chunk before the last
                    elif len(next_chunk) == 0:
                        checksum = chunk[-36:]
                        chunk = chunk[:-36]
                    # 3. The checksum is split between the last two chunks
                    else:
                        checksum = chunk[-(36 - len(next_chunk)):] + next_chunk
                        chunk = chunk[:-(36 - len(next_chunk))]

                file_hash.update(chunk)

                decrypted_chunk = cipher.decrypt(chunk)
                if is_zip:
                    try:
                        decrypted.write(z_obj.decompress(decrypted_chunk))
                    except zlib.error:
                        if test_decompression(decrypted_chunk):
                            l.info("Decrypted data is a ZIP file that I will not decompress automatically.")
                        else:
                            l.error("I can't recognize decrypted data. Decryption not successful.\n    "
                                "The key probably does not match with the encrypted file.")
                        is_zip = False
                        decrypted.write(decrypted_chunk)
                else:
                    decrypted.write(decrypted_chunk)

                # The presence of the checksum tells us it's the last chunk
                if checksum is not None:
                    is_multifile_backup = False

                    crypt12_footer = str(checksum[-4:])
                    jid = findall(r"(?:-|\d)(?:-|\d)(\d\d)", crypt12_footer)
                    if len(jid) == 1:
                        # Confirmed to be crypt12
                        checksum = checksum[:-4]
                        l.debug("Your phone number ends with {}".format(jid[0]))
                    else:
                        # Shift everything forward by 4 bytes
                        chunk = checksum[:4]
                        file_hash.update(chunk)
                        decrypted_chunk = cipher.decrypt(chunk)
                        if is_zip:
                            try:
                                decrypted.write(z_obj.decompress(decrypted_chunk))
                            except zlib.error:
                                l.error("Backup is corrupted.")
                                decrypted.write(decrypted_chunk)
                        else:
                            decrypted.write(decrypted_chunk)
                        checksum = checksum[4:]

                    file_hash.update(checksum[:16])
                    if file_hash.digest() != checksum[16:]:
                        is_multifile_backup = True
                    else:
                        l.debug("Checksum OK ({})!".format(file_hash.hexdigest()))
                    try:
                        if is_multifile_backup:
                            decrypted.write(cipher.decrypt(checksum[:16]))
                            cipher.verify(checksum[16:])
                        else:
                            cipher.verify(checksum[:16])
                    except ValueError as e:
                        l.error("Authentication tag mismatch: {}."
                            "\n    This probably means your backup is corrupted.".format(e))
                    break

                chunk = next_chunk

            if is_zip and not z_obj.eof:

                if not l.force:
                    decrypted.truncate(0)
                l.error("The encrypted database file is truncated (damaged).")

        decrypted.flush()

    except OSError as e:
        l.fatal("I/O error: {}".format(e))

    finally:
        decrypted.close()
        encrypted.close()


def main():

    args = parsecmdline()

    # set wa_crypt_tools l to debug
    l.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch.setFormatter(CustomFormatter())
    l.addHandler(ch)
    if not (0 < args.data_offset < HEADER_SIZE - 128):
        l.fatal("The data offset must be between 1 and {}".format(HEADER_SIZE - 129))
    if not (0 < args.iv_offset < HEADER_SIZE - 128):
        l.fatal("The IV offset must be between 1 and {}".format(HEADER_SIZE - 129))
    if args.buffer_size is not None:
        if not 1 < args.buffer_size < maxsize:
            l.fatal("Invalid buffer size")
    # Get the decryption key from the key file or the hex encoded string.
    key = KeyFactory.new(args.keyfile)
    l.debug(str(key))
    cipher = None
    file_hash = md5()

    db, file_hash = DatabaseFactory.from_file(file_hash, args.encrypted)
    cipher = AES.new(key.get(), AES.MODE_GCM, db.get_iv())
    # Now we have to get the IV and to guess where the data starts.
    # We have two approaches to do so.
    # First: try parsing the protobuf message.
    #if not args.no_protobuf:
    ##    # Check if the backup is crypt12 first.
    #    try:
    #        cipher = check_crypt12(file_hash, key, args.encrypted)
    #    except ValueError:
    #        cipher = parse_protobuf(file_hash=file_hash, key=key, encrypted=args.encrypted)

    #if cipher is None and not args.no_guess:
    #    # If parsing the protobuf message failed, we try guessing the offsets.
    #    cipher = guess_offsets(file_hash=file_hash, key=key.get(), encrypted=args.encrypted,
    #                           def_iv_offset=args.iv_offset, def_data_offset=args.data_offset)

    if args.buffer_size is not None:
        decrypt(file_hash, cipher, args.encrypted, args.decrypted, args.buffer_size)
    elif args.no_mem:
        decrypt(file_hash, cipher, args.encrypted, args.decrypted, io.DEFAULT_BUFFER_SIZE)
    else:
        decrypt(file_hash, cipher, args.encrypted, args.decrypted)

    if date.today().day == 1 and date.today().month == 4:
        l.info("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        l.info("Uploaded. The developer will now read and publish your messages!")
    else:
        l.info("Done")

from lib.logformat import CustomFormatter

if __name__ == "__main__":
    main()
