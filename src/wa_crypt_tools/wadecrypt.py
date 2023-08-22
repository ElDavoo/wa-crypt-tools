#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt12, Crypt14 or Crypt15.
"""

from __future__ import annotations
from lib.logformat import CustomFormatter

from wa_crypt_tools import l
from wa_crypt_tools.lib.databasefactory import DatabaseFactory
from wa_crypt_tools.lib.keyfactory import KeyFactory
from wa_crypt_tools.lib.utils import test_decompression

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
    parser.add_argument('-nm', '--no-mem', action='store_true',
                        help='Does not load files in RAM, stresses the disk more. '
                             'Default: load files into RAM')
    parser.add_argument('-bs', '--buffer-size', type=int, help='How many bytes of data to process at a time. '
                                                               'Implies -nm. Default: {}'.format(
        io.DEFAULT_BUFFER_SIZE))
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')

    return parser.parse_args()





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
    if args.buffer_size is not None:
        if not 1 < args.buffer_size < maxsize:
            l.fatal("Invalid buffer size")
    # Get the decryption key from the key file or the hex encoded string.
    key = KeyFactory.new(args.keyfile)
    l.debug(str(key))
    file_hash = md5()

    db, file_hash = DatabaseFactory.from_file(file_hash, args.encrypted)
    cipher = AES.new(key.get(), AES.MODE_GCM, db.get_iv())

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

if __name__ == "__main__":
    main()
