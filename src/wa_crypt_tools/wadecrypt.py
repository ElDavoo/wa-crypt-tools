#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt12, Crypt14 or Crypt15.
"""

from __future__ import annotations

from wa_crypt_tools.lib.logformat import CustomFormatter
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
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
            raise ModuleNotFoundError("You installed pycrypto and not pycryptodome(x). "
                                      "Pycrypto is old, deprecated and not supported. \n"
                                      "Run: python -m pip uninstall pycrypto\n"
                                      "And: python -m pip install pycryptodomex\n"
                                      "Or:  python -m pip install pycryptodome")
    except ModuleNotFoundError:
        # crypto (or nothing)
        raise ModuleNotFoundError("You need pycryptodome(x) to run these scripts!\n"
                                  "python -m pip install pycryptodome\n"
                                  "Or: python -m pip install pycryptodome\n"
                                  "You can also remove \"crypto\" if you have it installed\n"
                                  "python -m pip uninstall crypto")
# noinspection PyPackageRequirements
# This is from javaobj-py3

# noinspection PyPackageRequirements

import io
from re import findall
from sys import maxsize
from time import sleep
from datetime import date

import argparse
import zlib

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2023'
__license__ = 'GPLv3'
__status__ = 'Production'

import logging

log = logging.getLogger(__name__)


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
    parser.add_argument('-nd', '--no-decompress', action='store_true',
                        help='Does not decompress the decrypted data. '
                             'Default: decompresses the decrypted data')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')
    parser.add_argument('-f', '--force', action='store_true', help='Does nothing, but it is here for compatibility')

    return parser.parse_args()


def chunked_decrypt(file_hash, cipher, encrypted, decrypted, buffer_size: int = 0, no_decompress: bool = False):
    """
    Does the actual decryption chunking bytes, so the file does not get loaded into RAM.
    """

    z_obj = zlib.decompressobj()

    if cipher is None:
        log.fatal("Could not create a decryption cipher")

    try:

        if buffer_size < 17:
            log.info("Invalid buffer size, will use default of {}".format(io.DEFAULT_BUFFER_SIZE))
            buffer_size = io.DEFAULT_BUFFER_SIZE

            # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
            # Less RAM used, more I/O used

            is_zip = True

            chunk = encrypted.read(buffer_size)

            log.debug("Reading and decrypting...")

            while next_chunk := encrypted.read(buffer_size):

                # We will need to manage two chunks at a time, because we might have
                # the checksum in both the last chunk and the chunk before that.
                # This makes the logic more complicated, but it's the only way to.

                checksum = None

                try:
                    next_chunk = encrypted.read(buffer_size)
                except MemoryError:
                    log.fatal("Out of RAM, please use a smaller buffer size.")

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
                        if no_decompress:
                            decrypted.write(decrypted_chunk)
                        else:
                            decrypted.write(z_obj.decompress(decrypted_chunk))
                    except zlib.error:
                        if test_decompression(decrypted_chunk):
                            log.info("Decrypted data is a ZIP file that I will not decompress automatically.")
                        else:
                            log.error("I can't recognize decrypted data. Decryption not successful.\n    "
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
                        log.debug("Your phone number ends with {}".format(jid[0]))
                    else:
                        # Shift everything forward by 4 bytes
                        chunk = checksum[:4]
                        file_hash.update(chunk)
                        decrypted_chunk = cipher.decrypt(chunk)
                        if is_zip:
                            try:
                                if no_decompress:
                                    decrypted.write(decrypted_chunk)
                                else:
                                    decrypted.write(z_obj.decompress(decrypted_chunk))
                            except zlib.error:
                                log.error("Backup is corrupted.")
                                decrypted.write(decrypted_chunk)
                        else:
                            decrypted.write(decrypted_chunk)
                        checksum = checksum[4:]

                    file_hash.update(checksum[:16])
                    if file_hash.digest() != checksum[16:]:
                        is_multifile_backup = True
                    else:
                        log.debug("Checksum OK ({})!".format(file_hash.hexdigest()))
                    try:
                        if is_multifile_backup:
                            decrypted.write(cipher.decrypt(checksum[:16]))
                            cipher.verify(checksum[16:])
                        else:
                            cipher.verify(checksum[:16])
                    except ValueError as e:
                        log.error("Authentication tag mismatch: {}."
                                "\n    This probably means your backup is corrupted.".format(e))
                    break

                chunk = next_chunk

            if is_zip and not z_obj.eof:
                log.error("The encrypted database file is truncated (damaged).")

        decrypted.flush()

    except OSError as e:
        log.fatal("I/O error: {}".format(e))

    finally:
        decrypted.close()
        encrypted.close()


def main():
    args = parsecmdline()

    # set wa_crypt_tools l to debug
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch.setFormatter(CustomFormatter())
    log.addHandler(ch)
    # also add to "wa_crypt_tools.lib" logger
    logging.getLogger("wa_crypt_tools.lib").addHandler(ch)
    logging.getLogger("wa_crypt_tools.lib").setLevel(logging.DEBUG if args.verbose else logging.INFO)
    if args.buffer_size is not None:
        if not 1 < args.buffer_size < maxsize:
            log.fatal("Invalid buffer size")
    # Get the decryption key from the key file or the hex encoded string.
    key = KeyFactory.new(args.keyfile)
    log.debug(str(key))

    db = DatabaseFactory.from_file(args.encrypted)
    cipher = AES.new(key.get(), AES.MODE_GCM, db.get_iv())

    if args.buffer_size is not None:
        chunked_decrypt(db.file_hash, cipher, args.encrypted, args.decrypted, args.buffer_size, args.no_decompress)
    elif args.no_mem:
        chunked_decrypt(db.file_hash, cipher, args.encrypted, args.decrypted, io.DEFAULT_BUFFER_SIZE,
                        args.no_decompress)
    else:
        output_decrypted: bytearray = db.decrypt(key, args.encrypted.read())
        try:

            z_obj = zlib.decompressobj()
            if args.no_decompress:
                output_file = output_decrypted
            else:
                output_file = z_obj.decompress(output_decrypted)
                if not z_obj.eof:
                    log.error("The encrypted database file is truncated (damaged).")
        except zlib.error:
            output_file = output_decrypted
            if test_decompression(output_file[:io.DEFAULT_BUFFER_SIZE]):
                log.info("Decrypted data is a ZIP file that I will not decompress automatically.")
            else:
                log.error("I can't recognize decrypted data. Decryption not successful.\n    "
                        "The key probably does not match with the encrypted file.\n    "
                        "Or the backup is simply empty. (check with --force)")
        args.decrypted.write(output_file)

    if date.today().day == 1 and date.today().month == 4:
        log.info("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        log.info("Uploaded. The developer will now read and publish your messages!")
    else:
        log.info("Done")


if __name__ == "__main__":
    main()
