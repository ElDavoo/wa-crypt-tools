#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt14 or Crypt15.
"""

from __future__ import annotations

from lib.common_utils import SimpleLog
from lib.key import Key
from lib.common_utils import oscillate, test_decompression

from lib.common_utils import import_aes
AES = import_aes()

# noinspection PyPackageRequirements
from google.protobuf.message import DecodeError

from hashlib import md5
import io
from re import findall
from sys import exit, maxsize
from time import sleep
from datetime import date
from lib.constants import DEFAULT_IV_OFFSET, DEFAULT_DATA_OFFSET, HEADER_SIZE, ZLIB_HEADERS
import argparse
import zlib

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2023'
__license__ = 'GPLv3'
__status__ = 'Production'
__version__ = '6.1'

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
                                                               'Implies -nm. Default: {}'.format(io.DEFAULT_BUFFER_SIZE))
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


def guess_offsets(logger, key: bytes, file_hash, encrypted: io.BufferedReader, def_iv_offset: int,
                  def_data_offset: int):
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


def parse_protobuf(logger, file_hash, key: Key, encrypted):
    """Parses the database header, gets the IV,
     shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by parsing the protobuf message."""

    try:
        import src.proto.prefix_pb2 as prefix
        import src.proto.key_type_pb2 as key_type
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


def decrypt(logger, file_hash, cipher, encrypted, decrypted, buffer_size: int = 0):
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
                authentication_tag = encrypted_data[-32:-16]
                encrypted_data = encrypted_data[:-32]
                is_multifile_backup = False


                file_hash.update(encrypted_data)
                file_hash.update(authentication_tag)

                if file_hash.digest() != checksum:
                    # We are probably in a multifile backup, which does not have a checksum.
                    is_multifile_backup = True
                else:
                    logger.v("Checksum OK ({}). Decrypting...".format(file_hash.hexdigest()))

                try:
                    output_decrypted: bytearray = cipher.decrypt(encrypted_data)
                except ValueError as e:
                    logger.f("Decryption failed: {}."
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
                    logger.e("Authentication tag mismatch: {}."
                             "\n    This probably means your backup is corrupted.".format(e))

                try:
                    output_file = z_obj.decompress(output_decrypted)
                    if not z_obj.eof:
                        logger.e("The encrypted database file is truncated (damaged).")
                except zlib.error:
                    output_file = output_decrypted
                    if test_decompression(logger, output_file[:io.DEFAULT_BUFFER_SIZE]):
                        logger.i("Decrypted data is a ZIP file that I will not decompress automatically.")
                    else:
                        logger.e("I can't recognize decrypted data. Decryption not successful.\n    "
                                 "The key probably does not match with the encrypted file.\n    "
                                 "Or the backup is simply empty. (check with --force)")

                decrypted.write(output_file)

            except MemoryError:
                logger.f("Out of RAM, please use -nm.")

        else:

            if buffer_size < 17:
                logger.i("Invalid buffer size, will use default of {}".format(io.DEFAULT_BUFFER_SIZE))
                buffer_size = io.DEFAULT_BUFFER_SIZE

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

                if len(next_chunk) <= 32:
                    # Last bytes read. Three cases:
                    # 1. The checksum is entirely in the last chunk
                    if len(next_chunk) == 32:
                        checksum = next_chunk
                    # 2. The checksum is entirely in the chunk before the last
                    elif len(next_chunk) == 0:
                        checksum = chunk[-32:]
                        chunk = chunk[:-32]
                    # 3. The checksum is split between the last two chunks
                    else:
                        checksum = chunk[-(32 - len(next_chunk)):] + next_chunk
                        chunk = chunk[:-(32 - len(next_chunk))]

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
                    is_multifile_backup = False
                    file_hash.update(checksum[:16])
                    if file_hash.digest() != checksum[16:]:
                        is_multifile_backup = True
                    else:
                        logger.v("Checksum OK ({})!".format(file_hash.hexdigest()))
                    try:
                        if is_multifile_backup:
                            decrypted.write(cipher.decrypt(checksum[:16]))
                            cipher.verify(checksum[16:])
                        else:
                            cipher.verify(checksum[:16])
                    except ValueError as e:
                        logger.e("Authentication tag mismatch: {}."
                                 "\n    This probably means your backup is corrupted.".format(e))
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
    file_hash = md5()
    # Now we have to get the IV and to guess where the data starts.
    # We have two approaches to do so.
    # First: try parsing the protobuf message.
    if not args.no_protobuf:
        cipher = parse_protobuf(logger=logger, file_hash=file_hash, key=key, encrypted=args.encrypted)

    if cipher is None and not args.no_guess:
        # If parsing the protobuf message failed, we try guessing the offsets.
        cipher = guess_offsets(logger=logger, file_hash=file_hash, key=key.key, encrypted=args.encrypted,
                               def_iv_offset=args.iv_offset, def_data_offset=args.data_offset)

    if args.buffer_size is not None:
        decrypt(logger, file_hash, cipher, args.encrypted, args.decrypted, args.buffer_size)
    elif args.no_mem:
        decrypt(logger, file_hash, cipher, args.encrypted, args.decrypted, io.DEFAULT_BUFFER_SIZE)
    else:
        decrypt(logger, file_hash, cipher, args.encrypted, args.decrypted)

    if date.today().day == 1 and date.today().month == 4:
        logger.i("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        logger.i("Uploaded. The developer will now read and publish your messages!")
    else:
        logger.i("Done")


if __name__ == "__main__":
    main()
