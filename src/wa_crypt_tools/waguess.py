# AES import party!
# pycryptodome and PyCryptodomex's implementations of AES are the same,
# so we try to import one of these twos.
import argparse
import io
import zlib
from datetime import date
from re import findall

import logging
from time import sleep

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.logformat import CustomFormatter
from wa_crypt_tools.lib.utils import test_decompression

log = logging.getLogger(__name__)

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
        i -= c
        c += 1

        if i == 0 or i == n_min:
            break
        yield i
        i += c
        c += 1

    # Second phase (range of remaining numbers)
    # n != i/2 fixes a bug where we would yield min and max two times if n == (max-min)/2
    if i == n_min and n != i / 2:

        yield i
        i += c
        for j in range(i, n_max + 1):
            yield j

    if i == n_max and n != i / 2:

        yield n_max
        i -= c
        for j in range(i, n_min - 1, -1):
            yield j


def find_data_offset(header: bytes, iv_offset: int, key: bytes, starting_data_offset: int) -> int:
    """Tries to find the offset in which the encrypted data starts.
    Returns the offset or -1 if the offset is not found.
    Only works with ZLIB stream, not with ZIP file."""

    iv = header[iv_offset:iv_offset + 16]

    # oscillate ensures we try the closest values to the default value first.
    for i in oscillate(n=starting_data_offset, n_min=iv_offset + len(iv), n_max=C.HEADER_SIZE - 128):

        cipher = AES.new(key, AES.MODE_GCM, iv)

        # We only decrypt the first two bytes.
        test_bytes = cipher.decrypt(header[i:i + 2])

        for zheader in C.ZLIB_HEADERS:

            if test_bytes == zheader:
                # We found a match, but this might also happen by chance.
                # Let's run another test by decrypting some hundreds of bytes.
                # We need to reinitialize the cipher everytime as it has an internal status.
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted = cipher.decrypt(header[i:])
                if test_decompression(decrypted):
                    return i
    return -1


def guess_offsets(key: bytes, encrypted: io.BufferedReader, def_iv_offset: int,
                  def_data_offset: int):
    """Gets the IV, shifts the stream to the beginning of the encrypted data and returns the cipher.
    It does so by guessing the offset."""

    # Assign variables to suppress warnings
    db_header, data_offset, iv_offset = None, None, None

    # Restart the file stream
    encrypted.seek(0)

    db_header = encrypted.read(C.HEADER_SIZE)
    if len(db_header) < C.HEADER_SIZE:
        log.fatal("The encrypted database is too small.\n    "
                  "Did you swap the keyfile and the encrypted database file by mistake?")

    try:
        if db_header[:15].decode('ascii') == 'SQLite format 3':
            log.error("The database file is not encrypted.\n    "
                      "Did you swap the input and the output files by mistake?")
    except ValueError:
        pass

    # Finding WhatsApp's version is nice
    version = findall(b"\\d(?:\\.\\d{1,3}){3}", db_header)
    if len(version) != 1:
        log.info('WhatsApp version not found (Crypt12?)')
    else:
        log.debug("WhatsApp version: {}".format(version[0].decode('ascii')))

    # Determine IV offset and data offset.
    for iv_offset in oscillate(n=def_iv_offset, n_min=0, n_max=C.HEADER_SIZE - 128):
        data_offset = find_data_offset(db_header, iv_offset, key, def_data_offset)
        if data_offset != -1:
            log.info("Offsets guessed (IV: {}, data: {}).".format(iv_offset, data_offset))
            if iv_offset != def_iv_offset or data_offset != def_data_offset:
                log.info("Next time, use -ivo {} -do {} for guess-free decryption".format(iv_offset, data_offset))
            break
    if data_offset == -1:
        return None

    iv = db_header[iv_offset:iv_offset + 16]

    encrypted.seek(data_offset)

    return AES.new(key, AES.MODE_GCM, iv)


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
    parser.add_argument('-ivo', '--iv-offset', type=int, default=C.DEFAULT_IV_OFFSET,
                        help='The default offset of the IV in the encrypted file. '
                             'Default: {}'.format(C.DEFAULT_IV_OFFSET))
    parser.add_argument('-do', '--data-offset', type=int, default=C.DEFAULT_DATA_OFFSET,
                        help='The default offset of the encrypted data in the encrypted file. '
                             'Default: {}'.format(C.DEFAULT_DATA_OFFSET))
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')

    return parser.parse_args()


def decrypt(cipher, encrypted, decrypted):
    """Does the actual decryption."""

    z_obj = zlib.decompressobj()

    if cipher is None:
        log.fatal("Could not create a decryption cipher")

    try:

        try:
            encrypted_data = encrypted.read()
            # Crypt12 moment: the last 4 bytes are --xx, where xx
            # are the last 2 numbers of the jid (user's phone number).
            # We need to remove them.

            try:
                output_decrypted: bytearray = cipher.decrypt(encrypted_data)
            except ValueError as e:
                log.fatal("Decryption failed: {}."
                          "\n    This probably means your backup is corrupted.".format(e))
                # Dead code to make pycharm warning go away
                exit(1)

            try:
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

            decrypted.write(output_file)

        except MemoryError:
            log.fatal("Out of RAM, please use -nm.")

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
    if not (0 < args.data_offset < C.HEADER_SIZE - 128):
        log.fatal("The data offset must be between 1 and {}".format(C.HEADER_SIZE - 129))
    if not (0 < args.iv_offset < C.HEADER_SIZE - 128):
        log.fatal("The IV offset must be between 1 and {}".format(C.HEADER_SIZE - 129))
    # Get the decryption key from the key file or the hex encoded string.
    key = KeyFactory.new(args.keyfile)
    log.debug(str(key))

    cipher = guess_offsets(key=key.get(), encrypted=args.encrypted,
                           def_iv_offset=args.iv_offset, def_data_offset=args.data_offset)

    decrypt(cipher, args.encrypted, args.decrypted)

    if date.today().day == 1 and date.today().month == 4:
        log.info("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        log.info("Uploaded. The developer will now read and publish your messages!")
    else:
        log.info("Done")


if __name__ == '__main__':
    main()
