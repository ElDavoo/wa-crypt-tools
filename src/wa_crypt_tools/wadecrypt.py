#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt12, Crypt14 or Crypt15.
"""

from __future__ import annotations

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import (
    DecryptionError,
    HeaderError,
    IntegrityError,
    ScreenshotKeyError,
    WaCryptError,
)
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.key.nearby import typo_keys
from wa_crypt_tools.lib.key.ocr import alternative_keys, looks_like_image
from wa_crypt_tools.lib.logformat import setup_logging
from wa_crypt_tools.lib.utils import encryptionloop, test_decompression

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
        # The rebind is the whole point of the fallback, so mypy's no-redef does not apply.
        from Crypto.Cipher import AES  # type: ignore[no-redef]

        if not hasattr(AES, "MODE_GCM"):
            # pycrypto
            raise ModuleNotFoundError(
                "You installed pycrypto and not pycryptodome(x). "
                "Pycrypto is old, deprecated and not supported. \n"
                "Run: python -m pip uninstall pycrypto\n"
                "And: python -m pip install pycryptodomex\n"
                "Or:  python -m pip install pycryptodome"
            )
    except ModuleNotFoundError:
        # crypto (or nothing)
        raise ModuleNotFoundError(
            "You need pycryptodome(x) to run these scripts!\n"
            "python -m pip install pycryptodome\n"
            "Or: python -m pip install pycryptodome\n"
            'You can also remove "crypto" if you have it installed\n'
            "python -m pip uninstall crypto"
        ) from None
# noinspection PyPackageRequirements
# This is from javaobj-py3

# noinspection PyPackageRequirements

import argparse
import io
import sys
import zlib
from datetime import date
from pathlib import Path
from re import findall
from time import sleep

__author__ = "ElDavo"
__copyright__ = "Copyright (C) 2023"
__license__ = "GPLv3"
__status__ = "Production"

import logging

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description="Decrypts WhatsApp backup files encrypted with crypt12, 14 or 15")
    parser.add_argument(
        "keyfile",
        nargs="?",
        type=str,
        default="encrypted_backup.key",
        help="The WhatsApp encrypted_backup key file or the hex encoded key. Default: encrypted_backup.key",
    )
    parser.add_argument(
        "encrypted",
        nargs="?",
        type=argparse.FileType("rb"),
        default="msgstore.db.crypt15",
        help="The encrypted crypt12, 14 or 15 file. Default: msgstore.db.crypt15",
    )
    # Deliberately not argparse.FileType('wb'): that opens the file while the arguments are
    # still being parsed, so a run that fails for any reason -- an unreadable key, a file
    # that is not a backup -- would already have truncated whatever was at that path.
    parser.add_argument(
        "decrypted", nargs="?", type=str, default="msgstore.db", help="The decrypted output file. Default: msgstore.db"
    )
    parser.add_argument(
        "-nm",
        "--no-mem",
        action="store_true",
        help="Does not load files in RAM, stresses the disk more. Default: load files into RAM",
    )
    parser.add_argument(
        "-bs",
        "--buffer-size",
        type=int,
        help=f"How many bytes of data to process at a time. Implies -nm. Default: {io.DEFAULT_BUFFER_SIZE}",
    )
    parser.add_argument(
        "-nd",
        "--no-decompress",
        action="store_true",
        help="Does not decompress the decrypted data. Default: decompresses the decrypted data",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Prints all offsets and messages")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Write the output even if an integrity check fails. Default: stop on the first failed check",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Overwrite the output file if it exists.")

    return parser.parse_args()


def chunked_decrypt(file_hash, cipher, encrypted, decrypted, buffer_size: int = 0, no_decompress: bool = False):
    """
    Does the actual decryption chunking bytes, so the file does not get loaded into RAM.
    """

    z_obj = zlib.decompressobj()

    # Problems that leave the written output suspect but complete. They are raised together
    # once the file has been flushed and closed -- the bytes are already on disk by the time
    # we find out, so there is nothing to hand back through IntegrityError.data here.
    integrity_problems: list[str] = []

    if cipher is None:
        raise DecryptionError("Could not create a decryption cipher")

    try:
        if buffer_size < 17:
            log.info(f"Invalid buffer size, will use default of {io.DEFAULT_BUFFER_SIZE}")
            buffer_size = io.DEFAULT_BUFFER_SIZE

        # Does the thing above but only with DEFAULT_BUFFER_SIZE bytes at a time.
        # Less RAM used, more I/O used

        is_zip = True

        # Read the first data chunk (there must be at least one, otherwise the
        # encrypted file is clearly malformed).
        chunk = encrypted.read(buffer_size)

        log.debug("Reading and decrypting...")

        if not chunk:
            raise HeaderError("Encrypted file is empty or truncated.")
        while True:
            # We will need to manage two chunks at a time, because we might have
            # the checksum in both the last chunk and the chunk before that.
            # This makes the logic more complicated, but it's the only way to.

            checksum = None

            try:
                next_chunk = encrypted.read(buffer_size)
            except MemoryError:
                log.fatal("Out of RAM, please use a smaller buffer size.")
                break

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
                    checksum = chunk[-(36 - len(next_chunk)) :] + next_chunk
                    chunk = chunk[: -(36 - len(next_chunk))]

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
                        log.error(
                            "I can't recognize decrypted data. Decryption not successful.\n    "
                            "The key probably does not match with the encrypted file."
                        )
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
                    log.debug(f"Your phone number ends with {jid[0]}")
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
                    log.debug(f"Checksum OK ({file_hash.hexdigest()})!")
                try:
                    if is_multifile_backup:
                        decrypted.write(cipher.decrypt(checksum[:16]))
                        cipher.verify(checksum[16:])
                    else:
                        cipher.verify(checksum[:16])
                except ValueError as e:
                    integrity_problems.append(
                        f"Authentication tag mismatch: {e}.\n    This probably means your backup is corrupted."
                    )
                break

            # If there is no more data, we should already have seen a checksum.
            if not next_chunk:
                integrity_problems.append("The encrypted database file is truncated (no checksum found).")
                break

            # Move the sliding window forward.
            chunk = next_chunk

        if is_zip and not no_decompress and not z_obj.eof:
            integrity_problems.append("The encrypted database file is truncated (damaged).")

        decrypted.flush()

    except OSError as e:
        raise DecryptionError(f"I/O error: {e}") from e

    finally:
        decrypted.close()
        encrypted.close()

    if integrity_problems:
        raise IntegrityError("\n    ".join(integrity_problems))


def main():
    args = parsecmdline()

    setup_logging(log, verbose=args.verbose)
    try:
        decrypt(args)
    except IntegrityError as e:
        # Only reached when --force was not given: the forced path handles these itself.
        log.critical(f"{e}\n    Use --force to write the output anyway.")
        sys.exit(1)
    except WaCryptError as e:
        log.critical(str(e))
        sys.exit(1)

    if date.today().day == 1 and date.today().month == 4:
        log.info("Done. Uploading messages to the developer's server...")
        sleep(0.5)
        log.info("Uploaded. The developer will now read and publish your messages!")
    else:
        log.info("Done")


#: How much ciphertext to decrypt when checking whether a candidate key is the right one.
#: Two bytes is enough to reject almost everything; this much is enough for zlib to prove it.
PROBE_BYTES = 512

#: How often to say something while searching, at debug level. A candidate costs about 400us
#: and the search runs to roughly 15,000 of them.
PROGRESS_EVERY = 4000


def key_works(root: bytes, iv: bytes, probe: bytes) -> bool:
    """
    Whether a candidate root key decrypts the start of this backup into something meaningful.

    The same trick waguess uses on offsets, applied to keys: decrypt the first two bytes and
    compare them against the headers a compressed or zipped payload has to start with. That
    rejects a wrong key in microseconds, and only a candidate that gets past it is worth
    decompressing a few hundred bytes of to be sure.

    A payload that is neither zlib nor a ZIP -- a backup written with --no-compress -- cannot
    be recognised this way, so this says no and the caller simply does not correct anything.
    """
    try:
        # Key15.get() by hand. Building a Key15 per candidate would be correct and would also
        # log "Crypt15 / Raw key loaded" tens of thousands of times on the way to an answer.
        cipher_key = encryptionloop(first_iteration_data=root, message=Key15.BACKUP_ENCRYPTION, output_bytes=32)
        if AES.new(cipher_key, AES.MODE_GCM, iv).decrypt(probe[:2]) not in C.ZLIB_HEADERS:
            return False
        # A two-byte match comes up by chance about once in every 13000 keys, so confirm it
        # with a real decompression. GCM keeps internal state, so the cipher is rebuilt.
        return test_decompression(AES.new(cipher_key, AES.MODE_GCM, iv).decrypt(probe))
    except (ValueError, zlib.error):
        return False


def transcribed(keyfile) -> bool | None:
    """
    Whether this key was transcribed by anything, and if so by what.

    True for a screenshot -- OCR transcribed it. False for 64 digits given on the command
    line -- a person did. None for a key file, where nobody did: those digits came out of
    WhatsApp's own file byte for byte, so a near miss of them is not a thing that exists.
    """
    if looks_like_image(keyfile):
        return True
    return None if Path(keyfile).is_file() else False


def corrected(key, keyfile, encrypted, iv):
    """
    Returns `key`, or the near miss of it that actually decrypts this backup.

    A key reaches this program transcribed two ways -- read off a screenshot, or typed in off
    one -- and either way a single wrong digit fails exactly like a completely wrong key,
    with nothing in the message to tell those apart. This is what tells them apart: it tries
    the candidates near the key against the backup itself, so what comes back has decrypted
    something. It never returns a guess, only a key that was proved right.

    It is meant to be unnoticeable when it succeeds -- the user asked for a decryption, not
    for a report on how their key was arrived at -- so the whole search is at debug level.
    Only a screenshot that could not be read is worth interrupting anyone about, because that
    one is the program's own failure and has a specific way out. A typed key that cannot be
    repaired says nothing and lets the decryption fail on its own terms: the user can see
    what they typed, and the key may simply belong to a different backup.

    Anything unexpected leaves the original key alone. This is a recovery path for a run that
    was about to fail anyway, and it must not be able to make that worse.
    """
    from_a_picture = transcribed(keyfile)
    if not isinstance(key, Key15) or from_a_picture is None:
        return key
    try:
        here = encrypted.tell()
        probe = encrypted.read(PROBE_BYTES)
        encrypted.seek(here)
    except OSError as e:
        # Not every stream can be rewound. Nothing has been consumed that matters, so the
        # decryption goes ahead unchecked exactly as it did before this existed.
        log.debug("Could not probe the backup to check the key: %s", e)
        return key

    if key_works(key.get_root(), iv, probe):
        return key

    # Built only now: for a screenshot this reaches back into the OCR reading, and there is
    # no reason to do that for a key that turns out to work.
    guesses = alternative_keys(keyfile) if from_a_picture else typo_keys(key.get_root().hex())

    log.debug("The key does not decrypt this backup; trying near misses...")
    for attempt, candidate in enumerate(guesses, start=1):
        if attempt % PROGRESS_EVERY == 0:
            log.debug("    tried %d keys...", attempt)
        root = bytes.fromhex(candidate)
        if key_works(root, iv, probe):
            log.debug("It was a digit or two out; %s works, found after %d tries", candidate, attempt)
            return Key15(keyarray=root)

    if from_a_picture:
        # Blaming the reader is the honest reading of it: the key is 64 digits the user can
        # see with their own eyes, and the program is the part that got them wrong.
        raise ScreenshotKeyError(
            "Could not read the key from the screenshot: what it says does not decrypt this "
            "backup,\n    and neither does any near miss of it.\n    "
            "Transcribe the 64 digits from the screenshot by hand and pass those instead of "
            "the image."
        )
    log.debug("No near miss of the given key decrypts this backup either.")
    return key


def decrypt(args):
    """Decrypts the database, honouring --force for the checks that can be survived."""
    # Before anything else, and before the output is opened: refusing after the fact would
    # mean the file had already been emptied.
    if Path(args.decrypted).is_file() and not args.yes:
        # Raised rather than exited: main() turns it into the same message and the same exit
        # code, and the GUI -- which calls this function directly -- gets something it can
        # catch instead of a SystemExit through the middle of its event loop.
        raise WaCryptError("The output file already exists. Use --yes to overwrite it.")
    if args.buffer_size is not None and not 1 < args.buffer_size < sys.maxsize:
        raise WaCryptError(f"Invalid buffer size: {args.buffer_size}")
    # Get the decryption key from the key file or the hex encoded string.
    key = KeyFactory.new(args.keyfile)
    log.debug(str(key))

    try:
        db = DatabaseFactory.from_file(args.encrypted)
    except IntegrityError as e:
        db = forced(args, e)

    # A screenshot read with one digit wrong fails exactly like a wrong key. Before spending
    # the whole decryption on it, check it against the backup and repair it if it is close.
    key = corrected(key, args.keyfile, args.encrypted, db.get_iv())

    cipher = AES.new(key.get(), AES.MODE_GCM, db.get_iv())

    if args.buffer_size is not None or args.no_mem:
        buffer_size = args.buffer_size if args.buffer_size is not None else io.DEFAULT_BUFFER_SIZE
        try:
            with open(args.decrypted, "wb") as f:
                chunked_decrypt(db.file_hash, cipher, args.encrypted, f, buffer_size, args.no_decompress)
        except IntegrityError as e:
            # The output was already streamed to disk, so there is nothing to write here:
            # --force only decides whether a partial file is an error or not.
            forced(args, e)
        return

    try:
        output_decrypted: bytes = db.decrypt(key, args.encrypted.read())
    except IntegrityError as e:
        output_decrypted = forced(args, e)

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
        if test_decompression(output_file[: io.DEFAULT_BUFFER_SIZE]):
            log.info("Decrypted data is a ZIP file that I will not decompress automatically.")
        else:
            log.error(
                "I can't recognize decrypted data. Decryption not successful.\n    "
                "The key probably does not match with the encrypted file.\n    "
                "Or the backup is simply empty. (check with --force)"
            )
    with open(args.decrypted, "wb") as f:
        f.write(output_file)


def forced(args, error: IntegrityError):
    """Re-raises unless --force was given, in which case it hands back the salvaged result."""
    if not args.force:
        raise error
    log.error(f"{error}\n    Continuing anyway because --force was given.")
    return error.data


if __name__ == "__main__":
    main()
