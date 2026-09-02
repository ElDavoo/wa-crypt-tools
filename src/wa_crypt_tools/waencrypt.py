import argparse
import logging
import sys
import zlib
from pathlib import Path

from Cryptodome.Cipher import AES

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import IntegrityError, WaCryptError
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.logformat import setup_logging
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Parses the command line arguments."""
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description="Encrypts a file in Crypt14 or Crypt15 format.")
    parser.add_argument(
        "keyfile",
        nargs="?",
        type=str,
        default="encrypted_backup.key",
        help="The WhatsApp encrypted_backup key file or the hex encoded key. Default: encrypted_backup.key",
    )
    parser.add_argument(
        "decrypted",
        nargs="?",
        type=argparse.FileType("rb"),
        default="msgstore.db",
        help="The input file. Default: msgstore.db",
    )
    # Deliberately not argparse.FileType('wb'): that opens the file while the arguments are
    # still being parsed, so a run that fails for any reason -- an unreadable key, the wrong
    # --type -- would already have truncated whatever was at that path.
    parser.add_argument(
        "encrypted",
        nargs="?",
        type=str,
        default="msgstore.db.crypt15",
        help="The encrypted crypt15 or crypt14 file. Default: msgstore.db.crypt15",
    )
    parser.add_argument("-f", "--force", action="store_true", help="Carry on when an integrity check fails. Default: stop")
    parser.add_argument("-y", "--yes", action="store_true", help="Overwrite the output file if it exists.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Prints all offsets and messages")
    parser.add_argument(
        "--enable-features", type=int, nargs="*", default=C.DEFAULT_FEATURE_LIST, help="Enables the specified features. "
    )
    parser.add_argument(
        "--max-feature",
        type=int,
        default=39,
        help="The max feature number, the older is the backup the lower should be the number. ",
    )
    parser.add_argument(
        "--multi-file", action="store_true", help="Encrypts a multi-file backup (either stickers or wallpapers)"
    )
    parser.add_argument(
        "--type", type=int, choices=[12, 14, 15], default=15, help="The type of encryption to use. Default: 15"
    )
    parser.add_argument("--iv", type=str, help="The IV to use for crypt15 encryption. Default: random")
    parser.add_argument(
        "--reference",
        type=argparse.FileType("rb"),
        help="The reference file to use for crypt15 encryption. Highly recommended.",
    )
    parser.add_argument("--noparse", action="store_true", help="Do not parse the header of the reference file. Default: false")
    parser.add_argument(
        "--wa-version",
        type=str,
        default=C.DEFAULT_APP_VERSION,
        help="The WhatsApp version to use for crypt15 encryption. Default:" + C.DEFAULT_APP_VERSION,
    )
    parser.add_argument(
        "--jid", type=str, default=C.DEFAULT_JID_SUFFIX, help="The last 2 numbers of your phone number. Default: 00"
    )
    parser.add_argument(
        "--backup-version",
        type=int,
        default=C.DEFAULT_BACKUP_VERSION,
        help="The backup version to use in the header of the encrypted file. Default: 0",
    )
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Do not compress the file. This will make the backup not working. Only used in development. Default: false",
    )
    # This was hardcoded to 1, which is what WhatsApp itself used when it was written.
    # Current WhatsApp compresses at 9, so that is the default now -- but old backups were
    # built at 1 and reproducing one has to stay possible, hence the option. The default is
    # resolved in encrypt(), not here, so that --reference can supply it instead.
    parser.add_argument(
        "-c",
        "--compression-level",
        type=int,
        choices=range(10),
        metavar="[0-9]",
        default=None,
        help="The zlib compression level to use. Lower is faster and bigger. "
        "WhatsApp used 1 historically and uses 9 now. "
        f"Default: the level of --reference, else {C.DEFAULT_COMPRESSION_LEVEL}.",
    )
    return parser.parse_args()


def main():
    """Main function"""
    # Parse the command line arguments
    args = parsecmdline()
    setup_logging(log, verbose=args.verbose)
    log.warning("This script is in beta stage")

    try:
        encrypt(args)
    except IntegrityError as e:
        log.critical("%s\n    Use --force to carry on anyway.", e)
        sys.exit(1)
    except WaCryptError as e:
        log.critical(str(e))
        sys.exit(1)


def compression_level_of(key, reference, stream):
    """
    The zlib level the reference was compressed at, or None if it cannot be told.

    The level is part of what --reference reproduces: a backup from the era when WhatsApp
    compressed at 1 comes back out 3.5% larger at the current default of 9. The factory
    leaves the stream on the first ciphertext byte, so the level is two bytes away.
    """
    head = AES.new(key.get(), AES.MODE_GCM, reference.get_iv()).decrypt(stream.read(2))
    level = C.ZLIB_HEADER_LEVELS.get(head)
    if level is None:
        # A multi-file reference is a ZIP, and --no-compress leaves anything at all there.
        log.warning(
            "Cannot tell the compression level of the reference: it starts %s, which is not a zlib header. Using %d.",
            head.hex(),
            C.DEFAULT_COMPRESSION_LEVEL,
        )
    else:
        log.debug("Reference was compressed at level %d", level)
    return level


def encrypt(args):
    # Before anything else, and before the output is opened: refusing after the fact would
    # mean the file had already been emptied.
    if Path(args.encrypted).is_file() and not args.yes:
        log.fatal("The output file already exists. Use --yes to overwrite it.")
        sys.exit(1)
    # Read the key file
    key = KeyFactory.new(args.keyfile)
    # If specified, use the IV from the command line
    iv = None
    props = None
    prefix = None
    feature_table = None
    if not args.reference:
        if args.iv:
            iv = bytes.fromhex(args.iv)
        # Create the props object from the command line arguments
        props = Props(
            wa_version=args.wa_version,
            jid=args.jid,
            max_feature=args.max_feature,
            features=args.enable_features,
            backup_version=args.backup_version,
        )
    else:
        try:
            reference = DatabaseFactory.from_file(args.reference)
        except IntegrityError as e:
            if not args.force:
                raise
            log.error("%s\n    Continuing anyway because --force was given.", e)
            reference = e.data
        iv: bytes = reference.get_iv()
        props = reference.props
        # The reference's own header, carried through to the output: it may hold fields this
        # schema does not model, and reproducing the reference means keeping them.
        prefix = reference.prefix
        feature_table = reference.feature_table
        if args.compression_level is None:
            args.compression_level = compression_level_of(key, reference, args.reference)
    if args.compression_level is None:
        args.compression_level = C.DEFAULT_COMPRESSION_LEVEL
    data = args.decrypted.read()
    if args.type == 15:
        db = Database15(iv=iv)
    elif args.type == 14:
        db = Database14(iv=iv)
    else:
        db = Database12(key=key, iv=iv)
    db.prefix = prefix
    db.feature_table = feature_table
    if args.no_compress:
        encrypted = db.encrypt(key, props, data)
    else:
        compressed = zlib.compress(data, args.compression_level)
        encrypted = db.encrypt(key, props, compressed)
    Path(args.encrypted).write_bytes(encrypted)
    log.info("Done!")
    args.decrypted.close()


if __name__ == "__main__":
    main()
