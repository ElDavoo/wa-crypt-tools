import argparse
import hashlib
import os
import zlib
import logging

from wa_crypt_tools.lib.constants import C
from wa_crypt_tools.lib.db.db import Database
from wa_crypt_tools.lib.db.db12 import Database12
from wa_crypt_tools.lib.db.db14 import Database14
from wa_crypt_tools.lib.db.db15 import Database15
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.key import Key
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.logformat import CustomFormatter
from wa_crypt_tools.lib.props import Props

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Parses the command line arguments."""
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Encrypts a file in Crypt14 or Crypt15 format.')
    parser.add_argument('keyfile', nargs='?', type=str, default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file or the hex encoded key. '
                             'Default: encrypted_backup.key')
    parser.add_argument('decrypted', nargs='?', type=argparse.FileType('rb'), default="msgstore.db",
                        help='The input file. Default: msgstore.db')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('wb'), default="msgstore.db.crypt15",
                        help='The encrypted crypt15 or crypt14 file. Default: msgstore.db.crypt15')
    parser.add_argument('-f', '--force', action='store_true',
                        help='Makes errors non fatal. Default: false')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')
    parser.add_argument('--enable-features', type=int, nargs='*', default=C.DEFAULT_FEATURE_LIST,
                        help='Enables the specified features. ')
    parser.add_argument('--max-feature', type=int, default=39,
                        help='The max feature number, the older is the backup the lower should be the number. ')
    parser.add_argument('--multi-file', action='store_true',
                        help='Encrypts a multi-file backup (either stickers or wallpapers)')
    parser.add_argument('--type', type=int, choices=[12, 14, 15], default=15,
                        help='The type of encryption to use. Default: 15')
    parser.add_argument('--iv', type=str, help='The IV to use for crypt15 encryption. Default: random')
    parser.add_argument('--reference', type=argparse.FileType('rb'),
                        help='The reference file to use for crypt15 encryption. Highly recommended.')
    parser.add_argument('--noparse', action='store_true',
                        help='Do not parse the header of the reference file. Default: false')
    parser.add_argument('--wa-version', type=str, default=C.DEFAULT_APP_VERSION,
                        help='The WhatsApp version to use for crypt15 encryption. Default:' +
                             C.DEFAULT_APP_VERSION)
    parser.add_argument('--jid', type=str, default=C.DEFAULT_JID_SUFFIX,
                        help='The last 2 numbers of your phone number. Default: 00')
    parser.add_argument('--backup-version', type=int, default=C.DEFAULT_BACKUP_VERSION,
                        help='The backup version to use in the header of the encrypted file. Default: 0')
    parser.add_argument('--no-compress', action='store_true',
                        help='Do not compress the file. This will make the backup not working. Only used in development. Default: false')
    return parser.parse_args()


def main():
    """Main function"""
    # Parse the command line arguments
    args = parsecmdline()
    # set wa_crypt_tools l to debug
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch.setFormatter(CustomFormatter())
    log.addHandler(ch)
    log.warning("This script is in beta stage")

    # Read the key file
    key = KeyFactory.new(args.keyfile)
    # If specified, use the IV from the command line
    iv = None
    props = None
    if not args.reference:
        if args.iv:
            iv = bytes.fromhex(args.iv)
        # Create the props object from the command line arguments
        props = Props(wa_version=args.wa_version, jid=args.jid, max_feature=args.max_feature,
                      features=args.enable_features, backup_version=args.backup_version)
    else:
        reference = DatabaseFactory.from_file(args.reference)
        iv: bytes = reference.get_iv()
        props = reference.props
    data = args.decrypted.read()
    if args.type == 15:
        db = Database15(key=key, iv=iv)
    elif args.type == 14:
        db = Database14(key=key, iv=iv)
    else:
        db = Database12(key=key, iv=iv)
    if args.no_compress:
        encrypted = db.encrypt(key, props, data)
    else:
        compressed = zlib.compress(data, 1)
        encrypted = db.encrypt(key, props, compressed)
    args.encrypted.write(encrypted)
    # Close the files
    log.info("Done!")
    args.decrypted.close()
    args.encrypted.close()


if __name__ == '__main__':
    main()
