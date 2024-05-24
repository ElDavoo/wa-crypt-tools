#!/usr/bin/env python
"""
This script decrypts WhatsApp's DB files encrypted with Crypt12, Crypt14 or Crypt15.
"""

from __future__ import annotations

import os
from pathlib import Path

from wa_crypt_tools.lib.key.key14 import Key14
from wa_crypt_tools.lib.key.key15 import Key15
from wa_crypt_tools.lib.logformat import CustomFormatter
import argparse

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2023'
__license__ = 'GPLv3'
__status__ = 'Production'

import logging

lo = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Create a key or encrypted_backup.key from a hex input.'
                                                 'The only parameter a encrypted_backup.key stores is the key itself.')
    parser.add_argument('-c14', '--crypt14', action='store_true', default=False, help='Create a traditional key file.')
    parser.add_argument('-o', '--output', type=argparse.FileType('wb'),
                        help='The output file')
    parser.add_argument('-y', '--yes', action='store_true', help='Overwrite the output file if it exists.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all messages')
    parser.add_argument('--hex', type=str, nargs='?', help='The hex string to convert to a key')

    parser.add_argument('-cv', '--cipher-version', type=int, help='The cipher version to use. Default: 1')
    parser.add_argument('-kv', '--key-version', type=int, help='The key version to use. Default: 3')
    parser.add_argument('-ss', '--server-salt', type=str, help='The server salt to use. Default: random')
    parser.add_argument('-gi', '--googleid', type=str, help='The google id salt to use. Default: random')

    return parser.parse_args()


def main():
    args = parsecmdline()

    # set wa_crypt_tools l to debug
    lo.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    ch.setFormatter(CustomFormatter())
    lo.addHandler(ch)

    if args.hex is None:
        lo.warning("Key not specified, a random key will be generated.")

    if args.output is None:
        args.output = "key" if args.crypt14 else "encrypted_backup.key"

    if args.crypt14:
        if args.cipher_version is None:
            args.cipher_version = 1
        if args.key_version is None:
            args.key_version = 3
        if args.server_salt is None:
            lo.warning("Server salt not specified, a random one will be generated.")
        if args.googleid is None:
            lo.warning("Google id not specified, a random one will be generated.")
        key: Key14 = Key14(cipher_version=args.cipher_version.to_bytes(2, "big"),
                           key_version=args.key_version.to_bytes(1, "big"),
                           serversalt=args.server_salt, googleid=args.googleid,
                           iv=None, key=None)
    else:
        if args.cipher_version is not None:
            lo.warning("Cipher version specified, but it is not used for crypt15 keys, ignoring.")
        if args.key_version is not None:
            lo.warning("Key version specified, but it is not used for crypt15 keys, ignoring.")
        if args.server_salt is not None:
            lo.warning("Server salt specified, but it is not used for crypt15 keys, ignoring.")
        if args.googleid is not None:
            lo.warning("Google id specified, but it is not used for crypt15 keys, ignoring.")
        key: Key15 = Key15(keyarray=bytes.fromhex(args.hex) if args.hex is not None else None)

    # Check if the output file exists
    output_file = Path(args.output)
    print(os.getcwd())
    if output_file.is_file() and not args.yes:
        lo.fatal("The output file already exists.")
        return

    # Write the key file
    key.file_dump(output_file)

    lo.info("Key file \"{}\" created.".format(args.output))


if __name__ == "__main__":
    main()
