#!/usr/bin/env python
"""
This script prints info on WhatsApp's DB files.
"""

from __future__ import annotations

from wa_crypt_tools.lib.logformat import CustomFormatter
from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.key.keyfactory import KeyFactory

import argparse

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2024'
__license__ = 'GPLv3'
__status__ = 'Beta'

import logging

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Prints info on whatsapp crypted files')
    parser.add_argument('encrypted', nargs='?',
                        type=str,
                        default="msgstore.db.crypt15",
                        help='The encrypted crypt12, 14 or 15 file. Default: msgstore.db.crypt15')
    parser.add_argument('-k', '--key',
                        action='store_true',
                        help='tell the program that the file is a key file')
    return parser.parse_args()


def main():
    args = parsecmdline()

    # set wa_crypt_tools l to debug
    log.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    log.addHandler(ch)
    # also add to "wa_crypt_tools.lib" logger
    logging.getLogger("wa_crypt_tools.lib").addHandler(ch)
    logging.getLogger("wa_crypt_tools.lib").setLevel(logging.DEBUG)

    log.warning("This script is in beta stage.")

    if args.key:
        key = KeyFactory.from_file(args.encrypted)
        print(key)
        return
    try:
        DatabaseFactory.from_file(open(args.encrypted, 'rb'))
    except Exception as e:
        log.error("Error: {}".format(e))
        return
        # TODO
    # print(db)


if __name__ == "__main__":
    main()
