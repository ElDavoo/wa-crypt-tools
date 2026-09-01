#!/usr/bin/env python
"""
This script prints info on WhatsApp's DB files.
"""

from __future__ import annotations

import argparse
import sys

from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import IntegrityError, WaCryptError
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.logformat import setup_logging

__author__ = "ElDavo"
__copyright__ = "Copyright (C) 2024"
__license__ = "GPLv3"
__status__ = "Beta"

import logging

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description="Prints info on whatsapp crypted files")
    parser.add_argument(
        "encrypted",
        nargs="?",
        type=str,
        default="msgstore.db.crypt15",
        help="The encrypted crypt12, 14 or 15 file. Default: msgstore.db.crypt15",
    )
    parser.add_argument("-k", "--key", action="store_true", help="tell the program that the file is a key file")
    return parser.parse_args()


def main():
    args = parsecmdline()

    setup_logging(log, verbose=True)

    log.warning("This script is in beta stage.")

    try:
        if args.key:
            print(KeyFactory.from_file(args.encrypted))
            return
        with open(args.encrypted, "rb") as f:
            print(DatabaseFactory.from_file(f))
    except IntegrityError as e:
        # This tool only reports on a file, so show what could be read off it and say why
        # it is suspect, rather than refusing to print anything.
        log.error(str(e))
        if e.data is not None:
            print(e.data)
        sys.exit(1)
    except WaCryptError as e:
        log.critical(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
