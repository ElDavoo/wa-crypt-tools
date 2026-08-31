#!/usr/bin/env python
"""
This script decrypts a WhatsApp incremental backup and prints or exports the messages
found inside it.

`msgstore-increment-N.db.crypt15` is written by current WhatsApp Android alongside (or
instead of refreshing) the full `msgstore.db.crypt15` snapshot. `wadecrypt` already
decrypts it correctly -- decryption is payload-agnostic here, see `wadecrypt --help` --
but the result is a ZIP, not a SQLite database, and the messages inside it are protobuf,
not SQL rows. This is the tool that reads what comes out. See issue #129.
"""

from __future__ import annotations

import argparse
import json
import logging

from wa_crypt_tools.lib.db.dbfactory import DatabaseFactory
from wa_crypt_tools.lib.errors import WaCryptError
from wa_crypt_tools.lib.increment import is_incremental_backup, read_header, read_messages
from wa_crypt_tools.lib.key.keyfactory import KeyFactory
from wa_crypt_tools.lib.logformat import setup_logging

__author__ = 'ElDavo'
__copyright__ = 'Copyright (C) 2026'
__license__ = 'GPLv3'
__status__ = 'Beta'

log = logging.getLogger(__name__)


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(
        description='Decrypts a WhatsApp incremental backup and prints or exports its messages')
    parser.add_argument('keyfile', nargs='?', type=str, default="encrypted_backup.key",
                        help='The WhatsApp encrypted_backup key file or the hex encoded key. '
                             'Default: encrypted_backup.key')
    parser.add_argument('encrypted', nargs='?', type=argparse.FileType('rb'),
                        default="msgstore-increment-1.db.crypt15",
                        help='The encrypted incremental backup file. '
                             'Default: msgstore-increment-1.db.crypt15')
    parser.add_argument('-o', '--output', type=str,
                        help='Write the messages as a JSON array to this file, instead of '
                             'printing a one-line summary per message to stdout.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Prints all offsets and messages')
    return parser.parse_args()


def main():
    args = parsecmdline()
    setup_logging(log, verbose=args.verbose)
    log.warning("This script is in beta stage, and the message schema it reads is "
                "reverse-engineered, not published by WhatsApp -- see proto/NOTICE.md")
    try:
        run(args)
    except WaCryptError as e:
        log.critical(str(e))
        exit(1)


def run(args: argparse.Namespace):
    key = KeyFactory.new(args.keyfile)
    log.debug(str(key))

    db = DatabaseFactory.from_file(args.encrypted)
    payload = db.decrypt(key, args.encrypted.read())

    if not is_incremental_backup(payload):
        log.critical("This does not look like an incremental backup (no header.json + "
                     "messages.bin inside). Did you mean to use wadecrypt instead?")
        exit(1)

    header = read_header(payload)
    added = header.get("added_messages") or {}
    log.info("WhatsApp version: {}".format(header.get("header", {}).get("app_version", "?")))
    log.info("Messages on backup: {}, updated: {}, deleted: {}".format(
        added.get("messages_count_on_backup"),
        added.get("messages_updated"),
        added.get("messages_deleted"),
    ))

    messages = list(read_messages(payload))
    log.info("Parsed {} message(s)".format(len(messages)))

    if args.output:
        with open(args.output, 'w') as f:
            json.dump([m.__dict__ for m in messages], f, indent=2, ensure_ascii=False)
        log.info("Wrote {} message(s) to {}".format(len(messages), args.output))
    else:
        for m in messages:
            preview = (m.text or "").replace("\n", " ")[:60]
            print("{}\t{}\t{}\t{}\t{}".format(
                m.timestamp, m.chat_jid, m.sender_jid,
                "me" if m.from_me else "them", preview))


if __name__ == "__main__":
    main()
