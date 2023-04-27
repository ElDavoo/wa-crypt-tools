#!/usr/bin/env python
"""
This script transforms a hex string in an encrypted_backup.key file.
"""
from __future__ import annotations

import argparse

# noinspection PyPackageRequirements
# This is from javaobj-py3

import javaobj


# encrypted_backup.key file format:
# The encrypted_backup.key file is a serialized Java object, composed by:
# 1) A byte array of 32 bytes, which is the key.

class Log:
    """Simpler logger class. Supports 2 verbosity levels."""

    @staticmethod
    def i(msg: str):
        """Always prints message."""
        print('[I] {}'.format(msg))

    @staticmethod
    def f(msg: str):
        """Always prints message and exit."""
        print('[F] {}'.format(msg))
        exit(1)


def from_hex(string: str) -> bytes:
    """Converts a hex string into a bytes array"""
    if len(string) != 64:
        Log.f("Wrong string length: It's {} but should be 64 characters long".format(len(string)))

    barr = None
    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        Log.f("Couldn't convert the hex string.\n"
              "Exception: {}".format(e))
    if len(barr) != 32:
        Log.f("The key is not 32 bytes long but {} bytes long".format(len(barr)))
    return barr


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Creates an encrypted_backup.key from a hex string.')
    parser.add_argument('input', type=str, help='The raw decryption key.')
    parser.add_argument('output', nargs='?', type=argparse.FileType('wb'), default="encrypted_backup.key",
                        help='The output file. Default: encrypted_backup.key')
    return parser.parse_args()


def create_class_description() -> javaobj.JavaClass:
    """Builds a JavaByteArray class description using magic values"""
    description = javaobj.JavaClass()
    description.flags = 2
    description.name = '[B'
    description.serialVersionUID = -5984413125824719648
    return description


def serialize(j_key: javaobj.JavaByteArray, o_stream):
    """ Writes a serialized JavaByteArray to the o_stream output stream.
    This would be generally be done by javaobj.dumps(), but we must do
    what that function does by hand because of this issue:
    https://github.com/tcalmant/python-javaobj/issues/52
    """
    marshaller = javaobj.JavaObjectMarshaller()
    marshaller.object_obj = j_key
    marshaller.object_stream = o_stream
    marshaller._writeStreamHeader()
    marshaller.write_array(j_key)
    marshaller.object_stream.close()


def create_encrypted_backup_key_file(ikey: str, output):
    """Convert the key from a hex string to a java byte array"""

    key: bytes = from_hex(ikey)

    j_key: javaobj.JavaByteArray = javaobj.JavaByteArray(key, create_class_description())

    serialize(j_key=j_key, o_stream=output)


def main():
    args: argparse.Namespace = parsecmdline()
    create_encrypted_backup_key_file(ikey=args.input, output=args.output)
    Log.i("Done")


if __name__ == "__main__":
    main()
