#!/usr/bin/env python
"""
This script transforms a password_data.key file into a hashcat hash.
"""
from __future__ import annotations

import argparse

# noinspection PyPackageRequirements
# This is from javaobj-py3
import javaobj.v2 as javaobj

from base64 import b64encode


# password_data.key file format:
# The password_data.key file is a serialized Java object, composed by:
# 1) An int (4 bytes), which should be the version of the format.
# The only known value for now is 1, so we only support this version.
# 2) The encoded password (32 bytes), encoded with PBKDF2-HMAC-SHA512.
# PBKDF2 needs a salt and a permutation number, which are written after:
# 3) The salt (32 bytes), which is a random byte array.
# 4) The permutation number (4 bytes), which is an int. For now seems to be fixed at 100000.
# The script parses the permutation number for the file, so if it changes, no problem.

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


def parsecmdline() -> argparse.Namespace:
    """Sets up the argument parser"""
    parser = argparse.ArgumentParser(description='Gives a hashcat representation of the password data key')
    parser.add_argument('passworddatakeyfile', nargs='?', type=argparse.FileType('rb'), default="password_data.key",
                        help='The WhatsApp password data keyfile. Default: password_data.key')
    return parser.parse_args()


def barrtoint(barr: javaobj.beans.BlockData) -> int:
    """Converts a javaobj BlockData to an int"""
    return int.from_bytes(barr.data, byteorder='big', signed=False)


def javaintlist2bytes(barr: javaobj.beans.JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr.data:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out


def read_password_data_key(passworddatakeyfilestream) -> str:
    # Assign variables to suppress warnings
    deserialized: list = list()

    try:
        deserialized: list = javaobj.load(passworddatakeyfilestream)
    except OSError as e:
        Log.f("Couldn't read keyfile: {}".format(e))
    except (ValueError, RuntimeError) as e:
        Log.f("The keyfile is not a valid Java object: {}".format(e))

    if len(deserialized) != 4:
        Log.f("The keyfile has more fields than expected.")

    version: int = barrtoint(deserialized[0])
    if version != 1:
        Log.f("Unexpected key version: {}".format(version))

    encoded = javaintlist2bytes(deserialized[1])
    if len(encoded) != 64:
        Log.f("The encoded password has the wrong length")

    salt = javaintlist2bytes(deserialized[2])
    if len(salt) != 64:
        Log.f("The salt has the wrong length")

    permutations: int = barrtoint(deserialized[3])
    if permutations != 100000:
        Log.i("Unexpected permutation number: {}".format(permutations))

    return "sha512:{}:{}:{}".format(
        permutations,
        b64encode(salt).decode('ascii'),
        b64encode(encoded).decode('ascii')
    )


def main():
    args = parsecmdline()
    Log.i("Remember: hashcat mode is 12100 (PBKDF2-HMAC-SHA512)")
    pwd_hash = read_password_data_key(args.passworddatakeyfile)
    print(pwd_hash)


if __name__ == "__main__":
    main()
