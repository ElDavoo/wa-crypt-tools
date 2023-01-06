from __future__ import annotations

import collections
import zlib
from sys import exit
# noinspection PyPackageRequirements
# This is from javaobj-py3
from javaobj import v2 as javaobj

from src.lib.constants import ZIP_HEADER


class SimpleLog:
    """Simple logger class. Supports 4 verbosity levels."""

    def __init__(self, verbose: bool, force: bool):
        self.verbose = verbose
        self.force = force

    def v(self, msg: str):
        """Will only print message if verbose mode is enabled."""
        if self.verbose:
            print('[V] {}'.format(msg))

    @staticmethod
    def i(msg: str):
        """Always prints message."""
        print('[I] {}'.format(msg))

    def e(self, msg: str):
        """Prints message and exit, unless force is enabled."""
        print('[E] {}'.format(msg))
        if not self.force:
            print("To bypass checks, use the \"--force\" parameter")
            exit(1)

    @staticmethod
    def f(msg: str):
        """Always prints message and exit."""
        print('[F] {}'.format(msg))
        exit(1)


def from_hex(logger, string: str) -> bytes:
    """Converts a hex string into a bytes array"""
    if len(string) != 64:
        logger.f("The key file specified does not exist.\n    "
                 "If you tried to specify the key directly, note it should be "
                 "64 characters long and not {} characters long.".format(len(string)))

    barr = None
    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        logger.f("Couldn't convert the hex string.\n    "
                 "Exception: {}".format(e))
    if len(barr) != 32:
        logger.e("The key is not 32 bytes long but {} bytes long.".format(len(barr)))
    return barr


def oscillate(n: int, n_min: int, n_max: int) -> collections.Iterable:
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
        i = i - c
        c = c + 1

        if i == 0 or i == n_min:
            break
        yield i
        i = i + c
        c = c + 1

    # Second phase (range of remaining numbers)
    # n != i/2 fixes a bug where we would yield min and max two times if n == (max-min)/2
    if i == n_min and n != i / 2:

        yield i
        i = i + c
        for j in range(i, n_max + 1):
            yield j

    if i == n_max and n != i / 2:

        yield n_max
        i = i - c
        for j in range(i, n_min - 1, -1):
            yield j


def test_decompression(logger, test_data: bytes) -> bool:
    """Returns true if the SQLite header is valid.
    It is assumed that the data are valid.
    (If it is valid, it also means the decryption and decompression were successful.)"""

    # If we get a ZIP file header, return true
    if test_data[:4] == ZIP_HEADER:
        return True

    try:
        zlib_obj = zlib.decompressobj().decompress(test_data)
        # These two errors should never happen
        if len(zlib_obj) < 16:
            logger.e("Test decompression: chunk too small")
            return False
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            logger.e("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return logger.force
        else:
            return True
    except zlib.error:
        return False


def javaintlist2bytes(barr: javaobj.beans.JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out
