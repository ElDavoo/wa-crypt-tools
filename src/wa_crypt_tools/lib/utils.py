import zlib

from javaobj import JavaByteArray
from javaobj.v2.beans import JavaArray, JavaClassDesc, ClassDescType

import logging

from wa_crypt_tools.lib.constants import C

l = logging.getLogger(__name__)


def test_decompression(test_data: bytes) -> bool:
    """Returns true if the SQLite header is valid.
    It is assumed that the data are valid.
    (If it is valid, it also means the decryption and decompression were successful.)"""

    # If we get a ZIP file header, return true
    if test_data[:4] == C.ZIP_HEADER:
        return True

    try:
        zlib_obj = zlib.decompressobj().decompress(test_data)
        # These two errors should never happen
        if len(zlib_obj) < 16:
            l.error("Test decompression: chunk too small")
            return False
        if zlib_obj[:15].decode('ascii') != 'SQLite format 3':
            l.error("Test decompression: Decryption and decompression ok but not a valid SQLite database")
            return False
        else:
            return True
    except zlib.error:
        return False


def create_jba(out: bytes) -> JavaByteArray:
    """Creates a JavaByteArray object from a bytes array"""
    # Create the classdesc
    cd = JavaClassDesc(ClassDescType.NORMALCLASS)
    cd.name = "[B"
    cd.superclass = None
    cd.serial_version_uid = -5984413125824719648
    cd.desc_flags = 2

    return JavaByteArray(out, classdesc=cd)

def hexstring2bytes(string: str) -> bytes:
    """Converts a hex string into a bytes array"""
    if len(string) != 64:
        l.critical("The key file specified does not exist.\n    "
                 "If you tried to specify the key directly, note it should be "
                 "64 characters long and not {} characters long.".format(len(string)))

    barr = None
    try:
        barr = bytes.fromhex(string)
    except ValueError as e:
        l.critical("Couldn't convert the hex string.\n    "
                 "Exception: {}".format(e))
    if len(barr) != 32:
        l.error("The key is not 32 bytes long but {} bytes long.".format(len(barr)))
    return barr

def javaintlist2bytes(barr: JavaArray) -> bytes:
    """Converts a javaobj bytearray which somehow became a list of signed integers back to a Python byte array"""
    out: bytes = b''
    for i in barr:
        out += i.to_bytes(1, byteorder='big', signed=True)
    return out